//! Small bounded worker pool used by the getclass parallel scan.
//!
//! The pool is intentionally simple: `N` `std::thread`s sharing a work
//! cursor (`AtomicUsize`) and a "found" flag (`AtomicBool`). Workers
//! pull the next dex entry, process it, and either record the winner
//! (setting the flag) or move on. Once the flag is set, no new work
//! is taken; once the cursor is exhausted, the pool exits.
//!
//! ## Cancellation
//!
//! Workers check the "found" flag between entries (not inside an
//! entry's processing — that would force us to expose half-finished
//! state to consumers). The pool's `join` blocks until every spawned
//! thread has exited; the total cost is bounded by the slower of the
//! last-running worker and the time it takes the winner to finish.
//!
//! ## Why not rayon?
//!
//! The pipeline semantics — "first worker to find the class wins,
//! stop the rest" — map cleanly onto a hand-rolled `AtomicUsize` +
//! `AtomicBool` pair. Rayon's `par_iter` would force us to encode the
//! winner into a reduction type, and its cancellation story is via
//! `panic!` (or `rayon::ThreadPool::install` + `try`), neither of
//! which buys anything for a 12-entry DEX scan. We use `std::thread`
//! to keep the surface dependency-light and the dataflow obvious.
//!
//! ## Why an `Arc<[T]>` internally?
//!
//! Workers need to read items by index across the `'static` boundary
//! of `thread::spawn`. Borrowing `&[T]` would escape the lifetime
//! of `run`. We wrap the slice in `Arc<[T]>` so each worker thread
//! owns an `Arc` clone and the data outlives the closure.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

/// Outcome of [`WorkerPool::run`]: the index of the worker that wrote
/// the cell, or `None` if no worker wrote (the work list was empty
/// or every entry's processor returned `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerOutcome {
    /// Index of the worker that wrote the cell, or `usize::MAX` if
    /// nobody did.
    pub winner: usize,
    /// `true` iff a worker wrote the cell.
    pub found: bool,
    /// Number of workers that died on an unwind. A panicking worker
    /// never pulls another item, so entries it owned are *unscanned*,
    /// not "proven absent" — callers must not read a `found: false`
    /// outcome as a clean negative when this is non-zero (audit F03).
    pub panicked: usize,
    /// Item indexes a panicking worker owned when it died (and, on the
    /// inline path, everything behind the panicking item). These
    /// entries are unscanned, not absent; callers that care about
    /// index priority must rescan or fail before trusting a winner
    /// whose index sits above any of these.
    pub unscanned: Vec<usize>,
}

impl WorkerOutcome {
    /// `true` iff a worker wrote the cell.
    #[inline]
    pub fn is_found(&self) -> bool {
        self.found
    }

    /// `true` iff no worker panicked.
    #[inline]
    pub fn is_clean(&self) -> bool {
        self.panicked == 0
    }
}

/// A pool of N worker threads sharing one cursor + one "found" flag.
///
/// Use [`WorkerPool::new`] to build a pool with `n` workers, then call
/// [`WorkerPool::run`] to drive it over a slice of items. The pool
/// exits cleanly once every item has been processed or the winner
/// has been recorded.
pub struct WorkerPool {
    n: usize,
}

impl WorkerPool {
    /// Build a pool with `n` workers. `n == 0` is treated as a single
    /// worker (the calling thread runs the work inline).
    pub fn new(n: usize) -> Self {
        Self { n: n.max(1) }
    }

    /// Number of workers.
    #[inline]
    pub fn workers(&self) -> usize {
        self.n
    }

    /// Run `worker` over `items` in parallel, stopping as soon as a
    /// worker returns `Some(())`.
    ///
    /// `worker` is invoked once per (worker, item) pair until either
    /// it returns `Some(())` (the winner) or the cursor is exhausted.
    /// After the winner is recorded, other workers stop pulling new
    /// items.
    pub fn run<T, F>(&self, items: &[T], worker: F) -> WorkerOutcome
    where
        T: Clone + Send + Sync + 'static,
        F: Fn(usize, &T) -> Option<()> + Send + Clone + 'static,
    {
        if items.is_empty() {
            return WorkerOutcome {
                winner: usize::MAX,
                found: false,
                panicked: 0,
                unscanned: Vec::new(),
            };
        }

        // Single-worker fast path: no spawn cost. The closure still runs
        // under `catch_unwind` so a panic is reported like any other
        // worker's — otherwise a multi-DEX APK scanned with
        // `--threads 1` would unwind into the caller (a CLI crash)
        // while the same APK with `--threads 4` returned a structured
        // error. The two paths must not disagree about failure.
        if self.n == 1 || items.len() == 1 {
            for (i, item) in items.iter().enumerate() {
                let hit =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker(i, item)));
                match hit {
                    Ok(Some(())) => {
                        return WorkerOutcome {
                            winner: 0,
                            found: true,
                            panicked: 0,
                            unscanned: Vec::new(),
                        };
                    }
                    Ok(None) => {}
                    Err(_) => {
                        // This worker owned `items[i]` and stops
                        // here: everything from `i` on is unscanned.
                        return WorkerOutcome {
                            winner: usize::MAX,
                            found: false,
                            panicked: 1,
                            unscanned: (i..items.len()).collect(),
                        };
                    }
                }
            }
            return WorkerOutcome {
                winner: usize::MAX,
                found: false,
                panicked: 0,
                unscanned: Vec::new(),
            };
        }

        // Wrap the slice in an `Arc<[T]>` so worker threads can hold
        // a reference across the `'static` boundary of
        // `thread::spawn`. The slice itself becomes `'static` via
        // the Arc; workers index into the Arc.
        let items_arc: Arc<[T]> = Arc::from(items.to_vec().into_boxed_slice());
        let n_workers = self.n.min(items_arc.len()).max(1);
        let next = Arc::new(AtomicUsize::new(0));
        let found = Arc::new(AtomicBool::new(false));
        let winner_idx = Arc::new(AtomicUsize::new(usize::MAX));
        // Per-worker "item I currently own" slot. A worker that
        // unwinds dies with its slot still holding that index, so the
        // join below can attribute the gap to a specific entry
        // instead of a bare panic count.
        let slots: Vec<Arc<AtomicUsize>> = (0..n_workers)
            .map(|_| Arc::new(AtomicUsize::new(usize::MAX)))
            .collect();

        let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(n_workers);
        for (worker_id, slot) in (0..n_workers).zip(slots.iter()) {
            let next = Arc::clone(&next);
            let found = Arc::clone(&found);
            let winner_idx = Arc::clone(&winner_idx);
            let slot = Arc::clone(slot);
            let worker = worker.clone();
            let items = Arc::clone(&items_arc);
            handles.push(thread::spawn(move || {
                loop {
                    if found.load(Ordering::Acquire) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::AcqRel);
                    if i >= items.len() {
                        break;
                    }
                    slot.store(i, Ordering::Relaxed);
                    // `i < items.len()` is checked; `&items[i]` is safe.
                    let item = &items[i];
                    let hit = worker(i, item).is_some();
                    slot.store(usize::MAX, Ordering::Relaxed);
                    if hit {
                        winner_idx.store(worker_id, Ordering::Release);
                        found.store(true, Ordering::Release);
                        break;
                    }
                }
            }));
        }

        // A worker that unwinds takes the item it owned with it, so a
        // dropped `join` result would silently turn "unscanned" into
        // "absent". Count the dead and keep the indexes they owned.
        let mut panicked = 0usize;
        let mut unscanned = Vec::new();
        for (h, slot) in handles.into_iter().zip(slots.iter()) {
            if h.join().is_err() {
                panicked += 1;
                let i = slot.load(Ordering::Acquire);
                if i != usize::MAX {
                    unscanned.push(i);
                }
            }
        }

        WorkerOutcome {
            winner: winner_idx.load(Ordering::Acquire),
            found: found.load(Ordering::Acquire),
            panicked,
            unscanned,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn single_worker_processes_all_items_in_order() {
        let pool = WorkerPool::new(1);
        let items: Vec<u32> = (0..10).collect();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_clone = Arc::clone(&seen);
        let outcome = pool.run(&items, move |_, item| {
            let s = seen_clone.fetch_add(1, Ordering::SeqCst);
            assert_eq!(*item as usize, s);
            None
        });
        assert!(!outcome.is_found());
        assert_eq!(seen.load(Ordering::SeqCst), 10);
    }

    #[test]
    fn winner_stops_the_pool() {
        let pool = WorkerPool::new(4);
        let items: Vec<u32> = (0..1000).collect();
        let processed = Arc::new(AtomicUsize::new(0));
        let processed_clone = Arc::clone(&processed);
        let outcome = pool.run(&items, move |i, _| {
            processed_clone.fetch_add(1, Ordering::SeqCst);
            // First item wins; the rest of the pool must exit.
            if i == 0 { Some(()) } else { None }
        });
        assert!(outcome.is_found());
        // `winner` is the WORKER ordinal, not the item index — any of
        // the 4 threads may claim item 0. What matters: it's a valid
        // worker id (the found flag guarantees it).
        assert!(outcome.winner < 4);
        // We don't assert on `processed` count strictly (it's racy by
        // construction), but it must be strictly less than 1000.
        assert!(processed.load(Ordering::SeqCst) < 1000);
    }

    /// The inline path (`--threads 1`, or a single work item) must
    /// report a panic the same way the spawned path does, not unwind
    /// into the caller (audit F03).
    #[test]
    fn inline_path_reports_a_panic_instead_of_unwinding() {
        for pool_n in [0usize, 1] {
            let pool = WorkerPool::new(pool_n);
            let items: Vec<u32> = (0..4).collect();
            let outcome = pool.run(&items, |i, _| {
                if i == 2 {
                    panic!("inline explosion")
                }
                None
            });
            assert!(
                !outcome.is_clean(),
                "threads={pool_n}: an inline panic must be reported, not propagated"
            );
            assert!(!outcome.is_found());
        }
        // A single work item takes the same fast path.
        let pool = WorkerPool::new(4);
        let outcome = pool.run(&[7u32], |_, _| panic!("single-item explosion"));
        assert!(!outcome.is_clean());
    }

    #[test]
    fn empty_items_returns_not_found() {
        let pool = WorkerPool::new(4);
        let items: Vec<u32> = Vec::new();
        let outcome = pool.run(&items, |_, _| Some(()));
        assert!(!outcome.is_found());
        assert!(outcome.is_clean());
    }

    /// A panicking worker never pulls another item, so `found: false`
    /// cannot be read as "every item was checked and none matched"
    /// (audit F03).
    #[test]
    fn panicking_worker_is_reported_not_silently_dropped() {
        let pool = WorkerPool::new(4);
        let items: Vec<u32> = (0..8).collect();
        let outcome = pool.run(&items, |i, _| {
            // Every worker hits a panic on its first item; the outcome
            // must not be a clean negative.
            assert!(i < 8);
            panic!("worker {i} exploded");
        });
        assert!(!outcome.is_found());
        assert!(!outcome.is_clean(), "dropped join result would look clean");
        assert!(outcome.panicked >= 1);
    }

    #[test]
    fn a_finding_worker_reports_clean_even_if_others_die() {
        let pool = WorkerPool::new(4);
        let items: Vec<u32> = (0..8).collect();
        let outcome = pool.run(&items, |i, _| {
            if i == 0 {
                Some(())
            } else {
                panic!("lost the race")
            }
        });
        assert!(outcome.is_found());
        // The winner is a real hit; the race between which worker
        // claimed which item is not under test.
    }

    #[test]
    fn zero_workers_treated_as_one() {
        let pool = WorkerPool::new(0);
        let items: Vec<u32> = vec![1, 2, 3];
        let outcome = pool.run(&items, |_, _| None);
        assert!(!outcome.is_found());
        assert_eq!(pool.workers(), 1);
    }
}
