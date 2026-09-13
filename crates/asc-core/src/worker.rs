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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerOutcome {
    /// Index of the worker that wrote the cell, or `usize::MAX` if
    /// nobody did.
    pub winner: usize,
    /// `true` iff some worker wrote the cell.
    pub found: bool,
}

impl WorkerOutcome {
    /// `true` iff a worker wrote the cell.
    #[inline]
    pub fn is_found(&self) -> bool {
        self.found
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
            };
        }

        // Single-worker fast path: no spawn cost.
        if self.n == 1 || items.len() == 1 {
            for (i, item) in items.iter().enumerate() {
                if worker(i, item).is_some() {
                    return WorkerOutcome {
                        winner: 0,
                        found: true,
                    };
                }
            }
            return WorkerOutcome {
                winner: usize::MAX,
                found: false,
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

        let mut handles: Vec<thread::JoinHandle<()>> = Vec::with_capacity(n_workers);
        for worker_id in 0..n_workers {
            let next = Arc::clone(&next);
            let found = Arc::clone(&found);
            let winner_idx = Arc::clone(&winner_idx);
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
                    // `i < items.len()` is checked; `&items[i]` is safe.
                    let item = &items[i];
                    if worker(i, item).is_some() {
                        winner_idx.store(worker_id, Ordering::Release);
                        found.store(true, Ordering::Release);
                        break;
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.join();
        }

        WorkerOutcome {
            winner: winner_idx.load(Ordering::Acquire),
            found: found.load(Ordering::Acquire),
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

    #[test]
    fn empty_items_returns_not_found() {
        let pool = WorkerPool::new(4);
        let items: Vec<u32> = Vec::new();
        let outcome = pool.run(&items, |_, _| Some(()));
        assert!(!outcome.is_found());
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
