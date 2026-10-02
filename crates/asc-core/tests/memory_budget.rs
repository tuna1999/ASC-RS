//! Regression tests for the process-wide scan-memory budget (P5).
//!
//! Contract under test:
//! - exceeding the budget produces a STRUCTURED error
//!   (`CoreError::MemoryBudget` for getclass/disasm/callees; a
//!   recorded per-DEX `SearchError` + `complete=false` for findrefs),
//!   never a panic or abort;
//! - partial results are kept (findrefs skips only the entry that
//!   does not fit);
//! - budgets large enough for the workload change nothing;
//! - the budget is process-wide: two concurrent scans share it —
//!   proven deterministically by holding a guard, not by hoping two
//!   threads race;
//! - worker contention on the budget never changes the getclass
//!   winner: a temporarily unreservable DEX is deferred and
//!   rescanned, never counted as "does not contain the class".

mod common;

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use asc_core::{
    CoreError, FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions, run_findrefs,
    run_getclass,
};
use asc_query::Query;
use common::{Dex, OBJECT, STRING, u, write_apk};

const NEEDLE: &str = "needlehunter";
const MAIN: &str = "Lp/Main;";
const OTHER: &str = "Lp/Other;";

/// Every test in this file both reads and mutates the process-wide
/// `in_flight` counter, and several use caps with tiny slack. Cargo
/// runs the tests of one binary in parallel threads, so without
/// serialization a guard held by one test could flake a tight-cap
/// neighbour. This lock makes the suite deterministic against
/// itself (it does NOT protect against other test binaries, which
/// cargo runs sequentially).
static BUDGET_LOCK: Mutex<()> = Mutex::new(());

fn suite_lock() -> MutexGuard<'static, ()> {
    BUDGET_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn needle_dex_for(class: &str, marker: &str, pad: usize) -> Vec<u8> {
    let mut method_ids: Vec<common::Member> = vec![(class.to_string(), "m", (STRING, vec![]))];
    let mut dummies: Vec<String> = Vec::with_capacity(pad);
    for i in 0..pad {
        let desc = format!("Lpad/Q{i};");
        dummies.push(desc.clone());
        method_ids.push((desc, "p", ("V", vec![])));
    }
    let dex = Dex::new(&[OBJECT, class], vec![], method_ids, &[u(marker)]);
    let idx = dex.string(&u(marker)) as u16;
    let insns = vec![0x001A, idx, 0x0011];
    let mut classes: Vec<common::ClassSpec<'_>> = dummies
        .iter()
        .map(|d| (d.as_str(), vec![], vec![("p", 0x0009, 0, 0, vec![0x000E])]))
        .collect();
    classes.push((class, vec![], vec![("m", 0x0009, 1, 0, insns)]));
    dex.finish(&classes)
}

fn needle_dex(marker: &str, pad: usize) -> Vec<u8> {
    needle_dex_for(MAIN, marker, pad)
}

fn mixed_apk(tag: &str) -> (std::path::PathBuf, usize, usize) {
    // classes.dex: small, defines Lp/Main; classes2.dex: padded, also
    // defines Lp/Main; (dup determinism is covered by duplicate_class.rs,
    // here only the sizes matter).
    let small = needle_dex(NEEDLE, 0);
    let big = needle_dex(NEEDLE, 700);
    let sizes = (small.len(), big.len());
    let apk = write_apk(
        tag,
        &[
            ("classes.dex", small),
            ("classes2.dex", big),
            ("classes3.dex", needle_dex(NEEDLE, 400)),
        ],
    );
    (apk, sizes.0, sizes.1)
}

fn getclass_with(
    apk: &Path,
    budget: usize,
    threads: usize,
) -> Result<asc_core::GetClassResult, CoreError> {
    let job = GetClassJob::new(apk.to_path_buf(), MAIN.to_string());
    let opts = GetClassOptions {
        threads,
        scan_budget_bytes: budget,
        ..Default::default()
    };
    run_getclass(&job, &opts)
}

fn getclass(apk: &Path, budget: usize) -> Result<asc_core::GetClassResult, CoreError> {
    getclass_with(apk, budget, 8)
}

#[test]
fn budget_too_small_is_structured_error_not_panic() {
    let _lock = suite_lock();
    let (apk, _, _) = mixed_apk("toosmall");
    for budget in [1, 8, 64] {
        match getclass(&apk, budget) {
            Err(CoreError::MemoryBudget(msg)) => {
                assert!(msg.contains("budget"), "msg: {msg}");
            }
            other => panic!("budget={budget}: expected MemoryBudget, got {other:?}"),
        }
    }
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn budget_exactly_fits_all_entries_succeeds() {
    let _lock = suite_lock();
    let (apk, _, _) = mixed_apk("exactfit");
    // 8 workers may hold all three entries at once; that is the worst
    // case, and a budget of (sum of all entries) + slack must pass.
    let sum: u64 = {
        let mut z = 0u64;
        let f = std::fs::File::open(&apk).unwrap();
        let mut zf = zip::ZipArchive::new(f).unwrap();
        for i in 0..zf.len() {
            z += zf.by_index(i).unwrap().size();
        }
        z
    };
    let result = getclass(&apk, sum as usize + 16);
    assert!(
        result.is_ok(),
        "budget={} should fit: {:?}",
        sum,
        result.err().map(|e| e.to_string())
    );
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn findrefs_budget_failure_keeps_partial_results() {
    let _lock = suite_lock();
    let (apk, small, big) = mixed_apk("graded");
    // Budget fits ONLY classes.dex (plus one corrupt-free margin), so
    // classes2/classes3 are skipped as per-DEX errors while the
    // classes.dex hits survive.
    let budget = small + 16;
    assert!(big > budget, "fixture must be graded small->big");
    let job = FindRefsJob::new(
        apk.clone(),
        Query::String {
            pattern: NEEDLE.to_string(),
        },
    );
    let opts = FindRefsOptions {
        scan_budget_bytes: budget,
        ..Default::default()
    };
    let report = run_findrefs(&job, &opts).expect("run_findrefs never fails per-DEX");
    assert!(!report.complete, "skipped entries must flip complete");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.to_string().contains("budget")),
        "errors: {:?}",
        report.errors
    );
    let scanned: Vec<&str> = report.results.iter().map(|r| r.dex_name.as_str()).collect();
    assert_eq!(
        scanned,
        vec!["classes.dex"],
        "partial results kept: {scanned:?}"
    );
    assert!(
        !report.results[0].matches.is_empty(),
        "the scanned DEX must carry its hits"
    );
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn default_budget_leaves_normal_runs_untouched() {
    let _lock = suite_lock();
    let (apk, _, _) = mixed_apk("defaults");
    // Zero = engine default (2 GiB): everything scans.
    assert!(getclass(&apk, 0).is_ok());
    let job = FindRefsJob::new(
        apk.clone(),
        Query::String {
            pattern: NEEDLE.to_string(),
        },
    );
    let report = run_findrefs(&job, &FindRefsOptions::default()).unwrap();
    assert!(report.complete);
    assert_eq!(report.results.len(), 3);
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn budget_is_process_wide_across_concurrent_runs() {
    // Deterministic proof, no scheduling dependence: hold the ENTIRE
    // budget via a guard on this thread, then prove a getclass on
    // ANOTHER thread is denied while the guard lives, and admitted
    // right after it drops. `join` is the synchronization point — the
    // remote run has fully returned before the guard is released, so
    // both outcomes are forced, not raced. A panic in the thread
    // propagates through `join().expect`; nothing can hang.
    let _lock = suite_lock();
    let small = needle_dex(NEEDLE, 0);
    let apk = write_apk("budget_guard", &[("classes.dex", small.clone())]);
    let budget = small.len();
    for round in 0..3 {
        let guard = asc_core::budget::acquire(budget, budget)
            .unwrap_or_else(|e| panic!("round {round}: budget must be free: {e:?}"));
        let a = apk.clone();
        let denied = std::thread::spawn(move || getclass(&a, budget).map(|_| ()))
            .join()
            .expect("denial round must not panic");
        match denied {
            Err(CoreError::MemoryBudget(_)) => {}
            other => panic!("round {round}: held guard must deny, got {other:?}"),
        }
        drop(guard);
        // Guard released: the very same run must now be admitted —
        // acquire → deny → drop → re-acquire round-trips.
        let admitted = getclass(&apk, budget);
        assert!(
            admitted.is_ok(),
            "round {round}: run after release must succeed: {:?}",
            admitted.err().map(|e| e.to_string())
        );
    }
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn budget_contention_never_changes_the_winner() {
    // All three DEXes define Lp/Main;. The budget fits ANY single
    // entry but never two (small+big and big+medium both exceed it),
    // so with 8 workers at least one entry is deferred every round.
    // The winner must still be classes.dex (lowest index) for every
    // thread count, every scheduling — and the run must never fail:
    // before the deferral fix, a refused worker treated its entry as
    // a miss and classes2.dex could win, or the run errored with a
    // spurious MemoryBudget even though every entry fits alone.
    let _lock = suite_lock();
    let (apk, small, big) = mixed_apk("contend");
    let medium = needle_dex(NEEDLE, 400).len();
    let budget = big;
    assert!(
        small + big > budget && medium + big > budget,
        "pairs must contend"
    );
    for threads in [1usize, 2, 4, 8] {
        for round in 0..10 {
            match getclass_with(&apk, budget, threads) {
                Ok(res) => assert_eq!(
                    res.dex_name, "classes.dex",
                    "threads={threads} round={round}: lowest DEX must win"
                ),
                Err(e) => panic!(
                    "threads={threads} round={round}: budget fits every single \
                     entry, run must succeed: {e:?}"
                ),
            }
        }
    }
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn first_dex_only_hit_survives_worker_contention() {
    // Only classes.dex defines Lp/Main; the padded classes2/3.dex do
    // not. Budget fits any single entry, so if a big entry grabs the
    // budget first, classes.dex is deferred — and must still be found
    // (previously the deferral was indistinguishable from "class
    // absent", yielding ClassNotFound or a spurious MemoryBudget).
    let _lock = suite_lock();
    let small = needle_dex(NEEDLE, 0);
    let big = needle_dex_for(OTHER, NEEDLE, 700);
    let mid = needle_dex_for(OTHER, NEEDLE, 400);
    let budget = big.len();
    let apk = write_apk(
        "deferfirst",
        &[
            ("classes.dex", small),
            ("classes2.dex", big),
            ("classes3.dex", mid),
        ],
    );
    for threads in [2usize, 4, 8] {
        for round in 0..10 {
            let res = getclass_with(&apk, budget, threads)
                .unwrap_or_else(|e| panic!("threads={threads} round={round}: {e:?}"));
            assert_eq!(res.dex_name, "classes.dex");
        }
    }
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn guard_releases_on_panic() {
    // The reservation is RAII: a worker that panics mid-scan must
    // return its bytes during unwinding, or every later run in the
    // process would inherit a permanently shrunken budget.
    let _lock = suite_lock();
    let h = std::thread::spawn(|| {
        let _g = asc_core::budget::acquire(1 << 20, 4096).unwrap();
        panic!("simulated worker panic");
    });
    assert!(h.join().is_err(), "thread must have panicked");
    assert_eq!(
        asc_core::budget::in_flight(),
        0,
        "guard must unwind-drop with its thread"
    );
}
