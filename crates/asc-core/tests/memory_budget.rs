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
//! - the budget is process-wide: two concurrent scans share it.

mod common;

use std::path::Path;

use asc_core::{
    CoreError, FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions, run_findrefs,
    run_getclass,
};
use asc_query::Query;
use common::{Dex, OBJECT, STRING, u, write_apk};

const NEEDLE: &str = "needlehunter";
const MAIN: &str = "Lp/Main;";

fn needle_dex(marker: &str, pad: usize) -> Vec<u8> {
    let mut method_ids: Vec<common::Member> = vec![(MAIN.to_string(), "m", (STRING, vec![]))];
    let mut dummies: Vec<String> = Vec::with_capacity(pad);
    for i in 0..pad {
        let desc = format!("Lpad/Q{i};");
        dummies.push(desc.clone());
        method_ids.push((desc, "p", ("V", vec![])));
    }
    let dex = Dex::new(&[OBJECT, MAIN], vec![], method_ids, &[u(marker)]);
    let idx = dex.string(&u(marker)) as u16;
    let insns = vec![0x001A, idx, 0x0011];
    let mut classes: Vec<common::ClassSpec<'_>> = dummies
        .iter()
        .map(|d| (d.as_str(), vec![], vec![("p", 0x0009, 0, 0, vec![0x000E])]))
        .collect();
    classes.push((MAIN, vec![], vec![("m", 0x0009, 1, 0, insns)]));
    dex.finish(&classes)
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

fn getclass(apk: &Path, budget: usize) -> Result<asc_core::GetClassResult, CoreError> {
    let job = GetClassJob::new(apk.to_path_buf(), MAIN.to_string());
    let opts = GetClassOptions {
        threads: 8,
        scan_budget_bytes: budget,
        ..Default::default()
    };
    run_getclass(&job, &opts)
}

#[test]
fn budget_too_small_is_structured_error_not_panic() {
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
    // Single-entry APKs: each run needs the whole entry. With a budget
    // of one entry, exactly one concurrent run may hold it; the other
    // must get the structured error (which one wins is scheduling —
    // the assertion is on the OUTCOME SET).
    let small = needle_dex(NEEDLE, 0);
    let apk = write_apk("budget_race", &[("classes.dex", small.clone())]);
    let budget = small.len();
    let a = apk.clone();
    let b = apk.clone();
    let h1 = std::thread::spawn(move || getclass(&a, budget).map(|_| ()));
    let h2 = std::thread::spawn(move || getclass(&b, budget).map(|_| ()));
    let r1 = h1.join().unwrap();
    let r2 = h2.join().unwrap();
    let oks = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    let denied = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, Err(CoreError::MemoryBudget(_))))
        .count();
    assert_eq!(oks, 1, "one run must win the budget (got {r1:?} / {r2:?})");
    assert_eq!(denied, 1, "the other must be denied structurally");
    let _ = std::fs::remove_file(&apk);
}
