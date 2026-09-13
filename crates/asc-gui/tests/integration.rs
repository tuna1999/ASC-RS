//! Integration test for `asc-gui`'s headless selfcheck path.
//!
//! Verifies the same flow the `--selfcheck` CLI flag runs: open
//! `corpus/apk/workload.apk` → session → class list → one findrefs
//! → one getclass → manifest parse. Skips when the corpus fixture is
//! missing (so a fresh checkout still builds).

use std::path::Path;

#[test]
fn selfcheck_on_workload_apk() {
    let apk = Path::new("corpus").join("apk").join("workload.apk");
    if !apk.exists() {
        eprintln!("corpus fixture missing; skipping");
        return;
    }
    let report = asc_gui::run_selfcheck(&apk).expect("selfcheck should succeed");
    assert!(report.dex_count >= 1, "expected at least one DEX");
    assert!(
        report.class_count > 0,
        "expected non-empty class list, got {}",
        report.class_count
    );
    assert_eq!(
        report.findrefs_query, "string \"ClockFace\"",
        "selfcheck query label changed unexpectedly"
    );
    // The workload corpus is synthetic (no AndroidManifest.xml), so
    // manifest fields may be None. Engine calls must still succeed.
    assert!(
        report.findrefs_complete,
        "findrefs must report complete=true on the workload corpus"
    );
    assert!(
        report.findrefs_errors == 0,
        "findrefs must report zero errors, got {}",
        report.findrefs_errors
    );
    assert!(
        report.decompiled_source_bytes > 0,
        "getclass must decompile a non-empty class, got {}",
        report.decompiled_source_bytes
    );
    assert!(
        !report.decompiled_class.is_empty(),
        "getclass must report a winning dex name"
    );
}

#[test]
fn open_session_then_list_classes() {
    let apk = Path::new("corpus").join("apk").join("workload.apk");
    if !apk.exists() {
        eprintln!("corpus fixture missing; skipping");
        return;
    }
    let session = asc_gui::WorkspaceSession::open(&apk).expect("open");
    assert!(!session.dex_entries().is_empty());
    let classes = session.all_classes().expect("classes");
    assert!(!classes.is_empty());
    // Every entry should have a non-empty descriptor and dex_name.
    for c in &classes {
        assert!(
            c.descriptor.starts_with('L'),
            "bad descriptor: {:?}",
            c.descriptor
        );
        assert!(!c.dex_name.is_empty());
    }
}

#[test]
fn findrefs_history_caps_at_max() {
    use asc_gui::{FindRefsHistoryEntry, MAX_FINDREFS_HISTORY, WorkspaceSession};
    let apk = Path::new("corpus").join("apk").join("workload.apk");
    if !apk.exists() {
        eprintln!("corpus fixture missing; skipping");
        return;
    }
    let session = WorkspaceSession::open(&apk).expect("open");
    // Push more than the cap; expect the oldest to be evicted.
    for i in 0..(MAX_FINDREFS_HISTORY + 5) {
        session.push_findrefs_history(FindRefsHistoryEntry {
            label: format!("q-{i}"),
            line_count: 0,
            complete: true,
        });
    }
    let h = session.findrefs_history();
    assert_eq!(h.len(), MAX_FINDREFS_HISTORY);
    // The most-recent entries survived; the oldest were evicted.
    assert_eq!(h.first().unwrap().label, format!("q-5"));
    assert_eq!(
        h.last().unwrap().label,
        format!("q-{}", MAX_FINDREFS_HISTORY + 4)
    );
}
