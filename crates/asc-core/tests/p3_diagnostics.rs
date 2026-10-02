//! P3 regression: the two droidsaw structurer defects observed on
//! Locket 1.216.0 `MomentWidget.render` (see
//! `crates/asc-decompile/BACKENDS.md` §11) must stay *diagnosed*:
//!
//! - 13 SSA locals read but never assigned (phi drop at the converged
//!   handler join) — `unbound_locals` must flag them on the real
//!   decompiled source;
//! - five catch bodies sharing one fallback tail — the exact-match
//!   `duplicated_catch_bodies` heuristic must stay quiet there (the
//!   bodies differ in their SSA prologues; the unbound-locals warning
//!   is the signal for this shape), while verbatim duplication must
//!   still be counted (unit-covered in `diagnose.rs`).
//!
//! Corpus-gated: skips silently when `com.locket.Locket.apk` is absent.

use std::path::PathBuf;

use asc_core::{
    GetClassJob, GetClassOptions, duplicated_catch_bodies, run_getclass, unbound_locals,
};

fn corpus_locket() -> Option<PathBuf> {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/apk/com.locket.Locket.apk");
    p.exists().then_some(p)
}

#[test]
fn moment_widget_structurer_defects_stay_diagnosed() {
    let Some(apk) = corpus_locket() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let job = GetClassJob::new(apk, "Lcom/locket/Locket/Widgets/MomentWidget;");
    let result = run_getclass(&job, &GetClassOptions::default()).expect("getclass");
    let unbound = unbound_locals(&result.source);
    assert!(
        unbound.len() >= 10,
        "expected the phi-drop defect to keep firing, got {unbound:?}"
    );
    // The converged-tail duplication is NOT byte-identical per catch:
    // the exact-match heuristic must stay quiet on this sample.
    assert_eq!(
        duplicated_catch_bodies(&result.source),
        0,
        "catch bodies on this sample differ in their SSA prologues"
    );
}
