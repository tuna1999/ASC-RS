//! Verifies that each documented golden divergence corresponds to a
//! REAL method with non-zero `code_off` (i.e. the engine did not
//! hallucinate it).
//!
//! These tests do NOT assert shared `code_off` — earlier analysis
//! disproved that hypothesis. See `GOLDEN_DIVERGENCES.md` for the
//! full reasoning. The oracle's fuzzy-then-verified scanner is what
//! produces these extra engine hits; the engine's
//! `asc-bytecode::RefWalker` correctly parses every reference-bearing
//! instruction the oracle's verifier drops.
//!
//! If either test fails, the divergent method is no longer in the
//! engine output — that would mean the divergence has been fixed
//! (good) or the engine regressed (bad). Either way the divergence
//! allowlist in `GOLDEN_DIVERGENCES.md` must be updated.

use asc_dex::ids::MethodIdx;
use asc_dex::view::DexView;
use asc_query::{Query, find_refs};

mod common;

use common::parse_corpus_dex;

/// Returns `(class_descriptor, method_name, code_off)` for a `MethodIdx`.
fn method_signature(view: &DexView, mid: MethodIdx) -> (String, String, Option<u32>) {
    let m = view.method(mid).expect("method");
    let cls = view.type_(m.class).expect("type");
    let cls_descr = view.string(cls).expect("class descriptor");
    let name = view.string(m.name).expect("name");
    let descr = String::from_utf8_lossy(cls_descr.mutf8).into_owned();
    let n = String::from_utf8_lossy(name.mutf8).into_owned();
    let mut d = descr;
    if !d.starts_with('L') {
        d.insert(0, 'L');
    }
    if !d.ends_with(';') {
        d.push(';');
    }
    // Walk every class to find the class_data entry for this method.
    let code_off = (|| {
        for i in 0..view.class_def_count() {
            let cd = view.class_def(i).ok()?;
            if cd.class_data_off == 0 {
                continue;
            }
            let data = view.class_data(cd.class_data_off).ok()??;
            for em in data
                .direct_methods
                .iter()
                .chain(data.virtual_methods.iter())
            {
                if em.method_idx == mid {
                    return Some(em.code_off);
                }
            }
        }
        None
    })();
    (d, n, code_off)
}

fn find_method<'a>(view: &DexView<'a>, q: &Query, target: &str) -> Option<MethodIdx> {
    let report = find_refs(view, q);
    for mid in report.caller_methods_sorted() {
        let (cls, name, _) = method_signature(view, mid);
        if format!("{}->{}", cls, name) == target {
            return Some(mid);
        }
    }
    None
}

#[test]
fn workload_lambda_divergence_is_real_method() {
    let mut buf = Vec::new();
    let Some(view) = parse_corpus_dex("workload_classes.dex", &mut buf) else {
        eprintln!("workload missing; skipping");
        return;
    };
    let q = Query::method(Some("onClick"), None);
    let target = "Lcom/google/android/material/snackbar/Snackbar;->lambda$setAction$0$com-google-android-material-snackbar-Snackbar";
    let Some(mid) = find_method(&view, &q, target) else {
        panic!(
            "divergence vanished: {} not in engine output. \
             Update GOLDEN_DIVERGENCES.md and switch the test \
             back to assert_set_eq if the divergence was fixed.",
            target
        );
    };
    let (_, _, code_off) = method_signature(&view, mid);
    let code_off = code_off.expect("class_data lookup");
    assert!(
        code_off != 0,
        "{} has code_off 0 (abstract / native) — engine \
         should not have emitted it. This is a real engine bug.",
        target
    );
}

#[test]
fn aurora_force_stop_runnable_divergence_is_real_method() {
    let mut buf = Vec::new();
    let Some(view) = parse_corpus_dex("aurora_classes.dex", &mut buf) else {
        eprintln!("aurora missing; skipping");
        return;
    };
    let q = Query::string("https://");
    let target = "Landroidx/work/impl/utils/ForceStopRunnable;->run";
    let Some(mid) = find_method(&view, &q, target) else {
        panic!(
            "divergence vanished: {} not in engine output. \
             Update GOLDEN_DIVERGENCES.md and switch the test \
             back to assert_set_eq if the divergence was fixed.",
            target
        );
    };
    let (_, _, code_off) = method_signature(&view, mid);
    let code_off = code_off.expect("class_data lookup");
    assert!(
        code_off != 0,
        "{} has code_off 0 (abstract / native) — engine \
         should not have emitted it. This is a real engine bug.",
        target
    );
}
