//! One-hop callee tests against the real corpus DEX.
//!
//! Corpus-gated: every test skips silently when `corpus/dex/` is
//! absent (repo convention — a green run without fixtures must not
//! fail). The synthetic `Builder` mis-serializes type descriptors,
//! so these run against `workload_classes.dex` instead.

mod common;

use asc_query::callees_of;

/// `<init>` of a real view class must invoke at least its super
/// constructor; entries are `Lcls;->name` with a positive site count.
#[test]
fn callees_of_init_lists_super_calls() {
    let mut bytes = Vec::new();
    let Some(view) = common::parse_corpus_dex("workload_classes.dex", &mut bytes) else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let report = callees_of(
        &view,
        "Lcom/google/android/material/timepicker/ClockFaceView;",
        "<init>",
    );
    assert!(
        report.complete,
        "clean DEX must scan fully: {:?}",
        report.errors
    );
    let callees = &report.callees;
    assert!(
        !callees.is_empty(),
        "a real constructor must invoke something"
    );
    for c in callees {
        assert!(
            c.target.starts_with('L') && c.target.contains("->"),
            "{}",
            c.target
        );
        assert!(c.sites >= 1);
    }
    // The superclass constructor is the canonical first hop.
    assert!(
        callees.iter().any(|c| c.target.ends_with("-><init>")),
        "expected a super <init> call, got {callees:?}"
    );
}

/// Degenerate cases: codeless overload → empty + complete; unknown
/// class → incomplete with a `Locator` error.
#[test]
fn callees_of_degrades_cleanly() {
    let mut bytes = Vec::new();
    let Some(view) = common::parse_corpus_dex("workload_classes.dex", &mut bytes) else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let cls = "Lcom/google/android/material/timepicker/ClockFaceView;";
    // A name with no code-bearing overload in that class.
    let none = callees_of(&view, cls, "definitely_not_a_method_xyz");
    assert!(none.callees.is_empty());
    assert!(none.complete, "no matching overload is not a failed scan");
    // Undefined class descriptor.
    let missing = callees_of(&view, "Lno/such/Clazz;", "<init>");
    assert!(!missing.complete);
    assert!(missing.callees.is_empty());
    assert!(
        missing.errors.iter().any(|e| matches!(
            e,
            asc_query::SearchError::Locator {
                pool: "class_defs",
                ..
            }
        )),
        "got: {:?}",
        missing.errors
    );
}

/// A source-form class name normalizes exactly like the descriptor:
/// both `callees_of` and `strings_of_class` accept `com.foo.Bar` and
/// `Lcom/foo/Bar;` as the same class.
#[test]
fn dotted_class_name_matches_descriptor() {
    let mut bytes = Vec::new();
    let Some(view) = common::parse_corpus_dex("workload_classes.dex", &mut bytes) else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let dotted = "com.google.android.material.timepicker.ClockFaceView";
    let desc = "Lcom/google/android/material/timepicker/ClockFaceView;";
    let by_dotted = callees_of(&view, dotted, "<init>");
    let by_desc = callees_of(&view, desc, "<init>");
    assert!(by_desc.complete && by_dotted.complete);
    assert_eq!(by_dotted.callees.len(), by_desc.callees.len());
    let strings_dotted = asc_query::strings_of_class(&view, dotted);
    let strings_desc = asc_query::strings_of_class(&view, desc);
    assert_eq!(strings_dotted.strings.len(), strings_desc.strings.len());
    assert!(strings_desc.complete && strings_dotted.complete);
}
