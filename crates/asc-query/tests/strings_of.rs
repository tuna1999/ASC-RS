//! Class-scoped string inventory tests against the real corpus DEX.
//!
//! Corpus-gated: every test skips silently when `corpus/dex/` is
//! absent (repo convention). The synthetic `Builder` mis-serializes
//! type descriptors, so these run against `workload_classes.dex`
//! (same rationale as `callees.rs`).

mod common;

use asc_query::strings_of_class;

/// A real view class must load at least one string constant; every
/// entry has a positive site count and texts are distinct
/// (first-encounter order).
#[test]
fn strings_of_class_lists_constants() {
    let mut bytes = Vec::new();
    let Some(view) = common::parse_corpus_dex("workload_classes.dex", &mut bytes) else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let report = strings_of_class(&view, "Landroidx/core/text/util/LinkifyCompat;");
    assert!(
        report.complete,
        "clean DEX must scan fully: {:?}",
        report.errors
    );
    let strings = &report.strings;
    assert!(
        !strings.is_empty(),
        "LinkifyCompat loads URL scheme constants"
    );
    assert!(
        strings
            .iter()
            .any(|s| s.text == "http://" || s.text == "https://"),
        "expected a URL scheme constant, got {:?}",
        strings
    );
    assert!(!strings.is_empty(), "a real view class loads strings");
    for s in strings {
        assert!(s.sites >= 1, "site count must be positive: {s:?}");
    }
    let mut seen: Vec<&str> = Vec::new();
    for s in strings {
        assert!(!seen.contains(&s.text.as_str()), "duplicate {}", s.text);
        seen.push(&s.text);
    }
}

/// Unknown class → an incomplete report carrying the structured
/// `class_defs` locator error (same contract as `callees_of`).
#[test]
fn strings_of_class_degrades_cleanly() {
    let mut bytes = Vec::new();
    let Some(view) = common::parse_corpus_dex("workload_classes.dex", &mut bytes) else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let report = strings_of_class(&view, "Lno/such/Clazz;");
    assert!(!report.complete, "a missing class is not a complete scan");
    assert!(report.strings.is_empty());
    assert!(
        report.errors.iter().any(|e| matches!(
            e,
            asc_query::SearchError::Locator {
                pool: "class_defs",
                ..
            }
        )),
        "got: {:?}",
        report.errors
    );
}
