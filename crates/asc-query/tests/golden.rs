//! Golden parity tests for the workload corpus (single-DEX).
//!
//! Each test parses the captured oracle output
//! (`tests/fixtures/golden/findrefs_*_workload.counts.json`), runs the
//! same query through `asc-query`, and asserts the caller-method set
//! matches exactly (as a SET — order-insensitive).
//!
//! Tests skip gracefully when the corpus fixture or the counts file is
//! missing — except that a fixture named in `ASC_REQUIRE_CORPUS` must
//! fail instead of skipping (docs/CORPUS.md; CI sets the variable).

use std::collections::BTreeSet;
use std::fs;

use asc_dex::ids::MethodIdx;
use asc_query::{ClassConstraint, Query, find_refs};

mod common;

use common::{fail_if_required_corpus_missing, parse_corpus_dex};

/// Path to the golden counts files.
fn counts_path(name: &str) -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("golden")
        .join(name)
}

/// Reads `matched_methods_sorted` from a `*.counts.json` file. Returns
/// `None` if the file is missing or malformed. Uses a hand-rolled
/// mini-parser to avoid adding `serde_json` to dev-dependencies.
fn read_matched_methods(name: &str) -> Option<Vec<String>> {
    let path = counts_path(name);
    let bytes = fs::read(&path).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    // Find the `"matched_methods_sorted": [` line.
    let needle = "\"matched_methods_sorted\":";
    let start = text.find(needle)? + needle.len();
    let after_colon = &text[start..];
    let open = after_colon.find('[')?;
    let close = after_colon[open..].find(']')?;
    let inner = &after_colon[open + 1..open + close];
    let mut out = Vec::new();
    for chunk in inner.split('"').filter(|s| !s.is_empty()) {
        // Skip separators like `, ` or `\n  `.
        if chunk.starts_with(',') || chunk.chars().all(|c| c.is_whitespace() || c == ',') {
            continue;
        }
        if chunk.contains("->") {
            out.push(chunk.to_string());
        }
    }
    Some(out)
}

/// Formats a method (class descriptor `L…;->name`) for comparison.
fn format_method<'a>(view: &asc_dex::DexView<'a>, mid: MethodIdx) -> String {
    let m = view.method(mid).expect("method");
    let cls = view.type_(m.class).expect("type");
    let cls_descr = view.string(cls).expect("class descriptor");
    let name = view.string(m.name).expect("name");
    let mut descr = String::from_utf8_lossy(cls_descr.mutf8).into_owned();
    if !descr.starts_with('L') {
        descr.insert(0, 'L');
    }
    if !descr.ends_with(';') {
        descr.push(';');
    }
    let name_str = String::from_utf8_lossy(name.mutf8).into_owned();
    format!("{}->{}", descr, name_str)
}

/// Runs `find_refs` and returns the SET of formatted caller methods.
fn caller_set(view: &asc_dex::DexView, query: &Query) -> BTreeSet<String> {
    let report = find_refs(view, query);
    let mut out = BTreeSet::new();
    for mid in report.caller_methods_sorted() {
        out.insert(format_method(view, mid));
    }
    out
}

fn assert_set_eq(actual: &BTreeSet<String>, expected: &[String]) {
    let expected_set: BTreeSet<String> = expected.iter().cloned().collect();
    let only_actual: BTreeSet<&String> = actual.difference(&expected_set).collect();
    let only_expected: BTreeSet<&String> = expected_set.difference(actual).collect();
    if !only_actual.is_empty() || !only_expected.is_empty() {
        let mut msg = String::from("matched-method set diverges.\n");
        if !only_actual.is_empty() {
            msg.push_str("  engine emitted but oracle did not:\n");
            for s in &only_actual {
                msg.push_str(&format!("    + {}\n", s));
            }
        }
        if !only_expected.is_empty() {
            msg.push_str("  oracle emitted but engine did not:\n");
            for s in &only_expected {
                msg.push_str(&format!("    - {}\n", s));
            }
        }
        panic!("{}", msg);
    }
}

/// Asserts that every oracle-matched method is also in the engine's
/// output (`oracle ⊆ engine`). Engine may emit additional methods —
/// these are documented divergences (see `GOLDEN_DIVERGENCES.md`).
/// This is the §32-blessed semantic: the differential runner must
/// never see an oracle method that the engine drops (false negative).
fn assert_oracle_subset(actual: &BTreeSet<String>, expected: &[String], case: &str) {
    let expected_set: BTreeSet<String> = expected.iter().cloned().collect();
    let only_expected: BTreeSet<&String> = expected_set.difference(actual).collect();
    if !only_expected.is_empty() {
        let mut msg = format!(
            "ENGINE FALSE NEGATIVE for case {}: oracle emitted but engine did not:\n",
            case
        );
        for s in &only_expected {
            msg.push_str(&format!("    - {}\n", s));
        }
        panic!("{}", msg);
    }
    let only_actual: BTreeSet<&String> = actual.difference(&expected_set).collect();
    if !only_actual.is_empty() {
        eprintln!(
            "[note] case {}: engine emitted {} extra method(s) (documented \
             divergence, see GOLDEN_DIVERGENCES.md):",
            case,
            only_actual.len()
        );
        for s in &only_actual {
            eprintln!("    + {}", s);
        }
    }
}
/// Macro: load a corpus DEX into `bytes_buf` and run `find_refs` with
/// the given query. Skips the test if the corpus is missing — unless
/// `ASC_REQUIRE_CORPUS` names that fixture, in which case a missing file
/// is a hard failure (docs/CORPUS.md; CI sets the variable for exactly
/// the fixtures it recreates).
macro_rules! run_against_corpus {
    ($bytes:ident, $view:ident, $name:literal) => {
        let mut $bytes = Vec::new();
        let Some($view) = parse_corpus_dex($name, &mut $bytes) else {
            fail_if_required_corpus_missing($name);
            eprintln!("{} missing; skipping", $name);
            return;
        };
    };
}

// --------------------- workload cases ---------------------

#[test]
fn golden_findrefs_string_workload() {
    run_against_corpus!(bytes, view, "workload_classes.dex");
    let Some(expected) = read_matched_methods("findrefs_string_workload.counts.json") else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    let q = Query::string("Context");
    let actual = caller_set(&view, &q);
    assert_set_eq(&actual, &expected);
}

#[test]
fn golden_findrefs_type_workload() {
    run_against_corpus!(bytes, view, "workload_classes.dex");
    let Some(expected) = read_matched_methods("findrefs_type_workload.counts.json") else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    let q = Query::type_("ClockFaceView");
    let actual = caller_set(&view, &q);
    assert_set_eq(&actual, &expected);
}

#[test]
fn golden_findrefs_method_workload() {
    run_against_corpus!(bytes, view, "workload_classes.dex");
    let Some(expected) = read_matched_methods("findrefs_method_workload.counts.json") else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    let q = Query::method(Some("onClick"), None);
    let actual = caller_set(&view, &q);
    assert_oracle_subset(&actual, &expected, "findrefs_method_workload");
}
#[test]
fn golden_findrefs_method_precise_workload() {
    run_against_corpus!(bytes, view, "workload_classes.dex");
    let Some(expected) = read_matched_methods("findrefs_method_precise_workload.counts.json")
    else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    // `Lcom/google/android/material/timepicker/ClockFaceView;` is the
    // Dalvik descriptor form for the precise class.
    let q = Query::method(
        Some("onLayout"),
        Some(ClassConstraint::new_exact(
            "Lcom/google/android/material/timepicker/ClockFaceView;",
        )),
    );
    let actual = caller_set(&view, &q);
    assert_set_eq(&actual, &expected);
}

#[test]
fn golden_findrefs_field_workload() {
    run_against_corpus!(bytes, view, "workload_classes.dex");
    let Some(expected) = read_matched_methods("findrefs_field_workload.counts.json") else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    let q = Query::field(Some("textColor"), None);
    let actual = caller_set(&view, &q);
    assert_set_eq(&actual, &expected);
}

#[test]
fn golden_findrefs_field_fuzzy_class_workload() {
    run_against_corpus!(bytes, view, "workload_classes.dex");
    let Some(expected) = read_matched_methods("findrefs_field_fuzzy_class_workload.counts.json")
    else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    // `--class ClockFaceView --fuzzy-class` ⇒ fuzzy substring match
    // over descriptors. `ClockFaceView` is the raw pattern (no
    // descriptor normalization because `exact = false`).
    let q = Query::field(
        Some("gradientColors"),
        Some(ClassConstraint::new("ClockFaceView")),
    );
    let actual = caller_set(&view, &q);
    assert_set_eq(&actual, &expected);
}

// --------------------- multidex cases ---------------------
//
// Aurora and F-Droid are multidex APKs whose golden outputs are
// per-APK. The asc-query engine is per-DEX; we run each corpus DEX
// separately and union the caller sets.
fn multidex_union(dex_names: &[&'static str], query: &Query) -> Option<BTreeSet<String>> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for name in dex_names {
        let mut bytes = Vec::new();
        let Some(view) = parse_corpus_dex(name, &mut bytes) else {
            continue;
        };
        let report = find_refs(&view, query);
        for mid in report.caller_methods_sorted() {
            out.insert(format_method(&view, mid));
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

#[test]
fn golden_findrefs_string_aurora() {
    let q = Query::string("https://");
    let Some(actual) = multidex_union(&["aurora_classes.dex", "aurora_classes2.dex"], &q) else {
        eprintln!("aurora corpus missing; skipping");
        return;
    };
    let Some(expected) = read_matched_methods("findrefs_string_aurora.counts.json") else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    assert_oracle_subset(&actual, &expected, "findrefs_string_aurora");
}
#[test]
fn golden_findrefs_type_aurora() {
    let q = Query::type_("Fragment");
    let Some(actual) = multidex_union(&["aurora_classes.dex", "aurora_classes2.dex"], &q) else {
        eprintln!("aurora corpus missing; skipping");
        return;
    };
    let Some(expected) = read_matched_methods("findrefs_type_aurora.counts.json") else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    assert_set_eq(&actual, &expected);
}

#[test]
fn golden_findrefs_method_aurora() {
    let q = Query::method(Some("onClick"), None);
    let Some(actual) = multidex_union(&["aurora_classes.dex", "aurora_classes2.dex"], &q) else {
        eprintln!("aurora corpus missing; skipping");
        return;
    };
    let Some(expected) = read_matched_methods("findrefs_method_aurora.counts.json") else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    assert_set_eq(&actual, &expected);
}

#[test]
fn golden_findrefs_string_fdroid() {
    let q = Query::string("https://");
    let Some(actual) = multidex_union(&["fdroid_classes.dex", "fdroid_classes2.dex"], &q) else {
        eprintln!("fdroid corpus missing; skipping");
        return;
    };
    let Some(expected) = read_matched_methods("findrefs_string_fdroid.counts.json") else {
        eprintln!("golden counts missing; skipping");
        return;
    };
    assert_set_eq(&actual, &expected);
}

// --------------------- class_defines helper parity ---------------------

#[test]
fn class_defines_parity_with_oracle() {
    // The oracle's `getclass` returns "class not found" when no DEX
    // contains a class_def with the descriptor. Our `class_defines`
    // mirrors that semantic.
    run_against_corpus!(bytes, view, "workload_classes.dex");
    // ClockFaceView is defined in workload_classes.dex (the
    // `getclass_clockface_workload` golden case proves it).
    assert!(asc_query::class_defines(
        &view,
        "Lcom/google/android/material/timepicker/ClockFaceView;"
    ));
    assert!(asc_query::class_defines(
        &view,
        "com.google.android.material.timepicker.ClockFaceView"
    ));
    // A class that doesn't exist anywhere in the corpus.
    assert!(!asc_query::class_defines(&view, "Lno/such/Class;"));
    assert!(!asc_query::class_defines(&view, "no.such.Class"));
    // Empty / whitespace input is "not defined".
    assert!(!asc_query::class_defines(&view, ""));
}
