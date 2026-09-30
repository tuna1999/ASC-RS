//! `run_disasm` against real APKs/DEXes. Every test skips silently when
//! its fixture is absent (`corpus/` is gitignored; CI recreates it).
//!
//! The listing is still in flux, so these assert *shape* (header note,
//! `.class`, `.method`/`.end method` pairing, filter selectivity) rather
//! than pinning bytes.

use asc_core::{CoreError, DisasmJob, DisasmOptions, run_disasm};

/// A class with methods in `com.aurora.store_60.apk`; used as the
/// positive fixture for the APK and the raw-DEX paths.
const TARGET: &str = "Lcom/aurora/gplayapi/Address;";

fn corpus(kind: &str, name: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(kind)
        .join(name);
    if !p.exists() {
        eprintln!("skipping: {}/{name} not present", p.display());
    }
    p.exists().then_some(p)
}

fn apk() -> Option<std::path::PathBuf> {
    corpus("apk", "com.aurora.store_60.apk")
}

fn dex() -> Option<std::path::PathBuf> {
    corpus("dex", "aurora_classes2.dex")
}

fn disasm(path: &std::path::Path, target: &str, method: Option<&str>) -> Result<String, CoreError> {
    run_disasm(
        &DisasmJob::new(path, target, method),
        &DisasmOptions::default(),
    )
    .map(|r| r.listing)
}

/// Method names, one per `.method` block. The smali line is
/// `.method <flags…> <name><proto>`, so the name is the last token
/// up to the first `(`.
fn method_names(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|l| l.strip_prefix(".method "))
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|sig| sig.split('(').next())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn apk_listing_has_smali_shape() {
    let Some(p) = apk() else { return };
    let listing = disasm(&p, TARGET, None).expect("disasm must succeed");
    let first = listing.lines().next().unwrap_or_default();
    assert!(
        first.starts_with("# smali-syntax listing from asc-rs"),
        "missing header note, got: {first}"
    );
    assert!(listing.contains(&format!(".class public L{TARGET}")) || listing.contains(".class "));
    assert!(listing.contains(&format!(".super L{TARGET}")) || listing.contains(".super "));
    assert!(listing.contains(".method "));
    assert!(listing.contains("\n.end method"));
    // Every `.method` opens a block that closes.
    assert_eq!(
        listing.matches(".method ").count(),
        listing.matches(".end method").count()
    );
    assert!(!method_names(&listing).is_empty());
}

#[test]
fn missing_class_is_a_not_found_error() {
    let Some(p) = apk() else { return };
    match disasm(&p, "Lcom/aurora/does/not/Exist;", None) {
        Err(CoreError::ClassNotFound(name)) => {
            assert_eq!(name, "Lcom/aurora/does/not/Exist;");
        }
        other => panic!("expected ClassNotFound, got {other:?}"),
    }
}

#[test]
fn method_filter_returns_only_that_name() {
    let Some(p) = apk() else { return };
    let all = disasm(&p, TARGET, None).expect("disasm must succeed");
    let all_names = method_names(&all);
    // Prefer an overloaded name: the filter must return *every* block
    // with that name, not just the first.
    let pick = all_names
        .iter()
        .find(|n| all_names.iter().filter(|m| *m == *n).count() > 1)
        .or_else(|| all_names.first())
        .cloned()
        .expect("fixture class has no methods");
    let expected_blocks = all_names.iter().filter(|n| **n == pick).count();
    let filtered = disasm(&p, TARGET, Some(&pick)).expect("filter must succeed");
    let names = method_names(&filtered);
    assert!(!names.is_empty(), "filter emitted no methods");
    assert!(
        names.iter().all(|n| *n == pick),
        "filter leaked: {names:?} (wanted {pick})"
    );
    assert_eq!(names.len(), expected_blocks, "overloads were dropped");
    // A name filter drops the field inventory (renderer contract).
    assert!(!filtered.contains("\n.field "));
}

#[test]
fn missing_method_is_a_method_not_found_error() {
    let Some(p) = apk() else { return };
    match disasm(&p, TARGET, Some("noSuchMethodName")) {
        Err(CoreError::MethodNotFound(m)) => {
            assert!(m.contains("noSuchMethodName"), "msg: {m}");
        }
        other => panic!("expected MethodNotFound, got {other:?}"),
    }
}

#[test]
fn raw_dex_input_works_without_rebuild() {
    let Some(p) = dex() else { return };
    // Pick a class that is actually defined in this DEX.
    let classes = asc_core::run_listclasses(
        &asc_core::ListClassesJob::new(&p, None).expect("job"),
        &asc_core::ListClassesOptions::default(),
    )
    .expect("listclass");
    let Some(target) = classes
        .names
        .iter()
        .find(|n| n.starts_with("Lcom/") && n.matches('/').count() <= 3)
        .cloned()
    else {
        panic!("no com/* class in fixture dex");
    };
    let listing = disasm(&p, &target, None).expect("disasm must succeed");
    assert!(listing.contains(&format!(".class public L{target}")) || listing.contains(".class "));
    assert!(listing.contains(".method "));
    assert!(listing.contains("\n.end method"));
}
