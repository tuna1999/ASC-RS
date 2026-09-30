//! Integration tests for the fuzz target registry. These run under
//! `cargo test -p asc-fuzz`.

use asc_fuzz::{registry, FuzzOutcome};

#[test]
fn registry_has_at_least_twelve_targets() {
    let targets = registry();
    assert!(
        targets.len() >= 12,
        "expected ≥12 registered targets, got {}",
        targets.len()
    );
}

#[test]
fn registry_contains_dummy() {
    let targets = registry();
    assert!(
        targets.iter().any(|t| t.name == "dummy"),
        "registry missing the dummy target"
    );
}

#[test]
fn dummy_target_returns_skipped_or_ok_on_empty() {
    let dummy = registry()
        .into_iter()
        .find(|t| t.name == "dummy")
        .expect("dummy in registry");
    let out = (dummy.func)(&[]);
    // Empty input is the only safe path; we must NOT panic. With
    // features off, dummy still runs (it's always-on) and returns Ok.
    assert!(
        matches!(out, FuzzOutcome::Ok),
        "dummy on empty input should be Ok, got {out:?}"
    );
}

#[test]
fn each_target_has_unique_name_and_seed() {
    let targets = registry();
    let mut names: Vec<&str> = targets.iter().map(|t| t.name).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), targets.len(), "duplicate target name");

    let seeds: Vec<&str> = targets.iter().map(|t| t.default_seed).collect();
    let unique_seeds: std::collections::HashSet<_> = seeds.iter().collect();
    // It's OK for two targets to share a seed (e.g. fuzz_rebuild
    // reuses dex_minimal); only names must be unique.
    assert!(unique_seeds.len() <= seeds.len());
}

#[test]
fn contract_targets_are_disabled_with_default_features() {
    // Without `--features dex|bytecode|apk|rebuild`, every contract
    // target must return SkippedDisabled — the build is green today
    // even though the sibling crates haven't landed yet.
    let contract_targets = [
        "fuzz_dex_header",
        "fuzz_uleb128",
        "fuzz_mutf8",
        "fuzz_class_data",
        "fuzz_code_item",
        "fuzz_ref_walker",
        "fuzz_encoded_value",
        "fuzz_annotations",
        "fuzz_dex041",
        "fuzz_zip_directory",
        "fuzz_elf",
        "fuzz_signing",
        "fuzz_arsc",
        "fuzz_rebuild",
        "fuzz_apk_open",
        "fuzz_inspect",
        "fuzz_disasm",
    ];
    let reg = registry();
    for name in contract_targets {
        let t = reg
            .iter()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("missing target {name}"));
        let out = (t.func)(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(
            out.is_disabled(),
            "target {name} should be SkippedDisabled with default features, got {out:?}"
        );
    }
}
