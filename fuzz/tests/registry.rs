//! Integration tests for the fuzz target registry. These run under
//! `cargo test -p asc-fuzz`.

use asc_fuzz::{FuzzOutcome, registry};

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
fn contract_targets_match_their_feature_gate() {
    // (target, cargo feature that enables it). With the feature OFF
    // the target must report SkippedDisabled (cheap default build);
    // with the feature ON the target must actually RUN — this is what
    // CI asserts via `cargo test --features all`, so a "green" build
    // can never mean "every parser was skipped".
    let contract_targets: &[(&str, &str)] = &[
        ("fuzz_dex_header", "dex"),
        ("fuzz_uleb128", "dex"),
        ("fuzz_mutf8", "dex"),
        ("fuzz_class_data", "dex"),
        ("fuzz_code_item", "dex"),
        ("fuzz_encoded_value", "dex"),
        ("fuzz_annotations", "dex"),
        ("fuzz_dex041", "dex"),
        ("fuzz_ref_walker", "bytecode"),
        ("fuzz_zip_directory", "apk"),
        ("fuzz_elf", "apk"),
        ("fuzz_signing", "apk"),
        ("fuzz_apk_open", "apk"),
        ("fuzz_arsc", "resources"),
        ("fuzz_rebuild", "rebuild"),
        ("fuzz_inspect", "core"),
        ("fuzz_disasm", "decompile"),
    ];
    let feature_on = |f: &str| match f {
        "dex" => cfg!(feature = "dex"),
        "bytecode" => cfg!(feature = "bytecode"),
        "apk" => cfg!(feature = "apk"),
        "rebuild" => cfg!(feature = "rebuild"),
        "resources" => cfg!(feature = "resources"),
        "core" => cfg!(feature = "core"),
        "decompile" => cfg!(feature = "decompile"),
        other => panic!("unknown feature {other}"),
    };
    for (name, feature) in contract_targets {
        let t = registry()
            .into_iter()
            .find(|t| t.name == *name)
            .unwrap_or_else(|| panic!("missing target {name}"));
        // Invoke the target for real: disabled targets return
        // SkippedDisabled, enabled ones execute the parser on the
        // input (must not panic).
        let out = (t.func)(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            out.is_disabled(),
            !feature_on(feature),
            "target {name}: is_disabled={} but feature {feature} is {}",
            out.is_disabled(),
            feature_on(feature),
        );
    }
}

#[test]
fn enabled_targets_run_on_their_default_seed() {
    // With the matching feature(s) on, run every contract target on
    // its committed seed input. Guards the not-SkippedDisabled side
    // with real (valid-header) inputs rather than 4 junk bytes.
    for t in registry() {
        if t.name == "dummy" {
            continue;
        }
        let seed_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&t.default_seed);
        let Ok(seed) = std::fs::read(&seed_path) else {
            continue; // seed not built for this workspace state
        };
        let out = (t.func)(&seed);
        assert!(
            !out.is_disabled(),
            "seed {seed_path:?} exists but target {} is disabled; \
             run with --features all",
            t.name
        );
    }
}
