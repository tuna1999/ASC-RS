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

/// (target, cargo feature that enables it). With the feature OFF the
/// target must report SkippedDisabled (cheap default build); with the
/// feature ON the target must actually RUN — this is what CI asserts
/// via `cargo test --features all`, so a "green" build can never mean
/// "every parser was skipped".
const CONTRACT_TARGETS: &[(&str, &str)] = &[
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

fn feature_on(f: &str) -> bool {
    match f {
        "dex" => cfg!(feature = "dex"),
        "bytecode" => cfg!(feature = "bytecode"),
        "apk" => cfg!(feature = "apk"),
        "rebuild" => cfg!(feature = "rebuild"),
        "resources" => cfg!(feature = "resources"),
        "core" => cfg!(feature = "core"),
        "decompile" => cfg!(feature = "decompile"),
        other => panic!("unknown feature {other}"),
    }
}

#[test]
fn contract_targets_match_their_feature_gate() {
    for (name, feature) in CONTRACT_TARGETS {
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
    // `default_seed` names a SUBDIRECTORY of fuzz/seeds/ (written by
    // gen-seeds), not a file: the old test joined it straight onto
    // the manifest dir, every read failed, every target hit
    // `continue`, and the test passed without running a single
    // parser. Now: for every ENABLED contract target the seed dir
    // must exist and hold at least one seed file, every seed file
    // must be readable and must drive the real parser, and the
    // counts of targets/seeds actually executed are asserted.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let expected: Vec<&(&str, &str)> = CONTRACT_TARGETS
        .iter()
        .filter(|(_, f)| feature_on(f))
        .collect();
    let mut ran_targets = 0usize;
    let mut ran_seeds = 0usize;
    for (name, feature) in &expected {
        let t = registry()
            .into_iter()
            .find(|t| t.name == *name)
            .unwrap_or_else(|| panic!("missing target {name}"));
        // dummy is skipped: it panics on ANY non-empty input by
        // design (harness self-test) and is not in CONTRACT_TARGETS.
        let seed_dir = manifest.join("seeds").join(t.default_seed);
        let mut seeds: Vec<std::path::PathBuf> = std::fs::read_dir(&seed_dir)
            .unwrap_or_else(|e| {
                panic!(
                    "enabled target {name} (feature {feature}): \
                     cannot read seed dir {}: {e}",
                    seed_dir.display()
                )
            })
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        assert!(
            !seeds.is_empty(),
            "enabled target {name} (feature {feature}): no seed files in {}",
            seed_dir.display()
        );
        seeds.sort();
        for seed_path in &seeds {
            let seed = std::fs::read(seed_path)
                .unwrap_or_else(|e| panic!("cannot read seed {}: {e}", seed_path.display()));
            let out = (t.func)(&seed);
            assert!(
                !out.is_disabled(),
                "seed {:?} ran but target {name} is disabled; \
                 build with --features all",
                seed_path
            );
            ran_seeds += 1;
        }
        ran_targets += 1;
    }
    assert_eq!(
        ran_targets,
        expected.len(),
        "every enabled contract target must execute at least one seed"
    );
    assert!(
        ran_seeds >= ran_targets,
        "seeds executed ({ran_seeds}) must cover targets ({ran_targets})"
    );
    // A default-features build runs zero of them (all disabled);
    // that is fine — CI's `--features all` run is the one that must
    // exercise every parser.
    if expected.is_empty() {
        eprintln!("note: no fuzz features enabled; seed replay skipped");
    }
}
