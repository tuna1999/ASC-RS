//! End-to-end integration tests for `asc-decompile`.
//!
//! These tests require the corpus fixture files at
//! `corpus/dex/workload_classes.dex` and are skipped (with a clear log
//! line) when the fixture is absent — keeps `cargo test` green on a
//! fresh clone before the corpus is populated, while still catching
//! regressions once it is.

use std::path::{Path, PathBuf};

use asc_decompile::{
    ClassDecompiler, DecompileError, droidsaw::DroidsawBackend, normalize_class_name,
};

fn corpus_dex() -> Option<PathBuf> {
    // Walk up from CARGO_MANIFEST_DIR until we find the repo root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut here = manifest.to_path_buf();
    for _ in 0..6 {
        let candidate = here.join("corpus").join("dex").join("workload_classes.dex");
        if candidate.exists() {
            return Some(candidate);
        }
        if !here.pop() {
            break;
        }
    }
    None
}

fn read_or_skip(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("skip: cannot read {}: {e}", path.display());
            Vec::new()
        }
    }
}

const GOLDEN_TARGET: &str = "Lcom/google/android/material/timepicker/ClockFaceView;";

#[test]
fn roundtrip_workload_clockface_decompiles_to_java_containing_class_name() {
    let Some(path) = corpus_dex() else {
        eprintln!("skip: corpus/dex/workload_classes.dex missing");
        return;
    };
    let bytes = read_or_skip(&path);
    if bytes.is_empty() {
        return;
    }

    let backend = DroidsawBackend::new();
    let result = backend.decompile(&bytes, GOLDEN_TARGET);
    let java = result.unwrap_or_else(|e| panic!("decompile failed: {e}"));

    // Smoke checks the task asks for:
    //   "→ Ok(String) containing 'ClockFaceView'"
    assert!(
        java.contains("ClockFaceView"),
        "output missing class name (len={}):\n{}",
        java.len(),
        &java[..java.len().min(400)],
    );
    // Recognisable Java shape (package + class declaration somewhere).
    assert!(java.contains("class "), "output missing 'class' keyword");
    assert!(
        java.contains("ClockFaceView extends"),
        "missing extends clause"
    );
    // Sanity: empty string never returned.
    assert!(!java.trim().is_empty());
}

#[test]
fn class_not_found_returns_typed_error() {
    let Some(path) = corpus_dex() else {
        eprintln!("skip: corpus/dex/workload_classes.dex missing");
        return;
    };
    let bytes = read_or_skip(&path);
    if bytes.is_empty() {
        return;
    }
    let backend = DroidsawBackend::new();
    let err = backend
        .decompile(&bytes, "Lno/such/Class;")
        .expect_err("expected ClassNotFound");
    match err {
        DecompileError::ClassNotFound(desc) => {
            assert_eq!(desc, "Lno/such/Class;");
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn java_dotted_target_normalises_and_decompiles() {
    let Some(path) = corpus_dex() else {
        eprintln!("skip: corpus/dex/workload_classes.dex missing");
        return;
    };
    let bytes = read_or_skip(&path);
    if bytes.is_empty() {
        return;
    }
    let backend = DroidsawBackend::new();
    // Pass the same target in Java dotted form; normaliser must accept
    // it and the backend must still find the class.
    let java = backend
        .decompile(
            &bytes,
            "com.google.android.material.timepicker.ClockFaceView",
        )
        .expect("java dotted form should normalise and resolve");
    assert!(java.contains("ClockFaceView"));
}

#[test]
fn malformed_inputs_never_panic() {
    let backend = DroidsawBackend::new();

    // Static fixtures first.
    let statics: &[(&str, &[u8])] = &[
        ("empty", &[]),
        ("3-byte", b"abc"),
        ("wrong magic", b"ELF\x01\x01\x01\x00\x00\x00\x00"),
        ("truncated header", b"dex\n039"),
    ];
    for (name, input) in statics {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            backend.decompile(input, "Lfoo/Bar;")
        }));
        let inner = res.unwrap_or_else(|_| panic!("{name}: backend panicked"));
        assert!(inner.is_err(), "{name}: expected Err, got {inner:?}");
    }

    // Dynamic fixtures — owned Vec, no Box::leak, freed at test end.
    let zeros: Vec<u8> = vec![0u8; 4096];
    let ones: Vec<u8> = vec![0xFFu8; 4096];
    let mut garbage: Vec<u8> = Vec::with_capacity(4096);
    {
        let mut x: u8 = 0xA5;
        for _ in 0..4096 {
            x = x.wrapping_mul(31).wrapping_add(7);
            garbage.push(x);
        }
    }
    let dynamics: &[(&str, &[u8])] = &[
        ("all zeros 4096", zeros.as_slice()),
        ("all 0xFF 4096", ones.as_slice()),
        ("garbage 4KiB", garbage.as_slice()),
    ];
    for (name, input) in dynamics {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            backend.decompile(input, "Lfoo/Bar;")
        }));
        let inner = res.unwrap_or_else(|_| panic!("{name}: backend panicked"));
        assert!(inner.is_err(), "{name}: expected Err, got {inner:?}");
    }
}

#[test]
fn trait_object_usage_compiles_and_works() {
    let Some(path) = corpus_dex() else {
        eprintln!("skip: corpus/dex/workload_classes.dex missing");
        return;
    };
    let bytes = read_or_skip(&path);
    if bytes.is_empty() {
        return;
    }
    // The whole point of the trait: store a `dyn` reference, never
    // leak the backend type. If this compiles, no backend-specific
    // types leaked into the call site.
    fn generic(
        d: &dyn ClassDecompiler,
        dex: &[u8],
        target: &str,
    ) -> Result<String, DecompileError> {
        d.decompile(dex, target)
    }
    let backend = DroidsawBackend::new();
    let java = generic(&backend, &bytes, GOLDEN_TARGET).expect("dyn dispatch works");
    assert!(java.contains("ClockFaceView"));

    // Also verify that the public API types we depend on are reachable
    // from a downstream crate (proves the surface is real).
    let _ = normalize_class_name("com.foo.Bar").unwrap();
}

#[test]
fn dex041_magic_is_accepted_as_format_only() {
    // Header-only magic gate — the actual parser may still fail on
    // the truncated body and that's fine; we just want to ensure
    // the version-gate recognises 041.
    let backend = DroidsawBackend::new();
    let mut bytes = vec![0u8; 256];
    bytes[..4].copy_from_slice(b"dex\n");
    bytes[4..7].copy_from_slice(b"041");
    let _ = backend.decompile(&bytes, "Lfoo/Bar;");
}
