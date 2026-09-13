//! Criterion benchmark for `asc-decompile`.
//!
//! Measures two things:
//!
//! 1. **Cold path**: `DroidsawBackend::decompile(&bytes, target)` — full
//!    parse + census + emit, as wave-3 will invoke it per getclass call.
//! 2. **Warm path**: amortised emit only, with a pre-built `DexFile` and
//!    `TrampolineCensus` — the realistic inner cost when many classes
//!    share one DEX.
//!
//! Run with:
//!   cargo bench -p asc-decompile --bench decompile_bench

use std::path::PathBuf;

use asc_decompile::{ClassDecompiler, droidsaw::DroidsawBackend};
use criterion::{Criterion, criterion_group, criterion_main};
use droidsaw_dex::{
    classes::decompile_class_with_census, parser::DexFile, r8_inversion::build_trampoline_census,
};

fn workload_dex() -> Option<Vec<u8>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest
            .join("..")
            .join("..")
            .join("corpus")
            .join("dex")
            .join("workload_classes.dex"),
        manifest
            .join("corpus")
            .join("dex")
            .join("workload_classes.dex"),
    ];
    for c in candidates {
        if c.exists() {
            return std::fs::read(c).ok();
        }
    }
    None
}

const TARGET: &str = "Lcom/google/android/material/timepicker/ClockFaceView;";

fn bench_cold_path(c: &mut Criterion) {
    let Some(bytes) = workload_dex() else {
        eprintln!("bench skip: corpus/dex/workload_classes.dex missing");
        return;
    };
    let backend = DroidsawBackend::new();

    c.bench_function("decompile_clockface_workload_cold", |b| {
        b.iter(|| backend.decompile(&bytes, TARGET).expect("decompile ok"))
    });
}

fn bench_warm_path(c: &mut Criterion) {
    let Some(bytes) = workload_dex() else {
        eprintln!("bench skip: corpus/dex/workload_classes.dex missing");
        return;
    };
    let dex = DexFile::parse(&bytes, None).expect("parse ok");
    let census = build_trampoline_census(&dex);
    let cd = dex
        .class_defs
        .iter()
        .find(|cd| dex.get_type_descriptor(cd.class_idx).ok() == Some(TARGET))
        .expect("class def");

    c.bench_function("decompile_clockface_workload_warm_emit_only", |b| {
        b.iter(|| decompile_class_with_census(&dex, &bytes, cd, &census))
    });
}

criterion_group!(benches, bench_cold_path, bench_warm_path);
criterion_main!(benches);
