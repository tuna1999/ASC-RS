//! §42 first integration gate: APK → classes*.dex discovery → extract
//! one DEX → `DexView::parse` → strings/types/method metadata →
//! `class_data` → `code_item` → correct instruction boundaries via
//! `RefWalker`/`walk_verify`.
//!
//! Runs against the real corpus fixtures (Agent A); every test skips
//! (passing) when its fixture is absent so a corpus-less checkout
//! stays green.

use asc_apk::{Apk, EntryBytes};
use asc_bytecode::{RefWalker, DexRef};
use asc_dex::DexView;

const WORKLOAD: &str = "corpus/apk/workload.apk";
const AURORA: &str = "corpus/apk/com.aurora.store_60.apk";

fn fixture(path: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(path);
    p.exists().then_some(p)
}

/// Full pipeline on the single-dex workload APK, ending in an
/// instruction-boundary verification of EVERY code item in the DEX.
#[test]
fn gate_workload_end_to_end() {
    let Some(path) = fixture(WORKLOAD) else {
        eprintln!("skipping: {WORKLOAD} not present");
        return;
    };
    let apk = Apk::open(&path).expect("open workload apk");
    let dex_entries = apk.dex_entries();
    assert_eq!(dex_entries.len(), 1, "workload is single-dex");
    assert_eq!(dex_entries[0].name, "classes.dex");

    let bytes = apk.read_entry(&dex_entries[0]).expect("read classes.dex");
    let raw = bytes.as_slice();
    assert_eq!(raw.len() as u64, dex_entries[0].uncompressed_size);

    let view = DexView::parse(raw).expect("parse workload dex");
    assert!(matches!(
        view.version(),
        asc_dex::DexVersion::V035 | asc_dex::DexVersion::V037 | asc_dex::DexVersion::V038
            | asc_dex::DexVersion::V039
    ));

    // Strings: decode the ENTIRE pool lossily — no panic, sane count.
    let string_count = view.string_count();
    assert!(string_count > 1_000, "real dex has a large string pool");
    let mut descriptors = 0u32;
    for (_idx, s) in view.strings() {
        let text = s.decode_lossy();
        if text.starts_with('L') && text.ends_with(';') {
            descriptors += 1;
        }
    }
    assert!(descriptors > 100, "expected many class descriptors");

    // Method metadata: resolve names for the first few methods.
    let method_count = view.method_count();
    assert!(method_count > 100);
    for i in 0..method_count.min(50) {
        let m = view.method(asc_dex::MethodIdx(i)).expect("method id in range");
        let name = view.string(m.name).expect("method name string");
        assert!(!name.mutf8.is_empty() || name.utf16_len == 0);
    }

    // class_data → code_off dedup → code_item → boundary verification.
    let mut code_items_checked = 0u32;
    let mut ref_hits = 0u64;
    let mut boundary_errors: Vec<String> = Vec::new();
    'classes: for ci in 0..view.class_def_count() {
        let def = view.class_def(ci).expect("class def in range");
        if def.class_data_off == 0 {
            continue;
        }
        let off = def.class_data_off;
        let Some(data) = view.class_data(off).expect("class_data parse") else {
            continue 'classes;
        };
        // dedupe code_off: R8-deduplicated bodies verified once
        let mut seen: Vec<u32> = Vec::new();
        for method in data.direct_methods.iter().chain(data.virtual_methods.iter()) {
            if method.code_off == 0 || seen.contains(&method.code_off) {
                continue;
            }
            seen.push(method.code_off);
            let Some(item) = view.code_item(method.code_off).expect("code_item parse") else {
                continue;
            };
            code_items_checked += 1;
            if let Err(e) = asc_bytecode::walk_verify(item.insns_exact(), item.insns_size) {
                boundary_errors.push(format!(
                    "code_off={} method={:?}: {e:?}",
                    method.code_off, method.method_idx
                ));
                if boundary_errors.len() > 8 {
                    break 'classes;
                }
            }
            for hit in RefWalker::new(item.insns_exact(), item.insns_size).expect("walker") {
                let hit = hit.expect("verified walk above");
                assert!(hit.offset < item.insns_size);
                assert!(hit.primary.is_some() || hit.secondary.is_some());
                let _ = matches!(hit.primary, Some(DexRef::Method(_)));
                ref_hits += 1;
            }
        }
    }
    assert!(code_items_checked > 500, "checked {code_items_checked} code items");
    assert!(ref_hits > 1_000, "collected {ref_hits} ref hits");
    assert!(
        boundary_errors.is_empty(),
        "instruction boundary errors:\n{}",
        boundary_errors.join("\n")
    );
}

/// Multidex APK: numeric discovery of classes.dex + classes2.dex + …,
/// each parseable.
#[test]
fn gate_multidex_discovery_and_parse() {
    let Some(path) = fixture(AURORA) else {
        eprintln!("skipping: {AURORA} not present");
        return;
    };
    let apk = Apk::open(&path).expect("open aurora apk");
    let entries = apk.dex_entries();
    assert!(entries.len() >= 2, "aurora is multidex");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names[0], "classes.dex");
    assert_eq!(names[1], "classes2.dex");
    // numeric ordering proof would need classes10.dex; at minimum the
    // first two must be in canonical order.
    for entry in &entries {
        let bytes = apk.read_entry(entry).expect("read dex entry");
        let view = DexView::parse(bytes.as_slice()).expect("parse multidex dex");
        assert!(view.string_count() > 0);
    }
}
