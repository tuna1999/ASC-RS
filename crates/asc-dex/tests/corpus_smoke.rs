//! Smoke tests against the corpus/dex/*.dex fixtures (added by OracleFixtures).
//!
//! These tests skip if the corpus is missing — they are run when fixtures
//! are available. The aim is to exercise the reader against real-world
//! bytecode, not to assert semantic correctness.

use asc_dex::DexView;
use std::path::Path;

fn corpus_dex_files() -> Vec<std::path::PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("corpus").join("dex"));
    let Some(dir) = dir else {
        return Vec::new();
    };
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("dex") {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn parses_each_corpus_dex_without_panic() {
    let files = corpus_dex_files();
    if files.is_empty() {
        eprintln!("no corpus/dex fixtures found; skipping");
        return;
    }
    for path in files {
        let bytes = std::fs::read(&path).unwrap();
        // Skip files too small to be a DEX.
        if bytes.len() < 0x70 {
            continue;
        }
        match DexView::parse(&bytes) {
            Ok(view) => {
                // Touch the string iterator so it actually runs.
                let _n = view.string_count();
                let _ = view.strings().next();
            }
            Err(e) => {
                eprintln!("DexView::parse rejected {}: {:?}", path.display(), e);
            }
        }
    }
}
