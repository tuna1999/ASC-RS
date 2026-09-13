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

/// Regression (Lead, wave-2 integration): the encoded_catch_handler_list
/// size field is ULEB128 (not u32) and try_item.handler_off is a byte
/// offset from the LIST start. Verified against production dex bytes
/// (`01 00 1f ...` = uleb size 1, handler sleb 0 with catch_all 0x1f).
/// Walks every code item with tries in every corpus dex and resolves
/// every try's handler; any parse error or miss is a failure.
#[test]
fn corpus_catch_handlers_resolve() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/dex");
    let mut checked = 0u32;
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => {
            eprintln!("skipping: no corpus/dex");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("dex") {
            continue;
        }
        let bytes = std::fs::read(&path).expect("read dex");
        let Ok(view) = DexView::parse(&bytes) else {
            panic!("corpus dex failed to parse: {}", path.display());
        };
        for ci in 0..view.class_def_count() {
            let def = view.class_def(ci).expect("class def");
            if def.class_data_off == 0 {
                continue;
            }
            let Some(data) = view.class_data(def.class_data_off).expect("class data") else {
                continue;
            };
            for m in data
                .direct_methods
                .iter()
                .chain(data.virtual_methods.iter())
            {
                let Some(code) = view.code_item(m.code_off).expect("code item") else {
                    continue;
                };
                if code.tries_size == 0 {
                    continue;
                }
                let list = view
                    .catch_handler_list(&code)
                    .expect("handler list parses")
                    .expect("tries present implies list");
                let offsets = list.handler_offsets().expect("handler offsets");
                for t in view.tries_iter(&code).expect("tries") {
                    let h = view.catch_handler(&list, &t).expect("handler resolves");
                    // A handler is either typed pairs or a catch-all (or both).
                    assert!(
                        !h.pairs.is_empty() || h.catch_all_addr.is_some(),
                        "empty handler at {}",
                        path.display()
                    );
                    assert!(
                        offsets.contains(&(t.handler_off as u32)),
                        "handler_off {} not an entry boundary (offsets {:?})",
                        t.handler_off,
                        offsets
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(
        checked > 10,
        "only {checked} handlers checked — corpus missing?"
    );
}
