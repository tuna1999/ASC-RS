//! Synthetic Hermes bundle tests: build a minimal v96 bytecode file with a
//! known string table (identifier + plain + overflowed UTF-16 entry), wrap
//! it in a ZIP, and check extraction end-to-end via `run_hermes`.

use std::io::Write as _;

const MAGIC: [u8; 8] = [0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F];

/// Build a v96 bundle: 0 functions, 3 strings
/// (0 = identifier "Lfoo", 1 = "https://example.com/api", 2 = overflow
/// UTF-16 "h\u{e9}llo"), 1 identifier hash.
fn bundle(version: u32, corrupt_storage_size: Option<u32>) -> Vec<u8> {
    let storage: Vec<u8> = {
        let mut s = b"Lfoohttps://example.com/api".to_vec();
        s.extend_from_slice(&[0x68, 0x00, 0xE9, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00]);
        s
    };
    let s0 = 4u32 << 24; // "Lfoo" at 0, len 4, utf8
    let s1 = (4u32 << 1) | ((23u32) << 24); // off 4, len 23, utf8
    let s2 = 1u32 | 0xFFu32 << 24; // utf16, overflow marker, overflow index 0
    let overflow: [u8; 8] = {
        let off = 27u32; // "h\u{e9}llo" at storage offset 27
        let mut e = Vec::new();
        e.extend_from_slice(&off.to_le_bytes());
        e.extend_from_slice(&10u32.to_le_bytes()); // 5 UTF-16 units = 10 bytes
        e.try_into().unwrap()
    };
    let mut b = Vec::new();
    b.extend_from_slice(&MAGIC);
    b.extend_from_slice(&version.to_le_bytes());
    b.extend_from_slice(&[0u8; 20]); // sourceHash
    let file_length_placeholder = b.len();
    b.extend_from_slice(&0u32.to_le_bytes()); // fileLength (patched)
    b.extend_from_slice(&0u32.to_le_bytes()); // globalCodeIndex
    b.extend_from_slice(&0u32.to_le_bytes()); // functionCount
    b.extend_from_slice(&2u32.to_le_bytes()); // stringKindCount
    b.extend_from_slice(&1u32.to_le_bytes()); // identifierCount
    b.extend_from_slice(&3u32.to_le_bytes()); // stringCount
    b.extend_from_slice(&1u32.to_le_bytes()); // overflowStringCount
    b.extend_from_slice(
        &corrupt_storage_size
            .unwrap_or(storage.len() as u32)
            .to_le_bytes(),
    );
    for v in [0u32, 0, 0, 0, 0, 0, 0] {
        // bigInt..objValue buffers
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&0u32.to_le_bytes()); // segmentID
    b.extend_from_slice(&0u32.to_le_bytes()); // cjsModuleCount
    b.extend_from_slice(&0u32.to_le_bytes()); // functionSourceCount
    b.extend_from_slice(&0u32.to_le_bytes()); // debugInfoOffset
    b.extend_from_slice(&[0u8; 20]); // options + padding → header = 128
    // segments (visitBytecodeSegmentsInOrder order)
    b.extend_from_slice(&0x8000_0001u32.to_le_bytes()); // kinds RLE: identifier ×1
    b.extend_from_slice(&0x0000_0002u32.to_le_bytes()); // kinds RLE: string ×2
    b.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // identifier hash
    b.extend_from_slice(&s0.to_le_bytes());
    b.extend_from_slice(&s1.to_le_bytes());
    b.extend_from_slice(&s2.to_le_bytes());
    b.extend_from_slice(&overflow);
    b.extend_from_slice(&storage);
    let file_len = b.len() as u32;
    b[file_length_placeholder..file_length_placeholder + 4]
        .copy_from_slice(&file_len.to_le_bytes());
    b
}

fn write_zip(path: &std::path::Path, entries: &[(&str, Vec<u8>)]) {
    let mut w = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    let opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap();
}

fn tmp_apk(tag: &str, entries: &[(&str, Vec<u8>)]) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("asc-hermes-{tag}.zip"));
    write_zip(&p, entries);
    p
}

#[test]
fn v96_bundle_strings_extracted() {
    let apk = tmp_apk("v96", &[("assets/index.android.bundle", bundle(96, None))]);
    let r = asc_core::hermes::run_hermes(&apk, &asc_core::hermes::HermesOptions::default())
        .expect("run");
    assert!(r.complete, "errors: {:?}", r.errors);
    assert_eq!(r.bundles.len(), 1);
    let b = &r.bundles[0];
    assert!(b.supported, "note: {:?}", b.note);
    assert_eq!(b.version, 96);
    assert_eq!(b.declared_string_count, 3);
    assert_eq!(b.strings.len(), 3);
    assert_eq!(b.strings[0].kind, "identifier");
    assert_eq!(b.strings[0].text, "Lfoo");
    assert_eq!(b.strings[1].kind, "string");
    assert_eq!(b.strings[1].text, "https://example.com/api");
    assert!(b.strings[2].is_utf16);
    assert_eq!(b.strings[2].text, "h\u{e9}llo");
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn pattern_filters_output() {
    let apk = tmp_apk("pat", &[("assets/index.android.bundle", bundle(96, None))]);
    let opts = asc_core::hermes::HermesOptions {
        pattern: Some("example.com".into()),
        ..Default::default()
    };
    let r = asc_core::hermes::run_hermes(&apk, &opts).expect("run");
    assert_eq!(r.bundles[0].strings.len(), 1);
    assert_eq!(r.bundles[0].strings[0].index, 1);
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn unsupported_version_is_reported_not_guessed() {
    let apk = tmp_apk("v95", &[("assets/index.android.bundle", bundle(95, None))]);
    let r = asc_core::hermes::run_hermes(&apk, &asc_core::hermes::HermesOptions::default())
        .expect("run");
    assert!(!r.complete);
    let b = &r.bundles[0];
    assert!(!b.supported);
    assert!(b.strings.is_empty());
    assert!(
        b.note
            .as_deref()
            .unwrap()
            .contains("unsupported hermes version 95")
    );
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn corrupt_storage_size_is_decode_failure_not_panic() {
    let apk = tmp_apk(
        "corrupt",
        &[("assets/index.android.bundle", bundle(96, Some(1 << 30)))],
    );
    let r = asc_core::hermes::run_hermes(&apk, &asc_core::hermes::HermesOptions::default())
        .expect("run");
    assert!(!r.complete);
    let b = &r.bundles[0];
    assert!(!b.supported);
    assert!(b.note.as_deref().unwrap().contains("decode failed"));
    let _ = std::fs::remove_file(&apk);
}

/// Corpus-gated: the real Locket bundle (v96, 62040 strings). Skips
/// silently when the fixture is absent.
#[test]
fn locket_bundle_end_to_end() {
    let apk = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apk/com.locket.Locket.apk");
    if !apk.exists() {
        eprintln!("skipping: corpus fixture missing");
        return;
    }
    let r = asc_core::hermes::run_hermes(&apk, &asc_core::hermes::HermesOptions::default())
        .expect("run");
    assert!(r.complete, "errors: {:?}", r.errors);
    let b = r
        .bundles
        .iter()
        .find(|b| b.name == "assets/index.android.bundle")
        .expect("bundle detected");
    assert!(b.supported, "note: {:?}", b.note);
    assert_eq!(b.version, 96);
    assert_eq!(b.declared_string_count, 62040);
    assert_eq!(b.strings.len(), 62040);
    assert!(!b.truncated);
    // A known endpoint from the verified table.
    let with_url = asc_core::hermes::run_hermes(
        &apk,
        &asc_core::hermes::HermesOptions {
            pattern: Some("clients3.google.com".into()),
            ..Default::default()
        },
    )
    .expect("run");
    assert!(
        with_url.bundles[0]
            .strings
            .iter()
            .any(|s| s.text.contains("clients3.google.com"))
    );
}
