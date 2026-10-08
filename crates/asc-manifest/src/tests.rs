//! Tests for the asc-manifest parser.
//!
//! Two kinds of fixtures are exercised:
//!
//! - **Real APKs** under `corpus/apk/` (skipped when missing, so the
//!   suite still builds in a fresh checkout).
//! - **Synthetic inputs** constructed in-place (empty input, wrong
//!   magic, truncated chunks, bad string indices, huge counts, …) to
//!   confirm the parser never panics and returns the expected error
//!   variant.

use super::*;

/// `true` when the fixture basename matches an entry of the
/// comma-separated `ASC_REQUIRE_CORPUS` list (CI sets it after
/// recreating the corpus fixtures it guarantees; a listed fixture that
/// is still missing must fail, not silently skip).
fn require_corpus(var: &str, p: &std::path::Path) -> bool {
    std::env::var(var).is_ok_and(|req| {
        req.split(',').any(|f| {
            let f = f.trim();
            !f.is_empty()
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(f))
        })
    })
}
fn corpus(name: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apk")
        .join(name);
    if !p.exists() && require_corpus("ASC_REQUIRE_CORPUS", &p) {
        panic!(
            "ASC_REQUIRE_CORPUS is set but fixture missing: {}",
            p.display()
        );
    }
    p.exists().then_some(p)
}

#[test]
fn empty_input_is_not_xml() {
    let err = parse_manifest(&[]).unwrap_err();
    assert!(matches!(err, ManifestError::NotAXml), "got {err:?}");
}

#[test]
fn wrong_magic_is_not_xml() {
    let mut bytes = vec![0u8; 16];
    bytes[..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::NotAXml), "got {err:?}");
}

#[test]
fn zeroed_root_type_still_parses() {
    // Anti-analysis trick seen in Virbox-packed malware: root header
    // `0x00080000` (type zeroed). Android ignores the type; so must we.
    let mut bytes = doc_with_start_element("manifest", start_element_fields(20, 0));
    bytes[..2].copy_from_slice(&0u16.to_le_bytes());
    parse_manifest(&bytes).expect("zeroed root type must be accepted");
}

#[test]
fn garbage_after_root_close_is_ignored() {
    // Chunks after `</manifest>` are never read by Android; malware
    // parks a zero-size chunk there to crash strict parsers.
    let mut bytes = doc_with_start_element("manifest", start_element_fields(20, 0));
    bytes.extend_from_slice(&0x0103u16.to_le_bytes()); // END_ELEMENT
    bytes.extend_from_slice(&0x0010u16.to_le_bytes());
    bytes.extend_from_slice(&24u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // lineNumber
    bytes.extend_from_slice(&NO_INDEX.to_le_bytes()); // comment
    bytes.extend_from_slice(&NO_INDEX.to_le_bytes()); // ns
    bytes.extend_from_slice(&0u32.to_le_bytes()); // name = "manifest"
    bytes.extend_from_slice(&[0u8; 8]); // garbage chunk: size 0 < headerSize
    let root_size = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&root_size.to_le_bytes());
    parse_manifest(&bytes).expect("garbage after </manifest> must be ignored");
}

#[test]
fn truncated_below_root_header_is_not_xml() {
    // Less than 8 bytes — the parser refuses because it can't even
    // read the magic.
    let bytes: Vec<u8> = vec![0x03, 0x00, 0x08, 0x00];
    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::NotAXml), "got {err:?}");
}

#[test]
fn root_size_overruns_input() {
    // Magic OK, declared root size 1 GiB but file is tiny. Our
    // sanity cap (64 MiB) catches this before any out-of-range read.
    let mut bytes = vec![0u8; 12];
    bytes[..4].copy_from_slice(&0x0008_0003u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&1_000_000_000u32.to_le_bytes());
    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::BadChunk(_)), "got {err:?}");
}

#[test]
fn root_size_below_header_size_errors() {
    // root_size = 6, which is less than the 8-byte ResChunk_header.
    let mut bytes = vec![0u8; 8];
    bytes[..4].copy_from_slice(&0x0008_0003u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&6u32.to_le_bytes());
    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::BadChunk(_)), "got {err:?}");
}

#[test]
fn first_inner_chunk_must_be_string_pool() {
    // 8-byte root header with size 16 (covers root header + 8-byte
    // child chunk that is NOT a string pool).
    let mut bytes = vec![0u8; 16];
    bytes[..4].copy_from_slice(&0x0008_0003u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&16u32.to_le_bytes());
    // child chunk: type=0x0180 (resource map), size=8.
    bytes[8..10].copy_from_slice(&0x0180u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&8u16.to_le_bytes());
    bytes[12..16].copy_from_slice(&8u32.to_le_bytes());
    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::BadChunk(_)), "got {err:?}");
}

#[test]
fn string_pool_with_bogus_count_errors() {
    // String pool with stringCount = MAX_STRING_COUNT+1 → BadChunk.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0008_0003u32.to_le_bytes());
    let root_size: u32 = 8 + 28;
    bytes.extend_from_slice(&root_size.to_le_bytes());
    // String pool chunk header
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0x001Cu16.to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());
    bytes.extend_from_slice(&(MAX_STRING_COUNT + 1).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::BadChunk(_)), "got {err:?}");
}

#[test]
fn garbage_string_offset_degrades_to_empty() {
    // Malware points unreferenced pool slots past the chunk. Android
    // decodes lazily and never trips on them; we decode that slot to ""
    // instead of rejecting the whole manifest.
    let mut bytes = doc_with_start_element("manifest", start_element_fields(20, 0));
    bytes[36..40].copy_from_slice(&0x7FFF_0000u32.to_le_bytes()); // offsets[0]
    parse_manifest(&bytes).expect("bad string offset must not fail the manifest");
}

#[test]
fn bad_string_index_in_attribute_errors_not_panics() {
    // Build a minimal but malformed document: valid string pool with
    // one string "manifest", then a START_ELEMENT that references
    // string index 999 (out of range).
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0008_0003u32.to_le_bytes());
    let root_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let sp_start = bytes.len();
    // String pool chunk: count=1, styleCount=0, flags=0 (UTF-16),
    // stringsStart=28, payload right after.
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0x001Cu16.to_le_bytes());
    let sp_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes()); // stringCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // styleCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
    bytes.extend_from_slice(&32u32.to_le_bytes()); // stringsStart
    bytes.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
    bytes.extend_from_slice(&0u32.to_le_bytes()); // offsets[0]
    // UTF-16LE payload: 8 chars "manifest" (each ASCII byte becomes
    // a UTF-16 code unit with a zero high byte).
    bytes.extend_from_slice(&8u16.to_le_bytes());
    for c in "manifest".bytes() {
        bytes.push(c);
        bytes.push(0);
    }
    bytes.extend_from_slice(&[0, 0]); // NUL terminator
    let sp_size = (bytes.len() - sp_start) as u32;
    bytes[sp_size_placeholder..sp_size_placeholder + 4].copy_from_slice(&sp_size.to_le_bytes());

    // START_ELEMENT chunk referencing string 999 (out of range).
    let se_start = bytes.len();
    bytes.extend_from_slice(&0x0102u16.to_le_bytes());
    bytes.extend_from_slice(&0x0010u16.to_le_bytes());
    let se_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // lineNumber
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns
    bytes.extend_from_slice(&999u32.to_le_bytes()); // name = 999 (bad)
    bytes.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
    bytes.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // attributeCount
    bytes.extend_from_slice(&0u16.to_le_bytes()); // idIndex
    bytes.extend_from_slice(&0u16.to_le_bytes()); // classIndex
    bytes.extend_from_slice(&0u16.to_le_bytes()); // styleIndex
    let se_size = (bytes.len() - se_start) as u32;
    bytes[se_size_placeholder..se_size_placeholder + 4].copy_from_slice(&se_size.to_le_bytes());

    let root_size = bytes.len() as u32;
    bytes[root_size_placeholder..root_size_placeholder + 4]
        .copy_from_slice(&root_size.to_le_bytes());

    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::BadChunk(_)), "got {err:?}");
}

/// Root header + a one-string UTF-16 pool containing `name` + a
/// START_ELEMENT chunk whose type-specific fields are `fields`
/// (20 bytes at chunk_start+16: ns, name, attributeStart,
/// attributeSize, attributeCount, idIndex, classIndex, styleIndex).
/// Used by the malformed-START_ELEMENT regression tests below.
fn doc_with_start_element(name: &str, fields: [u8; 20]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0008_0003u32.to_le_bytes());
    let root_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());

    let sp_start = bytes.len();
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0x001Cu16.to_le_bytes());
    let sp_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes()); // stringCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // styleCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // flags (UTF-16)
    bytes.extend_from_slice(&32u32.to_le_bytes()); // stringsStart
    bytes.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
    bytes.extend_from_slice(&0u32.to_le_bytes()); // offsets[0]
    let name_utf16: Vec<u16> = name.encode_utf16().collect();
    bytes.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
    for unit in &name_utf16 {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&[0, 0]); // NUL terminator
    let sp_size = (bytes.len() - sp_start) as u32;
    bytes[sp_size_placeholder..sp_size_placeholder + 4].copy_from_slice(&sp_size.to_le_bytes());

    let se_start = bytes.len();
    bytes.extend_from_slice(&0x0102u16.to_le_bytes());
    bytes.extend_from_slice(&0x0010u16.to_le_bytes());
    let se_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // lineNumber
    bytes.extend_from_slice(&NO_INDEX.to_le_bytes()); // comment
    bytes.extend_from_slice(&fields);
    let se_size = (bytes.len() - se_start) as u32;
    bytes[se_size_placeholder..se_size_placeholder + 4].copy_from_slice(&se_size.to_le_bytes());

    let root_size = bytes.len() as u32;
    bytes[root_size_placeholder..root_size_placeholder + 4]
        .copy_from_slice(&root_size.to_le_bytes());
    bytes
}

/// `ResXMLTree_attrExt` with a valid name index but the given
/// attributeSize / attributeCount, so tests only vary what they test.
fn start_element_fields(attr_size: u16, attr_count: u16) -> [u8; 20] {
    let mut f = [0u8; 20];
    f[0..4].copy_from_slice(&NO_INDEX.to_le_bytes()); // ns
    f[4..8].copy_from_slice(&0u32.to_le_bytes()); // name = "manifest"
    f[8..10].copy_from_slice(&20u16.to_le_bytes()); // attributeStart
    f[10..12].copy_from_slice(&attr_size.to_le_bytes()); // attributeSize
    f[12..14].copy_from_slice(&attr_count.to_le_bytes()); // attributeCount
    f
}

#[test]
fn string_pool_chunk_overrunning_root_errors_not_panics() {
    // The string-pool header is only complete, but its declared
    // chunk size runs past the root chunk end — so the string payload
    // that follows actually lives outside the document.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0008_0003u32.to_le_bytes());
    bytes.extend_from_slice(&36u32.to_le_bytes()); // root_size: 8 + 28
    let sp_start = bytes.len();
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0x001Cu16.to_le_bytes());
    bytes.extend_from_slice(&200u32.to_le_bytes()); // chunk_size → 208 > 36
    bytes.extend_from_slice(&1u32.to_le_bytes()); // stringCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // styleCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
    bytes.extend_from_slice(&28u32.to_le_bytes()); // stringsStart
    bytes.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
    assert_eq!(sp_start, 8);
    assert_eq!(bytes.len(), 36, "string pool header fills the root chunk");

    // A UTF-16 string "x" plus padding that makes the declared chunk
    // look complete when read against the file, not the root chunk.
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(b'x');
    bytes.push(0);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&[0u8; 168]);

    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::Truncated(_)), "got {err:?}");
}

#[test]
fn start_element_attribute_size_below_minimum_errors_not_panics() {
    // attributeSize = 4 (< 20): every attribute read would run off the
    // end of the chunk into the next one.
    let bytes = doc_with_start_element("manifest", start_element_fields(4, 1));
    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::BadChunk(_)), "got {err:?}");
}

#[test]
fn no_index_element_name_errors_not_panics() {
    // name = NO_INDEX with an attribute whose name index is also
    // NO_INDEX — neither may be used to index the string pool.
    let mut fields = start_element_fields(20, 1);
    fields[4..8].copy_from_slice(&NO_INDEX.to_le_bytes());
    let bytes = doc_with_start_element("manifest", fields);
    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::BadChunk(_)), "got {err:?}");
}

#[test]
fn utf8_string_pool_decodes() {
    // Build a string-pool chunk with the UTF-8 flag set, one string
    // "main", followed by a START_ELEMENT and END_ELEMENT for "main".
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0008_0003u32.to_le_bytes());
    let root_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());

    let sp_start = bytes.len();
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0x001Cu16.to_le_bytes());
    let sp_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes()); // count
    bytes.extend_from_slice(&0u32.to_le_bytes()); // styleCount
    bytes.extend_from_slice(&(1u32 << 8).to_le_bytes()); // UTF-8 flag
    bytes.extend_from_slice(&32u32.to_le_bytes()); // stringsStart
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // offsets[0]
    // UTF-8 payload: "main"
    bytes.push(4); // char_len
    bytes.push(4); // byte_len
    bytes.extend_from_slice(b"main");
    bytes.push(0); // terminator
    let sp_size = (bytes.len() - sp_start) as u32;
    bytes[sp_size_placeholder..sp_size_placeholder + 4].copy_from_slice(&sp_size.to_le_bytes());

    // START_ELEMENT referencing string 0 ("main") with no attrs.
    let se_start = bytes.len();
    bytes.extend_from_slice(&0x0102u16.to_le_bytes());
    bytes.extend_from_slice(&0x0010u16.to_le_bytes());
    let se_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // lineNumber
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns
    bytes.extend_from_slice(&0u32.to_le_bytes()); // name = 0
    bytes.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
    bytes.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // attributeCount
    bytes.extend_from_slice(&0u16.to_le_bytes()); // idIndex
    bytes.extend_from_slice(&0u16.to_le_bytes()); // classIndex
    bytes.extend_from_slice(&0u16.to_le_bytes()); // styleIndex
    let se_size = (bytes.len() - se_start) as u32;
    bytes[se_size_placeholder..se_size_placeholder + 4].copy_from_slice(&se_size.to_le_bytes());

    // END_ELEMENT referencing string 0.
    let ee_start = bytes.len();
    bytes.extend_from_slice(&0x0103u16.to_le_bytes());
    bytes.extend_from_slice(&0x0010u16.to_le_bytes());
    let ee_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // lineNumber
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns
    bytes.extend_from_slice(&0u32.to_le_bytes()); // name = 0
    let ee_size = (bytes.len() - ee_start) as u32;
    bytes[ee_size_placeholder..ee_size_placeholder + 4].copy_from_slice(&ee_size.to_le_bytes());

    let root_size = bytes.len() as u32;
    bytes[root_size_placeholder..root_size_placeholder + 4]
        .copy_from_slice(&root_size.to_le_bytes());

    let info = parse_manifest(&bytes).expect("parse ok");
    assert_eq!(info.activities.len(), 0);
    assert_eq!(info.permissions.len(), 0);
}

#[test]
fn aurora_store_manifest_real_fixture() {
    let Some(path) = corpus("com.aurora.store_60.apk") else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let info = parse_from_apk(&path).expect("aurora manifest should parse");
    assert_eq!(info.package.as_deref(), Some("com.aurora.store"));
    assert_eq!(info.version_code, Some(60));
    assert!(
        info.min_sdk.unwrap_or(0) >= 21,
        "minSdkVersion too low: {:?}",
        info.min_sdk
    );
    assert!(
        info.target_sdk.unwrap_or(0) >= 24,
        "targetSdkVersion too low: {:?}",
        info.target_sdk
    );
    assert!(
        info.permissions.len() >= 3,
        "expected several permissions, got {:?}",
        info.permissions.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
    let launcher = info
        .activities
        .iter()
        .find(|a| {
            a.intent_filters.iter().any(|f| {
                f.actions.iter().any(|a| a == "android.intent.action.MAIN")
                    && f.categories
                        .iter()
                        .any(|c| c == "android.intent.category.LAUNCHER")
            })
        })
        .expect("expected at least one launcher activity");
    assert!(!launcher.name.is_empty());
}

#[test]
fn fdroid_manifest_real_fixture() {
    let Some(path) = corpus("org.fdroid.fdroid_1016000.apk") else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let info = parse_from_apk(&path).expect("fdroid manifest should parse");
    assert_eq!(info.package.as_deref(), Some("org.fdroid.fdroid"));
    assert!(
        info.permissions.len() >= 3,
        "expected several permissions, got {:?}",
        info.permissions.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
}

#[test]
fn invalid_path_io_error() {
    // The APK-open path is wrapped so any IO error from asc-apk is
    // surfaced as `ManifestError::Truncated`. (We deliberately use the
    // path-level convenience so the error doesn't depend on the OS
    // variant of "file not found".)
    let err = parse_from_apk("/this/path/does/not/exist.apk").unwrap_err();
    assert!(matches!(err, ManifestError::Truncated(_)), "got {err:?}");
}

/// Hand-built single-entry STORED ZIP — the minimum `Apk::open` accepts.
/// (Test builders are duplicated per crate by house style; there is no
/// shared test-utils crate.)
fn stored_zip(name: &str, payload: &[u8]) -> Vec<u8> {
    let name = name.as_bytes();
    let crc = crc32fast::hash(payload);
    let mut zip: Vec<u8> = Vec::new();

    // Local file header (offset 0).
    let local_offset: u32 = 0;
    zip.extend_from_slice(b"PK\x03\x04");
    zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip.extend_from_slice(&0u16.to_le_bytes()); // flags
    zip.extend_from_slice(&0u16.to_le_bytes()); // compression = stored
    zip.extend_from_slice(&0u16.to_le_bytes()); // mod time
    zip.extend_from_slice(&0u16.to_le_bytes()); // mod date
    zip.extend_from_slice(&crc.to_le_bytes());
    zip.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed
    zip.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // uncompressed
    zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // extra
    zip.extend_from_slice(name);
    zip.extend_from_slice(payload);

    let central_off = zip.len() as u32;
    // Central directory.
    zip.extend_from_slice(b"PK\x01\x02");
    zip.extend_from_slice(&20u16.to_le_bytes()); // version made by
    zip.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip.extend_from_slice(&0u16.to_le_bytes()); // flags
    zip.extend_from_slice(&0u16.to_le_bytes()); // compression
    zip.extend_from_slice(&0u16.to_le_bytes()); // mod time
    zip.extend_from_slice(&0u16.to_le_bytes()); // mod date
    zip.extend_from_slice(&crc.to_le_bytes());
    zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // extra
    zip.extend_from_slice(&0u16.to_le_bytes()); // comment
    zip.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    zip.extend_from_slice(&0u16.to_le_bytes()); // internal attr
    zip.extend_from_slice(&0u32.to_le_bytes()); // external attr
    zip.extend_from_slice(&local_offset.to_le_bytes());
    zip.extend_from_slice(name);
    let central_size = (zip.len() as u32) - central_off;

    // End of central directory.
    zip.extend_from_slice(b"PK\x05\x06");
    zip.extend_from_slice(&0u16.to_le_bytes()); // disk number
    zip.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
    zip.extend_from_slice(&1u16.to_le_bytes()); // CD entries on this disk
    zip.extend_from_slice(&1u16.to_le_bytes()); // total CD entries
    zip.extend_from_slice(&central_size.to_le_bytes());
    zip.extend_from_slice(&central_off.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes()); // comment length
    zip
}

#[test]
fn apk_without_manifest_is_absence_not_failure() {
    // No AndroidManifest.xml entry at all: `parse_from_apk` must report
    // *absence* (`NotFound`) so a caller can print "no manifest" instead
    // of "manifest is corrupt", and must never panic or succeed.
    let tmp = std::env::temp_dir().join("asc_manifest_no_manifest.apk");
    std::fs::write(&tmp, stored_zip("empty.txt", b"hello")).unwrap();
    let err = parse_from_apk(&tmp).unwrap_err();
    assert!(matches!(err, ManifestError::NotFound(_)), "got {err:?}");
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn apk_with_corrupt_manifest_is_a_parse_failure() {
    // Present but not binary XML. Must be a *parse* error, distinct from
    // the absence case above, so the GUI can say "manifest parse failed"
    // rather than conflating it with "no manifest".
    let tmp = std::env::temp_dir().join("asc_manifest_corrupt.apk");
    std::fs::write(&tmp, stored_zip("AndroidManifest.xml", b"not axml at all")).unwrap();
    let err = parse_from_apk(&tmp).unwrap_err();
    assert!(matches!(err, ManifestError::NotAXml), "got {err:?}");
    assert!(
        !matches!(err, ManifestError::NotFound(_)),
        "a corrupt manifest is not an absent one"
    );
    let _ = std::fs::remove_file(&tmp);
}

// ---------------------------------------------------------------------------
// Binary-AXML fixture builder (test-only).
//
// Assembles a complete, AOSP-shaped binary XML document: root chunk, UTF-16
// string pool, namespace events, and element events with typed attributes.
// Used by the P0 regression tests and the full-manifest fixture.
// ---------------------------------------------------------------------------
mod axml {
    pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";
    pub const TOOLS_NS: &str = "http://schemas.android.com/tools";

    const TYPE_REFERENCE: u8 = 0x01;
    const TYPE_STRING: u8 = 0x03;
    const TYPE_INT_DEC: u8 = 0x10;
    const TYPE_INT_HEX: u8 = 0x11;
    const TYPE_INT_BOOLEAN: u8 = 0x12;
    const NO_INDEX: u32 = 0xFFFF_FFFF;

    /// A typed attribute value, mirroring how aapt compiles source XML.
    #[derive(Clone)]
    pub enum Val {
        /// `TYPE_STRING` with both `rawValue` and `typedValue.data` set.
        Str(&'static str),
        /// `TYPE_STRING` with `rawValue = NO_INDEX` and only `data` valid —
        /// the AOSP fallback path (`Res_value.data` holds the string index).
        StrDataOnly(&'static str),
        Bool(bool),
        IntDec(u32),
        IntHex(u32),
        Reference(u32),
    }

    #[derive(Clone)]
    pub struct Attr {
        pub ns: Option<&'static str>,
        pub name: &'static str,
        pub val: Val,
    }

    pub fn attr(ns: Option<&'static str>, name: &'static str, val: Val) -> Attr {
        Attr { ns, name, val }
    }

    pub struct Elem {
        pub name: &'static str,
        pub attrs: Vec<Attr>,
        pub children: Vec<Elem>,
    }

    pub fn elem(name: &'static str, attrs: Vec<Attr>, children: Vec<Elem>) -> Elem {
        Elem {
            name,
            attrs,
            children,
        }
    }

    /// String pool writer: strings deduplicated in insertion order; returns
    /// `(pool chunk bytes, lookup map)`.
    fn build_pool(strings: &[String]) -> (Vec<u8>, std::collections::HashMap<String, u32>) {
        let mut map = std::collections::HashMap::new();
        for (i, s) in strings.iter().enumerate() {
            map.insert(s.clone(), i as u32);
        }
        let mut data: Vec<u8> = Vec::new();
        let mut offsets = Vec::with_capacity(strings.len());
        for s in strings {
            let units: Vec<u16> = s.encode_utf16().collect();
            assert!(units.len() < 0x8000, "fixture string too long: {s}");
            offsets.push(data.len() as u32);
            data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in units {
                data.extend_from_slice(&u.to_le_bytes());
            }
            data.extend_from_slice(&0u16.to_le_bytes()); // NUL terminator
        }
        while !data.len().is_multiple_of(4) {
            data.push(0);
        }
        let strings_start = 28 + strings.len() * 4; // header + offsets table
        let size = strings_start + data.len();
        let mut pool = Vec::with_capacity(size);
        pool.extend_from_slice(&1u16.to_le_bytes()); // RES_STRING_POOL_TYPE
        pool.extend_from_slice(&28u16.to_le_bytes()); // headerSize
        pool.extend_from_slice(&(size as u32).to_le_bytes());
        pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes()); // styleCount
        pool.extend_from_slice(&0u32.to_le_bytes()); // flags: UTF-16
        pool.extend_from_slice(&(strings_start as u32).to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
        for off in offsets {
            pool.extend_from_slice(&off.to_le_bytes());
        }
        pool.extend_from_slice(&data);
        (pool, map)
    }

    fn collect_strings(e: &Elem, ns_uris: &mut Vec<String>, out: &mut Vec<String>) {
        // Element names are plain; attribute names/values may reference URIs.
        if !out.iter().any(|s| s == e.name) {
            out.push(e.name.to_string());
        }
        for a in &e.attrs {
            if let Some(uri) = a.ns
                && uri != ANDROID_NS // android URI also emitted explicitly below
                && !ns_uris.iter().any(|s| s == uri)
            {
                ns_uris.push(uri.to_string());
            }
            if !out.iter().any(|s| s == a.name) {
                out.push(a.name.to_string());
            }
            if let Val::Str(s) | Val::StrDataOnly(s) = a.val
                && !out.iter().any(|x| x == s)
            {
                out.push(s.to_string());
            }
        }
        for c in &e.children {
            collect_strings(c, ns_uris, out);
        }
    }

    fn push_element(out: &mut Vec<u8>, e: &Elem, map: &std::collections::HashMap<String, u32>) {
        let idx = |s: &str| map[s];
        let start_off = out.len();
        out.extend_from_slice(&0x0102u16.to_le_bytes()); // START_ELEMENT
        out.extend_from_slice(&16u16.to_le_bytes()); // headerSize
        let size_off = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // size (patched)
        out.extend_from_slice(&1u32.to_le_bytes()); // lineNumber (u32)
        out.extend_from_slice(&NO_INDEX.to_le_bytes()); // comment
        out.extend_from_slice(&NO_INDEX.to_le_bytes()); // ns (manifest elements are plain)
        out.extend_from_slice(&idx(e.name).to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
        out.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
        out.extend_from_slice(&(e.attrs.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // idIndex
        out.extend_from_slice(&0u16.to_le_bytes()); // classIndex
        out.extend_from_slice(&0u16.to_le_bytes()); // styleIndex
        for a in &e.attrs {
            let ns_idx = a.ns.map_or(NO_INDEX, idx);
            out.extend_from_slice(&ns_idx.to_le_bytes());
            out.extend_from_slice(&idx(a.name).to_le_bytes());
            let (raw, ty, data) = match &a.val {
                Val::Str(s) => (idx(s), TYPE_STRING, idx(s)),
                Val::StrDataOnly(s) => (NO_INDEX, TYPE_STRING, idx(s)),
                Val::Bool(b) => (NO_INDEX, TYPE_INT_BOOLEAN, u32::from(*b)),
                Val::IntDec(v) => (NO_INDEX, TYPE_INT_DEC, *v),
                Val::IntHex(v) => (NO_INDEX, TYPE_INT_HEX, *v),
                Val::Reference(v) => (NO_INDEX, TYPE_REFERENCE, *v),
            };
            out.extend_from_slice(&raw.to_le_bytes());
            out.extend_from_slice(&8u16.to_le_bytes()); // typedValue.size
            out.extend_from_slice(&0u8.to_le_bytes()); // res0
            out.extend_from_slice(&ty.to_le_bytes());
            out.extend_from_slice(&data.to_le_bytes());
        }
        let size = (out.len() - start_off) as u32;
        out[size_off..size_off + 4].copy_from_slice(&size.to_le_bytes());

        for c in &e.children {
            push_element(out, c, map);
        }

        // END_ELEMENT
        out.extend_from_slice(&0x0103u16.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(&24u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // lineNumber (u32)
        out.extend_from_slice(&NO_INDEX.to_le_bytes()); // comment
        out.extend_from_slice(&NO_INDEX.to_le_bytes()); // ns
        out.extend_from_slice(&idx(e.name).to_le_bytes());
    }

    /// Serialize the tree to a complete binary XML document.
    pub fn build(root: &Elem) -> Vec<u8> {
        // String pool: all names/values first, then the android URI + prefix
        // (the parser validates ns string indexes), then extra URIs.
        let mut ns_uris = Vec::new();
        let mut strings = Vec::new();
        collect_strings(root, &mut ns_uris, &mut strings);
        for extra in [ANDROID_NS, "android", "tools"] {
            if !strings.iter().any(|s| s == extra) {
                strings.push(extra.to_string());
            }
        }
        for u in &ns_uris {
            if !strings.iter().any(|s| s == u) {
                strings.push(u.clone());
            }
        }
        let (pool, map) = build_pool(&strings);

        let mut body = pool;
        // Namespace start events for every URI in play.
        for (i, uri) in std::iter::once(ANDROID_NS)
            .chain(ns_uris.iter().map(String::as_str))
            .enumerate()
        {
            let prefix = if uri == ANDROID_NS {
                "android"
            } else {
                "tools"
            };
            body.extend_from_slice(&0x0100u16.to_le_bytes()); // START_NAMESPACE
            body.extend_from_slice(&16u16.to_le_bytes());
            body.extend_from_slice(&24u32.to_le_bytes());
            body.extend_from_slice(&1u32.to_le_bytes()); // lineNumber (u32)
            body.extend_from_slice(&NO_INDEX.to_le_bytes()); // comment
            body.extend_from_slice(&map[prefix].to_le_bytes());
            body.extend_from_slice(&map[uri].to_le_bytes());
            let _ = i;
        }

        let elem_start = body.len();
        push_element(&mut body, root, &map);

        // Root chunk header: type ignored by the parser, headerSize 8.
        let total = 8 + body.len();
        let mut doc = Vec::with_capacity(total);
        doc.extend_from_slice(&0x0003u16.to_le_bytes());
        doc.extend_from_slice(&8u16.to_le_bytes());
        doc.extend_from_slice(&(total as u32).to_le_bytes());
        doc.extend_from_slice(&body[..elem_start]);
        doc.extend_from_slice(&body[elem_start..]);
        // (end-namespace events omitted: the parser ignores them and the
        // manifest element-close already terminates the document walk)
        doc
    }
}

// ---------------------------------------------------------------------------
// P0.4 regression tests (written against the pre-fix model; each failed
// before the corresponding fix).
// ---------------------------------------------------------------------------

/// P0.4.1: `<application>` is a child of `<manifest>` in every real AXML;
/// its label must still be captured.
#[test]
fn application_label_is_parsed_when_nested_under_manifest() {
    let doc = axml::elem(
        "manifest",
        vec![axml::attr(
            None,
            "package",
            axml::Val::Str("com.example.app"),
        )],
        vec![axml::elem(
            "application",
            vec![axml::attr(
                Some(axml::ANDROID_NS),
                "label",
                axml::Val::Str("Example App"),
            )],
            vec![],
        )],
    );
    let info = parse_manifest(&axml::build(&doc)).expect("parse");
    assert_eq!(info.application_label.as_deref(), Some("Example App"));
}

/// P0.4.2: `TYPE_STRING` with `rawValue = NO_INDEX` must resolve through
/// `typedValue.data` (AOSP `Res_value` semantics), not vanish.
#[test]
fn string_typed_attribute_without_rawvalue_resolves_via_data() {
    let doc = axml::elem(
        "manifest",
        vec![],
        vec![axml::elem(
            "application",
            vec![axml::attr(
                Some(axml::ANDROID_NS),
                "label",
                axml::Val::StrDataOnly("DataOnlyLabel"),
            )],
            vec![],
        )],
    );
    let info = parse_manifest(&axml::build(&doc)).expect("parse");
    assert_eq!(info.application_label.as_deref(), Some("DataOnlyLabel"));
}

/// P0.4.3: an attribute with the same local name in a non-Android namespace
/// (e.g. `tools:exported`) must not be mistaken for `android:exported`.
#[test]
fn attributes_in_non_android_namespace_are_ignored() {
    let doc = axml::elem(
        "manifest",
        vec![],
        vec![axml::elem(
            "application",
            vec![],
            vec![axml::elem(
                "activity",
                vec![
                    axml::attr(
                        Some(axml::ANDROID_NS),
                        "name",
                        axml::Val::Str("com.example.MainActivity"),
                    ),
                    axml::attr(Some(axml::TOOLS_NS), "exported", axml::Val::Bool(true)),
                ],
                vec![],
            )],
        )],
    );
    let info = parse_manifest(&axml::build(&doc)).expect("parse");
    let activity = info.activities.first().expect("activity captured");
    assert!(
        !activity.exported,
        "tools:exported leaked into android:exported: {activity:?}"
    );
}

/// Hand-built minimal document with one START_ELEMENT carrying exactly
/// one attribute with fully controllable raw fields (for malformed-index
/// regression tests; the fixture builder always emits valid indexes).
fn element_with_attr(attr_ns: u32, attr_name: u32, attr_raw: u32, ty: u8, data: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0003u16.to_le_bytes());
    bytes.extend_from_slice(&0x0008u16.to_le_bytes()); // headerSize
    let root_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());

    // String pool with 2 strings: "n0", "n1".
    let sp_start = bytes.len();
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0x001Cu16.to_le_bytes());
    let sp_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes()); // stringCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // styleCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // flags (UTF-16)
    bytes.extend_from_slice(&0x24u32.to_le_bytes()); // stringsStart
    bytes.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
    bytes.extend_from_slice(&0u32.to_le_bytes()); // offsets[0]
    bytes.extend_from_slice(&4u32.to_le_bytes()); // offsets[1]
    bytes.extend_from_slice(&1u16.to_le_bytes()); // len 1
    bytes.extend_from_slice(&0x6Eu16.to_le_bytes()); // 'n'
    bytes.extend_from_slice(&0u16.to_le_bytes()); // NUL
    bytes.extend_from_slice(&1u16.to_le_bytes()); // len 1
    bytes.extend_from_slice(&0x31u16.to_le_bytes()); // '1'
    bytes.extend_from_slice(&0u16.to_le_bytes()); // NUL
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
    let sp_size = (bytes.len() - sp_start) as u32;
    bytes[sp_size_placeholder..sp_size_placeholder + 4].copy_from_slice(&sp_size.to_le_bytes());

    // START_ELEMENT "n0" with one attribute.
    let se_start = bytes.len();
    bytes.extend_from_slice(&0x0102u16.to_le_bytes());
    bytes.extend_from_slice(&0x0010u16.to_le_bytes());
    let se_size_placeholder = bytes.len();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // lineNumber
    bytes.extend_from_slice(&NO_INDEX.to_le_bytes()); // comment
    bytes.extend_from_slice(&NO_INDEX.to_le_bytes()); // element ns
    bytes.extend_from_slice(&0u32.to_le_bytes()); // element name -> "n0"
    bytes.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
    bytes.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
    bytes.extend_from_slice(&1u16.to_le_bytes()); // attributeCount
    bytes.extend_from_slice(&0u16.to_le_bytes()); // idIndex
    bytes.extend_from_slice(&0u16.to_le_bytes()); // classIndex
    bytes.extend_from_slice(&0u16.to_le_bytes()); // styleIndex
    bytes.extend_from_slice(&attr_ns.to_le_bytes());
    bytes.extend_from_slice(&attr_name.to_le_bytes());
    bytes.extend_from_slice(&attr_raw.to_le_bytes());
    bytes.extend_from_slice(&8u16.to_le_bytes()); // typedValue.size
    bytes.extend_from_slice(&0u8.to_le_bytes()); // res0
    bytes.extend_from_slice(&ty.to_le_bytes());
    bytes.extend_from_slice(&data.to_le_bytes());
    let se_size = (bytes.len() - se_start) as u32;
    bytes[se_size_placeholder..se_size_placeholder + 4].copy_from_slice(&se_size.to_le_bytes());

    let root_size = bytes.len() as u32;
    bytes[root_size_placeholder..root_size_placeholder + 4]
        .copy_from_slice(&root_size.to_le_bytes());
    bytes
}

/// P0.4.3 companion: an out-of-range attribute-namespace index is a
/// hard error (malformed), never a panic or silent ignore.
#[test]
fn attribute_ns_index_out_of_range_errors_not_panics() {
    let doc = element_with_attr(0x0006_0000, 1, NO_INDEX, 0x12, 1);
    match parse_manifest(&doc) {
        Err(ManifestError::BadChunk(m)) => assert!(m.contains("attribute ns"), "{m}"),
        other => panic!("expected BadChunk, got {other:?}"),
    }
}

/// P0.1-P0.3 comprehensive synthetic fixture: data specs, autoVerify,
/// priority, activity-alias, meta-data at both levels, queries,
/// uses-feature, split markers, exported tri-state.
#[test]
fn full_manifest_fixture_extracts_p0_fields() {
    use axml::{ANDROID_NS, Val, attr, elem};
    let doc = elem(
        "manifest",
        vec![
            attr(None, "package", Val::Str("com.example.app")),
            attr(None, "split", Val::Str("config.arm64_v8a")),
            attr(Some(ANDROID_NS), "splitTypes", Val::Str("base__abi")),
            attr(Some(ANDROID_NS), "isFeatureSplit", Val::Bool(false)),
        ],
        vec![
            elem(
                "uses-sdk",
                vec![
                    attr(Some(ANDROID_NS), "minSdkVersion", Val::IntDec(21)),
                    attr(Some(ANDROID_NS), "targetSdkVersion", Val::IntDec(35)),
                ],
                vec![],
            ),
            elem(
                "uses-permission",
                vec![
                    attr(
                        Some(ANDROID_NS),
                        "name",
                        Val::Str("android.permission.CAMERA"),
                    ),
                    attr(Some(ANDROID_NS), "maxSdkVersion", Val::IntDec(28)),
                ],
                vec![],
            ),
            elem(
                "uses-feature",
                vec![
                    attr(
                        Some(ANDROID_NS),
                        "name",
                        Val::Str("android.hardware.camera"),
                    ),
                    attr(Some(ANDROID_NS), "required", Val::Bool(false)),
                ],
                vec![],
            ),
            elem(
                "uses-feature",
                vec![attr(
                    Some(ANDROID_NS),
                    "glEsVersion",
                    Val::IntHex(0x0003_0001),
                )],
                vec![],
            ),
            elem(
                "queries",
                vec![],
                vec![
                    elem(
                        "package",
                        vec![attr(
                            Some(ANDROID_NS),
                            "name",
                            Val::Str("com.example.other"),
                        )],
                        vec![],
                    ),
                    elem(
                        "intent",
                        vec![],
                        vec![
                            elem(
                                "action",
                                vec![attr(
                                    Some(ANDROID_NS),
                                    "name",
                                    Val::Str("android.intent.action.VIEW"),
                                )],
                                vec![],
                            ),
                            elem(
                                "category",
                                vec![attr(
                                    Some(ANDROID_NS),
                                    "name",
                                    Val::Str("android.intent.category.BROWSABLE"),
                                )],
                                vec![],
                            ),
                            elem(
                                "data",
                                vec![attr(Some(ANDROID_NS), "scheme", Val::Str("https"))],
                                vec![],
                            ),
                        ],
                    ),
                    elem(
                        "provider",
                        vec![attr(
                            Some(ANDROID_NS),
                            "authorities",
                            Val::Str("com.example.cp"),
                        )],
                        vec![],
                    ),
                ],
            ),
            elem(
                "application",
                vec![
                    attr(Some(ANDROID_NS), "label", Val::Str("Example")),
                    attr(Some(ANDROID_NS), "allowBackup", Val::Bool(false)),
                    attr(Some(ANDROID_NS), "debuggable", Val::Bool(true)),
                    attr(
                        Some(ANDROID_NS),
                        "networkSecurityConfig",
                        Val::Reference(0x7f15_0002),
                    ),
                ],
                vec![
                    elem(
                        "meta-data",
                        vec![
                            attr(Some(ANDROID_NS), "name", Val::Str("app.level")),
                            attr(Some(ANDROID_NS), "value", Val::Str("v1")),
                        ],
                        vec![],
                    ),
                    elem(
                        "activity",
                        vec![
                            attr(
                                Some(ANDROID_NS),
                                "name",
                                Val::Str("com.example.MainActivity"),
                            ),
                            attr(Some(ANDROID_NS), "process", Val::Str(":remote")),
                        ],
                        vec![
                            elem(
                                "intent-filter",
                                vec![
                                    attr(Some(ANDROID_NS), "autoVerify", Val::Bool(true)),
                                    attr(Some(ANDROID_NS), "priority", Val::IntDec(10)),
                                ],
                                vec![
                                    elem(
                                        "action",
                                        vec![attr(
                                            Some(ANDROID_NS),
                                            "name",
                                            Val::Str("android.intent.action.MAIN"),
                                        )],
                                        vec![],
                                    ),
                                    elem(
                                        "category",
                                        vec![attr(
                                            Some(ANDROID_NS),
                                            "name",
                                            Val::Str("android.intent.category.LAUNCHER"),
                                        )],
                                        vec![],
                                    ),
                                ],
                            ),
                            elem(
                                "intent-filter",
                                vec![attr(
                                    Some(ANDROID_NS),
                                    "priority",
                                    // -10 as aapt stores it: INT_DEC with
                                    // the u32 two's-complement payload.
                                    Val::IntDec(0xFFFF_FFF6),
                                )],
                                vec![
                                    elem(
                                        "action",
                                        vec![attr(
                                            Some(ANDROID_NS),
                                            "name",
                                            Val::Str("android.intent.action.VIEW"),
                                        )],
                                        vec![],
                                    ),
                                    elem(
                                        "category",
                                        vec![attr(
                                            Some(ANDROID_NS),
                                            "name",
                                            Val::Str("android.intent.category.BROWSABLE"),
                                        )],
                                        vec![],
                                    ),
                                    elem(
                                        "category",
                                        vec![attr(
                                            Some(ANDROID_NS),
                                            "name",
                                            Val::Str("android.intent.category.DEFAULT"),
                                        )],
                                        vec![],
                                    ),
                                    elem(
                                        "data",
                                        vec![
                                            attr(Some(ANDROID_NS), "scheme", Val::Str("https")),
                                            attr(Some(ANDROID_NS), "host", Val::Str("example.com")),
                                            attr(Some(ANDROID_NS), "port", Val::Str("8443")),
                                            attr(Some(ANDROID_NS), "pathPrefix", Val::Str("/app")),
                                        ],
                                        vec![],
                                    ),
                                    elem(
                                        "data",
                                        vec![attr(
                                            Some(ANDROID_NS),
                                            "mimeType",
                                            Val::Str("image/*"),
                                        )],
                                        vec![],
                                    ),
                                ],
                            ),
                            elem(
                                "meta-data",
                                vec![
                                    attr(Some(ANDROID_NS), "name", Val::Str("comp.level")),
                                    attr(Some(ANDROID_NS), "resource", Val::Reference(0x7f02_0001)),
                                ],
                                vec![],
                            ),
                        ],
                    ),
                    elem(
                        "activity-alias",
                        vec![
                            attr(Some(ANDROID_NS), "name", Val::Str("com.example.AliasMain")),
                            attr(
                                Some(ANDROID_NS),
                                "targetActivity",
                                Val::Str("com.example.MainActivity"),
                            ),
                            attr(Some(ANDROID_NS), "exported", Val::Bool(false)),
                        ],
                        vec![elem(
                            "intent-filter",
                            vec![],
                            vec![
                                elem(
                                    "action",
                                    vec![attr(
                                        Some(ANDROID_NS),
                                        "name",
                                        Val::Str("android.intent.action.MAIN"),
                                    )],
                                    vec![],
                                ),
                                elem(
                                    "category",
                                    vec![attr(
                                        Some(ANDROID_NS),
                                        "name",
                                        Val::Str("android.intent.category.LAUNCHER"),
                                    )],
                                    vec![],
                                ),
                            ],
                        )],
                    ),
                    elem(
                        "provider",
                        vec![
                            attr(Some(ANDROID_NS), "name", Val::Str("com.example.CP")),
                            attr(Some(ANDROID_NS), "authorities", Val::Str("com.example.cp")),
                            attr(Some(ANDROID_NS), "exported", Val::Bool(true)),
                            attr(
                                Some(ANDROID_NS),
                                "readPermission",
                                Val::Str("com.example.READ"),
                            ),
                        ],
                        vec![elem(
                            "meta-data",
                            vec![
                                attr(Some(ANDROID_NS), "name", Val::Str("provider.level")),
                                attr(Some(ANDROID_NS), "value", Val::Str("pv")),
                            ],
                            vec![],
                        )],
                    ),
                ],
            ),
        ],
    );
    let info = parse_manifest(&axml::build(&doc)).expect("parse");

    // Split markers (P0.3).
    assert_eq!(info.split.as_deref(), Some("config.arm64_v8a"));
    assert_eq!(info.split_types.as_deref(), Some("base__abi"));
    assert_eq!(info.is_feature_split, Some(false));

    // Permissions with maxSdkVersion.
    assert_eq!(
        info.permissions[0].max_sdk,
        Some(28),
        "{:?}",
        info.permissions
    );

    // Uses-features.
    assert_eq!(info.uses_features.len(), 2);
    assert_eq!(info.uses_features[0].required, Some(false));
    assert_eq!(
        info.uses_features[1].gl_es_version.as_deref(),
        Some("0x00030001")
    );

    // Queries.
    let q = info.queries.as_ref().expect("queries");
    assert_eq!(q.packages, ["com.example.other"]);
    assert_eq!(q.providers, ["com.example.cp"]);
    assert_eq!(q.intents.len(), 1);
    assert_eq!(q.intents[0].actions, ["android.intent.action.VIEW"]);
    assert_eq!(q.intents[0].data.len(), 1);
    assert_eq!(q.intents[0].data[0].scheme.as_deref(), Some("https"));

    // Application attributes and meta-data (P0.2).
    assert_eq!(info.application_label.as_deref(), Some("Example"));
    assert_eq!(info.application.allow_backup, Some(false));
    assert!(!info.effective_allow_backup());
    assert_eq!(info.application.debuggable, Some(true));
    assert_eq!(
        info.application.network_security_config.as_deref(),
        Some("@0x7f150002")
    );
    assert!(
        !info.effective_uses_cleartext_traffic(),
        "target 35 disables cleartext"
    );
    assert_eq!(info.application.meta_data.len(), 1);
    assert_eq!(info.application.meta_data[0].name, "app.level");
    assert_eq!(info.application.meta_data[0].value.as_deref(), Some("v1"));

    // Activity: process, tri-state exported, filters with data.
    let a = &info.activities[0];
    assert_eq!(a.process.as_deref(), Some(":remote"));
    assert_eq!(a.exported_explicit, None, "exported not declared");
    assert!(a.exported, "inferred exported from filters");
    assert_eq!(
        a.exported_state,
        ExportedState::MissingRequired,
        "target 35 + filter + no android:exported is install-invalid"
    );
    assert!(info.has_invalid_exported());
    assert_eq!(a.intent_filters.len(), 2);
    assert_eq!(a.intent_filters[0].auto_verify, Some(true));
    assert_eq!(a.intent_filters[0].priority, Some(10));
    let f1 = &a.intent_filters[1];
    assert_eq!(f1.priority, Some(-10), "negative INT_DEC priority");
    assert_eq!(f1.categories.len(), 2, "categories preserved");
    assert_eq!(f1.data.len(), 2, "raw <data> elements preserved verbatim");
    assert_eq!(f1.data[0].scheme.as_deref(), Some("https"));
    assert_eq!(f1.data[0].host.as_deref(), Some("example.com"));
    assert_eq!(f1.data[0].port.as_deref(), Some("8443"));
    assert_eq!(f1.data[0].path_prefix.as_deref(), Some("/app"));
    assert_eq!(f1.data[1].mime_type.as_deref(), Some("image/*"));
    // ... but Android pools them into one match set.
    assert_eq!(f1.effective_data.schemes, ["https"]);
    assert_eq!(f1.effective_data.authorities[0].host, "example.com");
    assert_eq!(
        f1.effective_data.authorities[0].port.as_deref(),
        Some("8443")
    );
    assert_eq!(f1.effective_data.paths[0].kind, PathMatchKind::Prefix);
    assert_eq!(f1.effective_data.mime_types, ["image/*"]);
    assert_eq!(a.meta_data.len(), 1);
    assert_eq!(a.meta_data[0].resource.as_deref(), Some("@0x7f020001"));

    // Activity-alias: declared exported=false wins over the LAUNCHER filter.
    let alias = &info.activity_aliases[0];
    assert_eq!(
        alias.target_activity.as_deref(),
        Some("com.example.MainActivity")
    );
    assert_eq!(alias.component.exported_explicit, Some(false));
    assert!(
        !alias.component.exported,
        "declared false beats filter inference"
    );
    assert_eq!(alias.component.intent_filters.len(), 1);

    // Provider: declared exported, read permission, nested meta-data.
    let p = &info.providers[0];
    assert_eq!(p.exported_explicit, Some(true));
    assert!(p.exported);
    assert_eq!(p.read_permission.as_deref(), Some("com.example.READ"));
    assert_eq!(p.meta_data.len(), 1, "provider meta-data must be routed");
    assert_eq!(p.meta_data[0].name, "provider.level");
    assert_eq!(p.meta_data[0].value.as_deref(), Some("pv"));
}

/// Locket Widget 1.216.0 real-fixture: deep links, aliases, queries,
/// application attrs — values cross-checked against androguard.
#[test]
fn locket_manifest_real_fixture_p0_fields() {
    let Some(path) = corpus("com.locket.Locket.apk") else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let info = parse_from_apk(&path).expect("locket manifest should parse");

    // Application attrs observed via androguard.
    assert_eq!(info.application.uses_cleartext_traffic, Some(true));
    assert_eq!(info.application.extract_native_libs, Some(false));
    // The label is a resource reference; it must be captured (P0.4.1)
    // and rendered as `@0x…` rather than dropped.
    let label = info.application_label.as_ref().expect("label captured");
    assert!(label.starts_with("@0x"), "unexpected label {label}");

    // MainActivity deep links.
    let main = info
        .activities
        .iter()
        .find(|a| a.name == "com.locket.Locket.MainActivity")
        .expect("MainActivity");
    assert_eq!(main.exported_explicit, Some(true));
    assert!(main.intent_filters.len() >= 4, "expected >=4 filters");
    let f0 = &main.intent_filters[0];
    assert_eq!(f0.auto_verify, Some(true));
    let hosts: Vec<&str> = f0.data.iter().filter_map(|d| d.host.as_deref()).collect();
    assert!(hosts.contains(&"locket.page.link"), "hosts {hosts:?}");
    let f1 = &main.intent_filters[1];
    let prefixes: Vec<&str> = f1
        .data
        .iter()
        .filter_map(|d| d.path_prefix.as_deref())
        .collect();
    assert!(
        prefixes.contains(&"/links") && prefixes.contains(&"/invites"),
        "pathPrefixes {prefixes:?}"
    );
    let schemes: Vec<&str> = main
        .intent_filters
        .iter()
        .flat_map(|f| f.data.iter().filter_map(|d| d.scheme.as_deref()))
        .collect();
    assert!(
        schemes.contains(&"com.locket.locket"),
        "custom scheme missing: {schemes:?}"
    );

    // Activity-alias with a LAUNCHER filter.
    assert!(
        info.activity_aliases
            .iter()
            .any(|a| a.target_activity.as_deref() == Some("com.locket.Locket.MainActivity")),
        "expected an alias targeting MainActivity"
    );

    // Queries: known package-visibility declarations.
    let q = info.queries.as_ref().expect("queries element");
    assert!(
        q.packages.iter().any(|p| p == "com.snapchat.android"),
        "packages {:?}",
        q.packages
    );
    assert!(
        q.intents
            .iter()
            .any(|f| f.data.iter().any(|d| d.scheme.as_deref() == Some("https")))
    );
}

/// Real bundletool split manifest, read out of the corpus XAPK without
/// extracting it to the repository (nested ZIP via `asc_apk::ZipView`).
#[test]
fn split_manifest_real_fixture_marks_split() {
    let Some(xapk) = corpus("Locket Widget_1.216.0_APKPure.xapk") else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let bytes = std::fs::read(&xapk).expect("read xapk");
    let outer = asc_apk::ZipView::parse(bytes.as_slice()).expect("outer zip");
    let entry = outer
        .entry("config.arm64_v8a.apk")
        .expect("config split present");
    let split_bytes = outer.read_entry(&entry).expect("read split");
    let inner = asc_apk::ZipView::parse(split_bytes.as_slice()).expect("inner zip");
    let m = inner.entry("AndroidManifest.xml").expect("manifest entry");
    let axml = inner.read_entry(&m).expect("read manifest");
    let info = parse_manifest(axml.as_slice()).expect("parse split manifest");

    assert_eq!(info.split.as_deref(), Some("config.arm64_v8a"));
    assert_eq!(info.split_types.as_deref(), Some("base__abi"));
    assert_eq!(info.application.has_code, Some(false));
    assert!(
        info.application
            .meta_data
            .iter()
            .any(|md| md.name == "com.android.vending.derived.apk.id"),
        "expected Play derived-apk-id meta-data"
    );
}

// ---------------------------------------------------------------------------
// Generic AXML decoder (axml module).
// ---------------------------------------------------------------------------

#[test]
fn axml_decodes_tree_with_namespaces_order_and_types() {
    use axml::{ANDROID_NS, Val, attr, elem};
    let doc = elem(
        "network-security-config",
        vec![],
        vec![elem(
            "base-config",
            vec![attr(
                Some(ANDROID_NS),
                "cleartextTrafficPermitted",
                Val::Bool(false),
            )],
            vec![elem(
                "trust-anchors",
                vec![],
                vec![elem(
                    "certificates",
                    vec![attr(Some(ANDROID_NS), "src", Val::Reference(0x010f_000f))],
                    vec![],
                )],
            )],
        )],
    );
    let parsed = crate::axml::parse_axml(&axml::build(&doc)).expect("parse");
    let root = parsed.root.as_ref().expect("root");
    assert_eq!(root.name, "network-security-config");
    assert_eq!(root.elements().count(), 1);
    let base = root.elements().next().unwrap();
    assert_eq!(base.name, "base-config");
    assert_eq!(base.attrs.len(), 1);
    let a = &base.attrs[0];
    assert_eq!(a.name, "cleartextTrafficPermitted");
    assert_eq!(a.value.as_deref(), Some("false"));
    assert_eq!(a.value_type, 0x12);
    let cert = base.elements().next().unwrap().elements().next().unwrap();
    assert_eq!(cert.name, "certificates");
    // Unresolved resource references stay visible as @0x….
    assert_eq!(cert.attrs[0].value.as_deref(), Some("@0x010f000f"));
    assert_eq!(cert.attrs[0].value_type, 0x01);
    // Text rendering qualifies the android namespace.
    let text = crate::axml::format_axml_text(&parsed);
    assert!(
        text.contains("<base-config android:cleartextTrafficPermitted=\"false\""),
        "{text}"
    );
}

#[test]
fn axml_mismatched_close_tag_errors() {
    use axml::{ANDROID_NS, Val, attr, elem};
    let doc = elem(
        "a",
        vec![attr(Some(ANDROID_NS), "x", Val::Bool(true))],
        vec![elem("b", vec![], vec![])],
    );
    let mut bytes = axml::build(&doc);
    // Layout is deterministic: [root 8][pool][ns 24][start a][start b]
    // [end b 24][end a 24]. Patch the inner end-element's name field
    // (chunk start + 20) to point at pool index 0 ("a" instead of "b").
    let end_b = bytes.len() - 48;
    let at = end_b + 20;
    bytes[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
    match crate::axml::parse_axml(&bytes) {
        Err(ManifestError::BadChunk(m)) => assert!(m.contains("does not match"), "{m}"),
        other => panic!("expected BadChunk, got {other:?}"),
    }
}

#[test]
fn cdata_chunks_are_skipped_not_rejected() {
    use axml::elem;
    let doc = elem("a", vec![], vec![elem("b", vec![], vec![])]);
    let mut bytes = axml::build(&doc);
    // Layout: [root 8][pool][ns 24][start a][start b][end b 24][end a 24].
    // Splice a ResXMLTree_cdata chunk (0x0104) before </a>: header(8) +
    // lineNumber(4) + comment(4) + dataRes(4) = 20 bytes, then grow the
    // root chunk size to cover it.
    let mut cdata = Vec::with_capacity(20);
    cdata.extend_from_slice(&0x0104u16.to_le_bytes());
    cdata.extend_from_slice(&16u16.to_le_bytes()); // headerSize
    cdata.extend_from_slice(&20u32.to_le_bytes()); // size
    cdata.extend_from_slice(&1u32.to_le_bytes()); // lineNumber
    cdata.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
    cdata.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // dataRes
    let at = bytes.len() - 24;
    bytes.splice(at..at, cdata);
    let root_size = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) + 20;
    bytes[4..8].copy_from_slice(&root_size.to_le_bytes());

    let parsed = crate::axml::parse_axml(&bytes).expect("CDATA must be skipped, not rejected");
    assert_eq!(
        parsed.root.as_ref().unwrap().elements().count(),
        1,
        "b survives"
    );
    // The manifest parser must skip CDATA the same way.
    parse_manifest(&bytes).expect("manifest parser skips CDATA too");
}

#[test]
fn axml_element_nesting_is_capped_for_recursion_safety() {
    use axml::elem;
    let chain = |depth: usize| {
        let mut e = elem("leaf", vec![], vec![]);
        for _ in 1..depth {
            e = elem("n", vec![], vec![e]);
        }
        e
    };
    // Within the cap: parses and renders (render/serde/drop recurse).
    let ok = crate::axml::parse_axml(&axml::build(&chain(200))).expect("200 deep is fine");
    assert!(crate::axml::format_axml_text(&ok).contains("<leaf"));
    // Over the cap: structured error, never a stack overflow.
    match crate::axml::parse_axml(&axml::build(&chain(300))) {
        Err(ManifestError::BadChunk(m)) => assert!(m.contains("nesting"), "{m}"),
        other => panic!("expected BadChunk for deep nesting, got {other:?}"),
    }
}

/// CDATA text nodes must be preserved, in document order, escaped — the
/// F-Droid APK's `res/4u.xml` (network-security-config) carries every
/// `<domain>` name as CDATA (audit F01: they used to vanish).
#[test]
fn cdata_text_is_preserved_in_order() {
    // Hand-rolled bytes: pool ["a","b","example.com"]; <a> TEXT0 <b/>
    // TEXT1 </a> — text before and after the child element.
    let strings = ["a", "b", "example.com"];
    let mut data: Vec<u8> = Vec::new();
    let mut offs = Vec::new();
    for s in &strings {
        offs.push(data.len() as u32);
        let u: Vec<u16> = s.encode_utf16().collect();
        data.extend_from_slice(&(u.len() as u16).to_le_bytes());
        data.extend(u.iter().flat_map(|x| x.to_le_bytes()));
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let strings_start = 28 + strings.len() * 4;
    let mut pool = Vec::new();
    pool.extend_from_slice(&0x0001u16.to_le_bytes());
    pool.extend_from_slice(&28u16.to_le_bytes());
    pool.extend_from_slice(&((strings_start + data.len()) as u32).to_le_bytes());
    pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes()); // styleCount
    pool.extend_from_slice(&0u32.to_le_bytes()); // UTF-16
    pool.extend_from_slice(&(strings_start as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
    for o in offs {
        pool.extend_from_slice(&o.to_le_bytes());
    }
    pool.extend_from_slice(&data);

    let start = |name: u32| -> Vec<u8> {
        let mut v = vec![0x02, 0x01, 16, 0];
        v.extend_from_slice(&36u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // line
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ns
        v.extend_from_slice(&name.to_le_bytes());
        v.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // attr ext, 0 attrs
        v
    };
    let end = |name: u32| -> Vec<u8> {
        let mut v = vec![0x03, 0x01, 16, 0];
        v.extend_from_slice(&24u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        v.extend_from_slice(&name.to_le_bytes());
        v
    };
    let cdata = |sidx: u32| -> Vec<u8> {
        let mut v = vec![0x04, 0x01, 16, 0];
        v.extend_from_slice(&20u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // line
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // comment
        v.extend_from_slice(&sidx.to_le_bytes()); // data
        v
    };

    let chunks = [start(0), cdata(2), start(1), end(1), cdata(2), end(0)];
    let body: usize = pool.len() + chunks.iter().map(Vec::len).sum::<usize>();
    let mut bytes = vec![0x03, 0x00, 8, 0];
    bytes.extend_from_slice(&((8 + body) as u32).to_le_bytes());
    bytes.extend_from_slice(&pool);
    for c in chunks {
        bytes.extend_from_slice(&c);
    }

    let parsed = crate::axml::parse_axml(&bytes).expect("mixed content parses");
    let root = parsed.root.as_ref().unwrap();
    use crate::axml::AxmlNode;
    let kinds: Vec<&str> = root
        .children
        .iter()
        .map(|c| match c {
            AxmlNode::Element(_) => "element",
            AxmlNode::Text { .. } => "text",
        })
        .collect();
    assert_eq!(kinds, ["text", "element", "text"], "order is kept");
    assert_eq!(root.elements().next().unwrap().name, "b");
    let text = crate::axml::format_axml_text(&parsed);
    assert!(text.contains("example.com\n"), "text nodes render: {text}");
}

/// Text bodies are XML-escaped on render.
#[test]
fn cdata_text_is_escaped() {
    let escaped = "a &amp; b &lt;tag&gt;";
    // Reuse the builder above by inlining the minimum: single element
    // with one CDATA "a & b <tag>".
    let raw = "a & b <tag>";
    let strings = ["a", raw];
    let mut data: Vec<u8> = Vec::new();
    let mut offs = Vec::new();
    for s in &strings {
        offs.push(data.len() as u32);
        let u: Vec<u16> = s.encode_utf16().collect();
        data.extend_from_slice(&(u.len() as u16).to_le_bytes());
        data.extend(u.iter().flat_map(|x| x.to_le_bytes()));
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let strings_start = 28 + strings.len() * 4;
    let mut pool = Vec::new();
    pool.extend_from_slice(&0x0001u16.to_le_bytes());
    pool.extend_from_slice(&28u16.to_le_bytes());
    pool.extend_from_slice(&((strings_start + data.len()) as u32).to_le_bytes());
    pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&(strings_start as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    for o in offs {
        pool.extend_from_slice(&o.to_le_bytes());
    }
    pool.extend_from_slice(&data);
    let mut start = vec![0x02, 0x01, 16, 0];
    start.extend_from_slice(&36u32.to_le_bytes());
    start.extend_from_slice(&1u32.to_le_bytes());
    start.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    start.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    start.extend_from_slice(&0u32.to_le_bytes());
    start.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut cdata = vec![0x04, 0x01, 16, 0];
    cdata.extend_from_slice(&20u32.to_le_bytes());
    cdata.extend_from_slice(&1u32.to_le_bytes());
    cdata.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    cdata.extend_from_slice(&1u32.to_le_bytes());
    let mut end = vec![0x03, 0x01, 16, 0];
    end.extend_from_slice(&24u32.to_le_bytes());
    end.extend_from_slice(&1u32.to_le_bytes());
    end.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    end.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    end.extend_from_slice(&0u32.to_le_bytes());
    let chunks = [start, cdata, end];
    let body: usize = pool.len() + chunks.iter().map(Vec::len).sum::<usize>();
    let mut bytes = vec![0x03, 0x00, 8, 0];
    bytes.extend_from_slice(&((8 + body) as u32).to_le_bytes());
    bytes.extend_from_slice(&pool);
    for c in chunks {
        bytes.extend_from_slice(&c);
    }
    let parsed = crate::axml::parse_axml(&bytes).expect("parse");
    let text = crate::axml::format_axml_text(&parsed);
    assert!(text.contains(escaped), "escaped body must render: {text}");
}

/// Attribute values must be escaped well-formed XML: `&`, `<` and
/// `"` (previously only `"` was escaped, so `&`/`<` produced invalid
/// XML in `axml --format text` output).
#[test]
fn attribute_values_are_escaped() {
    use axml::{ANDROID_NS, Val, attr, build, elem};

    let doc = elem(
        "manifest",
        vec![attr(Some(ANDROID_NS), "name", Val::Str("a & b < c \" d"))],
        vec![],
    );
    let text = crate::axml::format_axml_text(&crate::axml::parse_axml(&build(&doc)).unwrap());
    assert!(
        text.contains(r#"android:name="a &amp; b &lt; c &quot; d""#),
        "attribute value must be escaped: {text}"
    );
}

/// Declaration types are kept apart: `<uses-permission>`,
/// `<uses-permission-sdk-23>` (and its `-sdk-m` alias) and a custom
/// `<permission>` with `protectionLevel` (audit F04: they used to merge
/// into one indistinguishable list, and the sdk-23 variant vanished).
#[test]
fn permission_declaration_types_are_kept_apart() {
    use axml::{ANDROID_NS, Val, attr, elem};
    let doc = elem(
        "manifest",
        vec![attr(None, "package", Val::Str("com.example.app"))],
        vec![
            elem(
                "uses-permission",
                vec![attr(
                    Some(ANDROID_NS),
                    "name",
                    Val::Str("android.permission.INTERNET"),
                )],
                vec![],
            ),
            elem(
                "uses-permission-sdk-23",
                vec![attr(
                    Some(ANDROID_NS),
                    "name",
                    Val::Str("android.permission.ACCESS_COARSE_LOCATION"),
                )],
                vec![],
            ),
            elem(
                "uses-permission-sdk-m",
                vec![attr(
                    Some(ANDROID_NS),
                    "name",
                    Val::Str("android.permission.BODY_SENSORS"),
                )],
                vec![],
            ),
            elem(
                "permission",
                vec![
                    attr(Some(ANDROID_NS), "name", Val::Str("com.example.app.CUSTOM")),
                    attr(Some(ANDROID_NS), "protectionLevel", Val::Str("dangerous")),
                ],
                vec![],
            ),
        ],
    );
    let info = parse_manifest(&axml::build(&doc)).expect("parse");
    let perms: Vec<(&str, &str, Option<&str>)> = info
        .permissions
        .iter()
        .map(|p| (p.decl, p.name.as_str(), p.protection_level.as_deref()))
        .collect();
    assert_eq!(
        perms,
        [
            ("uses", "android.permission.INTERNET", None),
            (
                "uses-sdk-23",
                "android.permission.ACCESS_COARSE_LOCATION",
                None
            ),
            ("uses-sdk-23", "android.permission.BODY_SENSORS", None),
            ("declares", "com.example.app.CUSTOM", Some("dangerous")),
        ],
        "all four declarations survive with their types: {:?}",
        perms
    );
}

// ---------------------------------------------------------------------------
// Audit F1: <data> pooling. Android pools every <data> element of one
// intent-filter per attribute dimension, so a scheme declared in one
// element matches a host declared in another. The raw `data` vector must
// not be read as independent URI alternatives.
// ---------------------------------------------------------------------------

/// The Android docs' own equivalence example: scheme/host/path spread over
/// separate `<data>` elements is the same filter as one element per
/// dimension. Raw elements are preserved; the effective set pools.
#[test]
fn data_elements_of_one_filter_are_pooled_not_alternatives() {
    use axml::{ANDROID_NS, Val, attr, elem};
    let doc = elem(
        "manifest",
        vec![attr(None, "package", Val::Str("com.example.app"))],
        vec![
            elem(
                "uses-sdk",
                vec![attr(Some(ANDROID_NS), "targetSdkVersion", Val::IntDec(30))],
                vec![],
            ),
            elem(
                "application",
                vec![],
                vec![
                    elem(
                        "activity",
                        vec![attr(Some(ANDROID_NS), "name", Val::Str(".Main"))],
                        vec![elem(
                            "intent-filter",
                            vec![attr(Some(ANDROID_NS), "autoVerify", Val::Bool(true))],
                            vec![
                                elem(
                                    "action",
                                    vec![attr(
                                        Some(ANDROID_NS),
                                        "name",
                                        Val::Str("android.intent.action.VIEW"),
                                    )],
                                    vec![],
                                ),
                                elem(
                                    "data",
                                    vec![
                                        attr(Some(ANDROID_NS), "scheme", Val::Str("https")),
                                        attr(Some(ANDROID_NS), "host", Val::Str("a.example.com")),
                                    ],
                                    vec![],
                                ),
                                elem(
                                    "data",
                                    vec![
                                        attr(Some(ANDROID_NS), "scheme", Val::Str("myapp")),
                                        attr(Some(ANDROID_NS), "host", Val::Str("b.example.com")),
                                        attr(Some(ANDROID_NS), "pathPrefix", Val::Str("/deep")),
                                    ],
                                    vec![],
                                ),
                                // Path + mimeType only, no scheme/host: still
                                // pools into the same filter.
                                elem(
                                    "data",
                                    vec![
                                        attr(Some(ANDROID_NS), "mimeType", Val::Str("image/*")),
                                        attr(Some(ANDROID_NS), "pathPattern", Val::Str("/img/.*")),
                                    ],
                                    vec![],
                                ),
                            ],
                        )],
                    ),
                    // A second filter must NOT pool with the first.
                    elem(
                        "activity",
                        vec![attr(Some(ANDROID_NS), "name", Val::Str(".Other"))],
                        vec![elem(
                            "intent-filter",
                            vec![],
                            vec![elem(
                                "data",
                                vec![
                                    attr(Some(ANDROID_NS), "scheme", Val::Str("ftp")),
                                    attr(Some(ANDROID_NS), "host", Val::Str("c.example.com")),
                                ],
                                vec![],
                            )],
                        )],
                    ),
                ],
            ),
        ],
    );
    let info = parse_manifest(&axml::build(&doc)).expect("parse");

    let f = &info.activities[0].intent_filters[0];
    assert_eq!(
        f.data.len(),
        3,
        "raw <data> elements are preserved verbatim"
    );
    let eff = &f.effective_data;
    assert_eq!(eff.schemes, ["https", "myapp"], "schemes pool (dedup)");
    assert_eq!(
        eff.authorities
            .iter()
            .map(|a| a.host.as_str())
            .collect::<Vec<_>>(),
        ["a.example.com", "b.example.com"],
        "hosts from different <data> elements pool together: https://b.example.com \
         and myapp://a.example.com both match"
    );
    assert_eq!(eff.paths.len(), 2, "path and pathPattern pool too");
    assert_eq!(eff.paths[0].kind, PathMatchKind::Prefix);
    assert_eq!(eff.paths[0].value, "/deep");
    assert_eq!(eff.paths[1].kind, PathMatchKind::Pattern);
    assert_eq!(eff.paths[1].value, "/img/.*");
    assert_eq!(eff.mime_types, ["image/*"]);
    assert!(eff.has_uri());
    // The stored field (JSON) mirrors the on-demand helper.
    assert_eq!(&f.effective_data(), eff);
    assert_eq!(f.auto_verify, Some(true), "filter-level attr untouched");

    // A separate filter is its own match set.
    let g = &info.activities[1].intent_filters[0];
    assert_eq!(g.effective_data.schemes, ["ftp"]);
    assert_eq!(g.effective_data.authorities.len(), 1);
    assert_eq!(g.effective_data.authorities[0].host, "c.example.com");
    assert!(g.effective_data.paths.is_empty());
    assert!(g.effective_data.mime_types.is_empty());
}

/// Duplicate values across `<data>` elements collapse; a port stays bound to
/// the host declared on the same element.
#[test]
fn pooled_data_dedups_and_binds_port_to_its_host() {
    use axml::{ANDROID_NS, Val, attr, elem};
    let doc = elem(
        "manifest",
        vec![attr(None, "package", Val::Str("com.example.app"))],
        vec![elem(
            "application",
            vec![],
            vec![elem(
                "activity",
                vec![attr(Some(ANDROID_NS), "name", Val::Str(".M"))],
                vec![elem(
                    "intent-filter",
                    vec![],
                    vec![
                        elem(
                            "data",
                            vec![
                                attr(Some(ANDROID_NS), "scheme", Val::Str("https")),
                                attr(Some(ANDROID_NS), "host", Val::Str("x.example.com")),
                                attr(Some(ANDROID_NS), "port", Val::Str("8443")),
                            ],
                            vec![],
                        ),
                        elem(
                            "data",
                            vec![
                                attr(Some(ANDROID_NS), "scheme", Val::Str("https")),
                                attr(Some(ANDROID_NS), "host", Val::Str("x.example.com")),
                            ],
                            vec![],
                        ),
                    ],
                )],
            )],
        )],
    );
    let info = parse_manifest(&axml::build(&doc)).expect("parse");
    let eff = &info.activities[0].intent_filters[0].effective_data;
    assert_eq!(eff.schemes, ["https"], "duplicate scheme collapses");
    // Same host with a port and without are distinct authorities.
    assert_eq!(eff.authorities.len(), 2);
    assert_eq!(eff.authorities[0].port.as_deref(), Some("8443"));
    assert_eq!(eff.authorities[1].port, None);
}

// ---------------------------------------------------------------------------
// Audit F1 (2nd pass): the dependency between the URI dimensions.
// ---------------------------------------------------------------------------

/// One activity with one `<intent-filter>`, whose `<data>` children are
/// built from `data_attrs` (one attribute list per `<data>` element),
/// plus any extra filter children (e.g. `<uri-relative-filter-group>`).
fn single_filter_elems(children: Vec<axml::Elem>) -> IntentFilter {
    use axml::{ANDROID_NS, Val, attr, elem};
    let doc = elem(
        "manifest",
        vec![attr(None, "package", Val::Str("com.example.app"))],
        vec![elem(
            "application",
            vec![],
            vec![elem(
                "activity",
                vec![attr(Some(ANDROID_NS), "name", Val::Str(".M"))],
                vec![elem("intent-filter", vec![], children)],
            )],
        )],
    );
    let info = parse_manifest(&axml::build(&doc)).expect("parse");
    info.activities[0].intent_filters[0].clone()
}

/// [`single_filter_elems`] for `<data>`-only filters.
fn single_filter(data_attrs: Vec<Vec<axml::Attr>>) -> IntentFilter {
    use axml::elem;
    single_filter_elems(
        data_attrs
            .into_iter()
            .map(|attrs| elem("data", attrs, vec![]))
            .collect(),
    )
}

/// F1.1: a path declared without a host is **inert**. Android's `<data>`
/// docs: "If a host isn't specified for the filter, the port attribute and
/// all the path attributes are ignored", and AOSP `IntentFilter.matchData`
/// runs the path loop only inside the `mDataAuthorities != null` branch. So
/// with `scheme=https` + `pathPrefix=/private` and no host, Android matches
/// `https://example.com/public` — the declared path must stay visible
/// (fidelity) but must not read as an active restriction.
#[test]
fn path_without_host_is_declared_but_inert() {
    use axml::{ANDROID_NS, Val, attr};
    let f = single_filter(vec![
        vec![attr(Some(ANDROID_NS), "scheme", Val::Str("https"))],
        vec![attr(Some(ANDROID_NS), "pathPrefix", Val::Str("/private"))],
    ]);
    assert_eq!(f.data.len(), 2, "raw <data> kept verbatim");
    assert_eq!(f.data[1].path_prefix.as_deref(), Some("/private"));
    assert_eq!(f.effective_data.schemes, ["https"]);
    assert_eq!(
        f.effective_data.paths.len(),
        1,
        "the declared pool is kept for fidelity"
    );
    assert_eq!(f.effective_data.dependency, UriDependency::NoHost);
    assert!(
        f.effective_data.effective_paths().is_empty(),
        "a path without a host never matches"
    );
    assert!(f.effective_data.effective_authorities().is_empty());
}

/// F1.2: a host declared without a scheme is inert ("If a `scheme` isn't
/// specified for the intent filter, all the other URI attributes are
/// ignored"; `matchData` reaches the authority loop only under
/// `mDataSchemes != null`).
#[test]
fn host_without_scheme_is_declared_but_inert() {
    use axml::{ANDROID_NS, Val, attr};
    let f = single_filter(vec![vec![attr(
        Some(ANDROID_NS),
        "host",
        Val::Str("example.com"),
    )]]);
    assert_eq!(f.effective_data.authorities[0].host, "example.com");
    assert_eq!(f.effective_data.dependency, UriDependency::NoScheme);
    assert!(
        f.effective_data.effective_authorities().is_empty(),
        "a host without a scheme never matches"
    );
    // Same for a host+path that lost its scheme.
    let g = single_filter(vec![
        vec![attr(Some(ANDROID_NS), "host", Val::Str("example.com"))],
        vec![attr(Some(ANDROID_NS), "path", Val::Str("/x"))],
    ]);
    assert_eq!(g.effective_data.dependency, UriDependency::NoScheme);
    assert!(g.effective_data.effective_authorities().is_empty());
    assert!(g.effective_data.effective_paths().is_empty());
    assert_eq!(
        g.effective_data.paths.len(),
        1,
        "declared path still reported"
    );
}

/// F1.3: a MIME-only filter declares no URI, and Android then assumes the
/// `content:` and `file:` schemes ("If the filter has a data type set ...
/// but no scheme, the `content:` and `file:` schemes are assumed"). An
/// explicit scheme, or no MIME type, suppresses the implicit match.
#[test]
fn mime_only_filter_implies_content_and_file_schemes() {
    use axml::{ANDROID_NS, Val, attr};
    let f = single_filter(vec![vec![attr(
        Some(ANDROID_NS),
        "mimeType",
        Val::Str("image/*"),
    )]]);
    assert!(!f.effective_data.has_uri(), "a MIME type declares no URI");
    assert_eq!(f.effective_data.mime_types, ["image/*"]);
    assert_eq!(f.effective_data.dependency, UriDependency::NoScheme);
    assert_eq!(f.effective_data.implicit_schemes(), ["content", "file"]);

    // An explicit scheme wins: https, not content:/file:.
    let g = single_filter(vec![
        vec![attr(Some(ANDROID_NS), "scheme", Val::Str("https"))],
        vec![attr(Some(ANDROID_NS), "mimeType", Val::Str("image/*"))],
    ]);
    assert!(
        g.effective_data.implicit_schemes().is_empty(),
        "a declared scheme suppresses the implicit content:/file: match"
    );

    // No MIME type → no implicit scheme.
    let h = single_filter(vec![vec![attr(Some(ANDROID_NS), "path", Val::Str("/x"))]]);
    assert!(h.effective_data.implicit_schemes().is_empty());
}

/// F1.4: pooling is per filter and per dimension, so a host declared on a
/// *different* `<data>` re-enables a path declared beside no host — and
/// dropping the only scheme just as quickly makes the whole set inert.
#[test]
fn pooled_host_makes_a_sibling_path_effective() {
    use axml::{ANDROID_NS, Val, attr};
    let f = single_filter(vec![
        vec![attr(Some(ANDROID_NS), "scheme", Val::Str("https"))],
        vec![attr(Some(ANDROID_NS), "host", Val::Str("example.com"))],
        vec![attr(Some(ANDROID_NS), "pathPrefix", Val::Str("/private"))],
    ]);
    assert_eq!(f.effective_data.dependency, UriDependency::Complete);
    assert_eq!(f.effective_data.effective_authorities().len(), 1);
    assert_eq!(f.effective_data.effective_paths().len(), 1);
    assert!(f.effective_data.implicit_schemes().is_empty());

    // Same data minus the scheme: every URI attribute is inert, but nothing
    // is dropped from the declared pools.
    let g = single_filter(vec![
        vec![attr(Some(ANDROID_NS), "host", Val::Str("example.com"))],
        vec![attr(Some(ANDROID_NS), "pathPrefix", Val::Str("/private"))],
    ]);
    assert_eq!(g.effective_data.dependency, UriDependency::NoScheme);
    assert!(g.effective_data.effective_authorities().is_empty());
    assert!(g.effective_data.effective_paths().is_empty());
    assert_eq!(g.effective_data.authorities.len(), 1);
    assert_eq!(g.effective_data.paths.len(), 1);
    assert_eq!(g.data.len(), 2);
}

/// F3: `<uri-relative-filter-group>` (API 35) is parsed and preserved —
/// with its `android:allow` flag and its `<data>` children — instead of
/// being dropped silently. Its AND semantics are *not* modelled, so the
/// filter reports that its URI analysis is incomplete and the group's
/// `<data>` elements never leak into the filter's own pooled match set.
#[test]
fn uri_relative_filter_group_is_preserved_not_evaluated() {
    use axml::{ANDROID_NS, Val, attr, elem};
    let f = single_filter_elems(vec![
        elem(
            "data",
            vec![
                attr(Some(ANDROID_NS), "scheme", Val::Str("https")),
                attr(Some(ANDROID_NS), "host", Val::Str("example.com")),
            ],
            vec![],
        ),
        elem(
            "data",
            vec![attr(Some(ANDROID_NS), "path", Val::Str("/direct"))],
            vec![],
        ),
        elem(
            "uri-relative-filter-group",
            vec![attr(Some(ANDROID_NS), "allow", Val::Bool(false))],
            vec![
                elem(
                    "data",
                    vec![attr(Some(ANDROID_NS), "path", Val::Str("/private"))],
                    vec![],
                ),
                elem(
                    "data",
                    vec![attr(Some(ANDROID_NS), "query", Val::Str("token=1"))],
                    vec![],
                ),
            ],
        ),
        elem(
            "uri-relative-filter-group",
            vec![],
            vec![elem(
                "data",
                vec![attr(Some(ANDROID_NS), "pathPrefix", Val::Str("/public"))],
                vec![],
            )],
        ),
    ]);

    // The group's own <data> children are not filter <data> elements.
    assert_eq!(f.data.len(), 2, "only the direct <data> elements");
    assert_eq!(f.data[1].path.as_deref(), Some("/direct"));
    assert!(f.has_uri_relative_groups());
    assert_eq!(f.uri_relative_groups.len(), 2, "declaration order kept");

    let blocking = &f.uri_relative_groups[0];
    assert!(!blocking.allow, "android:allow=false kept");
    assert_eq!(blocking.data.len(), 2, "ANDed children kept, in order");
    assert_eq!(
        blocking.data[0].parts,
        [UriPartMatcher {
            part: UriPart::Path,
            kind: PathMatchKind::Exact,
            value: "/private".into(),
        }]
    );
    assert_eq!(
        blocking.data[1].parts,
        [UriPartMatcher {
            part: UriPart::Query,
            kind: PathMatchKind::Exact,
            value: "token=1".into(),
        }]
    );
    let allowing = &f.uri_relative_groups[1];
    assert!(allowing.allow, "android:allow defaults to true");
    assert_eq!(allowing.data[0].parts[0].kind, PathMatchKind::Prefix);

    // The pooled match set stays the direct-<data> one: group rules are
    // never folded in (that would claim reachability ASC-RS cannot prove).
    assert_eq!(f.effective_data.schemes, ["https"]);
    assert_eq!(f.effective_data.paths.len(), 1);
    assert_eq!(f.effective_data.paths[0].value, "/direct");
}

/// Audit F2: a `<data>` child of a `<uri-relative-filter-group>` must only
/// honour **Android** (or unqualified) matcher attributes. A foreign
/// namespace — `tools:path`, a custom namespace whose local name collides
/// with a real matcher — must never be read as Android data. This is the
/// same namespace policy `attr()`, `data_spec_from_attrs`, etc. already
/// enforce for every other manifest attribute; `relative_data_from_attrs`
/// was the one direct `XmlAttr` walk that skipped it.
#[test]
fn uri_relative_group_rejects_foreign_namespace_matchers() {
    use axml::{ANDROID_NS, TOOLS_NS, Val, attr, elem};
    const CUSTOM_NS: &str = "http://example.com/custom";
    let f = single_filter_elems(vec![elem(
        "uri-relative-filter-group",
        vec![],
        vec![elem(
            "data",
            vec![
                attr(Some(ANDROID_NS), "path", Val::Str("/valid")),
                attr(Some(TOOLS_NS), "path", Val::Str("/invalid")), // local-name collision
                attr(Some(CUSTOM_NS), "pathPrefix", Val::Str("/nope")), // collision
                attr(Some(TOOLS_NS), "query", Val::Str("evil=1")),
                attr(Some(ANDROID_NS), "query", Val::Str("token=1")),
                attr(Some(TOOLS_NS), "fragment", Val::Str("ignored")),
            ],
            vec![],
        )],
    )]);
    let group = &f.uri_relative_groups[0];
    assert_eq!(group.data.len(), 1);
    let parts = &group.data[0].parts;
    // Only the Android matchers survive; every foreign one is dropped.
    assert_eq!(parts.len(), 2, "got {parts:?}");
    assert_eq!(parts[0].value, "/valid");
    assert_eq!(parts[0].part, UriPart::Path);
    assert_eq!(parts[0].kind, PathMatchKind::Exact);
    assert_eq!(parts[1].value, "token=1");
    assert_eq!(parts[1].part, UriPart::Query);
    assert_eq!(parts[1].kind, PathMatchKind::Exact);
    assert!(
        !parts.iter().any(|p| p.value == "/invalid"),
        "tools:path must not become android:path: {parts:?}"
    );
    assert!(
        !parts.iter().any(|p| p.value == "/nope"),
        "a custom-namespace pathPrefix must not be read: {parts:?}"
    );
    assert!(!parts.iter().any(|p| p.value == "evil=1"));
    assert!(!parts.iter().any(|p| p.value == "ignored"));
    assert!(f.has_uri_relative_groups());
}

/// Audit F2: among the *accepted* (Android) matchers, declaration order is
/// preserved even when foreign-namespace attributes sit between them — the
/// `filter_map` drops the foreign ones without re-ordering the survivors.
#[test]
fn uri_relative_group_preserves_android_matcher_order() {
    use axml::{ANDROID_NS, TOOLS_NS, Val, attr, elem};
    let f = single_filter_elems(vec![elem(
        "uri-relative-filter-group",
        vec![],
        vec![elem(
            "data",
            vec![
                attr(Some(TOOLS_NS), "pathPrefix", Val::Str("/first")), // rejected
                attr(Some(ANDROID_NS), "pathPrefix", Val::Str("/second")),
                attr(Some(ANDROID_NS), "path", Val::Str("/third")),
                attr(Some(TOOLS_NS), "path", Val::Str("/fourth")), // rejected
                attr(Some(ANDROID_NS), "fragmentPrefix", Val::Str("fifth")),
            ],
            vec![],
        )],
    )]);
    let parts = &f.uri_relative_groups[0].data[0].parts;
    assert_eq!(parts.len(), 3, "got {parts:?}");
    assert_eq!(
        parts
            .iter()
            .map(|p| (p.value.as_str(), p.part, p.kind))
            .collect::<Vec<_>>(),
        [
            ("/second", UriPart::Path, PathMatchKind::Prefix),
            ("/third", UriPart::Path, PathMatchKind::Exact),
            ("fifth", UriPart::Fragment, PathMatchKind::Prefix),
        ]
    );
}

/// Audit F2: a group whose `<data>` carries **only** foreign-namespace
/// matchers must still be captured as a group — never dropped — so the
/// renderer keeps declaring that API 35 URI-relative groups are present and
/// NOT evaluated rather than silently claiming a fully-analysed filter.
#[test]
fn uri_relative_group_preserves_incomplete_analysis_warning() {
    use axml::{TOOLS_NS, Val, attr, elem};
    let f = single_filter_elems(vec![elem(
        "uri-relative-filter-group",
        vec![],
        vec![elem(
            "data",
            vec![attr(Some(TOOLS_NS), "path", Val::Str("/foreign-only"))],
            vec![],
        )],
    )]);
    assert!(
        f.has_uri_relative_groups(),
        "a group with only foreign matchers is still a declared group"
    );
    let group = &f.uri_relative_groups[0];
    assert_eq!(group.data.len(), 1, "the <data> child is preserved");
    assert!(
        group.data[0].parts.is_empty(),
        "the foreign-only matcher contributes nothing to the parsed parts"
    );
    assert!(group.allow, "android:allow defaults to true");
}

// ---------------------------------------------------------------------------
// Audit F4: android:exported semantics for targetSdk >= 31.
// ---------------------------------------------------------------------------

/// One-component manifest with an optional intent filter and optional
/// explicit `android:exported`, at a chosen targetSdkVersion.
fn component_manifest(
    sdk: u32,
    tag: &'static str,
    with_filter: bool,
    exported: Option<bool>,
) -> ManifestInfo {
    use axml::{ANDROID_NS, Val, attr, elem};
    let mut attrs = vec![attr(Some(ANDROID_NS), "name", Val::Str(".Comp"))];
    if let Some(v) = exported {
        attrs.push(attr(Some(ANDROID_NS), "exported", Val::Bool(v)));
    }
    if tag == "activity-alias" {
        attrs.push(attr(Some(ANDROID_NS), "targetActivity", Val::Str(".Comp")));
    }
    let children = if with_filter {
        vec![elem(
            "intent-filter",
            vec![],
            vec![elem(
                "action",
                vec![attr(
                    Some(ANDROID_NS),
                    "name",
                    Val::Str("android.intent.action.VIEW"),
                )],
                vec![],
            )],
        )]
    } else {
        Vec::new()
    };
    let doc = elem(
        "manifest",
        vec![attr(None, "package", Val::Str("com.example.app"))],
        vec![
            elem(
                "uses-sdk",
                vec![attr(Some(ANDROID_NS), "targetSdkVersion", Val::IntDec(sdk))],
                vec![],
            ),
            elem("application", vec![], vec![elem(tag, attrs, children)]),
        ],
    );
    parse_manifest(&axml::build(&doc)).expect("parse")
}

fn component_of<'a>(info: &'a ManifestInfo, tag: &str) -> &'a ComponentEntry {
    match tag {
        "activity" => &info.activities[0],
        "service" => &info.services[0],
        "receiver" => &info.receivers[0],
        "activity-alias" => &info.activity_aliases[0].component,
        other => panic!("unknown component tag {other}"),
    }
}

/// Audit F4: with an intent filter and no explicit `android:exported`,
/// targetSdk 31+ (Android 12) is an install-invalid manifest — reported as
/// such, never as a usable `(auto)` inference.
#[test]
fn missing_exported_is_install_invalid_for_target_31_plus() {
    // targetSdk < 31 admits the legacy inference.
    let a = component_manifest(30, "activity", true, None);
    let ca = component_of(&a, "activity");
    assert_eq!(ca.exported_state, ExportedState::LegacyInferred);
    assert!(ca.exported, "filter implies exported below API 31");
    assert!(!a.has_invalid_exported());

    // targetSdk >= 31 + filter + no declaration: install-invalid.
    for sdk in [31, 35] {
        let m = component_manifest(sdk, "activity", true, None);
        let c = component_of(&m, "activity");
        assert_eq!(
            c.exported_state,
            ExportedState::MissingRequired,
            "sdk {sdk}"
        );
        assert!(
            c.exported,
            "legacy value kept for backwards compatibility (sdk {sdk})"
        );
        assert_eq!(c.exported_explicit, None);
        assert!(m.has_invalid_exported(), "sdk {sdk}");
    }

    // targetSdk >= 31 without a filter: the platform default applies; valid.
    let d = component_manifest(35, "activity", false, None);
    let cd = component_of(&d, "activity");
    assert_eq!(cd.exported_state, ExportedState::LegacyInferred);
    assert!(!cd.exported);
    assert!(!d.has_invalid_exported());

    // An explicit declaration is always valid and wins.
    let e = component_manifest(31, "activity", true, Some(true));
    let ce = component_of(&e, "activity");
    assert_eq!(ce.exported_state, ExportedState::Explicit);
    assert!(ce.exported);
    assert!(!e.has_invalid_exported());

    let f = component_manifest(31, "activity", true, Some(false));
    let cf = component_of(&f, "activity");
    assert_eq!(cf.exported_state, ExportedState::Explicit);
    assert!(!cf.exported, "declared false beats filter inference");
    assert!(!f.has_invalid_exported());
}

/// The API 31 requirement covers exactly the filter-bearing kinds:
/// activity, activity-alias, service, receiver — with a filter only.
#[test]
fn exported_requirement_covers_filter_bearing_component_kinds() {
    for tag in ["activity", "activity-alias", "service", "receiver"] {
        let filtered = component_manifest(33, tag, true, None);
        assert_eq!(
            component_of(&filtered, tag).exported_state,
            ExportedState::MissingRequired,
            "filtered {tag}"
        );
        assert!(filtered.has_invalid_exported(), "filtered {tag}");
        let unfiltered = component_manifest(33, tag, false, None);
        assert_eq!(
            component_of(&unfiltered, tag).exported_state,
            ExportedState::LegacyInferred,
            "unfiltered {tag}"
        );
        assert!(!unfiltered.has_invalid_exported(), "unfiltered {tag}");
    }
}

/// Regression: providers carry no intent filters, so the API 31 rule never
/// applies; their own target-SDK default (>= 17 → false) stands and they are
/// never reported install-invalid.
#[test]
fn provider_exported_rule_stays_separate_from_the_api_31_requirement() {
    use axml::{ANDROID_NS, Val, attr, elem};
    for (sdk, expected) in [(16u32, true), (17, false), (33, false)] {
        let doc = elem(
            "manifest",
            vec![attr(None, "package", Val::Str("com.example.app"))],
            vec![
                elem(
                    "uses-sdk",
                    vec![attr(Some(ANDROID_NS), "targetSdkVersion", Val::IntDec(sdk))],
                    vec![],
                ),
                elem(
                    "application",
                    vec![],
                    vec![elem(
                        "provider",
                        vec![
                            attr(Some(ANDROID_NS), "name", Val::Str(".P")),
                            attr(Some(ANDROID_NS), "authorities", Val::Str("com.example.p")),
                        ],
                        vec![],
                    )],
                ),
            ],
        );
        let info = parse_manifest(&axml::build(&doc)).expect("parse");
        let p = &info.providers[0];
        assert_eq!(p.exported_explicit, None, "sdk {sdk}");
        assert_eq!(p.exported, expected, "provider default at sdk {sdk}");
        assert!(!info.has_invalid_exported(), "sdk {sdk}: provider exempt");
    }
}

// ---------------------------------------------------------------------------
// Security defaults keyed on the *effective* target SDK.
// ---------------------------------------------------------------------------

/// `usesCleartextTraffic`'s platform default is `effective target SDK < 28`.
/// An app that declares only `minSdkVersion` targets that level, so a
/// minSdk-28+ manifest must not report cleartext as allowed (false positive
/// that inverts the conclusion an analyst draws).
#[test]
fn cleartext_default_keys_off_the_effective_target_sdk() {
    use axml::{ANDROID_NS, Val, attr, elem};
    let build = |min: u32, target: Option<u32>, cleartext: Option<bool>| {
        let mut sdk_attrs = vec![attr(Some(ANDROID_NS), "minSdkVersion", Val::IntDec(min))];
        if let Some(t) = target {
            sdk_attrs.push(attr(Some(ANDROID_NS), "targetSdkVersion", Val::IntDec(t)));
        }
        let mut app_attrs = Vec::new();
        if let Some(v) = cleartext {
            app_attrs.push(attr(Some(ANDROID_NS), "usesCleartextTraffic", Val::Bool(v)));
        }
        let doc = elem(
            "manifest",
            vec![attr(None, "package", Val::Str("com.example.app"))],
            vec![
                elem("uses-sdk", sdk_attrs, vec![]),
                elem("application", app_attrs, vec![]),
            ],
        );
        parse_manifest(&axml::build(&doc)).expect("parse")
    };

    // No targetSdkVersion: the effective target is minSdkVersion.
    let a = build(30, None, None);
    assert_eq!(a.target_sdk, None);
    assert_eq!(a.effective_target_sdk(), 30);
    assert!(
        !a.effective_uses_cleartext_traffic(),
        "effective target 30 → cleartext denied by default"
    );

    // Same shape below API 28 keeps the pre-P default (allowed).
    assert!(build(27, None, None).effective_uses_cleartext_traffic());

    // An explicit targetSdkVersion wins over minSdkVersion.
    assert!(!build(21, Some(30), None).effective_uses_cleartext_traffic());
    assert!(build(30, Some(21), None).effective_uses_cleartext_traffic());

    // A declared value overrides the default in both directions.
    assert!(build(33, None, Some(true)).effective_uses_cleartext_traffic());
    assert!(!build(21, None, Some(false)).effective_uses_cleartext_traffic());
}
