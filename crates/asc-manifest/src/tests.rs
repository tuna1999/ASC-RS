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

fn corpus(name: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apk")
        .join(name);
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

#[test]
fn apk_without_manifest_errors() {
    // Hand-built minimal ZIP containing only `empty.txt`. No
    // AndroidManifest.xml entry — parse_from_apk must report a
    // truncated / not-found error rather than panic or silently
    // succeed.
    use std::io::Write as _;
    let mut zip_bytes: Vec<u8> = Vec::new();
    let name = b"empty.txt";
    let payload = b"hello";
    let crc = crc32fast::hash(payload);

    // Local file header (offset 0).
    let local_offset: u32 = 0;
    zip_bytes.extend_from_slice(b"PK\x03\x04");
    zip_bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // compression = stored
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // mod time
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // mod date
    zip_bytes.extend_from_slice(&crc.to_le_bytes());
    zip_bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // compressed
    zip_bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // uncompressed
    zip_bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // extra
    zip_bytes.extend_from_slice(name);
    zip_bytes.extend_from_slice(payload);

    let central_off = zip_bytes.len() as u32;
    // Central directory
    zip_bytes.extend_from_slice(b"PK\x01\x02");
    zip_bytes.extend_from_slice(&20u16.to_le_bytes()); // version made by
    zip_bytes.extend_from_slice(&20u16.to_le_bytes()); // version needed
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // compression
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // mod time
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // mod date
    zip_bytes.extend_from_slice(&crc.to_le_bytes());
    zip_bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    zip_bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    zip_bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // extra
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // comment
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // internal attr
    zip_bytes.extend_from_slice(&0u32.to_le_bytes()); // external attr
    zip_bytes.extend_from_slice(&local_offset.to_le_bytes());
    zip_bytes.extend_from_slice(name);
    let central_size = (zip_bytes.len() as u32) - central_off;

    // End of central directory
    zip_bytes.extend_from_slice(b"PK\x05\x06");
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // disk number
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
    zip_bytes.extend_from_slice(&1u16.to_le_bytes()); // CD entries on this disk
    zip_bytes.extend_from_slice(&1u16.to_le_bytes()); // total CD entries
    zip_bytes.extend_from_slice(&central_size.to_le_bytes());
    zip_bytes.extend_from_slice(&central_off.to_le_bytes());
    zip_bytes.extend_from_slice(&0u16.to_le_bytes()); // comment length

    let tmp = std::env::temp_dir().join("asc_manifest_no_manifest.apk");
    std::fs::File::create(&tmp)
        .unwrap()
        .write_all(&zip_bytes)
        .unwrap();
    let err = parse_from_apk(&tmp).unwrap_err();
    assert!(matches!(err, ManifestError::Truncated(_)), "got {err:?}");
    let _ = std::fs::remove_file(&tmp);
}
