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
    let p = std::path::Path::new("corpus").join("apk").join(name);
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
fn truncated_utf16_string_errors_not_panics() {
    // Build a string-pool chunk with 1 string, stringsStart=28, then
    // truncate the payload so the char length read past EOF.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0008_0003u32.to_le_bytes());
    let root_size: u32 = 8 + 36;
    bytes.extend_from_slice(&root_size.to_le_bytes());
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0x001Cu16.to_le_bytes());
    bytes.extend_from_slice(&36u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes()); // stringCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // styleCount
    bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
    bytes.extend_from_slice(&28u32.to_le_bytes()); // stringsStart
    bytes.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
    // char_len = 100 but no payload follows — read will truncate.
    bytes.extend_from_slice(&100u16.to_le_bytes());
    let err = parse_manifest(&bytes).unwrap_err();
    assert!(matches!(err, ManifestError::Truncated(_)), "got {err:?}");
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
    bytes.extend_from_slice(&28u32.to_le_bytes()); // stringsStart
    bytes.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
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
    bytes.extend_from_slice(&RES_STRING_POOL_UTF8_FLAG.to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes()); // stringsStart
    bytes.extend_from_slice(&0u32.to_le_bytes());
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
