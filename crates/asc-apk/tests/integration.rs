//! Integration tests for `asc-apk`.
//!
//! These tests build minimal ZIP archives in-process (no external corpus)
//! and exercise the engine end-to-end: directory parsing, `classes*.dex`
//! discovery, STORED / DEFLATE extraction, ZIP64 layout, and adversarial
//! inputs.

mod common;

use asc_apk::{Apk, ApkError, Compression, DexEntry, EntryBytes, InflateLimits, ZipView};

use common::{ZipBuilder, write_to_temp, zip64_extra};

/// Parse a `ZipView` from in-memory bytes (faster than round-tripping
/// through a temp file).
fn parse_view(bytes: &[u8]) -> Result<ZipView<'_>, ApkError> {
    ZipView::parse(bytes)
}

/// Tiny helper: build a 1 KiB buffer of mostly-zero bytes (highly
/// compressible).
fn highly_compressible() -> Vec<u8> {
    vec![0u8; 1024]
}

/// Tiny helper: build a buffer of incompressible pseudo-random bytes
/// (seeded so tests are deterministic).
fn incompressible(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut state: u64 = 0x9E3779B97F4A7C15;
    while out.len() < n {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

// =========================================================================
// classes*.dex discovery
// =========================================================================

#[test]
fn dex_entries_numeric_order_with_decoys() {
    let mut b = ZipBuilder::new();
    // Mixed insertion order; the engine must sort numerically.
    b.add_stored("classes10.dex", vec![10]);
    b.add_stored("classes.dex", vec![1]);
    b.add_stored("classes2.dex", vec![2]);

    // Decoys that must NOT be returned.
    b.add_stored("x/classes.dex", vec![99]); // in a subdirectory
    b.add_stored("classesx.dex", vec![98]); // no `.dex` extension (it has one — but the stem isn't numeric)
    b.add_stored("Classes.dex", vec![97]); // wrong case
    b.add_stored("other.dex", vec![96]); // not classes-prefix
    b.add_stored("classes", vec![95]); // not .dex
    b.add_stored("v1/classes.dex", vec![94]); // in a subdirectory

    let bytes = b.build();
    let view = parse_view(&bytes).expect("parse");
    let dex: Vec<DexEntry> = view.dex_entries();
    let names: Vec<&str> = dex.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["classes.dex", "classes2.dex", "classes10.dex"]);
}

#[test]
fn duplicate_dex_names_keep_first_record_only() {
    let mut b = ZipBuilder::new();
    b.add_stored("classes.dex", vec![1]);
    b.add_stored("classes.dex", vec![2]);
    let bytes = b.build();
    let view = parse_view(&bytes).expect("parse");
    let dex = view.dex_entries();
    assert_eq!(dex.len(), 1);
    assert_eq!(view.read_entry(&dex[0]).unwrap().as_slice(), &[1]);
}

#[test]
fn dex_entries_discover_only_one_when_present() {
    let mut b = ZipBuilder::new();
    b.add_stored("classes.dex", vec![1]);
    b.add_stored("resources.arsc", vec![0xAA; 16]);
    let archive = b.build();
    let view = parse_view(&archive).expect("parse");
    assert_eq!(view.dex_entries().len(), 1);
    assert_eq!(view.entry_count(), 2);
    assert!(view.entry("resources.arsc").is_some());
}

#[test]
fn entry_lookup_exact_name() {
    let mut b = ZipBuilder::new();
    b.add_stored("AndroidManifest.xml", b"<?xml/>".to_vec());
    b.add_stored("classes.dex", vec![0xCA, 0xFE, 0xBA, 0xBE]);
    let archive = b.build();
    let view = parse_view(&archive).expect("parse");
    let xml = view.entry("AndroidManifest.xml").expect("xml present");
    assert_eq!(xml.method, Compression::Stored);
    let bytes = view.read_entry(&xml).expect("read xml");
    assert_eq!(bytes.as_slice(), b"<?xml/>");
    assert!(view.entry("does-not-exist").is_none());
}

// =========================================================================
// STORED round-trip
// =========================================================================

#[test]
fn stored_entry_borrowed_zero_copy() {
    // Build a STORED entry with a recognisable pattern.
    let payload = b"hello-stored-1234".to_vec();
    let mut b = ZipBuilder::new();
    b.add_stored("data.bin", payload.clone());

    // Write to a file and open via Apk (mmap path).
    let tmp = write_to_temp(&b.build());
    let apk = Apk::open(tmp.path()).expect("open apk");
    let entry = apk.entry("data.bin").expect("entry present");
    let got = apk.read_entry(&entry).expect("read entry");
    match got {
        EntryBytes::Borrowed(slice) => {
            // The slice must point at valid mmap memory. We cannot easily
            // get the mmap pointer out of `Apk` (no public accessor), so
            // verify the slice is non-empty and equal to the original
            // payload as a strong signal of zero-copy.
            assert!(!slice.is_empty(), "Borrowed slice must be non-empty");
            assert_eq!(slice.len(), payload.len());
            assert_eq!(slice, payload.as_slice());
        }
        other => panic!("expected Borrowed, got {:?}", other),
    }
}

#[test]
fn stored_entry_via_zipview_borrows_input_slice() {
    let payload = vec![0u8; 2048];
    let mut b = ZipBuilder::new();
    b.add_stored("data.bin", payload.clone());
    let bytes = b.build();
    let view = parse_view(&bytes).expect("parse");
    let entry = view.entry("data.bin").expect("entry");
    let got = view.read_entry(&entry).expect("read");
    match got {
        EntryBytes::Borrowed(slice) => {
            // Verify the slice points into the original `bytes` buffer.
            assert!(slice.as_ptr() >= bytes.as_ptr());
            assert!(slice.as_ptr() < unsafe { bytes.as_ptr().add(bytes.len()) });
        }
        other => panic!("expected Borrowed, got {:?}", other),
    }
}

// =========================================================================
// DEFLATE round-trip
// =========================================================================

#[test]
fn deflated_empty_entry_roundtrip() {
    let mut b = ZipBuilder::new();
    b.add_deflated("empty.dex", Vec::new());
    let archive = b.build();
    let view = parse_view(&archive).expect("parse");
    let entry = view.entry("empty.dex").expect("entry");
    let bytes = view.read_entry(&entry).expect("read");
    assert!(bytes.is_empty());
    assert_eq!(bytes.len(), 0);
}

#[test]
fn deflated_highly_compressible_roundtrip() {
    let payload = highly_compressible();
    let mut b = ZipBuilder::new();
    b.add_deflated("compressed.dex", payload.clone());
    let archive = b.build();
    let view = parse_view(&archive).expect("parse");
    let entry = view.entry("compressed.dex").expect("entry");
    let bytes = view.read_entry(&entry).expect("read");
    assert_eq!(bytes.as_slice(), payload.as_slice());
    // sanity: DEFLATE should have shrunk it significantly
    assert!(entry.compressed_size < entry.uncompressed_size / 2);
}

#[test]
fn deflated_incompressible_roundtrip() {
    let payload = incompressible(4096);
    let mut b = ZipBuilder::new();
    b.add_deflated("random.bin", payload.clone());
    let archive = b.build();
    let view = parse_view(&archive).expect("parse");
    let entry = view.entry("random.bin").expect("entry");
    let bytes = view.read_entry(&entry).expect("read");
    assert_eq!(bytes.as_slice(), payload.as_slice());
}

#[test]
fn deflated_via_apk_roundtrip() {
    let payload = b"deflate-via-mmap".to_vec();
    let mut b = ZipBuilder::new();
    b.add_deflated("d.dex", payload.clone());
    let tmp = write_to_temp(&b.build());
    let apk = Apk::open(tmp.path()).expect("open");
    let entry = apk.entry("d.dex").expect("entry");
    let bytes = apk.read_entry(&entry).expect("read");
    assert_eq!(bytes.as_slice(), payload.as_slice());
}

// =========================================================================
// Failure modes
// =========================================================================

#[test]
fn declared_size_mismatch_returns_size_mismatch() {
    let mut b = ZipBuilder::new();
    b.add_deflated("bad.dex", b"actual-payload".to_vec())
        .next_usize_override(999_999);
    let archive = b.build();
    let view = parse_view(&archive).expect("parse");
    let entry = view.entry("bad.dex").expect("entry");
    let err = view.read_entry(&entry).unwrap_err();
    assert!(
        matches!(err, ApkError::SizeMismatch { .. }),
        "got {:?}",
        err
    );
}

#[test]
fn corrupt_deflate_stream_returns_deflate() {
    // Build a valid DEFLATE entry, then corrupt one byte in the middle
    // of its compressed payload.
    let mut b = ZipBuilder::new();
    b.add_deflated(
        "corrupt.dex",
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    );
    let mut bytes = b.build();
    // Find the local-header data offset for the only entry: parse via
    // ZipView, locate the entry, flip a byte inside the compressed
    // window.
    {
        let view = parse_view(&bytes).expect("parse");
        let entry = view.entry("corrupt.dex").expect("entry");
        // Re-resolve local header to find data offset; the simplest
        // approach is to find the LFH signature and walk forward to
        // 30 + name_len + extra_len.
        let payload_off = entry.local_header_offset as usize + 30 + entry.name.len();
        // Flip the first byte of the compressed stream.
        bytes[payload_off] ^= 0xFF;
    }
    let view = parse_view(&bytes).expect("still parses");
    let entry = view.entry("corrupt.dex").expect("entry");
    let err = view.read_entry(&entry).unwrap_err();
    assert!(
        matches!(err, ApkError::Deflate(_) | ApkError::SizeMismatch { .. }),
        "got {:?}",
        err
    );
}

#[test]
fn zip_bomb_truncated_by_cap() {
    // 1 MiB of zeros is highly compressible; a tiny cap must trip.
    let bomb: Vec<u8> = vec![0u8; 1 << 20];
    let mut b = ZipBuilder::new();
    b.add_deflated("bomb.dex", bomb);
    let archive = b.build();
    let view = parse_view(&archive).expect("parse");
    let entry = view.entry("bomb.dex").expect("entry");
    let limits = InflateLimits::with_max_output(64 * 1024).unwrap();
    let err = view.read_entry_with_limits(&entry, limits).unwrap_err();
    assert!(matches!(err, ApkError::TooLarge { .. }), "got {:?}", err);
}

#[test]
fn zip_bomb_via_apk_bounded_memory() {
    // Same as above, but via the mmap-backed `Apk`. The whole archive is
    // ~1 KiB on disk; the cap kicks in before we allocate the bomb.
    let bomb: Vec<u8> = vec![0u8; 1 << 20];
    let mut b = ZipBuilder::new();
    b.add_deflated("bomb.dex", bomb);
    let tmp = write_to_temp(&b.build());
    let apk = Apk::open(tmp.path()).expect("open");
    let entry = apk.entry("bomb.dex").expect("entry");
    let limits = InflateLimits::with_max_output(64 * 1024).unwrap();
    let err = apk.read_entry_with_limits(&entry, limits).unwrap_err();
    assert!(matches!(err, ApkError::TooLarge { .. }), "got {:?}", err);
}

#[test]
fn truncated_eocd_returns_not_a_zip() {
    // Just a few bytes — no EOCD signature present.
    let bytes = vec![0u8; 100];
    let err = parse_view(&bytes).unwrap_err();
    assert!(matches!(err, ApkError::NotAZip), "got {:?}", err);
}

#[test]
fn cd_off_oob_returns_truncated() {
    // Manually build a ZIP-shaped blob whose EOCD says cd_off points past EOF.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[b'P', b'K', 5, 6]);
    bytes.extend_from_slice(&0u16.to_le_bytes()); // disk number
    bytes.extend_from_slice(&0u16.to_le_bytes()); // disk where CD starts
    bytes.extend_from_slice(&1u16.to_le_bytes()); // entries disk
    bytes.extend_from_slice(&1u16.to_le_bytes()); // entries total
    bytes.extend_from_slice(&46u32.to_le_bytes()); // cd size
    bytes.extend_from_slice(&10_000u32.to_le_bytes()); // cd_off (OOB)
    bytes.extend_from_slice(&0u16.to_le_bytes()); // comment len
    let err = parse_view(&bytes).unwrap_err();
    assert!(matches!(err, ApkError::Truncated(_)), "got {:?}", err);
}

#[test]
fn entry_name_oob_returns_truncated() {
    // Build a CD entry whose name_len exceeds the remaining CD bytes.
    let mut bytes = Vec::new();
    // Local header stub (so local_header_offset points somewhere).
    bytes.extend_from_slice(&[b'P', b'K', 3, 4]);
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
    bytes.extend_from_slice(&0u16.to_le_bytes()); // method
    bytes.extend_from_slice(&0u16.to_le_bytes()); // mtime
    bytes.extend_from_slice(&0u16.to_le_bytes()); // mdate
    bytes.extend_from_slice(&0u32.to_le_bytes()); // crc
    bytes.extend_from_slice(&0u32.to_le_bytes()); // csize
    bytes.extend_from_slice(&0u32.to_le_bytes()); // usize
    bytes.extend_from_slice(&9u16.to_le_bytes()); // name_len = 9
    bytes.extend_from_slice(&0u16.to_le_bytes()); // extra_len
    bytes.extend_from_slice(b"a/name.xx"); // 9 bytes
    // Central entry with name_len = 999 (OOB).
    let cd_off = bytes.len() as u32;
    bytes.extend_from_slice(&[b'P', b'K', 1, 2]);
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&999u16.to_le_bytes()); // huge name_len
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    // EOCD
    let cd_size = bytes.len() as u32 - cd_off;
    bytes.extend_from_slice(&[b'P', b'K', 5, 6]);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&cd_size.to_le_bytes());
    bytes.extend_from_slice(&cd_off.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    let err = parse_view(&bytes).unwrap_err();
    assert!(matches!(err, ApkError::Truncated(_)), "got {:?}", err);
}

#[test]
fn bad_local_header_signature_returns_bad_signature() {
    let mut b = ZipBuilder::new();
    b.add_stored("bad.dex", b"abc".to_vec())
        .next_local_sig(*b"NOPE");
    let archive = b.build();
    let view = parse_view(&archive).expect("parse");
    let entry = view.entry("bad.dex").expect("entry");
    let err = view.read_entry(&entry).unwrap_err();
    assert!(
        matches!(err, ApkError::BadSignature { .. }),
        "got {:?}",
        err
    );
}

#[test]
fn encrypted_flag_returns_unsupported() {
    let mut b = ZipBuilder::new();
    b.add_stored("enc.dex", b"abc".to_vec()).next_encrypted();
    let archive = b.build();
    let err = parse_view(&archive).unwrap_err();
    assert!(matches!(err, ApkError::Unsupported(_)), "got {:?}", err);
}

#[test]
fn unsupported_method_returns_unsupported() {
    let mut b = ZipBuilder::new();
    // Method 99 (bzip2 or similar) — not supported.
    b.add_stored("weird.dex", b"abc".to_vec())
        .next_method_override(99);
    let archive = b.build();
    let err = parse_view(&archive).unwrap_err();
    assert!(matches!(err, ApkError::Unsupported(_)), "got {:?}", err);
}

// =========================================================================
// EOCD with trailing comment
// =========================================================================

#[test]
fn eocd_with_trailing_comment_parses() {
    let mut b = ZipBuilder::new();
    b.add_stored("a.dex", vec![1, 2, 3]);
    let comment = b"ASC-RS comment padding".to_vec();
    b.set_comment(&comment);
    let bytes = b.build();
    // Verify the comment bytes are actually at the tail.
    assert!(bytes.ends_with(&comment));
    let view = parse_view(&bytes).expect("parse");
    assert_eq!(view.entry_count(), 1);
}

// =========================================================================
// Forged EOCD inside the archive comment (audit F01)
// =========================================================================

/// A complete-looking EOCD record (22 bytes) that claims "0 entries,
/// empty central directory". Placed inside the real archive comment it
/// cannot be distinguished from a valid record by a signature-only scan.
fn forged_eocd_record(cd_off: u32) -> Vec<u8> {
    let mut v = 0x0605_4b50u32.to_le_bytes().to_vec();
    common::write_u16(&mut v, 0); // disk number
    common::write_u16(&mut v, 0); // disk with CD
    common::write_u16(&mut v, 0); // entries on this disk
    common::write_u16(&mut v, 0); // entries total  <-- lies
    common::write_u32(&mut v, 0); // CD size        <-- lies
    common::write_u32(&mut v, cd_off); // CD offset
    common::write_u16(&mut v, 0); // comment length
    v
}

#[test]
fn forged_eocd_in_comment_does_not_hide_dex_entries() {
    let mut b = ZipBuilder::new();
    b.add_stored(
        "classes.dex",
        vec![0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00],
    );
    // Pad so the forged record sits well inside the comment window and
    // the real EOCD is followed by enough bytes for a full record read.
    let mut comment = vec![b'A'; 40];
    comment.extend(forged_eocd_record(0));
    comment.extend(vec![b'B'; 40]);
    b.set_comment(&comment);
    let bytes = b.build();

    let view = parse_view(&bytes).expect("archive with a comment must still parse");
    assert_eq!(
        view.dex_entries().len(),
        1,
        "forged EOCD in the comment must not hide the real classes.dex"
    );
    assert_eq!(view.entry_count(), 1);
}

#[test]
fn forged_eocd_in_comment_does_not_hide_zip64_dex_entries() {
    let mut b = ZipBuilder::new();
    b.add_stored(
        "classes.dex",
        vec![0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00],
    );
    b.force_zip64();
    let mut comment = vec![b'A'; 40];
    comment.extend(forged_eocd_record(0));
    comment.extend(vec![b'B'; 40]);
    b.set_comment(&comment);
    let bytes = b.build();

    let view = parse_view(&bytes).expect("ZIP64 archive with a comment must still parse");
    assert_eq!(view.dex_entries().len(), 1, "ZIP64 path must be unaffected");
}

#[test]
fn forged_eocd_in_comment_does_not_hide_signed_dex_entries() {
    let mut b = ZipBuilder::new();
    b.add_stored(
        "classes.dex",
        vec![0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00],
    );
    // A minimal APK Signing Block spliced between the last local entry
    // and the central directory, as v2/v3 signing produces.
    let cd_off = b.entries[0].data.len() as u64 + 30 + "classes.dex".len() as u64;
    let mut pairs: Vec<u8> = Vec::new();
    common::write_u64(&mut pairs, 8); // pair length: 4-byte id + 4 bytes value
    common::write_u32(&mut pairs, 0x7109_871a); // v2 block id
    common::write_u32(&mut pairs, 0);
    let size = (pairs.len() + 24) as u64;
    let mut sig_block = size.to_le_bytes().to_vec();
    sig_block.extend_from_slice(&pairs);
    sig_block.extend(size.to_le_bytes().to_vec());
    sig_block.extend_from_slice(b"APK Sig Block 42");

    let mut comment = vec![b'A'; 40];
    comment.extend(forged_eocd_record(0));
    comment.extend(vec![b'B'; 40]);
    b.set_comment(&comment);
    let bytes = b.build();
    // Splice the signing block in at the real central-directory offset.
    let mut archive = bytes[..cd_off as usize].to_vec();
    archive.extend_from_slice(&sig_block);
    archive.extend_from_slice(&bytes[cd_off as usize..]);
    // The central-directory offset shifted by the block we just inserted.
    // The *real* EOCD is the one the comment length pins to EOF; the
    // forged record lives inside the comment and is not it.
    let comment_len = 40 + 22 + 40;
    let eocd = archive.len() - 22 - comment_len;
    assert_eq!(
        &archive[eocd..eocd + 4],
        &0x0605_4b50u32.to_le_bytes(),
        "real EOCD must sit where the comment length says"
    );
    let cd_field = eocd + 16;
    let real_cd_off = u32::from_le_bytes(archive[cd_field..cd_field + 4].try_into().unwrap())
        + sig_block.len() as u32;
    archive[cd_field..cd_field + 4].copy_from_slice(&real_cd_off.to_le_bytes());

    let view = parse_view(&archive).expect("signed archive with a comment must still parse");
    assert_eq!(
        view.dex_entries().len(),
        1,
        "forged EOCD in the comment must not hide a signed APK's classes.dex"
    );
    // The signing block itself must still be discoverable.
    let scan = asc_apk::signing::scan(&archive);
    assert!(
        matches!(scan.block, asc_apk::signing::BlockStatus::Present { .. }),
        "signing block must survive: {:?}",
        scan.block
    );
}

/// A forgery that *self-terminates* — placed as the last 22 bytes of the
/// comment with its own `comment_len` = 0 — satisfies
/// `pos + 22 + comment_len == len` and so passes the termination check.
/// Pinned as a documented residual rather than left implicit: the engine
/// returns an empty directory, which is what Python's `zipfile` and
/// .NET's `ZipFile` also do on the same bytes. Matching mainstream ZIP
/// readers is deliberate; see `locate_eocd`.
#[test]
fn self_terminating_forged_eocd_matches_mainstream_parsers() {
    let mut b = ZipBuilder::new();
    b.add_stored(
        "classes.dex",
        vec![0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00],
    );
    let mut comment = vec![b'A'; 64];
    comment.extend(forged_eocd_record(0)); // forged record's own comment_len is 0
    b.set_comment(&comment);
    let bytes = b.build();

    let view = parse_view(&bytes).expect("a self-terminating EOCD is still a valid EOCD");
    assert_eq!(
        view.dex_entries().len(),
        0,
        "known residual: we agree with zipfile / .NET here rather than \
         applying a non-standard CD heuristic"
    );
}

#[test]
fn corrupt_real_eocd_is_reported_not_guessed() {
    // Damage the real EOCD's entry count so no candidate validates.
    let mut b = ZipBuilder::new();
    b.add_stored("classes.dex", vec![1, 2, 3, 4]);
    b.set_comment(b"tail");
    let mut bytes = b.build();
    let len = bytes.len();
    let eocd = len - 4 - 22;
    // Point the real EOCD at a central directory far past EOF.
    bytes[eocd + 16..eocd + 20].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
    let err = parse_view(&bytes).expect_err("damaged EOCD must be an error, not a guess");
    assert!(
        matches!(err, ApkError::Truncated(_) | ApkError::BadSignature { .. }),
        "got {err:?}"
    );
}

// =========================================================================
// ZIP64
// =========================================================================

#[test]
fn zip64_layout_parses() {
    let mut b = ZipBuilder::new();
    b.add_deflated("z.dex", highly_compressible());
    b.force_zip64();
    let bytes = b.build();
    // Confirm the EOCD has placeholders (entries_total == 0xFFFF).
    let len = bytes.len();
    assert_eq!(
        &bytes[len - 12..len - 10],
        &0xFFFFu16.to_le_bytes(),
        "entries_total must be 0xFFFF in ZIP64 layout"
    );
    let view = parse_view(&bytes).expect("parse zip64");
    let entry = view.entry("z.dex").expect("entry");
    assert_eq!(entry.method, Compression::Deflated);
    let got = view.read_entry(&entry).expect("read");
    assert_eq!(got.as_slice(), highly_compressible().as_slice());
}

#[test]
fn zip64_extra_field_in_central_resolves_placeholders() {
    // Hand-craft a central entry that has ZIP64 placeholders and a ZIP64
    // extra field pointing at them.
    //
    // Layout: [local header for z.dex][z.dex stored data][central dir with
    // ZIP64 extra][EOCD with ZIP64 placeholder for csize]
    let stored = vec![0xAAu8; 8];
    let mut bytes = Vec::new();

    // Local header.
    bytes.extend_from_slice(&[b'P', b'K', 3, 4]);
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // flags
    bytes.extend_from_slice(&0u16.to_le_bytes()); // method stored
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // crc
    bytes.extend_from_slice(&(stored.len() as u32).to_le_bytes()); // csize
    bytes.extend_from_slice(&(stored.len() as u32).to_le_bytes()); // usize
    bytes.extend_from_slice(&5u16.to_le_bytes()); // name_len
    bytes.extend_from_slice(&0u16.to_le_bytes()); // extra_len
    bytes.extend_from_slice(b"z.dex");
    let local_header_offset = 0u32;
    bytes.extend_from_slice(&stored);

    // Central directory with ZIP64 placeholders + extra.
    let cd_off = bytes.len() as u64;
    let extra = zip64_extra(
        stored.len() as u64,
        stored.len() as u64,
        local_header_offset as u64,
    );
    bytes.extend_from_slice(&[b'P', b'K', 1, 2]);
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 flag set
    bytes.extend_from_slice(&0u16.to_le_bytes()); // method
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // crc
    bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // csize placeholder
    bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // usize placeholder
    bytes.extend_from_slice(&5u16.to_le_bytes()); // name_len
    bytes.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes()); // comment_len
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // lho placeholder
    bytes.extend_from_slice(b"z.dex");
    bytes.extend_from_slice(&extra);
    let cd_end = bytes.len() as u64;
    let cd_size = cd_end - cd_off;

    // ZIP64 EOCD + locator.
    let eocd64_off = bytes.len() as u64;
    bytes.extend_from_slice(&[b'P', b'K', 6, 6]);
    bytes.extend_from_slice(&44u64.to_le_bytes()); // size of record
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&20u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u64.to_le_bytes()); // entries on disk
    bytes.extend_from_slice(&1u64.to_le_bytes()); // entries total
    bytes.extend_from_slice(&cd_size.to_le_bytes());
    bytes.extend_from_slice(&cd_off.to_le_bytes());
    bytes.extend_from_slice(&[b'P', b'K', 6, 7]);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&eocd64_off.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&[b'P', b'K', 5, 6]);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
    bytes.extend_from_slice(&0xFFFFu16.to_le_bytes());
    bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    let view = parse_view(&bytes).expect("parse zip64");
    let entry = view.entry("z.dex").expect("entry");
    assert_eq!(entry.uncompressed_size, stored.len() as u64);
    assert_eq!(entry.compressed_size, stored.len() as u64);
    let got = view.read_entry(&entry).expect("read");
    assert_eq!(got.as_slice(), stored.as_slice());
}

// =========================================================================
// Empty zip

// CRC verification path
// =========================================================================

#[test]
fn read_entry_verified_succeeds_for_correct_crc() {
    let payload = b"correct-crc".to_vec();
    let mut b = ZipBuilder::new();
    b.add_stored("ok.bin", payload.clone());
    let tmp = write_to_temp(&b.build());
    let apk = Apk::open(tmp.path()).expect("open");
    let entry = apk.entry("ok.bin").expect("entry");
    let got = apk.read_entry_verified(&entry).expect("verified");
    assert_eq!(got.as_slice(), payload.as_slice());
}

#[test]
fn read_entry_verified_detects_corrupted_payload() {
    // Build a valid archive, then mutate one byte of the STORED payload
    // (the central CRC stays the original, so verification fails).
    let payload = b"correct-crc".to_vec();
    let mut b = ZipBuilder::new();
    b.add_stored("ok.bin", payload.clone());
    let mut bytes = b.build();
    // Locate the local-header data offset for "ok.bin" via a first parse.
    let data_off = {
        let v = parse_view(&bytes).expect("parse");
        let entry = v.entry("ok.bin").expect("entry");
        entry.local_header_offset as usize + 30 + entry.name.len()
    };
    bytes[data_off] ^= 0xFF; // flip one bit
    let tmp = write_to_temp(&bytes);
    let apk = Apk::open(tmp.path()).expect("open");
    let entry = apk.entry("ok.bin").expect("entry");
    let err = apk.read_entry_verified(&entry).unwrap_err();
    assert!(
        matches!(err, ApkError::SizeMismatch { .. }),
        "CRC mismatch should be reported as SizeMismatch, got {:?}",
        err
    );
}

// =========================================================================
// Bounds-checked input
// =========================================================================

#[test]
fn too_small_to_be_zip() {
    let bytes = vec![0u8; 5];
    assert!(matches!(parse_view(&bytes), Err(ApkError::NotAZip)));
}

#[test]
fn random_bytes_are_not_a_zip() {
    let bytes = incompressible(8192);
    assert!(matches!(parse_view(&bytes), Err(ApkError::NotAZip)));
}

#[test]
fn apk_open_nonexistent_returns_io_error() {
    let result = Apk::open(std::path::Path::new(
        "Z:/nonexistent/asc-rs-does-not-exist.apk",
    ));
    assert!(matches!(result, Err(ApkError::Io(_))), "got {:?}", result);
}

// =========================================================================
// Smoke test that exercises Apk + DeflateDecoder with a larger APK-shaped
// archive (multiple entries, mixed stored/deflated).
// =========================================================================

#[test]
fn mixed_apk_open_and_read_all_entries() {
    let mut b = ZipBuilder::new();
    b.add_stored("AndroidManifest.xml", b"<?xml version='1.0'?>".to_vec());
    b.add_stored("resources.arsc", vec![0xAB; 1024]);
    b.add_deflated("classes.dex", b"dex-payload".to_vec());
    b.add_deflated("classes2.dex", highly_compressible());
    b.add_stored("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n".to_vec());
    b.add_stored("assets/index.html", b"<html/>".to_vec());
    let tmp = write_to_temp(&b.build());
    let apk = Apk::open(tmp.path()).expect("open");
    let dex: Vec<DexEntry> = apk.dex_entries();
    assert_eq!(dex.len(), 2);
    assert_eq!(dex[0].name, "classes.dex");
    assert_eq!(dex[1].name, "classes2.dex");

    // Read each entry to confirm round-trip.
    for e in apk.entries() {
        let bytes = apk.read_entry(&e).expect("read");
        // Just verify it didn't error and the length matches what we wrote.
        if e.name == "classes.dex" {
            assert_eq!(bytes.as_slice(), b"dex-payload");
        } else if e.name == "classes2.dex" {
            assert_eq!(bytes.as_slice(), highly_compressible().as_slice());
        } else if e.name == "AndroidManifest.xml" {
            assert_eq!(bytes.as_slice(), b"<?xml version='1.0'?>");
        } else if e.name == "META-INF/MANIFEST.MF" {
            assert_eq!(bytes.as_slice(), b"Manifest-Version: 1.0\n");
        } else if e.name == "assets/index.html" {
            assert_eq!(bytes.as_slice(), b"<html/>");
        } else if e.name == "resources.arsc" {
            assert_eq!(bytes.len(), 1024);
            assert!(bytes.as_slice().iter().all(|&b| b == 0xAB));
        }
    }
}

// =========================================================================
// Sync/Send (compile-time) checks
// =========================================================================

fn _assert_send_sync<T: Send + Sync>() {}

#[test]
fn apk_and_zipview_are_send_and_sync() {
    _assert_send_sync::<Apk>();
    _assert_send_sync::<ZipView<'static>>();
}

// =========================================================================
// Ground-truth: real APK fixture discovery + byte-for-byte extraction
// =========================================================================
//
// `corpus/apk/workload.apk` is a single-dex APK whose `classes.dex`
// should match `corpus/dex/workload_classes.dex` byte-for-byte.
// `corpus/apk/com.aurora.store_60.apk` is a multidex APK with
// `classes.dex` and `classes2.dex`.
//
// If the corpus is missing the test is skipped via the `path.exists()`
// guard so this file compiles and runs in trees without fixtures.

#[test]
fn corpus_workload_apk_single_dex_matches_dex_fixture() {
    use std::path::Path;
    let apk_path = Path::new("../../../corpus/apk/workload.apk");
    let dex_path = Path::new("../../../corpus/dex/workload_classes.dex");
    if !apk_path.exists() || !dex_path.exists() {
        eprintln!("corpus fixtures missing; skipping");
        return;
    }
    let apk = Apk::open(apk_path).expect("open workload.apk");
    let dex_entries = apk.dex_entries();
    let names: Vec<&str> = dex_entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["classes.dex"], "expected single dex entry");
    let entry = &dex_entries[0];
    let bytes = apk.read_entry(entry).expect("read classes.dex");
    let expected = std::fs::read(dex_path).expect("read workload_classes.dex");
    assert_eq!(
        bytes.len(),
        expected.len(),
        "classes.dex length mismatch (got {}, expected {})",
        bytes.len(),
        expected.len()
    );
    assert_eq!(
        bytes.as_slice(),
        expected.as_slice(),
        "classes.dex content mismatch"
    );
}

#[test]
fn corpus_aurora_apk_multidex_matches_dex_fixtures() {
    use std::path::Path;
    let apk_path = Path::new("../../../corpus/apk/com.aurora.store_60.apk");
    let dex1_path = Path::new("../../../corpus/dex/aurora_classes.dex");
    let dex2_path = Path::new("../../../corpus/dex/aurora_classes2.dex");
    if !apk_path.exists() || !dex1_path.exists() || !dex2_path.exists() {
        eprintln!("aurora fixtures missing; skipping");
        return;
    }
    let apk = Apk::open(apk_path).expect("open aurora.apk");
    let dex_entries = apk.dex_entries();
    let names: Vec<&str> = dex_entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["classes.dex", "classes2.dex"],
        "expected multidex ordering"
    );
    let map_dex1 = apk.read_entry(&dex_entries[0]).expect("read classes.dex");
    let map_dex2 = apk.read_entry(&dex_entries[1]).expect("read classes2.dex");
    let expected1 = std::fs::read(dex1_path).expect("read aurora_classes.dex");
    let expected2 = std::fs::read(dex2_path).expect("read aurora_classes2.dex");
    assert_eq!(map_dex1.len(), expected1.len(), "classes.dex length");
    assert_eq!(
        map_dex1.as_slice(),
        expected1.as_slice(),
        "classes.dex content"
    );
    assert_eq!(map_dex2.len(), expected2.len(), "classes2.dex length");
    assert_eq!(
        map_dex2.as_slice(),
        expected2.as_slice(),
        "classes2.dex content"
    );
}

// =========================================================================
// Raw DEX input (no ZIP wrapper)
// =========================================================================

#[test]
fn raw_dex_opens_as_single_borrowed_entry() {
    let mut bytes = b"dex\n035\0".to_vec();
    bytes.extend_from_slice(&[7u8; 64]);
    let tmp = write_to_temp(&bytes);
    let apk = Apk::open(tmp.path()).expect("open raw dex");
    assert!(apk.is_raw_dex());
    let entries = apk.dex_entries();
    assert_eq!(entries.len(), 1);
    let got = apk.read_entry(&entries[0]).expect("read");
    assert!(matches!(got, EntryBytes::Borrowed(_)));
    assert_eq!(got.as_slice(), bytes.as_slice());
    // No ZIP CRC exists: verified read must refuse rather than pass.
    assert!(matches!(
        apk.read_entry_verified(&entries[0]),
        Err(ApkError::Unsupported(_))
    ));
    // A foreign entry must not be interpreted as a ZIP local header.
    let mut foreign = entries[0].clone();
    foreign.name = "other".into();
    assert!(apk.read_entry(&foreign).is_err());
}

#[test]
fn zip_is_not_raw_dex() {
    let mut b = ZipBuilder::new();
    b.add_stored("classes.dex", b"dex\n035\0".to_vec());
    let tmp = write_to_temp(&b.build());
    assert!(!Apk::open(tmp.path()).expect("open").is_raw_dex());
}

#[test]
fn cdex_odex_vdex_rejected_clearly() {
    for magic in [&b"cdex001\0"[..], b"dey\n036\0", b"vdex027\0"] {
        let tmp = write_to_temp(magic);
        let err = Apk::open(tmp.path()).unwrap_err();
        assert!(
            matches!(err, ApkError::Unsupported(m) if m.contains("CDEX")),
            "{magic:?}: {err:?}"
        );
    }
}

// =========================================================================
// Prefix sampling
// =========================================================================

#[test]
fn prefix_sampling_stored_and_deflated() {
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut b = ZipBuilder::new();
    b.add_stored("s.bin", big.clone());
    b.add_deflated("d.bin", big.clone());
    let tmp = write_to_temp(&b.build());
    let apk = Apk::open(tmp.path()).expect("open");
    for name in ["s.bin", "d.bin"] {
        let e = apk.entry(name).unwrap();
        let (p, complete) = apk.read_entry_prefix(&e, 1000).expect("prefix");
        assert_eq!(p.as_slice(), &big[..1000], "{name}");
        assert!(!complete, "{name}");
        let (p, complete) = apk.read_entry_prefix(&e, big.len()).expect("exact");
        assert_eq!(p.len(), big.len(), "{name}");
        assert!(complete, "exact-size prefix is complete: {name}");
        let (p, complete) = apk.read_entry_prefix(&e, big.len() * 2).expect("over");
        assert_eq!(p.len(), big.len());
        assert!(complete);
    }
}

#[test]
fn prefix_sampling_large_deflated_entry_is_not_full_extraction() {
    // 64 MiB of zeros deflates to ~64 KiB; a 4 KiB prefix must succeed
    // even under an inflate cap far below the entry size.
    let mut b = ZipBuilder::new();
    b.add_deflated("z.bin", vec![0u8; 64 << 20]);
    let tmp = write_to_temp(&b.build());
    let apk = Apk::open(tmp.path()).expect("open");
    let e = apk.entry("z.bin").unwrap();
    let (p, complete) = apk.read_entry_prefix(&e, 4096).expect("prefix");
    assert_eq!(p.len(), 4096);
    assert!(!complete);
}

#[test]
fn prefix_sampling_raw_dex() {
    let mut bytes = b"dex\n035\0".to_vec();
    bytes.extend_from_slice(&[1u8; 100]);
    let tmp = write_to_temp(&bytes);
    let apk = Apk::open(tmp.path()).expect("open");
    let e = &apk.dex_entries()[0];
    let (p, complete) = apk.read_entry_prefix(e, 10).expect("prefix");
    assert_eq!(p.as_slice(), &bytes[..10]);
    assert!(!complete);
}
