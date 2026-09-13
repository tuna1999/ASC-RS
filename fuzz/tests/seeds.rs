//! Integration tests for the seed corpus generator. Calls
//! `asc_fuzz::seeds::emit_all` against a temporary directory and
//! asserts that the resulting tree is non-empty and matches the
//! registry one-for-one.
use asc_fuzz::seeds::{count_files, emit_all};

use asc_fuzz::registry;

#[test]
fn emit_all_produces_files() {
    let tmp = std::env::temp_dir().join(format!(
        "asc-fuzz-test-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    let n = emit_all(&tmp).expect("emit_all should succeed");
    assert!(n > 0, "emit_all wrote zero files");

    let total = count_files(&tmp).expect("count_files should succeed");
    assert!(
        total >= 20,
        "expected at least 20 seed files total, got {total}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn emit_all_covers_every_target_subdir() {
    let tmp = std::env::temp_dir().join(format!(
        "asc-fuzz-test-cov-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    emit_all(&tmp).expect("emit_all should succeed");

    let targets = registry();
    for t in &targets {
        let dir = tmp.join(t.default_seed);
        assert!(
            dir.is_dir(),
            "missing seed subdir for target '{}' at {}",
            t.name,
            dir.display()
        );
        let n = count_files(&dir).expect("count_files");
        assert!(
            n >= 1,
            "target '{}' got zero seeds at {}",
            t.name,
            dir.display()
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn dex_minimal_header_is_well_formed() {
    use asc_fuzz::seeds::dex_minimal_header;
    let h = dex_minimal_header();
    assert_eq!(h.len(), 0x70, "DEX header must be 0x70 bytes");
    assert_eq!(&h[0..4], b"dex\n");
    assert_eq!(h[7], 0x00);
    assert_eq!(h[0x28], 0x01, "endian tag first byte");
    assert_eq!(h[0x29], b'L', "endian tag second byte");
}

#[test]
fn zip_one_stored_class_has_consistent_sizes() {
    use asc_fuzz::seeds::zip_one_stored_class;
    let z = zip_one_stored_class();
    assert!(z.starts_with(b"PK\x03\x04"), "starts with LFH signature");
    assert!(z.windows(4).any(|w| w == b"PK\x05\x06"), "ends with EOCD");
    // Payload is 16 bytes — verify the size fields agree.
    // Skip the local header fields up to compressed size (offset 18).
    let compressed_size = u32::from_le_bytes([z[18], z[19], z[20], z[21]]);
    assert_eq!(compressed_size, 16);
}
