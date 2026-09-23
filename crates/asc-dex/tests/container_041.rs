//! Tests for DEX 041 physical containers and logical-header discovery.

mod common;

use asc_dex::DexView;
use common::tiny_dex;

#[test]
fn logical_header_offsets_single_dex_returns_zero() {
    let buf = tiny_dex();
    let offs = DexView::logical_header_offsets(&buf).unwrap();
    // tiny_dex is a 035 single DEX (not a 041 container), so the helper
    // falls back to [0] and reports no logical headers.
    assert_eq!(offs, vec![0]);
}

/// Build a two-logical-DEX 041 container.
///
/// The `tiny_dex()` helper produces a 035 header; we patch each copy to
/// 041 and shift the second one's internal offsets by `first_size` so they
/// remain absolute. The `file_size` field itself is preserved (it describes
/// the size of the logical DEX, not its container offset).
fn build_041_container() -> Vec<u8> {
    let mut a = tiny_dex();
    a[0..8].copy_from_slice(b"dex\n041\0");
    let mut b = tiny_dex();
    b[0..8].copy_from_slice(b"dex\n041\0");
    let first_size = a.len() as u32;
    let mut combined = a.clone();
    combined.extend_from_slice(&b);
    let mut shift = |off: usize| {
        let v = u32::from_le_bytes(
            combined[first_size as usize + off..first_size as usize + off + 4]
                .try_into()
                .unwrap(),
        );
        combined[first_size as usize + off..first_size as usize + off + 4]
            .copy_from_slice(&(v + first_size).to_le_bytes());
    };
    shift(0x30); // link_off
    shift(0x34); // map_off
    shift(0x3C); // string_ids_off
    shift(0x44); // type_ids_off
    shift(0x4C); // proto_ids_off
    shift(0x54); // field_ids_off
    shift(0x5C); // method_ids_off
    shift(0x64); // class_defs_off
    combined
}

#[test]
fn build_041_container_with_two_logical_dex() {
    let combined = build_041_container();
    let first_size = tiny_dex().len();
    let offs = DexView::logical_header_offsets(&combined).unwrap();
    assert_eq!(offs.len(), 2);
    assert_eq!(offs[0], 0);
    assert_eq!(offs[1], first_size);
}

#[test]
fn parse_at_finds_second_logical_dex() {
    let combined = build_041_container();
    let first_size = tiny_dex().len();
    let view = DexView::parse_at(&combined, first_size).unwrap();
    assert_eq!(view.version().as_str(), "041");
    assert_eq!(view.string_count(), 3);
}

/// Regression: the Python oracle builds DEX-041 logical headers with
/// `header_size == 0x78` (see `MG1937/ASC @ 5395f17 tests/test_listclass.py`).
/// Earlier this crate hard-rejected any header other than `0x70`, silently
/// dropping every real-world 041 logical member. This test patches the
/// magic to 041 and the header_size to 0x78, and asserts that
/// `DexView::parse` succeeds.
#[test]
fn parse_accepts_dex041_logical_header_size_0x78() {
    use asc_dex::header::DexHeader;
    let mut buf = tiny_dex();
    buf[0..8].copy_from_slice(b"dex\n041\0");
    // Re-stamp file_size (unchanged) and bump header_size from 0x70 to 0x78.
    let file_size = u32::from_le_bytes(buf[0x20..0x24].try_into().unwrap());
    buf[0x24..0x28].copy_from_slice(&0x78u32.to_le_bytes());
    // The body offsets are all below 0x70 so they remain valid under a
    // 0x78-byte header.
    let _ = file_size;
    let view = DexView::parse(&buf).expect("0x78 DEX-041 header must parse");
    assert_eq!(view.version().as_str(), "041");
    assert_eq!(
        DexHeader::SIZE_041,
        0x78,
        "DexHeader::SIZE_041 should be 0x78"
    );
}

/// Regression: a `header_size` that is neither 0x70 nor 0x78 must still
/// be rejected as `InvalidHeader` (no silent acceptance of arbitrary
/// values).
#[test]
fn parse_rejects_unknown_header_size() {
    let mut buf = tiny_dex();
    buf[0x24..0x28].copy_from_slice(&0x80u32.to_le_bytes());
    assert!(DexView::parse(&buf).is_err());
}
