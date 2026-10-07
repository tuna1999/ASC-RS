//! Regression tests for the `class_data_item` preflight.
//!
//! The preflight used to demand `8 * entries` remaining bytes — an
//! *over*-estimate (a compact encoded field is 2 bytes, a method 3), so a
//! well-formed, maximally compact `class_data_item` sitting at the end of
//! the physical buffer was rejected as `Truncated`. The guard is now the
//! exact lower bound; these tests pin both halves: valid compact items
//! parse, genuinely truncated / capped / overflowing ones still error.

use asc_dex::{DexError, DexView};

/// Offset where the synthetic `class_data_item` starts (right after the
/// 0x70-byte header).
const CLASS_DATA_OFF: u32 = 0x70;

/// Builds a minimal DEX whose physical buffer is `header || tail`, with
/// `file_size` covering the whole thing and every pool empty. `parse` does
/// not verify the checksum/signature, so only the header fields the reader
/// validates need to be real.
fn dex_with_tail(tail: &[u8]) -> Vec<u8> {
    const HEADER: usize = 0x70;
    let mut buf = vec![0u8; HEADER + tail.len()];
    let file_size = buf.len() as u32;
    buf[..8].copy_from_slice(b"dex\n035\0");
    buf[0x20..0x24].copy_from_slice(&file_size.to_le_bytes()); // file_size
    buf[0x24..0x28].copy_from_slice(&(HEADER as u32).to_le_bytes()); // header_size
    buf[0x28..0x2C].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // endian_tag
    buf[HEADER..].copy_from_slice(tail);
    buf
}

/// One static field and nothing else: sizes `(1, 0, 0, 0)` then a compact
/// encoded field (`idx-diff = 0`, `access_flags = 1`) — 2 payload bytes.
/// The old guard demanded 8.
#[test]
fn compact_class_data_at_eof_parses() {
    let bytes = dex_with_tail(&[1, 0, 0, 0, 0, 1]);
    let view = DexView::parse(&bytes).expect("minimal header parses");

    let cd = view
        .class_data(CLASS_DATA_OFF)
        .expect("a compact class_data_item at EOF is valid")
        .expect("non-zero offset yields data");
    assert_eq!(cd.static_fields.len(), 1);
    assert_eq!(cd.instance_fields.len(), 0);
    assert_eq!(cd.direct_methods.len(), 0);
    assert_eq!(cd.virtual_methods.len(), 0);
    assert_eq!(cd.static_fields[0].field_idx.0, 0);
    assert_eq!(cd.static_fields[0].access_flags, 1);
}

/// One direct + one virtual method: sizes `(0, 0, 1, 1)` then 3 compact
/// ulebs each — 6 payload bytes, while the old guard demanded 16.
#[test]
fn compact_method_lists_at_eof_parse() {
    let bytes = dex_with_tail(&[
        0, 0, 1, 1, // sizes
        0, 1, 0, // direct method: idx-diff 0, access 1, code_off 0
        0, 1, 0, // virtual method
    ]);
    let view = DexView::parse(&bytes).expect("minimal header parses");

    let cd = view
        .class_data(CLASS_DATA_OFF)
        .expect("compact method lists are valid")
        .expect("non-zero offset");
    assert_eq!(cd.direct_methods.len(), 1);
    assert_eq!(cd.virtual_methods.len(), 1);
    assert_eq!(cd.direct_methods[0].method_idx.0, 0);
    assert_eq!(cd.direct_methods[0].code_off, 0);
    assert_eq!(cd.virtual_methods[0].method_idx.0, 0);
}

/// The claimed list is not actually present: 1 field promised, only the
/// idx-diff byte exists. Must still fail cleanly as `Truncated`.
#[test]
fn truncated_class_data_still_errors() {
    let bytes = dex_with_tail(&[1, 0, 0, 0, 0]); // access_flags byte missing
    let view = DexView::parse(&bytes).expect("minimal header parses");
    assert!(
        matches!(
            view.class_data(CLASS_DATA_OFF),
            Err(DexError::Truncated { .. })
        ),
        "a truncated class_data must not parse"
    );
}

/// A list longer than `MAX_LIST` is rejected before any allocation, no
/// matter how much buffer follows.
#[test]
fn oversized_list_still_capped() {
    // static_fields_size = (1 << 20) + 1, uleb-encoded.
    let bytes = dex_with_tail(&[0x81, 0x80, 0x40, 0, 0, 0]);
    let view = DexView::parse(&bytes).expect("minimal header parses");
    assert!(
        matches!(
            view.class_data(CLASS_DATA_OFF),
            Err(DexError::InvalidLength { .. })
        ),
        "list size cap must still fire"
    );
}

/// Cumulative idx-diff overflow is still reported as such (not silently
/// wrapped, not misreported as truncation).
#[test]
fn delta_overflow_still_errors() {
    let mut tail = vec![2, 0, 0, 0]; // 2 static fields
    tail.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00]); // idx-diff = u32::MAX, access 0
    tail.extend_from_slice(&[0x01, 0x00]); // idx-diff = 1 → overflow
    let bytes = dex_with_tail(&tail);
    let view = DexView::parse(&bytes).expect("minimal header parses");
    assert!(
        matches!(
            view.class_data(CLASS_DATA_OFF),
            Err(DexError::ClassDataDeltaOverflow { .. })
        ),
        "checked_add must reject the overflowing cumulative index"
    );
}

/// Offset zero means "no class data" and an offset past the buffer is a
/// bounds error — both unchanged by the preflight fix.
#[test]
fn zero_and_out_of_bounds_offsets() {
    let bytes = dex_with_tail(&[0, 0, 0, 0]);
    let view = DexView::parse(&bytes).expect("minimal header parses");
    assert!(view.class_data(0).expect("off 0 is not an error").is_none());
    assert!(matches!(
        view.class_data(bytes.len() as u32),
        Err(DexError::OffsetOutOfBounds { .. })
    ));
}
