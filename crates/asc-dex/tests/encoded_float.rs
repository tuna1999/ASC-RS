//! float/double `encoded_value`s are RIGHT-zero-extended (DEX spec): the
//! payload bytes are the high-order bytes of the bit pattern. They used to
//! be zero-extended on the left like `char`, so `1.0f` (`[80 3F]`) read
//! as 0x3F80 instead of 0x3F800000.

mod common;

use asc_dex::{DexView, EncodedValue};

#[test]
fn float_and_double_payloads_are_right_extended() {
    let buf = common::tiny_dex();
    let view = DexView::parse(&buf).unwrap();
    // VALUE_FLOAT (0x10), arg 1 → 2 bytes: 1.0f = 0x3F80_0000.
    let (v, n) = view.encoded_value(&[0x30, 0x80, 0x3F], 0).unwrap();
    assert_eq!((v, n), (EncodedValue::Float(1.0f32.to_bits()), 3));
    // VALUE_DOUBLE (0x11), arg 1 → 2 bytes: 1.0 = 0x3FF0_0000_0000_0000.
    let (v, _) = view.encoded_value(&[0x31, 0xF0, 0x3F], 0).unwrap();
    assert_eq!(v, EncodedValue::Double(1.0f64.to_bits()));
    // Full width is unchanged.
    let (v, _) = view
        .encoded_value(&[0x70, 0x00, 0x00, 0x80, 0x3F], 0)
        .unwrap();
    assert_eq!(v, EncodedValue::Float(1.0f32.to_bits()));
    // A float can't be wider than 4 bytes.
    assert!(view.encoded_value(&[0x90, 0, 0, 0, 0, 0, 0], 0).is_err());
}
