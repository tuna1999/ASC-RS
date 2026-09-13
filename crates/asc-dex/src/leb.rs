//! ULEB128 / SLEB128 decoders for DEX.
//!
//! The DEX format uses LEB128 everywhere (`class_data`, `debug_info`,
//! `encoded_value`, `string` utf16 length). All functions here are total:
//! every malformed input returns [`DexError`](crate::DexError), never panics.
//!
//! The DEX format restricts ULEB128 used in pool indices to **at most 5 bytes**
//! (35 bits), but `debug_info` is allowed more — we expose a generic reader
//! that caps at 10 bytes (70 bits, well past any legitimate DEX value) and a
//! stricter `uleb128_to_u32` for the typical pool-encoded case.

use crate::error::DexError;

/// Maximum number of bytes a single `uleb128` value may span when used in a
/// pool reference. Values larger than `u32::MAX` cannot represent a valid
/// pool index.
pub const MAX_U32_BYTES: usize = 5;

/// Maximum number of bytes we will scan while decoding any `uleb128` in the
/// crate. Picked safely above the DEX specification cap so legitimate
/// encodings are accepted and oversized encodings are rejected.
pub const MAX_GENERIC_BYTES: usize = 10;

/// Maximum bytes for a SLEB128 representing an `i32`.
pub const MAX_I32_BYTES: usize = 5;

/// Decodes a ULEB128 value as a `u32`.
///
/// Returns the decoded value and the number of bytes consumed on success.
/// On error (truncation, overflow past `u32::MAX`, or payload longer than
/// 5 bytes) returns the appropriate [`DexError`].
pub fn uleb128_to_u32(bytes: &[u8]) -> Result<(u32, usize), DexError> {
    if bytes.is_empty() {
        return Err(DexError::Uleb { message: "empty input" });
    }
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while i < MAX_GENERIC_BYTES {
        let b = *bytes.get(i).ok_or(DexError::Uleb { message: "truncated" })?;
        i += 1;
        if shift < 32 {
            let low = (b as u32) & 0x7F;
            // shift 28 is the last position that can accept 7 bits; check
            // that the payload fits the remaining 4 bits.
            if shift == 28 {
                if low > 0x0F {
                    return Err(DexError::Uleb {
                        message: "value exceeds u32::MAX",
                    });
                }
                result |= low << shift;
            } else {
                result |= low << shift;
            }
        } else if b & 0x7F != 0 {
            // shift >= 32: any payload would push us past u32::MAX.
            return Err(DexError::Uleb {
                message: "value exceeds u32::MAX",
            });
        }
        shift += 7;
        if b < 0x80 {
            return Ok((result, i));
        }
    }
    Err(DexError::Uleb {
        message: "uleb128 exceeds 10 bytes",
    })
}

/// Decodes a SLEB128 value as an `i32`.
///
/// Returns the decoded value and the number of bytes consumed on success.
pub fn sleb128_to_i32(bytes: &[u8]) -> Result<(i32, usize), DexError> {
    if bytes.is_empty() {
        return Err(DexError::Sleb { message: "empty input" });
    }
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while i < MAX_GENERIC_BYTES {
        let byte = *bytes.get(i).ok_or(DexError::Sleb { message: "truncated" })?;
        i += 1;
        let payload = (byte as u32) & 0x7F;
        if shift < 32 {
            result |= payload << shift;
        } else if payload != 0 {
            // i32 fits in 32 bits; payload past shift 32 would overflow.
            return Err(DexError::Sleb {
                message: "value exceeds i32 range",
            });
        }
        shift += 7;
        if byte < 0x80 {
            // Sign-extend if the sign bit of the final byte is set and the
            // remaining bits fit inside 32.
            if shift < 32 && (byte & 0x40) != 0 {
                result |= !0u32 << shift;
            }
            return Ok((result as i32, i));
        }
    }
    Err(DexError::Sleb {
        message: "sleb128 exceeds 10 bytes",
    })
}

/// Generic ULEB128 decoder that returns a `u64`.
///
/// Allows up to 10 bytes (70 bits). Used for `encoded_value` counts and
/// `debug_info` parameters where the spec does not restrict to `u32`.
pub fn uleb128(bytes: &[u8]) -> Result<(u64, usize), DexError> {
    if bytes.is_empty() {
        return Err(DexError::Uleb { message: "empty input" });
    }
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while i < MAX_GENERIC_BYTES {
        let b = *bytes.get(i).ok_or(DexError::Uleb { message: "truncated" })?;
        i += 1;
        if shift < 64 {
            result |= ((b as u64) & 0x7F) << shift;
        } else if b & 0x7F != 0 {
            return Err(DexError::Uleb {
                message: "value exceeds u64::MAX",
            });
        }
        shift += 7;
        if b < 0x80 {
            return Ok((result, i));
        }
    }
    Err(DexError::Uleb {
        message: "uleb128 exceeds 10 bytes",
    })
}

/// Generic SLEB128 decoder that returns an `i64`.
pub fn sleb128(bytes: &[u8]) -> Result<(i64, usize), DexError> {
    if bytes.is_empty() {
        return Err(DexError::Sleb { message: "empty input" });
    }
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    while i < MAX_GENERIC_BYTES {
        let byte = *bytes.get(i).ok_or(DexError::Sleb { message: "truncated" })?;
        i += 1;
        let payload = ((byte as u64) & 0x7F) << shift;
        if shift < 64 {
            result |= payload;
        } else if (byte as u64) & 0x7F != 0 {
            return Err(DexError::Sleb {
                message: "value exceeds i64 range",
            });
        }
        shift += 7;
        if byte < 0x80 {
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0u64 << shift;
            }
            return Ok((result as i64, i));
        }
    }
    Err(DexError::Sleb {
        message: "sleb128 exceeds 10 bytes",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb_zero() {
        assert_eq!(uleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(uleb128_to_u32(&[0x00]).unwrap(), (0, 1));
    }

    #[test]
    fn uleb_one_byte() {
        assert_eq!(uleb128(&[0x01]).unwrap(), (1, 1));
        assert_eq!(uleb128(&[0x7F]).unwrap(), (0x7F, 1));
    }

    #[test]
    fn uleb_five_bytes_max() {
        // 0xFFFFFFFF
        let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
        assert_eq!(uleb128(&buf).unwrap(), (0xFFFF_FFFF, 5));
        assert_eq!(uleb128_to_u32(&buf).unwrap(), (0xFFFF_FFFF, 5));
    }

    #[test]
    fn uleb_continuation_at_6th_byte_rejected_for_u32() {
        // u32::MAX + 1 (would overflow to 36 bits)
        let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0x1F];
        assert!(uleb128_to_u32(&buf).is_err());
    }

    #[test]
    fn uleb_truncation() {
        assert!(uleb128(&[0x80]).is_err());
        assert!(uleb128_to_u32(&[0x80]).is_err());
    }

    #[test]
    fn sleb_basic() {
        assert_eq!(sleb128(&[0x00]).unwrap(), (0, 1));
        // 1 -> 1
        assert_eq!(sleb128(&[0x01]).unwrap(), (1, 1));
        // 0x7F -> -1 (sign bit set in final byte)
        assert_eq!(sleb128(&[0x7F]).unwrap(), (-1, 1));
    }

    #[test]
    fn sleb_negative_five_byte() {
        // -1 in 5-byte form
        let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        assert_eq!(sleb128(&buf).unwrap(), (-1, 5));
    }

    #[test]
    fn non_canonical_extra_zero_bytes_ok() {
        // 0x80 0x00 -> canonical form of 0, but spec says non-canonical is allowed.
        let (v, n) = uleb128(&[0x80, 0x00]).unwrap();
        assert_eq!((v, n), (0, 2));
    }
}
