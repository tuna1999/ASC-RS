//! Checked readers for fixed-width DEX fields.
//!
//! Every accessor in this crate that previously did
//! `bytes[off..off+N].try_into().unwrap()` now goes through one of these
//! helpers, which performs the bounds check exactly once and returns a
//! [`crate::DexError`] on failure.
//!
//! Behavior is byte-identical to the previous implementation: the same
//! errors are produced for the same malformed inputs.

use crate::error::DexError;

/// Returns the byte at `off` if `off` is in range.
#[inline]
pub fn read_u8(bytes: &[u8], off: usize) -> Result<u8, DexError> {
    if off >= bytes.len() {
        return Err(DexError::Truncated {
            needed: off + 1,
            actual: bytes.len(),
        });
    }
    Ok(bytes[off])
}

/// Reads a little-endian `u16` at `off`.
#[inline]
pub fn read_u16(bytes: &[u8], off: usize) -> Result<u16, DexError> {
    let s = slice(bytes, off, 2)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

/// Reads a little-endian `i16` at `off`.
#[inline]
pub fn read_i16(bytes: &[u8], off: usize) -> Result<i16, DexError> {
    let s = slice(bytes, off, 2)?;
    Ok(i16::from_le_bytes([s[0], s[1]]))
}

/// Reads a little-endian `u32` at `off`.
#[inline]
pub fn read_u32(bytes: &[u8], off: usize) -> Result<u32, DexError> {
    let s = slice(bytes, off, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Returns the sub-slice `[off, off+len)` if it fits inside `bytes`.
#[inline]
pub fn slice(bytes: &[u8], off: usize, len: usize) -> Result<&[u8], DexError> {
    let end = off.checked_add(len).ok_or(DexError::Truncated {
        needed: usize::MAX,
        actual: bytes.len(),
    })?;
    if end > bytes.len() {
        return Err(DexError::Truncated {
            needed: end,
            actual: bytes.len(),
        });
    }
    Ok(&bytes[off..end])
}
