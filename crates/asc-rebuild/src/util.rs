//! Small helpers shared across the rebuild pipeline.
//!
//! - MUTF-8 string-data encoding (`encode_mutf8`) for the rewritten DEX.
//! - ULEB128 encoders (we re-encode sizes + index refs in catch handlers,
//!   debug_info, and annotation/encoded_value payloads).
//! - 4-byte alignment for sections the spec mandates aligned.
//!
//! All helpers are allocation-aware and capped where they touch untrusted
//! lengths, in keeping with the crate's `no panic on untrusted input`
//! policy.

use crate::error::RebuildError;

/// Maximum bytes an in-place re-encoded `uleb128` value is allowed to
/// occupy. The DEX format restricts pool-index ulebs to 5 bytes; we copy
/// that cap when emitting pool references in uleb-encoded payloads
/// (catch handler types, debug_info names, annotation element names,
/// encoded_value indices).
pub const ULEB_MAX_BYTES: usize = 5;

/// ULEB128 cap used by `encoded_value` count + `debug_info` `parameters_size`.
/// asc-dex uses 10 bytes for the generic reader; we mirror it on the write side.
pub const ULEB_GENERIC_MAX: usize = 10;

/// Encodes `value` as a ULEB128 and appends to `out`.
///
/// Returns the number of bytes appended. Returns `Err` only when `value`
/// is so large that encoding would exceed `max_bytes` (defensive guard,
/// not normally reachable for u32-sized inputs).
#[inline]
pub fn write_uleb128_to(
    out: &mut Vec<u8>,
    value: u64,
    max_bytes: usize,
) -> Result<usize, RebuildError> {
    let start = out.len();
    let mut v = value;
    loop {
        if out.len() - start >= max_bytes {
            return Err(RebuildError::Internal("uleb128 encoding would exceed cap"));
        }
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
    Ok(out.len() - start)
}

/// Encodes an `i32` as SLEB128 and appends to `out`. Used for
/// `encoded_catch_handler` size prefix (negative ⇒ catch-all present).
#[inline]
pub fn write_sleb128_to(out: &mut Vec<u8>, value: i64) -> usize {
    let start = out.len();
    let mut v = value;
    let mut more = true;
    while more {
        let byte = (v as u8) & 0x7F;
        v >>= 7;
        if (v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0) {
            out.push(byte);
            more = false;
        } else {
            out.push(byte | 0x80);
        }
    }
    out.len() - start
}

/// Writes a string_data record preserving the ORIGINAL raw MUTF-8 bytes
/// and the original `utf16_len` — no decode/re-encode cycle (§9: never
/// introduce lossy roundtrips in the rebuild path). The only synthesized
/// bytes are the ULEB length prefix and the NUL terminator.
pub fn push_raw_string_data(out: &mut Vec<u8>, sref: &asc_dex::DexStringRef<'_>) {
    let _ = write_uleb128_to(out, sref.utf16_len as u64, ULEB_GENERIC_MAX);
    out.extend_from_slice(sref.mutf8);
    out.push(0x00);
}

/// Byte length of the string_data record [`push_raw_string_data`] would
/// write (uleb prefix + raw payload + NUL).
pub fn raw_string_data_len(sref: &asc_dex::DexStringRef<'_>) -> usize {
    let mut probe = Vec::with_capacity(5 + sref.mutf8.len());
    let _ = write_uleb128_to(&mut probe, sref.utf16_len as u64, ULEB_GENERIC_MAX);
    probe.len() + sref.mutf8.len() + 1
}

/// Pads `out` with zero bytes until its length is a multiple of 4.
#[inline]
pub fn align_to_4(out: &mut Vec<u8>) {
    while out.len() & 3 != 0 {
        out.push(0);
    }
}
