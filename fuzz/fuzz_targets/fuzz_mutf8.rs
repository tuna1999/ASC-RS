//! Contract: `asc_dex::decode_mutf8_lossy(bytes, utf16_len_hint) ->
//! Cow<str>`. Behind `dex` feature.
//!
//! Lossy semantics: truncated multi-byte sequences, surrogate halves
//! and overlong encodings decode to U+FFFD — never panic. The hint is
//! fuzz-controlled too (first 4 bytes, LE).

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::decode_mutf8_lossy;

    // (a) Decode the whole input with a fuzz-controlled length hint.
    let hint = if input.len() >= 4 {
        u32::from_le_bytes([input[0], input[1], input[2], input[3]])
    } else {
        input.len() as u32
    };
    let s = decode_mutf8_lossy(input, hint);
    let boundary = s.chars().any(|c| c == '\u{FFFD}');

    // (b) Decode from a derived offset so mutating early bytes
    // shifts the window.
    let len = input.len();
    let off = if len >= 8 {
        (u32::from_le_bytes([input[4], input[5], input[6], input[7]]) as usize).min(len)
    } else {
        0
    };
    let _ = decode_mutf8_lossy(&input[off..], (len - off) as u32);

    if boundary {
        FuzzOutcome::BoundaryHit("mutf8_replacement_char")
    } else {
        FuzzOutcome::Ok
    }
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
