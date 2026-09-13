//! Contract: `asc_dex::decode_mutf8_lossy(&[u8]) -> String`.
//! Behind `dex` feature.

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::decode_mutf8_lossy;

    // (a) Decode the whole input. Lossy semantics means we accept
    // truncated multi-byte sequences, surrogate halves, and overlong
    // encodings — never panic.
    let s = decode_mutf8_lossy(input);
    let boundary = s.chars().any(|c| c == '\u{FFFD}');

    // (b) Decode from a derived offset so mutating early bytes
    // shifts the window.
    let len = input.len();
    let off = if len >= 4 {
        (u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize)
            .min(len)
    } else {
        0
    };
    let _ = decode_mutf8_lossy(&input[off..]);

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
