//! Contract: `asc_dex::encoded_value(&[u8]) -> Result<(Value, usize), Error>`
//! (or whichever entry point the asc-dex agent lands — we depend on
//! the name only). Behind `dex` feature.
//!
//! Wire format: whole input is the encoded_value buffer. The first
//! byte is the value type/arg; subsequent bytes are the value body.

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::encoded_value;

    if input.is_empty() {
        return FuzzOutcome::Ok;
    }

    // Decode from offset 0 and from a derived offset so early
    // mutations shift the window.
    let r1 = encoded_value(input);
    let len = input.len();
    let off = if len >= 4 {
        (u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize).min(len)
    } else {
        0
    };
    let r2 = encoded_value(&input[off..]);

    if r1.is_err() || r2.is_err() {
        FuzzOutcome::BoundaryHit("encoded_value_boundary")
    } else {
        FuzzOutcome::Ok
    }
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
