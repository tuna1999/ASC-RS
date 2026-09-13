//! Contract: `asc_dex::uleb128(&[u8]) -> Result<(u64, usize), Error>`.
//! Decodes a single ULEB128 from the fuzz input. The real decoder
//! must cap continuation bytes to defeat malicious encodings; we
//! bound the loop to `ULEB_MAX_BYTES` and treat long encodings as a
//! boundary hit, never a hang.
//!
//! Behind `dex` feature.
use crate::FuzzOutcome;

#[cfg(feature = "dex")]
use crate::ULEB_MAX_BYTES;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::uleb128;

    // (a) Decode at the start of the buffer.
    let r1 = uleb128(input);

    // (b) Decode at a derived offset so mutating early bytes shifts
    // where we look. Use min(len, 16) to avoid `add` overflow.
    let len = input.len();
    let off = if len >= 4 {
        (u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize)
            .min(len.saturating_sub(1))
    } else {
        0
    };
    let r2 = uleb128(&input[off..]);

    // (c) Walk byte-by-byte: every position should decode in bounded
    // time. Long encodings get truncated to ULEB_MAX_BYTES.
    let mut boundary = false;
    let mut i = 0;
    while i < len {
        let remaining = &input[i..];
        let slice = if remaining.len() > ULEB_MAX_BYTES {
            &remaining[..ULEB_MAX_BYTES]
        } else {
            remaining
        };
        if uleb128(slice).is_err() {
            boundary = true;
        }
        i += 1;
    }

    if r1.is_err() || r2.is_err() || boundary {
        FuzzOutcome::BoundaryHit("uleb_boundary")
    } else {
        FuzzOutcome::Ok
    }
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
