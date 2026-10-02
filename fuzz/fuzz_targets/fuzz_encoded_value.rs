//! Contract: `asc_dex::DexView::encoded_value/encoded_array/
//! encoded_annotation(bytes, off)` — fuzzing the encoded-value state
//! machine without needing a fully valid DEX around it.
//!
//! Wire format: a minimal valid DEX header (all pools empty) is
//! prepended once, the whole fuzz input is appended after it, and the
//! fuzz input's first 4 bytes (LE) select the value offset. The header
//! guarantees `DexView::parse` succeeds, so mutations reach deep into
//! the encoded_value / encoded_array / encoded_annotation decoders.

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::DexView;

    if input.len() < 4 {
        return FuzzOutcome::Ok;
    }

    let host = crate::host_dex(input);
    let Ok(view) = DexView::parse(&host) else {
        return FuzzOutcome::Ok;
    };

    let off =
        (u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize).min(host.len() - 1);
    let mut boundary = false;

    if view.encoded_value(&host, off).is_err() {
        boundary = true;
    }
    if view.encoded_array(&host, off).is_err() {
        boundary = true;
    }
    if view.encoded_annotation(&host, off).is_err() {
        boundary = true;
    }

    if boundary {
        FuzzOutcome::BoundaryHit("encoded_value_boundary")
    } else {
        FuzzOutcome::Ok
    }
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
