//! Contract: `asc_dex::DexView::parse_at` + `logical_header_offsets`
//! exercised specifically against a two-header (DEX 041) layout.
//! Behind `dex` feature.
//!
//! Wire format: first 4 bytes LE = candidate offset of the second
//! logical header; remaining bytes are the raw DEX-041 physical
//! buffer. We also try `parse_at` with offsets 0 and the candidate.

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::DexView;

    if input.len() < 4 {
        return FuzzOutcome::Ok;
    }
    let candidate = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;

    // Try the candidate.
    let r1 = DexView::parse_at(input, candidate);
    // Try offset 0.
    let r2 = DexView::parse_at(input, 0);

    // Try enumerating logical headers — DEX 041 returns multiple
    // entries; older formats return a single offset.
    let offs = DexView::logical_header_offsets(input);
    if let Ok(offsets) = offs {
        if offsets.len() > 1 {
            return FuzzOutcome::BoundaryHit("dex041_multi_logical_header");
        }
    }

    if r1.is_err() || r2.is_err() {
        FuzzOutcome::BoundaryHit("dex041_parse_at_boundary")
    } else {
        FuzzOutcome::Ok
    }
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
