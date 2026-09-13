//! Contract: `DexView::code_item(off: u32) -> Result<CodeItem, Error>`.
//! Behind `dex` feature.
//!
//! Wire format: first 4 bytes LE = offset into the raw DEX buffer
//! (which is the rest of the input).

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::DexView;

    if input.len() < 4 {
        return FuzzOutcome::Ok;
    }
    let off = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);

    if let Ok(view) = DexView::parse(input) {
        let r = view.code_item(off);
        if r.is_err() {
            return FuzzOutcome::BoundaryHit("code_item_boundary");
        }
    }

    FuzzOutcome::Ok
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
