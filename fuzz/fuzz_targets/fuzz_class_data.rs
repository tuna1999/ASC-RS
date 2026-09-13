//! Contract: `DexView::class_data(off: u32) -> Result<ClassData, Error>`.
//! Behind `dex` feature.
//!
//! Wire format: first 4 bytes LE = the offset to feed into
//! `class_data`. Remaining bytes are the raw DEX buffer we hand to
//! `DexView::parse`. If parse fails, the target trivially returns
//! `Ok` — DexView itself isn't the unit under test here.

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::DexView;

    if input.len() < 4 {
        return FuzzOutcome::Ok;
    }
    let off = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);

    // Try to lift a view; failure means we cannot probe class_data,
    // but that's not a crash.
    if let Ok(view) = DexView::parse(input) {
        let r = view.class_data(off);
        if r.is_err() {
            return FuzzOutcome::BoundaryHit("class_data_boundary");
        }
    }

    FuzzOutcome::Ok
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
