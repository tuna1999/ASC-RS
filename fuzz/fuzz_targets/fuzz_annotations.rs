//! Contract: `asc_dex::annotations(&[u8])` / `annotation_set` / etc.
//! The exact entry point will be determined by the asc-dex agent —
//! the harness below uses `asc_dex::annotations` and `parse_annotations`
//! names as plausible placeholders. Behind `dex` feature.

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::annotations;

    if input.len() < 4 {
        return FuzzOutcome::Ok;
    }
    let off = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);

    // Two entry points: top-level annotations parse, and
    // annotations-at-offset on a DexView.
    let r1 = annotations(input);
    let r2 = asc_dex::DexView::parse(input).and_then(|view| view.annotations(off));

    if r1.is_err() || r2.is_err() {
        FuzzOutcome::BoundaryHit("annotations_boundary")
    } else {
        FuzzOutcome::Ok
    }
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
