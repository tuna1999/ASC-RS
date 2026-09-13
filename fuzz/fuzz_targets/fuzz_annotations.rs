//! Contract: `asc_dex::DexView::{annotations_directory, annotation_set,
//! annotation_set_ref_list, annotation_item}` — lazy annotation views.
//!
//! A minimal valid DEX header is prepended to the fuzz input so the
//! view always parses; the first 4 bytes (LE) of the fuzz input select
//! the annotation offset. All four entry points must never panic.

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::DexView;

    if input.len() < 4 {
        return FuzzOutcome::Ok;
    }
    let off = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);

    let host = crate::host_dex(input);
    let Ok(view) = DexView::parse(&host) else {
        return FuzzOutcome::Ok;
    };

    let mut boundary = false;
    if let Ok(Some(_dir)) = view.annotations_directory(off) {
        // touch the parsed directory
    } else if view.annotations_directory(off).is_err() {
        boundary = true;
    }
    if view.annotation_set(off).is_err() {
        boundary = true;
    }
    if view.annotation_set_ref_list(off).is_err() {
        boundary = true;
    }
    if view.annotation_item(off).is_err() {
        boundary = true;
    }

    if boundary {
        FuzzOutcome::BoundaryHit("annotations_boundary")
    } else {
        FuzzOutcome::Ok
    }
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
