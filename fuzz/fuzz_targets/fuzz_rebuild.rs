//! Contract: `asc_rebuild::rebuild(view, class) -> Result<Vec<u8>, Error>`.
//! `rebuild` is a wave-2 crate that depends on `asc-dex` and
//! `asc-bytecode`; today it is a stub. The harness compiles against
//! the contract shape so it can flip on at integration, but the
//! feature stays OFF by default and the binary never compiles the
//! rebuild dependency unless explicitly requested.
//!
//! Behind `rebuild` feature (which also implicitly requires `dex`).

use crate::FuzzOutcome;

#[cfg(feature = "rebuild")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::DexView;
    use asc_rebuild::rebuild;

    if input.len() < 8 {
        return FuzzOutcome::Ok;
    }
    // Wire format: first 4 bytes = class name hash (placeholder —
    // real rebuild will accept a class type_idx or L-class string).
    // Second 4 bytes = offset to feed into DexView::parse_at when
    // the input is a DEX-041 container; for single-header DEX we
    // ignore it.
    let _class_param = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let off = u32::from_le_bytes([input[4], input[5], input[6], input[7]]) as usize;

    let view = match DexView::parse_at(input, off) {
        Ok(v) => v,
        Err(_) => return FuzzOutcome::BoundaryHit("rebuild_view"),
    };

    // Rebuild on the type_idx 0 placeholder — the real rebuild will
    // accept a class descriptor. The point of this target is to
    // prove that adversarial inputs do not panic / OOM the rebuild
    // pipeline.
    match rebuild(&view, asc_dex::TypeIdx(0)) {
        Ok(_bytes) => FuzzOutcome::Ok,
        Err(_) => FuzzOutcome::BoundaryHit("rebuild_boundary"),
    }
}

#[cfg(not(feature = "rebuild"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
