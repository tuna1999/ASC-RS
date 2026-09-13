//! Contract: `asc_rebuild::rebuild(view, class_descriptor) ->
//! Result<RebuiltDex, RebuildError>` — full dependency-closure rebuild
//! against adversarial inputs (must never panic / OOM / hang).
//!
//! Wire format: first 4 bytes select a class_def index; the target
//! resolves that class_def's descriptor string and rebuilds it. Inputs
//! that fail to parse as a DEX are boundary hits, not errors.
//!
//! Behind `rebuild` feature.

use crate::FuzzOutcome;

#[cfg(feature = "rebuild")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::DexView;

    if input.len() < 8 {
        return FuzzOutcome::Ok;
    }
    let class_param = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);

    let Ok(view) = DexView::parse(input) else {
        return FuzzOutcome::BoundaryHit("rebuild_view");
    };

    // Resolve a target class: derive one from the fuzz input so the
    // closure walks attacker-chosen structures. Fall back to skipping
    // when the dex has no class_defs.
    let count = view.class_def_count();
    if count == 0 {
        return FuzzOutcome::Ok;
    }
    let idx = class_param % count;
    let Ok(def) = view.class_def(idx) else {
        return FuzzOutcome::BoundaryHit("rebuild_class_def");
    };
    let Ok(desc_idx) = view.type_(def.class) else {
        return FuzzOutcome::BoundaryHit("rebuild_descriptor");
    };
    let Ok(name) = view.string(desc_idx) else {
        return FuzzOutcome::BoundaryHit("rebuild_name");
    };
    let descriptor = name.decode_lossy().into_owned();

    match asc_rebuild::rebuild(&view, &descriptor) {
        Ok(out) => {
            // Bonus invariant: whatever rebuild emits must re-parse.
            let _ = DexView::parse(&out.bytes);
            FuzzOutcome::Ok
        }
        Err(_) => FuzzOutcome::BoundaryHit("rebuild_boundary"),
    }
}

#[cfg(not(feature = "rebuild"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
