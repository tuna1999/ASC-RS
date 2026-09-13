//! Contract: `asc_dex::DexView::parse`, `parse_at`, `logical_header_offsets`.
//! Real impl lands with the asc-dex agent. Behind `dex` feature.

use crate::FuzzOutcome;

#[cfg(feature = "dex")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_dex::DexView;

    if input.len() < 4 {
        return FuzzOutcome::Ok;
    }
    let off = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;

    // (a) Parse the buffer in full.
    if let Ok(view) = DexView::parse(input) {
        // Probe header-shaped fields: every accessor the contract
        // exposes must not panic even on a half-valid header. We
        // touch the ones we know about and let the rest be added
        // by the asc-dex agent.
        let _ = view.magic();
        let _ = view.version();
        let _ = view.string_count();
        let _ = view.type_count();
        let _ = view.proto_count();
        let _ = view.field_count();
        let _ = view.method_count();
    }

    // (b) parse_at — exercises the DEX-041 "logical header at offset"
    // entry point. Offset is attacker-controlled; we must not panic
    // when it points past the buffer.
    let _ = DexView::parse_at(input, off);

    // (c) logical_header_offsets — DEX-041 walks. Empty or single
    // result is fine; the contract must never panic.
    let _ = DexView::logical_header_offsets(input);

    FuzzOutcome::BoundaryHit("dex_header_parse")
}

#[cfg(not(feature = "dex"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
