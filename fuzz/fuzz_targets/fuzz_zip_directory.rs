//! Contract: `asc_apk::ZipView::parse(input)` + iterate entries
//! (names only). Memory-bounded by construction: `ZipView` borrows
//! from the input; we never inflate. Behind `apk` feature.

use crate::FuzzOutcome;

#[cfg(feature = "apk")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_apk::ZipView;

    let view = match ZipView::parse(input) {
        Ok(v) => v,
        Err(_) => return FuzzOutcome::BoundaryHit("zip_parse"),
    };

    // Iterate entries. The contract promises name-only access is
    // O(1) per entry and never inflates. We sum name lengths to
    // make sure the loop body actually executes — the fuzzer can
    // observe a meaningful difference between "0 entries" and
    // "many entries with weird names".
    let mut total: u64 = 0;
    let mut count: u32 = 0;
    for entry in view.entries() {
        let name = entry.name();
        // Skip names that would overflow our accumulator.
        total = total.saturating_add(name.len() as u64);
        count = count.saturating_add(1);
        // Hard cap: never let a single input make us visit > 1M
        // entries (defensive — adversarial central directories
        // exist). After the cap, treat as a boundary hit and bail.
        if count >= 1_000_000 {
            return FuzzOutcome::BoundaryHit("zip_entry_count_cap");
        }
    }
    let _ = total;

    // Bonus: ask the view for `classes_dex_offsets()` — the
    // discoverer used by `getclass`. Memory-bounded by construction.
    let _ = view.classes_dex_offsets();

    FuzzOutcome::Ok
}

#[cfg(not(feature = "apk"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
