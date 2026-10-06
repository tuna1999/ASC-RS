//! Contract: the Hermes v96 string-table extractor
//! (`asc_core::hermes::extract_strings`, bytes-level API) never panics
//! on arbitrary bundles — arbitrary header counts, string-kind RLE,
//! small/overflow table entries, UTF-16 extents, truncated tables —
//! and bounds its output by the option limit. Behind `core` feature.

use crate::FuzzOutcome;

#[cfg(feature = "core")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_core::hermes::{extract_strings, HermesOptions, MAX_STRINGS};

    let opts = HermesOptions {
        pattern: None,
        limit: MAX_STRINGS,
    };
    match extract_strings(input, &opts, MAX_STRINGS) {
        Ok((strings, _truncated)) => {
            assert!(strings.len() <= MAX_STRINGS, "limit exceeded");
            FuzzOutcome::Ok
        }
        Err(_) => FuzzOutcome::BoundaryHit("hermes_reject"),
    }
}

#[cfg(not(feature = "core"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
