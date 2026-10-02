//! Contract: the four `asc_core` entry points that take a *path*
//! (`run_inspect`, `run_native`, `run_cert`, `run_resources`) never
//! panic on an arbitrary file — they either return a report or `Err`.
//! `run_*` is IO-bound (mmap), so the input is staged into a uniquely
//! named temp file that is deleted on drop. Behind `core` feature.

use crate::FuzzOutcome;

#[cfg(feature = "core")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_core::{ResourcesQuery, run_cert, run_inspect, run_native, run_resources};

    let staged = match crate::stage_temp_file("inspect", input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fuzz_inspect: cannot stage temp file: {e}");
            return FuzzOutcome::BoundaryHit("inspect_temp_file_io");
        }
    };
    let path = &staged.0;
    let result = (|| {
        let mut parsed = false;
        if let Ok(r) = run_inspect(path) {
            parsed = true;
            assert_eq!(r.entries.len(), r.entry_count, "inspect entry inventory");
            for e in &r.entries {
                assert!(e.sample_bytes <= (1 << 20), "sample cap exceeded");
            }
        }
        if let Ok(r) = run_native(path) {
            parsed = true;
            assert_eq!(r.direct_count + r.virtual_count, r.methods.len());
        }
        if let Ok(r) = run_cert(path) {
            parsed = true;
            assert!(r.schemes.iter().all(|s| s.signers.len() <= 16));
        }
        if let Ok(r) = run_resources(
            path,
            // Query = "no filter": every id, no substring, bounded hits.
            &ResourcesQuery {
                id: None,
                pattern: None,
                limit: 0,
            },
        ) {
            parsed = true;
            // No id and no pattern ⇒ nothing can match.
            assert_eq!(
                (r.total_matches, r.hits.len()),
                (0, 0),
                "unfiltered query matched something"
            );
        }
        if parsed {
            FuzzOutcome::Ok
        } else {
            FuzzOutcome::BoundaryHit("inspect_reject")
        }
    })();
    result
}

#[cfg(not(feature = "core"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
