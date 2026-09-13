//! Contract: `asc_bytecode::RefWalker::new(insns, insns_units) ->
//! Result<RefWalker>` iterated to exhaustion under a step budget.
//!
//! The walker must NEVER panic on truncated / misaligned /
//! unknown-opcode inputs; every oddity is reported as an `Err` variant
//! and terminates the stream. Panics are caught by the process panic
//! hook; infinite loops by the step budget.

use crate::FuzzOutcome;

#[cfg(feature = "bytecode")]
use crate::REF_WALKER_STEP_BUDGET;

#[cfg(feature = "bytecode")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_bytecode::RefWalker;

    // Split: first 4 bytes = auxiliary parameter; rest = the code body.
    // units is exactly body.len()/2 so construction cannot fail on a
    // length mismatch (defensive let-else regardless).
    let body = if input.len() >= 4 { &input[4..] } else { &[] };
    let units = u32::try_from(body.len() / 2).unwrap_or(u32::MAX);

    let Ok(mut walker) = RefWalker::new(body, units) else {
        return FuzzOutcome::BoundaryHit("ref_walker_len_mismatch");
    };
    let mut steps: u64 = 0;
    let mut hits = 0u64;
    let mut errs = 0u64;

    loop {
        if steps >= REF_WALKER_STEP_BUDGET {
            return FuzzOutcome::BoundaryHit("ref_walker_step_budget");
        }
        steps += 1;
        match walker.next() {
            None => break,
            Some(Ok(_item)) => {
                hits += 1;
                // Crash-freeness is the contract, not semantic accuracy.
            }
            Some(Err(_e)) => {
                errs += 1;
                // Errors are expected on adversarial input; the walker
                // terminates after the first one, so the loop ends.
            }
        }
    }

    let _ = (hits, errs);
    FuzzOutcome::Ok
}

#[cfg(not(feature = "bytecode"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
