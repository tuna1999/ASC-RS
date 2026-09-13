//! Contract: `asc_bytecode::RefWalker::new(input, units) -> RefWalker`
//! where `units = input.len() / 2`, plus `.next()` until exhausted or
//! `REF_WALKER_STEP_BUDGET` reached.
//!
//! The walker must NEVER panic on truncated / misaligned /
//! opcode-unknown inputs; every oddity is reported as an `Err`
//! variant. We catch both panics (via the process panic hook) and
//! infinite loops (via the step budget).
//!
//! Behind `bytecode` feature.
use crate::FuzzOutcome;

#[cfg(feature = "bytecode")]
use crate::REF_WALKER_STEP_BUDGET;

#[cfg(feature = "bytecode")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_bytecode::RefWalker;

    // Split: first 4 bytes = auxiliary parameter (e.g. registers
    // count); rest = the code body. The walker contract says
    // `units = input.len() / 2`, but we feed the actual buffer
    // length here so mutations in the prefix still touch the body
    // length.
    let body = if input.len() >= 4 { &input[4..] } else { &[] };
    let units = body.len() / 2;

    let mut walker = RefWalker::new(body, units);
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
                // Ignore the item contents — the contract is about
                // crash-freeness, not semantic accuracy.
            }
            Some(Err(_e)) => {
                errs += 1;
                // Errors are expected on adversarial input. If the
                // walker keeps yielding errors without terminating,
                // the step budget catches it above.
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
