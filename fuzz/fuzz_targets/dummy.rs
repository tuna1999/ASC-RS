//! DELIBERATELY BUGGY target — used to prove the fuzzer infrastructure
//! actually catches panics and persists crashes. NEVER call from
//! production code. Always compiled (no feature gate) so the
//! acceptance check can run it on a fresh tree.
//!
//! Bugs (intentional):
//! 1. A naive "uleb128-like" loop that shifts 7 bits/byte for up to
//!    10 bytes (spec max is 5) — in debug mode the shift overflow
//!    on `(i as u32) * 7` past 63 panics immediately.
//! 2. An unchecked slice read where the index is derived from the
//!    accumulator modulo `(len + 64)`. The 64-byte window past the
//!    end guarantees an OOB panic in **both** debug and release
//!    builds, so the runner reliably finds a crashing input.

use crate::FuzzOutcome;

pub fn run(input: &[u8]) -> FuzzOutcome {
    if input.is_empty() {
        return FuzzOutcome::Ok;
    }

    // Bug 1: uleb that ignores the 5-byte limit.
    let take = input.len().min(10);
    let mut acc: u64 = 0;
    for i in 0..take {
        acc |= ((input[i] & 0x7F) as u64) << (i as u32 * 7);
    }
    let _ = acc;

    // Bug 2: OOB read. `probe` lives in `[0, len + 63]`; any value
    // `>= len` panics. With non-zero high half-bits in `acc` this
    // fires for almost every non-empty input.
    let probe = (acc as usize) % (input.len() + 64);
    let _ = input[probe];

    FuzzOutcome::Ok
}
