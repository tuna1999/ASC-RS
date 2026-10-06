//! Process-wide budget for DEX bytes held concurrently by scans.
//!
//! ## Why
//!
//! Every per-entry guard rail so far is per-ENTRY (inflate output cap,
//! MUTF-8 scan cap, …). Nothing bounded the TOTAL: the getclass/disasm
//! worker pools hold one DEX per worker, the GUI spawns one engine
//! task per user action, and each `findrefs` holds one entry at a
//! time — concurrently that is `workers × tasks × entry_size` bytes of
//! live heap, with no ceiling. A malicious multidex APK (several ~1
//! GiB declared DEX entries) could previously push the process toward
//! OOM; now it gets a structured [`CoreError::MemoryBudget`].
//!
//! ## How
//!
//! One process-global atomic counter of bytes currently reserved by
//! scans. Before reading a DEX entry, a scan reserves the entry's
//! declared uncompressed size; the RAII [`Guard`] releases it when the
//! entry's bytes are dropped. When the reservation would push the
//! total over the cap, [`acquire`] fails — no panic, no abort.
//!
//! Participants: `getclass` / `disasm` worker pools (`find_defining_dex`),
//! the `findrefs` per-entry loop and `run_callees`. Sequential
//! display-only pipelines (`listclass`, `inspect`, `cert`, `native`,
//! `resources`) hold at most one entry per run and are not budgeted
//! (known limitation — many concurrent GUI `inspect` tasks can still
//! multiply one entry each).
//!
//! A lying ZIP header can no longer under-declare an inflated entry by
//! much: `inflate_into_vec` fails with `SizeMismatch` as soon as the
//! stream produces more than the declared size, so the actual `Vec`
//! exceeds the reservation by at most one inflate chunk (64 KiB) before
//! it is dropped. The one DEX a getclass/disasm keeps as its winner
//! briefly outlives its guard and is likewise bounded by the per-entry
//! inflate cap (`asc-apk`, 1 GiB).
//!
//! The default cap is generous (2 GiB) so legitimate scans — dozens of
//! concurrently-held corpus DEXes — never hit it; it exists to convert
//! pathological inputs into an error instead of an OOM kill.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::CoreError;

/// Default total budget for concurrently-held DEX entry bytes.
pub const DEFAULT_SCAN_BUDGET: usize = 2 << 30;

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// RAII release for reserved bytes. Dropping returns them to the pool.
#[derive(Debug)]
pub struct Guard {
    reserved: usize,
}

impl Drop for Guard {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(self.reserved, Ordering::AcqRel);
    }
}

/// Reserve `bytes` of scan budget against a total cap of `cap`
/// (use [`DEFAULT_SCAN_BUDGET`] unless configured otherwise). `0` is
/// always allowed (an empty entry cannot grow the footprint).
pub fn acquire(cap: usize, bytes: usize) -> Result<Guard, CoreError> {
    // CAS loop instead of the deprecated `fetch_update` (renamed
    // `try_update` in 1.98, above our MSRV 1.93). `weak` is fine here:
    // a spurious failure just retries with the observed value.
    let mut cur = IN_FLIGHT.load(Ordering::Acquire);
    loop {
        let next = cur.saturating_add(bytes);
        if next > cap {
            return Err(CoreError::MemoryBudget(format!(
                "scan budget exceeded: reserving {bytes} more bytes would push \
                 concurrently-held DEX bytes over the {cap}-byte cap"
            )));
        }
        match IN_FLIGHT.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(Guard { reserved: bytes }),
            Err(actual) => cur = actual,
        }
    }
}

/// Bytes currently reserved by all scans in this process (for tests).
pub fn in_flight() -> usize {
    IN_FLIGHT.load(Ordering::Acquire)
}
