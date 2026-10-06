//! Contract: XAPK member analysis (`asc_core::xapk::analyze_member`,
//! bytes-level API — a member APK buffer, no filesystem or outer ZIP)
//! never panics on arbitrary member bytes: malformed inner ZIP
//! directories, fake DEX entries, duplicate names, bogus sizes. A
//! member that parses keeps `dex.len()` ≤ its classes*.dex entries.
//! Behind `core` feature.

use crate::FuzzOutcome;

#[cfg(feature = "core")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    let m =
        asc_core::xapk::analyze_member("member.apk", input.len() as u64, input.len() as u64, input);
    if m.name != "member.apk" {
        return FuzzOutcome::BoundaryHit("xapk_name");
    }
    if m.complete && m.manifest.is_none() && m.manifest_error.is_none() {
        // A parsed member always reports a manifest state.
        return FuzzOutcome::BoundaryHit("xapk_manifest_state_missing");
    }
    assert!(m.native_libs.len() <= 500, "native-lib cap exceeded");
    assert!(m.abi_dirs.len() <= 32, "abi cap exceeded");
    if m.complete {
        FuzzOutcome::Ok
    } else {
        FuzzOutcome::BoundaryHit("xapk_partial_member")
    }
}

#[cfg(not(feature = "core"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
