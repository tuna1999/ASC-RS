//! Contract: `asc_apk::elf::parse_elf(input)` never panics and never
//! allocates beyond its caps; a parsed result's export list stays within
//! `MAX_SYMBOLS`. Behind `apk` feature.

use crate::FuzzOutcome;

#[cfg(feature = "apk")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    match asc_apk::elf::parse_elf(input) {
        Ok(info) => {
            assert!(info.exports.len() <= asc_apk::elf::MAX_SYMBOLS);
            FuzzOutcome::Ok
        }
        Err(_) => FuzzOutcome::BoundaryHit("elf_header"),
    }
}

#[cfg(not(feature = "apk"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
