//! Fuzz target registry — one module per target. Each module exposes
//! a single `pub fn run(input: &[u8]) -> FuzzOutcome`.
//!
//! Targets calling sibling-crate APIs are gated behind the matching
//! Cargo feature (`dex`, `bytecode`, `apk`, `rebuild`, `resources`,
//! `core`). With the feature OFF, the target returns
//! `FuzzOutcome::SkippedDisabled` so `cargo build` in `fuzz/` stays
//! green while the APIs land.

pub mod dummy;
pub mod fuzz_annotations;
pub mod fuzz_apk_open;
pub mod fuzz_arsc;
pub mod fuzz_axml;
pub mod fuzz_class_data;
pub mod fuzz_code_item;
pub mod fuzz_dex041;
pub mod fuzz_dex_header;
pub mod fuzz_disasm;
pub mod fuzz_elf;
pub mod fuzz_encoded_value;
pub mod fuzz_hermes;
pub mod fuzz_inspect;
pub mod fuzz_mutf8;
pub mod fuzz_rebuild;
pub mod fuzz_ref_walker;
pub mod fuzz_signing;
pub mod fuzz_uleb128;
pub mod fuzz_xapk;
pub mod fuzz_zip_directory;
