//! # asc-apk
//!
//! Read-only APK (ZIP) engine: mmap-backed central-directory parsing,
//! `classes*.dex` discovery, bounded STORED/DEFLATE extraction.
//!
//! ## Responsibility split
//!
//! - Responsible for: ZIP structure parsing (EOCD + ZIP64 + central
//!   directory), entry listing, dex-entry discovery (numeric ordering),
//!   bounded inflation with configurable output caps, in-memory variant
//!   (`ZipView`) for fuzzing/differential tests.
//! - **Not** responsible for: DEX parsing ([`asc_dex`]), parallel scan
//!   orchestration ([`asc_core`])
//!
//! ## Invariants
//!
//! - Never trusts sizes/offsets without bounds checks.
//! - STORED entries borrow directly from the mmap; no copy.
//! - DEFLATE output is capped (`InflateLimits::max_output`).
//! - APIs are synchronous, `Send + Sync`, cancellation-friendly.
//! - Never panics on untrusted input: every offset from the file is
//!   bounds-checked before use; counts bounded by remaining bytes before
//!   iteration.
//!
//! ## Quick tour
//!
//! `Apk::open(path)` mmaps the file read-only; `ZipView::parse(bytes)`
//! wraps a borrowed buffer. Both expose `dex_entries()`, `entry(name)`,
//! `entries()`, `read_entry(entry)` and return `EntryBytes<'_>`.
mod apk;
pub mod elf;
mod entry;
mod error;
mod inflate;
mod zip;

pub use crate::apk::{Apk, ZipView};
pub use crate::entry::{Compression, DexEntry, EntryBytes};
pub use crate::error::ApkError;
pub use crate::inflate::{DEFAULT_MAX_OUTPUT, InflateLimits};
