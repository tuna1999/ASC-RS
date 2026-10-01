//! # asc-core
//!
//! Orchestration for ASC-RS: the `findrefs` and `getclass` pipelines,
//! bounded worker pool, class-name normalization, and output formatting
//! shared by `asc-cli` and `asc-gui`.
//!
//! ## Architecture (see design §17 / §24 / §25 / §29)
//!
//! - [`pipeline::run_findrefs`] — open APK once, iterate `classes*.dex`
//!   entries (with DEX-041 logical-header expansion), run
//!   `asc_query::find_refs` per view, aggregate per-DEX hits into a
//!   [`report::SearchReport`]. Malformed-DEX / parse errors are recorded
//!   and the scan continues.
//! - [`pipeline::run_getclass`] — bounded parallel scan: a small
//!   `std::thread` pool with `AtomicUsize` work cursor + `AtomicBool`
//!   "found" flag + `OnceLock` winner cell. Winner's DEX goes through
//!   [`asc_rebuild::rebuild`] → [`asc_decompile::ClassDecompiler`].
//! - [`pipeline::run_listclasses`] — enumerate every class descriptor
//!   across all DEX entries (DEX-041-aware, optional ASCII prefix
//!   filter). Mirrors the oracle's `droidasc listclass` subcommand.
//! - [`pipeline::run_disasm`] — same class-defining-DEX scan as
//!   [`pipeline::run_getclass`], but the winning DEX goes to
//!   [`asc_decompile::ClassDecompiler::disassemble`] whole: no
//!   `asc-rebuild` closure, no minimal-DEX rewrite.
//! - [`report`] — the [`report::SearchReport`] / [`report::DexResults`]
//!   / [`report::SearchError`] public types and their serde shape.
//! - [`format`] — `text` and `json` emitters used by the CLI.
//! - [`class_name`] — class-name normalization (wrapper around
//!   [`asc_decompile::normalize_class_name`]).
//!
//! ## Invariants
//!
//! - No `unwrap` / `expect` / `panic` in input-facing paths; every
//!   offset is bounds-checked, every allocation bounded.
//! - The pipelines are cancellation-friendly: workers check the
//!   "found" flag between entries and stop pulling new work.
//! - Output text format mirrors the Python oracle exactly (see
//!   `reference/BEHAVIOR.md` §2). The only documented divergences live
//!   in `crates/asc-query/GOLDEN_DIVERGENCES.md` and are `oracle ⊆ engine`.

#![deny(unsafe_op_in_unsafe_fn)]
// No `unsafe` in this crate.

pub mod budget;
pub mod cert;
pub mod class_name;
pub mod format;
pub mod inspect;
pub mod native;
mod paranoid;
pub mod pipeline;
pub mod report;
pub mod resources;
pub mod worker;

pub use crate::budget::{DEFAULT_SCAN_BUDGET, Guard};
pub use crate::cert::{CertReport, format_cert_text, run_cert};
pub use crate::class_name::normalize_class_name;
pub use crate::format::{
    JsonReport, format_getclass_json, format_getclass_text, format_listclasses_json,
    format_listclasses_text, format_search_report_json, format_search_report_text,
};
pub use crate::inspect::{InspectReport, format_inspect_text, run_inspect};
pub use crate::native::{NativeReport, format_native_text, run_native};
pub use crate::pipeline::{
    CalleesJob, CalleesResult, CoreError, DisasmJob, DisasmOptions, DisasmResult, FindRefsJob,
    FindRefsOptions, GetClassJob, GetClassOptions, GetClassResult, ListClassesJob,
    ListClassesOptions, ListClassesResult, logical_dex_name, run_callees, run_disasm, run_findrefs,
    run_getclass, run_listclasses,
};
pub use crate::report::{DexResults, RenderedMatch, SearchError, SearchErrorKind, SearchReport};
pub use crate::resources::{ResourcesQuery, ResourcesReport, format_resources_text, run_resources};
pub use crate::worker::{WorkerOutcome, WorkerPool};
pub use asc_decompile::diagnose::unbound_locals;
