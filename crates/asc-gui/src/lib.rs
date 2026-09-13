//! # asc-gui
//!
//! eframe/egui desktop UI for ASC-RS: package/class tree, source tabs,
//! search filtering, find-refs UI, manifest display, `WorkspaceSession`
//! interactive caches. Calls asc-core / asc-manifest only — never
//! duplicates engine logic.
//!
//! ## Modules
//!
//! - [`session`] — the `WorkspaceSession` struct that holds the open
//!   APK plus per-dex lazy caches (the GUI's caching license per
//!   `reference/BEHAVIOR.md` §36).
//! - [`worker`] — background-thread plumbing for long-running engine
//!   ops (`findrefs`, `getclass`).
//! - [`selfcheck`] — `--selfcheck` headless path used by the binary
//!   and the integration test.
//! - [`app`] — the eframe `App` implementation that draws the panels.

pub mod session;
pub mod worker;
pub mod selfcheck;
pub mod app;

pub use crate::session::{
    WorkspaceSession, SessionError, SessionResult, ClassEntry, SourceTab, FindRefsHistoryEntry,
    MAX_OPEN_TABS, MAX_FINDREFS_HISTORY,
};
pub use crate::selfcheck::{run_selfcheck, SelfcheckReport};

use std::path::Path;

/// Convenience: open an APK and return a session, or return a
/// `SessionError` describing the failure.
pub fn open_session(path: impl AsRef<Path>) -> SessionResult<WorkspaceSession> {
    WorkspaceSession::open(path.as_ref())
}