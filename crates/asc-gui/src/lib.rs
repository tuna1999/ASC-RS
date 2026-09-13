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

use std::path::Path;

pub mod app;
pub mod selfcheck;
pub mod session;
pub mod worker;

pub use crate::app::AscApp;
pub use crate::selfcheck::{SelfcheckReport, run_selfcheck};
pub use crate::session::{
    ClassEntry, FindRefsHistoryEntry, MAX_FINDREFS_HISTORY, MAX_OPEN_TABS, SessionError,
    SessionResult, SourceTab, WorkspaceSession,
};

/// Convenience: open an APK and return a session, or return a
/// `SessionError` describing the failure.
pub fn open_session(path: impl AsRef<Path>) -> SessionResult<WorkspaceSession> {
    WorkspaceSession::open(path.as_ref())
}
