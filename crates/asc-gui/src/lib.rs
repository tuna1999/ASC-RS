//! # asc-gui
//!
//! eframe/egui desktop UI for ASC-RS: package/class tree, source tabs,
//! search filtering, find-refs UI, manifest display, `WorkspaceSession`
//! interactive caches. Calls asc-core / asc-manifest only — never
//! duplicates engine logic.
//!
//! ## Modules
//!
//! - [`app`] — the eframe `App` shell: task pump + command dispatch.
//! - [`command`] — the centralized command model (shortcuts → data).
//! - [`design`] — design tokens + theme ("ASC Instant Workbench").
//! - [`session`] — the `WorkspaceSession` handle: open APK plus
//!   per-dex lazy class caches (the GUI's caching license per
//!   `reference/BEHAVIOR.md` §36).
//! - [`state`] — headless controllers: documents, tabs, navigation,
//!   search.
//! - [`task`] — identity-stamped background tasks
//!   (`TaskId`/`SessionGeneration` staleness gate).
//! - [`ui`] — workspace surfaces (explorer/editor/inspector/bottom/
//!   status/palette).
//! - [`selfcheck`] — `--selfcheck` headless path used by the binary
//!   and the integration test.

use std::path::Path;

pub mod app;
pub mod command;
pub mod design;
pub mod highlight;
pub mod icons;
pub mod package_tree;
pub mod selfcheck;
pub mod semantic;
pub mod session;
pub mod source_edit;
pub mod state;
pub mod task;
#[cfg(test)]
pub(crate) mod test_zip;
pub mod ui;

pub use crate::app::AscApp;
pub use crate::selfcheck::{SelfcheckReport, run_selfcheck};
pub use crate::session::{
    ClassEntry, FindRefsHistoryEntry, MAX_FINDREFS_HISTORY, SessionError, SessionResult,
    WorkspaceSession,
};

/// Convenience: open an APK and return a session, or return a
/// `SessionError` describing the failure.
pub fn open_session(path: impl AsRef<Path>) -> SessionResult<WorkspaceSession> {
    WorkspaceSession::open(path.as_ref())
}
