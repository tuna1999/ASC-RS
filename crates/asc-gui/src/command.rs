//! Centralized command model (redesign Phase 3 groundwork / Phase 8
//! shortcuts). Draw functions report user intent as [`Command`] data;
//! [`crate::app::AscApp`] is the single dispatcher. Shortcut handling
//! lives next to dispatch — never inside draw functions.

use crate::state::NavOrigin;

/// A user intent, resolved once in the app shell.
#[derive(Debug, Clone)]
pub enum Command {
    // --- artifact ---
    OpenArtifact,
    ReloadArtifact,

    // --- navigation ---
    NavigateBack,
    NavigateForward,
    /// Open a class (preview unless `pin`), remembering the location.
    OpenClass {
        descriptor: String,
        pin: bool,
        line: Option<usize>,
        origin: NavOrigin,
    },

    // --- search ---
    GlobalSearch,
    /// Run the current search-controller inputs.
    RunSearch,
    FindReferences,
    FindInDocument,
    QuickOpen,

    // --- tabs ---
    CloseTab,
    PinTab,
    NextTab,
    PreviousTab,

    // --- layout ---
    ToggleExplorer,
    ToggleInspector,
    ToggleBottomPanel,

    // --- tasks ---
    CancelTask,

    // --- palette ---
    ToggleCommandPalette,
}
