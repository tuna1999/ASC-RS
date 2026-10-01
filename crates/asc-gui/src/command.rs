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
    /// "Used by this class" inline button: same engine as
    /// `FindReferences` (type-query on the descriptor) but the
    /// caller is bound to the active class and the resulting rows
    /// land in the bottom-panel REFERENCES tab. Powers
    /// `ASC-RS-GUI-002` (used by class X inline button).
    UsedByClass,
    /// Member-scoped find triggered by `X` on the clicked identifier.
    /// Wraps `RunSearch` with `SearchKind::Method` and the click's
    /// token + descriptor pre-filled (workflow B).
    FindUsagesOfClicked,
    /// Ctrl+D / Ctrl+Click on an `L...;` descriptor: open the
    /// resolved class. Used by the click + shortcut handlers
    /// (workflow D).
    GoToDeclaration,
    FindInDocument,
    /// Open the rename bar for the clicked symbol (`n`).
    BeginRenameSymbol,
    /// Apply a method-scoped rename and rebuild the document.
    RenameSymbol {
        new_name: String,
    },
    /// Open the line-comment bar for the last clicked line (`;`).
    BeginLineComment,
    /// Attach a `// note` to a line and rebuild the document.
    SetLineComment {
        line: usize,
        text: String,
    },
    QuickOpen,
    /// Open the Smali (disasm) listing of the active class in a tab
    /// (JADX-GUI-018, unblocked by the `asc-rs disasm` renderer).
    ShowSmali,
    /// Show the Smali listing of the clicked method only
    /// (`disasm --method`, ASC-RS-GUI-004).
    ShowSmaliMethod,
    /// One-hop callees of the clicked method (`run_callees`,
    /// ASC-RS-GUI-001) — rendered in the REFERENCES tab.
    ShowCallees,
    /// Toggle a bookmark on the active tab at the clicked line
    /// (JADX-GUI-010).
    ToggleBookmark,
    /// Jump to the active tab's bookmark line (JADX-GUI-010).
    GoToBookmark,
    /// Open a recently-used artifact (File ▸ Open recent,
    /// JADX-GUI-007).
    OpenRecent {
        path: std::path::PathBuf,
    },
    /// Open the tab-overflow picker: filterable list of open tabs
    /// (ASC-GUI-029 / JADX-GUI-004).
    ShowOpenTabs,

    // --- tabs ---
    CloseTab,
    /// Close every tab except the active one.
    CloseOthers,
    /// Close every tab.
    CloseAll,
    PinTab,
    /// Pin every preview tab. Drives JADX-GUI-011.
    PinAll,
    NextTab,
    PreviousTab,
    /// Ctrl+1..9 → jump to the n-th tab (1-indexed, clamped).
    QuickSwitch {
        n: u8,
    },

    // --- layout ---
    ToggleExplorer,
    ToggleInspector,
    ToggleBottomPanel,
    ToggleTheme,
    /// Decode Paranoid/LSParanoid strings in decompiled classes and
    /// string searches; re-decompiles the active class.
    ToggleParanoid,

    // --- tasks ---
    CancelTask,

    // --- palette ---
    ToggleCommandPalette,

    // --- clipboard ---
    /// Copy the active class's descriptor (`Lcom/foo/Bar;`) to the
    /// system clipboard. The descriptor is the canonical reference
    /// (JADX-GUI-006 / JADX-GUI-015).
    CopyDescriptor,
    /// Copy the active class's fully-qualified Java form
    /// (`com.foo.Bar`) to the system clipboard.
    CopyFqn,

    // --- navigation helpers ---
    /// Open the goto-line input (Ctrl+G). Bound by the keyboard
    /// dispatcher; the input bar lives in the editor surface.
    GotoLine,

    // --- settings ---
    /// Open the settings dialog (JADX-GUI-009 / ASC-GUI-025).
    /// Lists themes; selecting a theme is wired by the picker itself.
    OpenSettings,
}
