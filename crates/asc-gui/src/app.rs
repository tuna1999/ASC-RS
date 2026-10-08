//! eframe shell: owns workspace state, pumps background tasks, and
//! dispatches commands. All rendering lives in [`crate::ui`]; all
//! mutation logic lives in [`crate::state`] controllers driven by
//! [`Self::apply_task`] and [`Self::dispatch`].
//!
//! Determinism contract (docs/gui-architecture.md §2):
//! - Every engine result arrives as an identity-stamped task
//!   ([`crate::task`]); stale results are dropped before mutating
//!   anything.
//! - Tab activation is driven by tab state, not by completion order:
//!   the visible tab is whatever the user last opened; results that
//!   land for other tabs only fill the document cache.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;

use crate::command::Command;
use crate::design;
use crate::package_tree::PackageTree;
use crate::session::WorkspaceSession;
use crate::state::{
    Document, DocumentCache, NavOrigin, NavigationHistory, NavigationLocation, SearchController,
    SearchKind, SearchResults, TabController,
};
use crate::task::{CompletedTask, LoadedArtifact, TaskId, TaskKind, TaskManager, TaskOutcome};
use crate::ui::bottom_panel::BottomTab;
use crate::ui::palette::PaletteMode;

mod render;

/// One-line status message with sentiment.
pub(crate) struct StatusLine {
    pub(crate) text: String,
    pub(crate) ok: bool,
}

/// Clicked-identifier selection (rename/comment analysis aid): the
/// token, its enclosing method's byte range, and code-state
/// occurrences — valid for one document version only.
///
/// `descriptor` is the *document key* the click happened in (anti-stale
/// identity; audit F1). The semantic meaning of the click — what the
/// identifier *is* and which class declares it — lives in `resolved`
/// (audit F2) and is never re-derived from the document owner.
#[derive(Debug, Clone)]
pub(crate) struct SymbolSelection {
    pub(crate) descriptor: String,
    pub(crate) token: String,
    /// Byte range of the enclosing method/block (rename scope).
    pub(crate) method: (usize, usize),
    pub(crate) occurrences: Vec<(usize, usize)>,
    /// Semantic identity of the clicked identifier, when the view could
    /// prove it. `Unknown`/`None` identifiers must not dispatch member
    /// actions.
    pub(crate) resolved: Option<crate::semantic::ResolvedSymbol>,
}

/// Main application shell.
pub struct AscApp {
    // --- session / engine ---
    pub(crate) session: Option<WorkspaceSession>,
    pub(crate) tree: PackageTree,
    pub(crate) dex_counts: Vec<(String, usize)>,
    pub(crate) manifest: Option<asc_manifest::ManifestInfo>,
    /// Manifest decode failure, when the APK *has* a manifest we could not
    /// parse. `None` with `manifest: None` = genuinely no manifest.
    pub(crate) manifest_error: Option<String>,
    pub(crate) tasks: TaskManager,
    pub(crate) loading_artifact: bool,
    /// Latest open-task id (only its result may become the session).
    pub(crate) pending_open: Option<TaskId>,

    // --- state controllers ---
    pub(crate) documents: DocumentCache,
    pub(crate) tabs: TabController,
    pub(crate) nav: NavigationHistory,
    pub(crate) search: SearchController,

    // --- view state ---
    pub(crate) tree_filter: String,
    pub(crate) expanded: BTreeSet<String>,
    pub(crate) selected_class: Option<String>,
    pub(crate) active_doc: Option<Arc<Document>>,
    pub(crate) pending_scroll: Option<usize>,
    pub(crate) show_explorer: bool,
    pub(crate) show_inspector: bool,
    pub(crate) show_bottom: bool,
    pub(crate) show_find: bool,
    pub(crate) find_input: String,
    pub(crate) find_matches: Vec<usize>,
    pub(crate) find_index: Option<usize>,
    /// Descriptor of the document the current `find_matches` were
    /// computed for. Identity key: when the active document changes,
    /// [`Self::reconcile_find_to_document`] rebinds (F2) so results
    /// never belong to another document.
    pub(crate) find_for_descriptor: Option<String>,
    pub(crate) show_rename: bool,
    pub(crate) rename_input: String,
    /// Document key + 0-based line the pending line-comment targets.
    /// The key is the document identity the bar was armed for (audit
    /// F1): a document switch while the bar is open must not append
    /// the note to the new document at the old line.
    pub(crate) comment_target: Option<(String, usize)>,
    pub(crate) comment_input: String,
    /// Document key + 0-based line of the last code click. A line
    /// number is only meaningful against the document it was clicked
    /// in (audit F1), so the anchor carries its document identity.
    pub(crate) last_click: Option<(String, usize)>,
    /// Identifier selection from the last code click (rename anchor).
    /// [`SymbolSelection::descriptor`] is the *document key* the click
    /// happened in — both the validity identity and the source of the
    /// class an action resolves to. Read it through
    /// [`Self::active_symbol_sel`].
    pub(crate) symbol_sel: Option<SymbolSelection>,
    /// Pointer over the code surface this frame (bare-key scope).
    pub(crate) code_hovered: bool,
    pub(crate) bottom_tab: BottomTab,
    /// True once the user has taken manual control of the bottom panel
    /// since the current search/references request was issued.
    ///
    /// Results must not steal that choice (AGENTS.md "GUI flow"): a
    /// result still stores its data, it just does not move the panel or
    /// select a tab. Reset when a new request is issued.
    pub(crate) bottom_focus_pinned: bool,
    pub(crate) focus_search: bool,
    pub(crate) palette: Option<PaletteMode>,
    pub(crate) focus_palette: bool,
    pub(crate) palette_input: String,
    /// Outline type-ahead filter (`STRUCTURE` panel). Empty string
    /// shows every outline entry; non-empty substring filters
    /// case-insensitively against `doc.outline[*].text`.
    pub(crate) outline_filter: String,
    /// Most-recent text written via the copy-to-clipboard surface
    /// (JADX-GUI-006, JADX-GUI-015). Production dispatches this to
    /// `egui::Context::copy_text`; the field exists so unit tests
    /// can observe the write without an active GUI.
    pub(crate) last_clipboard: Option<String>,
    /// Ctrl+G goto-line input: shows when `Some(_)`. `pending_scroll`
    /// is set when the user presses Enter on a valid 1-indexed line.
    pub(crate) goto_line_input: Option<String>,
    /// Settings dialog visibility (JADX-GUI-009).
    pub(crate) show_settings: bool,
    /// Open-tabs picker visibility (ASC-GUI-029 / JADX-GUI-004).
    pub(crate) show_open_tabs: bool,
    /// Filter text for the open-tabs picker.
    pub(crate) open_tabs_filter: String,
    /// Decode Paranoid strings (`GetClassOptions::paranoid` /
    /// `FindRefsOptions::paranoid`) for new decompiles and searches.
    pub(crate) paranoid: bool,
    pub(crate) status: Option<StatusLine>,
    pub(crate) last_error: Option<String>,
    pub(crate) commands: Vec<Command>,
    pub(crate) initial_path: Option<PathBuf>,
    /// Desired window title (pushed to the viewport on change).
    pub(crate) window_title: String,
    /// Selected row in the open palette.
    pub(crate) palette_sel: usize,
    /// Last "references to selected class" report (Analysis menu) —
    /// shown in the REFERENCES bottom tab.
    pub(crate) references: Option<SearchResults>,
    /// Jadx-style workspace icons (folders / source files), uploaded
    /// once on the first frame that has a context.
    pub(crate) icons: Option<crate::icons::Icons>,
}

impl AscApp {
    /// Create the app. The window paints immediately; `initial_path`
    /// (CLI argument) is opened as a background task on the first
    /// frame — no synchronous engine work blocks startup.
    pub fn new(initial_path: Option<PathBuf>) -> Self {
        Self {
            session: None,
            tree: PackageTree::build(Vec::new()),
            dex_counts: Vec::new(),
            manifest: None,
            manifest_error: None,
            tasks: TaskManager::new(),
            loading_artifact: false,
            pending_open: None,
            documents: DocumentCache::default(),
            tabs: TabController::default(),
            nav: NavigationHistory::default(),
            search: SearchController::default(),
            tree_filter: String::new(),
            expanded: BTreeSet::new(),
            selected_class: None,
            active_doc: None,
            pending_scroll: None,
            show_explorer: true,
            show_inspector: true,
            show_bottom: true,
            show_find: false,
            find_input: String::new(),
            find_matches: Vec::new(),
            find_index: None,
            find_for_descriptor: None,
            show_rename: false,
            rename_input: String::new(),
            comment_target: None,
            comment_input: String::new(),
            last_click: None,
            symbol_sel: None,
            code_hovered: false,
            bottom_tab: BottomTab::Results,
            bottom_focus_pinned: false,
            focus_search: false,
            palette: None,
            focus_palette: false,
            palette_input: String::new(),
            outline_filter: String::new(),
            last_clipboard: None,
            goto_line_input: None,
            show_settings: false,
            show_open_tabs: false,
            open_tabs_filter: String::new(),
            paranoid: false,
            status: None,
            last_error: None,
            commands: Vec::new(),
            initial_path,
            window_title: "asc-gui".to_string(),
            palette_sel: 0,
            references: None,
            icons: None,
        }
    }

    /// Test-only: construct around an already-open session,
    /// performing the class enumeration synchronously (what the
    /// LoadArtifact task does on a worker thread).
    #[cfg(test)]
    fn from_session(session: WorkspaceSession) -> Self {
        let mut app = Self::new(None);
        let list = session.all_classes().unwrap_or_default();
        let dex_counts = session.class_counts_per_dex();
        let (manifest, manifest_error) = crate::task::load_manifest(session.path());
        app.manifest = manifest.clone();
        app.manifest_error = manifest_error.clone();
        app.apply_artifact(LoadedArtifact {
            dex_counts,
            session,
            manifest,
            manifest_error,
            classes: list.classes,
            warnings: list.warnings,
        });
        app
    }

    /// Queue a command for dispatch at the end of this frame.
    pub(crate) fn queue(&mut self, cmd: Command) {
        self.commands.push(cmd);
    }

    pub(crate) fn set_status(&mut self, text: impl Into<String>, ok: bool) {
        self.status = Some(StatusLine {
            text: text.into(),
            ok,
        });
    }

    // ----------------------------------------------------------------
    // click-derived state (audit F1)
    // ----------------------------------------------------------------

    /// The clicked-identifier selection, but only while it still
    /// belongs to the document on screen.
    ///
    /// A [`SymbolSelection`] is captured from one document version:
    /// its descriptor is that document's key, its `method` range and
    /// `occurrences` are byte offsets into that document's source.
    /// Acting on it after a document switch would dispatch the
    /// previous document's descriptor and token (audit F1), so every
    /// consumer reads it through here.
    pub(crate) fn active_symbol_sel(&self) -> Option<&SymbolSelection> {
        let sel = self.symbol_sel.as_ref()?;
        let doc = self.active_doc.as_ref()?;
        (sel.descriptor == doc.descriptor).then_some(sel)
    }

    /// The clicked line, but only while the click belongs to the
    /// document on screen (audit F1: a bookmark or comment must never
    /// land on another document's line number).
    pub(crate) fn clicked_line(&self) -> Option<usize> {
        let (doc, line) = self.last_click.as_ref()?;
        (Some(doc.as_str()) == self.active_doc.as_ref().map(|d| d.descriptor.as_str()))
            .then_some(*line)
    }

    /// The (declaring class, method name) the active selection resolved
    /// to, but only when it actually *is* a method with a known declaring
    /// class (audit F2).
    ///
    /// The document on screen is never used as the target class: a
    /// `B.foo()` click in A's document resolves to `B` when the view
    /// proves it (Smali `invoke-*`), and is refused (rather than
    /// masqueraded as `A::foo`) when it cannot be proven.
    pub(crate) fn resolved_method(&self) -> Option<(String, String)> {
        let sel = self.active_symbol_sel()?;
        let r = sel.resolved.as_ref()?;
        if r.kind != crate::semantic::SymbolKind::Method {
            return None;
        }
        let owner = r.owner.as_ref()?;
        Some((owner.clone(), r.name.clone()))
    }

    /// Why the method-scoped actions (ShowSmaliMethod / ShowCallees) and
    /// the method-find are currently unavailable, or `None` when a method
    /// is resolved and may proceed.
    pub(crate) fn method_action_block(&self) -> Option<&'static str> {
        match self.active_symbol_sel() {
            None => Some("click a method identifier first"),
            Some(sel) => match &sel.resolved {
                None => Some("selected identifier is not a method"),
                Some(r) if r.kind != crate::semantic::SymbolKind::Method => {
                    Some("selected identifier is not a method")
                }
                Some(r) if r.owner.is_none() => {
                    Some("method's declaring class is not resolvable in this view")
                }
                _ => None,
            },
        }
    }

    /// The key of the document on screen, when there is one.
    fn active_doc_key(&self) -> Option<&str> {
        self.active_doc.as_ref().map(|d| d.descriptor.as_str())
    }

    // ----------------------------------------------------------------
    // artifact lifecycle
    // ----------------------------------------------------------------

    /// Open (or reload) an APK as a background task. The previous
    /// open is superseded; only the newest open result applies.
    pub(crate) fn open_path(&mut self, path: &std::path::Path, ctx: &egui::Context) {
        let id = self.tasks.spawn_load(path, ctx);
        self.pending_open = Some(id);
        self.loading_artifact = true;
        // Surface a "running" hint at the status bar so the user sees
        // the load is in progress even before the task lands
        // (ASC-GUI-035: per-DEX load progress feedback — at minimum
        // the artifact-level status, since per-DEX progress lives on
        // the worker thread and is not observable from the UI loop).
        self.set_status(format!("opening {}…", path.display()), true);
    }

    /// Install a successfully loaded artifact as the current session.
    fn apply_artifact(&mut self, artifact: LoadedArtifact) {
        // Invalidate every in-flight result from the old session.
        self.tasks.bump_generation();
        let title = artifact
            .session
            .path()
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.session = Some(artifact.session);
        self.tree = PackageTree::build(artifact.classes);
        self.dex_counts = artifact.dex_counts;
        self.manifest = artifact.manifest;
        self.manifest_error = artifact.manifest_error;
        self.documents = DocumentCache::default();
        self.tabs.clear();
        self.nav = NavigationHistory::default();
        self.search.clear_results();
        self.references = None;
        self.bottom_focus_pinned = false;
        self.selected_class = None;
        self.active_doc = None;
        self.pending_scroll = None;
        self.symbol_sel = None;
        self.last_click = None;
        self.comment_target = None;
        // Session swap: drop find results that belonged to the old
        // artifact's documents (F2).
        self.find_matches.clear();
        self.find_index = None;
        self.find_for_descriptor = None;
        self.show_open_tabs = false;
        self.open_tabs_filter.clear();
        self.show_rename = false;
        self.loading_artifact = false;
        self.window_title = if title.is_empty() {
            "asc-gui".to_string()
        } else {
            format!("asc-gui — {title}")
        };
        // Record the artifact for File ▸ Open recent (JADX-GUI-007).
        // `tabs.clear()` above already reset tabs but keeps recents.
        if let Some(session) = &self.session {
            self.tabs.push_recent_artifact(session.path().to_path_buf());
        }
        if !artifact.warnings.is_empty() {
            let msg = artifact.warnings.join("; ");
            self.set_status(format!("class list partial: {msg}"), false);
        }
    }

    /// Replace the active document's source (rename / comment edit):
    /// rebuild derived artifacts, refresh the cache, and drop the
    /// symbol selection (its byte offsets are stale after the edit).
    fn replace_active_document(&mut self, descriptor: String, dex_name: String, source: String) {
        let doc = Arc::new(Document::new(descriptor, dex_name, source));
        self.active_doc = Some(doc.clone());
        self.documents.put(doc);
        self.symbol_sel = None;
        // The source changed under the same descriptor, so cached find
        // match offsets are stale (F2): drop them and defer a rebind to
        // the next reconciliation.
        self.find_matches.clear();
        self.find_index = None;
        self.find_for_descriptor = None;
    }

    /// Apply a method-scoped rename of the selected symbol (F25).
    fn apply_symbol_rename(&mut self, new_name: &str) {
        let Some(sel) = self.symbol_sel.clone() else {
            return;
        };
        if !crate::source_edit::is_identifier(new_name) {
            self.last_error = Some(format!("'{new_name}' is not a valid identifier"));
            return;
        }
        let Some(doc) = self.active_doc.clone() else {
            return;
        };
        if doc.descriptor != sel.descriptor {
            // The selection was captured in another document (audit F1):
            // its byte range does not belong to this source.
            self.set_status("rename: the selection belongs to another document", false);
            return;
        }
        if let Some(src) = crate::source_edit::rename_in_range(
            &doc.source,
            sel.method.0,
            sel.method.1,
            &sel.token,
            new_name,
        ) {
            self.replace_active_document(doc.descriptor.clone(), doc.dex_name.clone(), src);
            self.set_status(
                format!("renamed {} → {new_name} (in method)", sel.token),
                true,
            );
        }
    }

    /// Append a `// note` to a source line and rebuild (F26).
    fn apply_line_comment(&mut self, line: usize, text: &str) {
        let Some(doc) = self.active_doc.clone() else {
            return;
        };
        let Some(line_start) = doc
            .line(line)
            .map(|l| l.as_ptr() as usize - doc.source.as_ptr() as usize)
        else {
            return;
        };
        let src = crate::source_edit::append_line_comment(&doc.source, line_start, text);
        self.replace_active_document(doc.descriptor.clone(), doc.dex_name.clone(), src);
        self.set_status(format!("commented line {}", line + 1), true);
    }

    // ----------------------------------------------------------------
    // navigation / tabs
    // ----------------------------------------------------------------

    /// Open a class as preview (or pinned), decompiling on demand.
    pub(crate) fn navigate_to(
        &mut self,
        descriptor: &str,
        pin: bool,
        line: Option<usize>,
        origin: NavOrigin,
        ctx: &egui::Context,
    ) {
        // A view key (`L…;#smali…`) identifies a tab, not a class: it must
        // not taint the class selection, or a later class-scoped action
        // would fall back to a synthetic descriptor (audit F2).
        if crate::state::tabs::class_of_tab_key(descriptor) == Some(descriptor) {
            self.selected_class = Some(descriptor.to_string());
        }
        if pin {
            self.tabs.open_pinned(descriptor);
        } else {
            self.tabs.open_preview(descriptor);
        }
        if origin != NavOrigin::History {
            self.nav.push(NavigationLocation {
                descriptor: descriptor.to_string(),
                line,
                origin,
            });
        }
        if self.documents.contains(descriptor) {
            self.active_doc = self.documents.get(descriptor);
            // F1: the tab may have been freshly recreated as `Loading`
            // by `open_preview`/`open_pinned` (e.g. reopened right after
            // close while the document is still cached). With a cached
            // doc no worker is spawned, so restore `Ready` from the
            // document itself — otherwise the spinner would persist
            // forever. A cached doc only exists after a successful
            // decompile, so this is never a false `Ready`.
            self.tabs.set_ready(
                descriptor,
                self.active_doc.as_ref().map(|d| d.dex_name.clone()),
            );
        } else {
            self.active_doc = None;
            // Re-issue the engine job that produces this *view*: a class
            // tab is a getclass job, a `L…;#smali…` view key a disasm job.
            // `spawn_decompile` alone would be a silent no-op for a view
            // key and leave the recreated `Loading` tab with no worker —
            // navigation back to an evicted Smali view would then hang the
            // tab on Loading forever (audit F1).
            self.reload_document(descriptor, ctx);
        }
        // Rebind find results to the (possibly changed) active document
        // (F2) before the navigation scroll target is set below, so the
        // rebind's own scroll hint is overridden by the explicit target.
        self.reconcile_find_to_document();
        // Scroll target persists until the document is visible.
        self.pending_scroll = Some(line.unwrap_or(0));
    }

    /// Spawn a decompile task for `descriptor` (deduplicated).
    ///
    /// Only a class descriptor maps to a `getclass` job: a view key
    /// (`L…;#smali…`, produced by [`TaskManager::spawn_disasm`]) or a text
    /// sentinel must not be sent to the engine. One guard at the single
    /// decompile entry point covers every caller (audit F2).
    pub(crate) fn spawn_decompile(&mut self, descriptor: &str, ctx: &egui::Context) {
        if crate::state::tabs::class_of_tab_key(descriptor) != Some(descriptor) {
            return;
        }
        self.tasks.spawn_decompile(
            self.session.as_ref().expect("session").path(),
            descriptor,
            self.paranoid,
            ctx,
        );
    }

    /// Re-issue the engine job that produces the document for `key`
    /// (audit F2): a Smali view reloads as a *disasm* job — whole class, or
    /// the one method it was scoped to — a class tab as a getclass job, and
    /// any other key (a text tab) has no engine job at all.
    ///
    /// Every spawn is deduplicated by [`TaskManager`], so calling this
    /// while the same job is already in flight is a no-op. The view key is
    /// decoded once, through [`crate::state::tabs::smali_view_of`].
    pub(crate) fn reload_document(&mut self, key: &str, ctx: &egui::Context) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let apk = session.path().to_path_buf();
        match crate::state::tabs::smali_view_of(key) {
            Some((class, method)) => {
                self.tasks.spawn_disasm(&apk, class, method, ctx);
            }
            // A view key is never a class descriptor; `spawn_decompile`
            // rejects everything that is not exactly a class descriptor.
            None => self.spawn_decompile(key, ctx),
        }
    }

    /// Class identity of the current focus, for every class-scoped
    /// action (references, copy descriptor/FQN, Smali, strings, …).
    ///
    /// Tab keys are *view* identities — `L…;#smali` / `L…;#smali#<m>` for
    /// Smali listings, a non-`L…;` sentinel for a text tab — so a
    /// class-scoped command must never use `tabs.active_descriptor()`
    /// raw (audit F2: the synthetic key reached the engine and produced a
    /// false-negative search). Resolution: the active tab's owning class
    /// when the tab is class-shaped, else the tree selection.
    pub(crate) fn active_class_descriptor(&self) -> Option<&str> {
        self.tabs
            .active_descriptor()
            .and_then(crate::state::tabs::class_of_tab_key)
            .or(self.selected_class.as_deref())
    }

    fn nav_back(&mut self, ctx: &egui::Context) {
        if let Some(loc) = self.nav.back() {
            let (d, line) = (loc.descriptor, loc.line);
            self.navigate_to(&d, false, line, NavOrigin::History, ctx);
        }
    }

    fn nav_forward(&mut self, ctx: &egui::Context) {
        if let Some(loc) = self.nav.forward() {
            let (d, line) = (loc.descriptor, loc.line);
            self.navigate_to(&d, false, line, NavOrigin::History, ctx);
        }
    }

    /// Close a tab; documents stay cached (cheap) until evicted.
    pub(crate) fn close_tab(&mut self, descriptor: &str) {
        let was_active = self.tabs.active_descriptor() == Some(descriptor);
        let next = self.tabs.close(descriptor);
        if !was_active {
            // A background tab closed: the visible document is unchanged.
            return;
        }
        match next {
            Some(next) if self.documents.contains(&next) => {
                self.active_doc = self.documents.get(&next);
                self.pending_scroll = Some(0);
            }
            _ => self.active_doc = None,
        }
    }

    // ----------------------------------------------------------------
    // find in document
    // ----------------------------------------------------------------

    /// Recompute find matches over the active document.
    pub(crate) fn recompute_find_matches(&mut self) {
        self.find_matches.clear();
        self.find_index = None;
        let Some(doc) = self.active_doc.clone() else {
            self.find_for_descriptor = None;
            return;
        };
        self.find_for_descriptor = Some(doc.descriptor.clone());
        let needle = self.find_input.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return;
        }
        // One reused buffer for the lowercased line: a scan over a
        // 500 KiB source is tens of thousands of lines, and a fresh
        // `String` per line is pure allocator churn (audit F3). Same
        // comparison as before — `make_ascii_lowercase` leaves
        // non-ASCII bytes untouched, exactly like `to_ascii_lowercase`.
        let mut lowered = String::new();
        for idx in 0..doc.line_count() {
            if let Some(line) = doc.line(idx) {
                lowered.clear();
                lowered.push_str(line);
                lowered.make_ascii_lowercase();
                if lowered.contains(&needle) {
                    self.find_matches.push(idx);
                }
            }
        }
        self.find_step(true);
    }

    /// Keep find results bound to the active document (F2).
    ///
    /// When the active document's identity differs from the one the
    /// cached [`Self::find_matches`] were computed for, recompute them
    /// against the current document. Preserves [`Self::pending_scroll`]
    /// so a rebind never overrides an explicit navigation target.
    ///
    /// Nothing reads the matches while the bar is closed (`draw_code`
    /// tints and `nav_or_find_line` are both gated on `show_find`, and
    /// opening the bar recomputes — `Command::FindInDocument`), so a
    /// hidden bar only drops the binding instead of rescanning the whole
    /// document on every switch (audit F3).
    pub(crate) fn reconcile_find_to_document(&mut self) {
        if !self.show_find {
            self.find_for_descriptor = None;
            return;
        }
        let Some(doc) = self.active_doc.clone() else {
            self.find_for_descriptor = None;
            self.find_matches.clear();
            self.find_index = None;
            return;
        };
        if self.find_for_descriptor.as_deref() == Some(doc.descriptor.as_str()) {
            return;
        }
        let saved_scroll = self.pending_scroll;
        self.recompute_find_matches();
        self.pending_scroll = saved_scroll;
    }

    pub(crate) fn find_step(&mut self, forward: bool) {
        if self.find_matches.is_empty() {
            self.find_index = None;
            return;
        }
        let next = match self.find_index {
            None => 0,
            Some(i) if forward => (i + 1) % self.find_matches.len(),
            Some(i) => i.wrapping_sub(1).min(self.find_matches.len() - 1),
        };
        self.find_index = Some(next);
        self.pending_scroll = Some(self.find_matches[next]);
    }

    /// Line to highlight (current find match or last nav target).
    pub(crate) fn nav_or_find_line(&self) -> Option<usize> {
        if self.show_find {
            self.find_index
                .and_then(|i| self.find_matches.get(i))
                .copied()
        } else {
            None
        }
    }

    // ----------------------------------------------------------------
    // task application — the single place results mutate state
    // ----------------------------------------------------------------

    fn poll_workers(&mut self, ctx: &egui::Context) {
        let completed = self.tasks.poll();
        let any = !completed.is_empty();
        for task in completed {
            self.apply_task(task);
        }
        if any {
            ctx.request_repaint();
        } else if self.tasks.has_in_flight() {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
    }

    /// Select the bottom tab for an arriving result, unless the user has
    /// taken manual control of the bottom panel since the request was
    /// issued. The data is always stored; only the focus moves.
    fn focus_bottom_tab(&mut self, tab: BottomTab) {
        if !self.bottom_focus_pinned {
            self.bottom_tab = tab;
        }
    }

    /// As [`Self::focus_bottom_tab`], and also open the panel.
    fn reveal_bottom_tab(&mut self, tab: BottomTab) {
        if !self.bottom_focus_pinned {
            self.show_bottom = true;
            self.bottom_tab = tab;
        }
    }

    /// The user has just chosen the bottom panel's tab or visibility
    /// themselves; results of any request already in flight must leave it
    /// alone.
    pub(crate) fn pin_bottom_focus(&mut self) {
        self.bottom_focus_pinned = true;
    }

    /// A new request is being issued: results may move the panel again.
    fn unpin_bottom_focus(&mut self) {
        self.bottom_focus_pinned = false;
    }

    fn apply_task(&mut self, task: CompletedTask) {
        if task.stale {
            return;
        }
        match (task.kind, task.outcome) {
            (TaskKind::LoadArtifact, TaskOutcome::Loaded(artifact)) => {
                if self.pending_open == Some(task.id) {
                    self.pending_open = None;
                    self.apply_artifact(*artifact);
                }
                // Older open results are ignored: superseded by a
                // newer open request.
            }
            (TaskKind::LoadArtifact, TaskOutcome::Failed(e)) => {
                if self.pending_open == Some(task.id) {
                    self.pending_open = None;
                    self.loading_artifact = false;
                    self.last_error = Some(format!("open: {e}"));
                    self.set_status(format!("open failed: {e}"), false);
                }
            }
            (TaskKind::DecompileClass, TaskOutcome::Decompiled(document)) => {
                let descriptor = document.descriptor.clone();
                let dex_name = document.dex_name.clone();
                self.documents.put(document);
                let keep = self.active_doc.as_ref().map(|d| d.descriptor.clone());
                self.documents.enforce_budget(keep.as_deref());
                self.tabs.set_ready(&descriptor, Some(dex_name));
                // The visible tab picks the document up next frame;
                // refresh it eagerly so activation scrolls correctly.
                if self.tabs.active_descriptor() == Some(descriptor.as_str()) {
                    self.active_doc = self.documents.get(&descriptor);
                }
                self.set_status(format!("decompiled {descriptor}"), true);
            }
            (TaskKind::DecompileClass, TaskOutcome::Failed(e)) => {
                self.tabs.set_failed(&task.label, e.clone());
                self.last_error = Some(format!("getclass: {e}"));
                self.set_status(format!("getclass failed: {e}"), false);
            }
            (TaskKind::Disasm, TaskOutcome::Disassembled { dex_name, listing }) => {
                // Smali listing lands as a `#smali`-keyed document in
                // the normal cache + tab flow (JADX-GUI-018).
                let key = task.label;
                let document = Document::new(key.clone(), dex_name.clone(), listing);
                self.documents.put(Arc::new(document));
                let keep = self.active_doc.as_ref().map(|d| d.descriptor.clone());
                self.documents.enforce_budget(keep.as_deref());
                self.tabs.set_ready(&key, Some(dex_name));
                if self.tabs.active_descriptor() == Some(key.as_str()) {
                    self.active_doc = self.documents.get(&key);
                }
                self.set_status(format!("disasm ready: {key}"), true);
            }
            (TaskKind::Callees, TaskOutcome::Callees(result)) => {
                // One-hop call fan-out, rendered as rows in the
                // REFERENCES tab (callee class · member · site count).
                let label = format!("callees of {}", task.label);
                let rows = result
                    .callees
                    .iter()
                    .map(|c| {
                        let (class, member) = match c.target.split_once("->") {
                            Some((a, b)) => (a.to_string(), b.to_string()),
                            None => (c.target.clone(), String::new()),
                        };
                        crate::state::SearchRow {
                            dex_name: result.dex_name.clone(),
                            caller_class: class,
                            caller_member: member,
                            matched: vec![format!("×{}", c.sites)],
                            code_off: None,
                        }
                    })
                    .collect();
                self.references = Some(crate::state::SearchResults {
                    label,
                    rows,
                    complete: result.complete,
                    errors: result.errors.iter().map(|e| e.to_string()).collect(),
                });
                self.reveal_bottom_tab(BottomTab::References);
                let ok = result.complete && result.errors.is_empty();
                self.set_status(
                    if ok {
                        format!("callees ready: {} rows", result.callees.len())
                    } else {
                        format!("callees incomplete: {} rows", result.callees.len())
                    },
                    ok,
                );
            }
            (TaskKind::Callees, TaskOutcome::Failed(e)) => {
                self.last_error = Some(format!("callees: {e}"));
                self.set_status(format!("callees failed: {e}"), false);
                self.references = Some(SearchResults::from_error(task.label, e));
                self.focus_bottom_tab(BottomTab::References);
            }
            (TaskKind::ClassStrings, TaskOutcome::ClassStrings(result)) => {
                // Class-scoped string constants, rendered as rows in
                // the REFERENCES tab (class · string · site count).
                let label = format!("strings of {}", task.label);
                let rows = result
                    .strings
                    .iter()
                    .map(|s| crate::state::SearchRow {
                        dex_name: result.dex_name.clone(),
                        caller_class: task.label.clone(),
                        caller_member: s.text.clone(),
                        matched: vec![format!("×{}", s.sites)],
                        code_off: None,
                    })
                    .collect();
                self.references = Some(crate::state::SearchResults {
                    label,
                    rows,
                    complete: result.complete,
                    errors: result.errors.iter().map(|e| e.to_string()).collect(),
                });
                self.reveal_bottom_tab(BottomTab::References);
                let ok = result.complete && result.errors.is_empty();
                self.set_status(
                    if ok {
                        format!("class strings ready: {} strings", result.strings.len())
                    } else {
                        format!("class strings incomplete: {} strings", result.strings.len())
                    },
                    ok,
                );
            }
            (TaskKind::ClassStrings, TaskOutcome::Failed(e)) => {
                self.last_error = Some(format!("class strings: {e}"));
                self.set_status(format!("class strings failed: {e}"), false);
                self.references = Some(SearchResults::from_error(task.label, e));
                self.focus_bottom_tab(BottomTab::References);
            }
            (TaskKind::Disasm, TaskOutcome::Failed(e)) => {
                self.tabs.set_failed(&task.label, e.clone());
                self.last_error = Some(format!("disasm: {e}"));
                self.set_status(format!("disasm failed: {e}"), false);
            }
            (TaskKind::FindRefs, TaskOutcome::Search(report)) => {
                let results = SearchResults::from_report(task.label, &report);
                let summary_ok = results.complete && results.errors.is_empty();
                let hits = results.rows.len();
                self.search.set_results(results);
                self.focus_bottom_tab(BottomTab::Results);
                self.set_status(
                    if summary_ok {
                        format!("findrefs: {hits} hits")
                    } else {
                        format!("findrefs incomplete: {hits} hits")
                    },
                    summary_ok,
                );
            }
            (TaskKind::FindRefs, TaskOutcome::Failed(e)) => {
                self.last_error = Some(format!("findrefs: {e}"));
                self.set_status(format!("findrefs failed: {e}"), false);
                self.search
                    .set_results(SearchResults::from_error(task.label, e));
                self.focus_bottom_tab(BottomTab::Results);
            }
            (TaskKind::FindRefsClass, TaskOutcome::Search(report)) => {
                let results = SearchResults::from_report(task.label, &report);
                let hits = results.rows.len();
                let ok = results.complete && results.errors.is_empty();
                self.references = Some(results);
                self.focus_bottom_tab(BottomTab::References);
                self.set_status(
                    if ok {
                        format!("references: {hits} callers")
                    } else {
                        format!("references incomplete: {hits} callers")
                    },
                    ok,
                );
            }
            (TaskKind::FindRefsClass, TaskOutcome::Failed(e)) => {
                self.last_error = Some(format!("references: {e}"));
                self.set_status(format!("references failed: {e}"), false);
                self.references = Some(SearchResults::from_error(task.label, e));
                self.focus_bottom_tab(BottomTab::References);
            }
            // Payload/kind mismatches cannot occur (engine contract);
            // surfaced instead of silently dropped.
            (kind, outcome) => {
                self.last_error = Some(format!(
                    "internal: task payload mismatch for {} ({})",
                    kind.label(),
                    task_label_of(&outcome)
                ));
            }
        }
    }

    // ----------------------------------------------------------------
    // command dispatch
    // ----------------------------------------------------------------

    fn dispatch(&mut self, cmd: Command, ctx: &egui::Context) {
        match cmd {
            Command::OpenArtifact => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Android package", &["apk"])
                    .add_filter("DEX", &["dex"])
                    .set_title("Open APK or DEX")
                    .pick_file()
                {
                    self.open_path(&path, ctx);
                }
            }
            Command::ReloadArtifact => {
                if let Some(session) = &self.session {
                    let path = session.path().to_path_buf();
                    self.open_path(&path, ctx);
                }
            }
            Command::NavigateBack => self.nav_back(ctx),
            Command::NavigateForward => self.nav_forward(ctx),
            Command::OpenClass {
                descriptor,
                pin,
                line,
                origin,
            } => self.navigate_to(&descriptor, pin, line, origin, ctx),
            Command::GlobalSearch | Command::RunSearch => {
                self.focus_search = true;
                if matches!(cmd, Command::RunSearch)
                    // One search lane. There is no engine-side
                    // cancellation, so a second submit would leave the
                    // first worker running to completion for nothing
                    // (audit F09). Every submit path — the Run button,
                    // Enter-on-lost-focus, the toolbar Enter — lands
                    // here, so this one check bounds them all.
                    // `findrefs_live`, not `findrefs_running`: a
                    // cancelled or superseded worker keeps running but
                    // must not lock the user out of re-running.
                    && !self.tasks.findrefs_live()
                    && let Some(session) = &self.session
                    && let Some(query) = self.search.query()
                {
                    let apk = session.path().to_path_buf();
                    let label = self.search.label();
                    self.tasks
                        .spawn_findrefs(&apk, query, label, self.paranoid, ctx);
                    self.unpin_bottom_focus();
                    // Record this query for the history dropdown
                    // (JADX-GUI-013 / ASC-GUI-036). GlobalSearch only
                    // focuses the input; it never submits a query.
                    self.search.commit_to_history();
                    self.set_status(format!("findrefs running: {}", self.search.input), true);
                }
            }
            Command::FindReferences => {
                // References to the active class: an engine type-query
                // keyed on the full descriptor, routed to the
                // REFERENCES tab.
                let descriptor = self.active_class_descriptor().map(str::to_string);
                if let (Some(session), Some(descriptor)) = (&self.session, descriptor) {
                    let apk = session.path().to_path_buf();
                    self.tasks.spawn_findrefs_class(&apk, &descriptor, ctx);
                    self.unpin_bottom_focus();
                    self.show_bottom = true;
                    self.bottom_tab = BottomTab::References;
                    self.set_status(format!("references: {descriptor}"), true);
                } else {
                    self.set_status("open a class first", false);
                }
            }
            Command::ShowSmali => {
                // Smali listing of the active class, opened as a
                // `#smali`-keyed document/tab. Cache hit and cache miss
                // are the *same* navigation now: `navigate_to` reuses a
                // cached listing or re-issues the disasm job for a view
                // key. The old miss-only branch bypassed the navigation
                // history, so the listing could never be reached by
                // Back/Forward and the recorded location stayed the Java
                // class (audit F2).
                let Some(descriptor) = self.active_class_descriptor().map(str::to_string) else {
                    self.set_status("open a class first", false);
                    return;
                };
                let key = crate::task::TaskManager::smali_key(&descriptor, None);
                self.navigate_to(&key, false, None, NavOrigin::Tree, ctx);
            }
            Command::ShowSmaliMethod | Command::ShowCallees => {
                // Both act on the clicked identifier, only while it
                // applies to the document on screen AND resolves to a
                // method with a known declaring class (audit F2: the
                // document on screen is never the target class).
                let Some((descriptor, method)) = self.resolved_method() else {
                    self.set_status(
                        self.method_action_block().unwrap_or("no method selected"),
                        false,
                    );
                    return;
                };
                let Some(session) = &self.session else { return };
                let apk = session.path().to_path_buf();
                if matches!(cmd, Command::ShowCallees) {
                    self.tasks.spawn_callees(&apk, &descriptor, &method, ctx);
                    self.unpin_bottom_focus();
                    self.show_bottom = true;
                    self.bottom_tab = BottomTab::References;
                    self.set_status(format!("callees: {descriptor}->{method}"), true);
                    return;
                }
                let key = crate::task::TaskManager::smali_key(&descriptor, Some(&method));
                self.navigate_to(&key, false, None, NavOrigin::Tree, ctx);
            }
            Command::ShowClassStrings => {
                // Class-scoped: the class of the active tab / tree
                // selection — never a `#smali` view key and never a
                // method's declaring class (this shows *this* class's
                // own strings).
                let Some(descriptor) = self.active_class_descriptor().map(str::to_string) else {
                    self.set_status("select a class first", false);
                    return;
                };
                let Some(session) = &self.session else { return };
                self.tasks
                    .spawn_class_strings(session.path(), &descriptor, ctx);
                self.unpin_bottom_focus();
                self.show_bottom = true;
                self.bottom_tab = BottomTab::References;
                self.set_status(format!("strings: {descriptor}"), true);
            }
            Command::ToggleBookmark => {
                // Bookmark the active tab at the clicked line (or
                // line 1 when nothing is clicked); a line clicked in
                // another document does not count (audit F1).
                // Second toggle on the same line clears it.
                if let Some(d) = self.tabs.active_descriptor().map(str::to_string) {
                    let line = self.clicked_line().map(|l| l + 1).unwrap_or(1);
                    let on = self.tabs.toggle_bookmark(&d, Some(line));
                    self.set_status(
                        if on {
                            format!("bookmark set: {d}:{line}")
                        } else {
                            format!("bookmark cleared: {d}")
                        },
                        true,
                    );
                } else {
                    self.set_status("open a class first", false);
                }
            }
            Command::GoToBookmark => {
                if let Some(d) = self
                    .tabs
                    .active_descriptor()
                    .and_then(|d| self.tabs.bookmark(d).map(|line| (d.to_string(), line)))
                {
                    let line = d.1;
                    self.apply_goto_line(line);
                } else {
                    self.set_status("no bookmark on this tab", false);
                }
            }
            Command::OpenRecent { path } => {
                if path.exists() {
                    self.open_path(&path, ctx);
                } else {
                    self.set_status(
                        format!("recent artifact missing: {}", path.display()),
                        false,
                    );
                }
            }
            Command::ShowOpenTabs => {
                self.show_open_tabs = true;
                self.open_tabs_filter.clear();
            }
            Command::UsedByClass => {
                // Same engine as FindReferences (type query on the
                // descriptor) but the surface emphasis is the
                // inline button in the REFERENCES / inspector.
                self.queue(Command::FindReferences);
            }
            Command::FindInDocument => {
                self.show_find = true;
                self.recompute_find_matches();
            }
            Command::FindUsagesOfClicked => {
                // Workflow B: prefill the search bar with the *resolved*
                // method and pin the class filter to its *declaring*
                // class (audit F2 — never the document on screen, never a
                // raw token that is not actually a method). A resolved
                // method with an unknown declaring class, or a non-method
                // identifier, falls back to a plain global search instead
                // of masquerading as a member-method find.
                if let Some((class, method)) = self.resolved_method() {
                    self.search.input = method;
                    self.search.class_filter =
                        asc_core::normalize_class_name(&class).unwrap_or(class);
                    self.search.kind = SearchKind::Method;
                    self.focus_search = true;
                    self.queue(Command::RunSearch);
                    return;
                }
                self.queue(Command::GlobalSearch);
            }
            Command::GoToDeclaration => {
                // Workflow D: open the class that actually *declares*
                // the selected symbol (audit F2). A class reference opens
                // itself; a method/field with a resolved declaring class
                // opens that class; everything else — a local, an
                // unresolved identifier, an owner we could not prove — is
                // refused instead of re-opening the document on screen.
                let sel = self.active_symbol_sel();
                let target = match sel.and_then(|s| s.resolved.as_ref()) {
                    Some(r) if r.kind == crate::semantic::SymbolKind::Class => Some(r.name.clone()),
                    Some(r) if r.owner.is_some() => r.owner.clone(),
                    _ => None,
                };
                let Some(descriptor) = target else {
                    self.set_status(
                        "go to declaration: no class/declaration target resolved for this identifier",
                        false,
                    );
                    return;
                };
                self.queue(Command::OpenClass {
                    descriptor,
                    pin: false,
                    line: None,
                    origin: NavOrigin::Declaration,
                });
            }
            Command::QuickOpen => {
                self.palette = Some(PaletteMode::QuickOpen);
                self.focus_palette = true;
            }
            Command::ToggleCommandPalette => {
                self.palette = Some(PaletteMode::Commands);
                self.focus_palette = true;
            }
            Command::CloseTab => {
                if let Some(d) = self.tabs.active_descriptor().map(str::to_string) {
                    self.close_tab(&d);
                }
            }
            Command::CloseOthers { descriptor } => {
                let dropped = self.tabs.close_others(descriptor.as_deref());
                for d in &dropped {
                    self.documents.remove(d);
                }
                self.set_status(format!("closed {} other tab(s)", dropped.len()), true);
            }
            Command::CloseAll => {
                let dropped = self.tabs.close_all();
                for d in &dropped {
                    self.documents.remove(d);
                }
                self.set_status(format!("closed {} tab(s)", dropped.len()), true);
            }
            Command::CloseRight { descriptor } => {
                let dropped = self.tabs.close_right(&descriptor);
                for d in &dropped {
                    self.documents.remove(d);
                }
                self.set_status(
                    format!("closed {} tab(s) to the right", dropped.len()),
                    true,
                );
            }
            Command::PinTab => {
                self.tabs.pin(None);
            }
            Command::PinAll => {
                let n = self.tabs.pin_all();
                self.set_status(format!("pinned {n} preview tab(s)"), true);
            }
            Command::NextTab => self.tabs.cycle(true),
            Command::PreviousTab => self.tabs.cycle(false),
            Command::ToggleExplorer => self.show_explorer = !self.show_explorer,
            Command::ToggleInspector => self.show_inspector = !self.show_inspector,
            Command::ToggleBottomPanel => {
                self.show_bottom = !self.show_bottom;
                self.pin_bottom_focus();
            }
            Command::ToggleTheme => {
                let next = match design::theme() {
                    design::Theme::Dark => design::Theme::Light,
                    design::Theme::Light => design::Theme::Dark,
                };
                design::set_theme(next);
                design::apply(ctx);
            }
            Command::ToggleParanoid => {
                self.paranoid = !self.paranoid;
                // Cached/in-flight sources were built in the other mode.
                self.tasks.cancel_kind(TaskKind::DecompileClass);
                self.documents.clear();
                self.active_doc = None;
                // The click anchors pointed into the dropped sources.
                self.symbol_sel = None;
                self.last_click = None;
                self.comment_target = None;
                if self.session.is_some()
                    && let Some(d) = self.active_class_descriptor().map(str::to_string)
                {
                    self.spawn_decompile(&d, ctx);
                }
                let state = if self.paranoid { "on" } else { "off" };
                self.set_status(format!("Paranoid string decoding {state}"), true);
            }
            Command::QuickSwitch { n } => {
                // Ctrl+1..9 jumps to the n-th tab. The tab list is
                // pinned-first / preview-last; `n` is 1-indexed and
                // clamped.
                let count = self.tabs.tabs().len();
                if count == 0 {
                    self.set_status("no tabs to switch to", false);
                    return;
                }
                let idx = (n as usize).saturating_sub(1).min(count - 1);
                let descriptor = self.tabs.tabs()[idx].descriptor.clone();
                self.tabs.activate(&descriptor);
                self.nav.push(crate::state::NavigationLocation {
                    descriptor,
                    line: None,
                    origin: crate::state::NavOrigin::Tab,
                });
            }
            Command::BeginRenameSymbol => {
                // Only a selection that applies to the document on
                // screen may open the rename bar (audit F1).
                let token = self.active_symbol_sel().map(|s| s.token.clone());
                if let Some(token) = token {
                    self.rename_input = token;
                    self.show_rename = true;
                } else {
                    self.set_status("rename: click an identifier in the editor first", false);
                }
            }
            Command::RenameSymbol { new_name } => {
                self.show_rename = false;
                self.apply_symbol_rename(&new_name);
            }
            Command::BeginLineComment => {
                // The anchor must belong to the document on screen:
                // otherwise the bar would show the previous document's
                // line and append the note there (audit F1).
                let Some(line) = self.clicked_line() else {
                    self.set_status("comment: click a code line first", false);
                    return;
                };
                let doc = self.active_doc_key().map(str::to_string);
                if let Some(doc) = doc {
                    self.comment_input.clear();
                    self.comment_target = Some((doc, line));
                }
            }
            Command::SetLineComment { line, text } => {
                // Apply the note only to the document the bar was armed
                // for: a document switch while the bar is open must not
                // comment the new document at the old line (audit F1).
                let target = self.comment_target.take();
                let text = text.trim().to_string();
                if text.is_empty() {
                    return;
                }
                let active = self.active_doc_key().map(str::to_string);
                if let Some((doc, _)) = target
                    && Some(doc.as_str()) == active.as_deref()
                {
                    self.apply_line_comment(line, &text);
                }
            }
            Command::CancelTask => {
                self.tasks.cancel_kind(TaskKind::FindRefs);
                self.set_status("search cancelled", false);
            }
            Command::CopyDescriptor => {
                let descriptor = self.active_class_descriptor().map(str::to_string);
                let Some(d) = descriptor else {
                    self.set_status("copy descriptor: no active class", false);
                    return;
                };
                self.last_clipboard = Some(d.clone());
                ctx.copy_text(d.clone());
                self.set_status(format!("copied descriptor: {d}"), true);
            }
            Command::CopyFqn => {
                let descriptor = self.active_class_descriptor().map(str::to_string);
                let Some(d) = descriptor else {
                    self.set_status("copy FQN: no active class", false);
                    return;
                };
                let fqn = asc_core::normalize_class_name(&d)
                    .ok()
                    .map(|c| {
                        // The normalized form is the descriptor; the FQN
                        // is the Java form which is the descriptor with
                        // leading `L` and trailing `;` stripped, and
                        // `/` → `.`.
                        if c.starts_with('L') && c.ends_with(';') {
                            c[1..c.len() - 1].replace('/', ".")
                        } else {
                            c
                        }
                    })
                    .unwrap_or_else(|| d.clone());
                self.last_clipboard = Some(fqn.clone());
                ctx.copy_text(fqn.clone());
                self.set_status(format!("copied FQN: {fqn}"), true);
            }
            Command::GotoLine => {
                // Surface the input bar. The bar lives in the editor
                // (drawn when `goto_line_input.is_some()`); pressing
                // Enter with a numeric value calls
                // `apply_goto_line(line)` which sets `pending_scroll`.
                self.goto_line_input = Some(String::new());
                self.set_status("goto line (1-indexed):", true);
            }
            Command::OpenSettings => {
                // Toggle the settings dialog window. The dialog lists
                // themes and forwards each pick back through
                // `Command::ToggleTheme`.
                self.show_settings = !self.show_settings;
                if self.show_settings {
                    self.set_status("settings", true);
                }
            }
        }
    }

    /// Apply a 1-indexed `line` to `pending_scroll`. The editor reads
    /// `pending_scroll` and offsets the scroll area accordingly.
    /// Public so the editor surface (or a future modal) can call
    /// it without duplicating the bounds check.
    #[allow(dead_code)] // test-driven; the goto bar + bookmark jump call it
    pub(crate) fn apply_goto_line(&mut self, line: usize) {
        if line == 0 {
            // Treat 0 as "no-op" (avoids underflowing the 1-indexed
            // → 0-based conversion).
            return;
        }
        self.pending_scroll = Some(line - 1);
        self.set_status(format!("jumped to line {line}"), true);
        self.goto_line_input = None;
    }

    /// Frame keyboard shortcuts → commands. Single place, no draw fn
    /// reads raw key events.
    fn frame_shortcuts(&mut self, ctx: &egui::Context) {
        let pressed = |ctx: &egui::Context, m: egui::Modifiers, k: egui::Key| {
            ctx.input(|i| m.matches_exact(i.modifiers) && i.key_pressed(k))
        };
        let m = egui::Modifiers {
            ctrl: true,
            ..Default::default()
        };
        let ms = egui::Modifiers {
            ctrl: true,
            shift: true,
            ..Default::default()
        };
        let alt = egui::Modifiers {
            alt: true,
            ..Default::default()
        };
        // Escape stack: palette → overlays → find → cancel task.
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            if self.palette.is_some() {
                self.palette = None;
                self.palette_input.clear();
            } else if self.show_open_tabs {
                self.show_open_tabs = false;
            } else if self.show_settings {
                self.show_settings = false;
            } else if self.goto_line_input.is_some() {
                self.goto_line_input = None;
            } else if self.show_rename {
                self.show_rename = false;
            } else if self.comment_target.is_some() {
                self.comment_target = None;
            } else if self.show_find {
                self.show_find = false;
            } else {
                self.queue(Command::CancelTask);
            }
            return;
        }
        if pressed(ctx, m, egui::Key::O) {
            self.queue(Command::OpenArtifact);
        } else if pressed(ctx, m, egui::Key::P) {
            self.queue(Command::QuickOpen);
        } else if pressed(ctx, ms, egui::Key::P) {
            self.queue(Command::ToggleCommandPalette);
        } else if pressed(ctx, ms, egui::Key::F) {
            self.queue(Command::GlobalSearch);
        } else if pressed(ctx, m, egui::Key::F) {
            self.queue(Command::FindInDocument);
        } else if pressed(ctx, m, egui::Key::W) {
            self.queue(Command::CloseTab);
        } else if pressed(ctx, m, egui::Key::Tab) {
            self.queue(Command::NextTab);
        } else if pressed(ctx, ms, egui::Key::Tab) {
            self.queue(Command::PreviousTab);
        } else if pressed(ctx, m, egui::Key::Num1) {
            self.queue(Command::ToggleExplorer);
        } else if pressed(ctx, m, egui::Key::Num2) {
            self.queue(Command::ToggleInspector);
        } else if pressed(ctx, m, egui::Key::Num3) {
            self.queue(Command::ToggleBottomPanel);
        } else if pressed(ctx, ms, egui::Key::C) {
            self.queue(Command::CopyFqn);
        } else if pressed(ctx, m, egui::Key::C) {
            self.queue(Command::CopyDescriptor);
        } else if pressed(ctx, m, egui::Key::D) {
            self.queue(Command::GoToDeclaration);
        } else if pressed(ctx, m, egui::Key::G) {
            self.queue(Command::GotoLine);
        } else if pressed(ctx, alt, egui::Key::ArrowLeft) {
            self.queue(Command::NavigateBack);
        } else if pressed(ctx, m, egui::Key::B) {
            self.queue(Command::ToggleBookmark);
        } else if pressed(ctx, ms, egui::Key::B) {
            self.queue(Command::GoToBookmark);
        } else if pressed(ctx, ms, egui::Key::H) {
            self.queue(Command::ShowOpenTabs);
        } else if pressed(ctx, alt, egui::Key::ArrowRight) {
            self.queue(Command::NavigateForward);
        }
        // Quick switch: Alt+1..9 selects the n-th tab. The Ctrl+digit
        // lane is already the panel toggles (Ctrl+1/2/3), so this uses
        // Alt rather than the JADX Ctrl+1..9 convention.
        const QUICK_SWITCH_KEYS: [egui::Key; 9] = [
            egui::Key::Num1,
            egui::Key::Num2,
            egui::Key::Num3,
            egui::Key::Num4,
            egui::Key::Num5,
            egui::Key::Num6,
            egui::Key::Num7,
            egui::Key::Num8,
            egui::Key::Num9,
        ];
        for (i, key) in QUICK_SWITCH_KEYS.iter().enumerate() {
            if pressed(ctx, alt, *key) {
                self.queue(Command::QuickSwitch { n: (i + 1) as u8 });
                break;
            }
        }
        // Source-edit keys (oracle `n` / `;`): only when the code
        // surface is hovered, a document is open, and no text input
        // owns the keyboard.
        if self.code_hovered && self.active_doc.is_some() && !ctx.egui_wants_keyboard_input() {
            if pressed(ctx, egui::Modifiers::default(), egui::Key::N) {
                self.queue(Command::BeginRenameSymbol);
            } else if pressed(ctx, egui::Modifiers::default(), egui::Key::X) {
                self.queue(Command::FindUsagesOfClicked);
            } else if ctx.input(|i| {
                i.events
                    .iter()
                    .any(|e| matches!(e, egui::Event::Text(s) if s == ";"))
            }) {
                self.queue(Command::BeginLineComment);
            }
        }
    }

    /// One eframe frame headlessly: `logic` then the `ui` pass.
    /// eframe 0.35+ split `App::update` into `logic` + `ui`; tests drive
    /// both explicitly since there is no eframe event loop here.
    #[cfg(test)]
    pub(crate) fn test_frame(&mut self, ui: &mut egui::Ui) {
        use eframe::App as _;
        self.logic(ui.ctx(), &mut eframe::Frame::_new_kittest());
        eframe::App::ui(self, ui, &mut eframe::Frame::_new_kittest());
    }

    /// `Context::run_ui` and the texture-upload warm-up both produce a
    /// `FullOutput` we never apply. egui 0.35+ `debug_assert!`s on
    /// dropping `TexturesDelta` with pending deltas, so drain them.
    #[cfg(test)]
    pub(crate) fn run_ui(ctx: &egui::Context, f: impl FnMut(&mut egui::Ui)) {
        ctx.run_ui(Default::default(), f)
            .drop_without_applying_deltas();
    }

    /// As [`Self::run_ui`], but with an explicit `RawInput` so tests can
    /// inject key events and exercise `frame_shortcuts` end to end.
    #[cfg(test)]
    pub(crate) fn run_ui_with_input(
        ctx: &egui::Context,
        input: egui::RawInput,
        f: impl FnMut(&mut egui::Ui),
    ) {
        ctx.run_ui(input, f).drop_without_applying_deltas();
    }
}

fn task_label_of(outcome: &TaskOutcome) -> &'static str {
    match outcome {
        TaskOutcome::Decompiled(_) => "decompiled",
        TaskOutcome::Loaded(_) => "loaded",
        TaskOutcome::Disassembled { .. } => "disassembled",
        TaskOutcome::Callees(_) => "callees",
        TaskOutcome::ClassStrings(_) => "class strings",
        TaskOutcome::Search(_) => "search",
        TaskOutcome::Failed(_) => "failed",
    }
}

#[cfg(test)]
mod tests;
