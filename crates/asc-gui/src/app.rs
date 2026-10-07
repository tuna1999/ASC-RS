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
#[derive(Debug, Clone)]
pub(crate) struct SymbolSelection {
    pub(crate) descriptor: String,
    pub(crate) token: String,
    pub(crate) method: (usize, usize),
    pub(crate) occurrences: Vec<(usize, usize)>,
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
    pub(crate) show_rename: bool,
    pub(crate) rename_input: String,
    /// Line the pending line-comment targets (0-based).
    pub(crate) comment_target: Option<usize>,
    pub(crate) comment_input: String,
    /// Last line clicked in the code area (comment anchor).
    pub(crate) last_clicked_line: Option<usize>,
    /// Identifier selection from the last code click (rename anchor).
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
            show_rename: false,
            rename_input: String::new(),
            comment_target: None,
            comment_input: String::new(),
            last_clicked_line: None,
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
        self.last_clicked_line = None;
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
        self.selected_class = Some(descriptor.to_string());
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
        } else {
            self.active_doc = None;
            self.spawn_decompile(descriptor, ctx);
        }
        // Scroll target persists until the document is visible.
        self.pending_scroll = Some(line.unwrap_or(0));
    }

    /// Spawn a decompile task for `descriptor` (deduplicated).
    pub(crate) fn spawn_decompile(&mut self, descriptor: &str, ctx: &egui::Context) {
        self.tasks.spawn_decompile(
            self.session.as_ref().expect("session").path(),
            descriptor,
            self.paranoid,
            ctx,
        );
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
            return;
        };
        let needle = self.find_input.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return;
        }
        for idx in 0..doc.line_count() {
            if let Some(line) = doc.line(idx)
                && line.to_ascii_lowercase().contains(&needle)
            {
                self.find_matches.push(idx);
            }
        }
        self.find_step(true);
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
                let descriptor = self
                    .tabs
                    .active_descriptor()
                    .or(self.selected_class.as_deref())
                    .map(str::to_string);
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
                // `#smali`-keyed document/tab. Cached listings reuse
                // the normal navigation path.
                let descriptor = self
                    .tabs
                    .active_descriptor()
                    .filter(|d| !d.contains("#smali"))
                    .or(self.selected_class.as_deref())
                    .map(str::to_string);
                let Some(descriptor) = descriptor else {
                    self.set_status("open a class first", false);
                    return;
                };
                let key = crate::task::TaskManager::smali_key(&descriptor, None);
                if self.documents.contains(&key) {
                    self.navigate_to(&key, false, None, NavOrigin::Tree, ctx);
                    return;
                }
                if let Some(session) = &self.session {
                    let apk = session.path().to_path_buf();
                    self.tabs.open_preview(&key);
                    self.tabs.activate(&key);
                    self.active_doc = None;
                    self.tasks.spawn_disasm(&apk, &descriptor, None, ctx);
                    self.set_status(format!("disasm: {descriptor}"), true);
                }
            }
            Command::ShowSmaliMethod | Command::ShowCallees => {
                // Both act on the clicked identifier. The class is the
                // symbol's own descriptor (its enclosing class), with
                // the active tab as fallback — but never a `#smali`
                // view key (`{class}#smali[#{method}]`).
                let descriptor = self
                    .symbol_sel
                    .as_ref()
                    .map(|s| s.descriptor.clone())
                    .filter(|d| !d.is_empty())
                    .or_else(|| {
                        // Prefer the active tab's class, but never a
                        // `#smali` view key: filter the active descriptor
                        // BEFORE falling back to the tree selection, so a
                        // smali tab active over a selected class still
                        // resolves the class (`.or(..).filter(..)` would
                        // pick the smali key, then drop it to `None`).
                        self.tabs
                            .active_descriptor()
                            .filter(|d| !d.contains("#smali"))
                            .or(self.selected_class.as_deref())
                            .map(str::to_string)
                    });
                let method = self.symbol_sel.as_ref().map(|s| s.token.clone());
                let (Some(descriptor), Some(method)) = (descriptor, method) else {
                    let msg = if self.symbol_sel.is_some() {
                        "open a class first"
                    } else {
                        "click a method identifier first"
                    };
                    self.set_status(msg, false);
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
                if self.documents.contains(&key) {
                    self.navigate_to(&key, false, None, NavOrigin::Tree, ctx);
                    return;
                }
                self.tabs.open_preview(&key);
                self.tabs.activate(&key);
                self.active_doc = None;
                self.tasks
                    .spawn_disasm(&apk, &descriptor, Some(&method), ctx);
                self.set_status(format!("disasm: {descriptor}->{method}"), true);
            }
            Command::ShowClassStrings => {
                // Class-scoped: symbol's class, else active tab /
                // tree selection — never a `#smali` view key.
                let descriptor = self
                    .symbol_sel
                    .as_ref()
                    .map(|s| s.descriptor.clone())
                    .filter(|d| !d.is_empty())
                    .or_else(|| {
                        // Prefer the active tab's class, but never a
                        // `#smali` view key: filter the active descriptor
                        // BEFORE falling back to the tree selection, so a
                        // smali tab active over a selected class still
                        // resolves the class (`.or(..).filter(..)` would
                        // pick the smali key, then drop it to `None`).
                        self.tabs
                            .active_descriptor()
                            .filter(|d| !d.contains("#smali"))
                            .or(self.selected_class.as_deref())
                            .map(str::to_string)
                    });
                let Some(descriptor) = descriptor else {
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
                // line 1 when nothing is clicked). Second toggle on
                // the same line clears it.
                if let Some(d) = self.tabs.active_descriptor().map(str::to_string) {
                    let line = self.last_clicked_line.map(|l| l + 1).unwrap_or(1);
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
                // Workflow B: prefill the search bar with the clicked
                // identifier as a method-scoped find with a class
                // filter pinned to the click's descriptor. Falls back
                // to global search when the click didn't target a
                // member (still useful — same UI surface).
                if let Some(sel) = self.symbol_sel.as_ref()
                    && !sel.descriptor.is_empty()
                {
                    self.search.input = sel.token.clone();
                    self.search.class_filter = asc_core::normalize_class_name(&sel.descriptor)
                        .unwrap_or_else(|_| sel.descriptor.clone());
                    self.search.kind = SearchKind::Method;
                    self.focus_search = true;
                    self.queue(Command::RunSearch);
                    return;
                }
                self.queue(Command::GlobalSearch);
            }
            Command::GoToDeclaration => {
                // Workflow D: open the descriptor the click landed on,
                // if any. For non-class tokens we still run a search —
                // "go to declaration" of a member in the absence of a
                // class-keyed find is a TODO at the engine level.
                if let Some(sel) = self.symbol_sel.as_ref()
                    && sel.descriptor.starts_with('L')
                    && sel.descriptor.ends_with(';')
                {
                    self.queue(Command::OpenClass {
                        descriptor: sel.descriptor.clone(),
                        pin: false,
                        line: None,
                        origin: NavOrigin::Declaration,
                    });
                    return;
                }
                self.set_status("go to declaration: no class identifier selected", false);
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
            Command::CloseOthers => {
                let dropped = self.tabs.close_others(None);
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
                if self.session.is_some()
                    && let Some(d) = self.tabs.active_descriptor().map(str::to_string)
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
                if let Some(sel) = self.symbol_sel.as_ref() {
                    self.rename_input = sel.token.clone();
                    self.show_rename = true;
                }
            }
            Command::RenameSymbol { new_name } => {
                self.show_rename = false;
                self.apply_symbol_rename(&new_name);
            }
            Command::BeginLineComment => {
                if self.last_clicked_line.is_some() {
                    self.comment_input.clear();
                    self.comment_target = self.last_clicked_line;
                }
            }
            Command::SetLineComment { line, text } => {
                self.comment_target = None;
                let text = text.trim().to_string();
                if !text.is_empty() {
                    self.apply_line_comment(line, &text);
                }
            }
            Command::CancelTask => {
                self.tasks.cancel_kind(TaskKind::FindRefs);
                self.set_status("search cancelled", false);
            }
            Command::CopyDescriptor => {
                let descriptor = self
                    .tabs
                    .active_descriptor()
                    .or(self.selected_class.as_deref())
                    .map(str::to_string);
                let Some(d) = descriptor else {
                    self.set_status("copy descriptor: no active class", false);
                    return;
                };
                self.last_clipboard = Some(d.clone());
                ctx.copy_text(d.clone());
                self.set_status(format!("copied descriptor: {d}"), true);
            }
            Command::CopyFqn => {
                let descriptor = self
                    .tabs
                    .active_descriptor()
                    .or(self.selected_class.as_deref())
                    .map(str::to_string);
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
