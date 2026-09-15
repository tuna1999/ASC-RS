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
    SearchResults, TabController,
};
use crate::task::{CompletedTask, LoadedArtifact, TaskId, TaskKind, TaskManager, TaskOutcome};
use crate::ui::bottom_panel::BottomTab;
use crate::ui::palette::PaletteMode;

/// One-line status message with sentiment.
pub(crate) struct StatusLine {
    pub(crate) text: String,
    pub(crate) ok: bool,
}

/// Main application shell.
pub struct AscApp {
    // --- session / engine ---
    pub(crate) session: Option<WorkspaceSession>,
    pub(crate) tree: PackageTree,
    pub(crate) dex_counts: Vec<(String, usize)>,
    pub(crate) manifest: Option<asc_manifest::ManifestInfo>,
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
    pub(crate) bottom_tab: BottomTab,
    pub(crate) focus_search: bool,
    pub(crate) palette: Option<PaletteMode>,
    pub(crate) focus_palette: bool,
    pub(crate) palette_input: String,
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
            bottom_tab: BottomTab::Results,
            focus_search: false,
            palette: None,
            focus_palette: false,
            palette_input: String::new(),
            status: None,
            last_error: None,
            commands: Vec::new(),
            initial_path,
            window_title: "asc-gui".to_string(),
            palette_sel: 0,
            references: None,
        }
    }

    /// Test-only: construct around an already-open session,
    /// performing the class enumeration synchronously (what the
    /// LoadArtifact task does on a worker thread).
    #[cfg(test)]
    fn from_session(session: WorkspaceSession) -> Self {
        let mut app = Self::new(None);
        let classes = session.all_classes().unwrap_or_default();
        let dex_counts = session
            .dex_entries()
            .iter()
            .map(|e| (e.name.clone(), 0))
            .collect();
        app.manifest = asc_manifest::parse_from_apk(session.path()).ok();
        app.apply_artifact(LoadedArtifact {
            dex_counts: count_per_dex(&classes, dex_counts),
            session,
            manifest: app.manifest.clone(),
            classes,
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
        self.documents = DocumentCache::default();
        self.tabs.clear();
        self.nav = NavigationHistory::default();
        self.search.clear_results();
        self.references = None;
        self.selected_class = None;
        self.active_doc = None;
        self.pending_scroll = None;
        self.loading_artifact = false;
        self.window_title = if title.is_empty() {
            "asc-gui".to_string()
        } else {
            format!("asc-gui — {title}")
        };
        self.set_status("artifact ready", true);
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
        if let Some(next) = self.tabs.close(descriptor) {
            if self.documents.contains(&next) {
                self.active_doc = self.documents.get(&next);
                self.pending_scroll = Some(0);
            } else {
                self.active_doc = None;
            }
        } else {
            self.active_doc = None;
        }
        if self.active_doc.as_ref().map(|d| d.descriptor.as_str()) == Some(descriptor) {
            self.active_doc = None;
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
            if let Some(line) = doc.line(idx) {
                if line.to_ascii_lowercase().contains(&needle) {
                    self.find_matches.push(idx);
                }
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
            (TaskKind::FindRefs, TaskOutcome::Search(report)) => {
                let results = SearchResults::from_report(task.label, &report);
                let summary_ok = results.complete && results.errors.is_empty();
                let hits = results.rows.len();
                self.search.set_results(results);
                self.bottom_tab = BottomTab::Results;
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
                self.bottom_tab = BottomTab::Results;
            }
            (TaskKind::FindRefsClass, TaskOutcome::Search(report)) => {
                let results = SearchResults::from_report(task.label, &report);
                let hits = results.rows.len();
                let ok = results.complete && results.errors.is_empty();
                self.references = Some(results);
                self.bottom_tab = BottomTab::References;
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
                self.bottom_tab = BottomTab::References;
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
                    .set_title("Open APK")
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
                if let Some(session) = &self.session {
                    if let Some(query) = self.search.query() {
                        let apk = session.path().to_path_buf();
                        let label = self.search.label();
                        self.tasks.spawn_findrefs(&apk, query, label, ctx);
                        self.set_status(format!("findrefs running: {}", self.search.input), true);
                    }
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
                    self.show_bottom = true;
                    self.bottom_tab = BottomTab::References;
                    self.set_status(format!("references: {descriptor}"), true);
                } else {
                    self.set_status("open a class first", false);
                }
            }
            Command::FindInDocument => {
                self.show_find = true;
                self.recompute_find_matches();
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
            Command::PinTab => {
                self.tabs.pin(None);
            }
            Command::NextTab => self.tabs.cycle(true),
            Command::PreviousTab => self.tabs.cycle(false),
            Command::ToggleExplorer => self.show_explorer = !self.show_explorer,
            Command::ToggleInspector => self.show_inspector = !self.show_inspector,
            Command::ToggleBottomPanel => self.show_bottom = !self.show_bottom,
            Command::CancelTask => {
                self.tasks.cancel_kind(TaskKind::FindRefs);
                self.set_status("search cancelled", false);
            }
        }
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
        // Escape stack: palette → find → cancel task.
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            if self.palette.is_some() {
                self.palette = None;
                self.palette_input.clear();
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
        } else if pressed(ctx, alt, egui::Key::ArrowLeft) {
            self.queue(Command::NavigateBack);
        } else if pressed(ctx, alt, egui::Key::ArrowRight) {
            self.queue(Command::NavigateForward);
        }
    }
}

fn task_label_of(outcome: &TaskOutcome) -> &'static str {
    match outcome {
        TaskOutcome::Decompiled(_) => "decompiled",
        TaskOutcome::Loaded(_) => "loaded",
        TaskOutcome::Search(_) => "search",
        TaskOutcome::Failed(_) => "failed",
    }
}

/// Count classes per DEX (preserving order). Test-helper support
/// (mirrors `task::per_dex_counts`, which runs on the worker).
#[cfg(test)]
fn count_per_dex(
    classes: &[crate::session::ClassEntry],
    mut order: Vec<(String, usize)>,
) -> Vec<(String, usize)> {
    for c in classes {
        if let Some((_, n)) = order.iter_mut().find(|(name, _)| *name == c.dex_name) {
            *n += 1;
        }
    }
    order
}

impl eframe::App for AscApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.initial_path.is_some() {
            let path = self.initial_path.take().unwrap();
            self.open_path(&path, ctx);
        }

        // 1. Drain worker results first so this frame sees them.
        self.poll_workers(ctx);
        let want_title = self.window_title.clone();
        if want_title != "asc-gui" {
            let current = ctx.input(|i| i.viewport().title.clone());
            if current.as_deref() != Some(want_title.as_str()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Title(want_title));
            }
        }

        // 2. Frame-level shortcuts.
        self.frame_shortcuts(ctx);

        // 3. Menu bar.
        egui::TopBottomPanel::top("menubar").show(ctx, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open artifact…  (Ctrl+O)").clicked() {
                        ui.close();
                        self.queue(Command::OpenArtifact);
                    }
                    if ui.button("Reload artifact").clicked() {
                        ui.close();
                        self.queue(Command::ReloadArtifact);
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Navigate", |ui| {
                    if ui.button("Back  (Alt+←)").clicked() {
                        ui.close();
                        self.queue(Command::NavigateBack);
                    }
                    if ui.button("Forward  (Alt+→)").clicked() {
                        ui.close();
                        self.queue(Command::NavigateForward);
                    }
                });
                ui.menu_button("Search", |ui| {
                    if ui.button("Search artifact  (Ctrl+Shift+F)").clicked() {
                        ui.close();
                        self.queue(Command::GlobalSearch);
                    }
                    if ui.button("Find in document  (Ctrl+F)").clicked() {
                        ui.close();
                        self.queue(Command::FindInDocument);
                    }
                    if ui.button("Quick open class  (Ctrl+P)").clicked() {
                        ui.close();
                        self.queue(Command::QuickOpen);
                    }
                });
                ui.menu_button("Analysis", |ui| {
                    let target = self
                        .tabs
                        .active_descriptor()
                        .or(self.selected_class.as_deref())
                        .map(super::ui::short_name)
                        .unwrap_or_else(|| "—".to_string());
                    let has_target = self
                        .tabs
                        .active_descriptor()
                        .or(self.selected_class.as_deref())
                        .is_some();
                    if ui
                        .add_enabled(
                            has_target,
                            egui::Button::new(format!("Find references to {target}")),
                        )
                        .on_disabled_hover_text("open a class first")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::FindReferences);
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.toggle_value(&mut self.show_explorer, "Explorer  (Ctrl+1)");
                    ui.toggle_value(&mut self.show_inspector, "Inspector  (Ctrl+2)");
                    ui.toggle_value(&mut self.show_bottom, "Bottom panel  (Ctrl+3)");
                });
                ui.menu_button("Help", |ui| {
                    ui.label("ASC Instant Workbench");
                    ui.weak(if let Some(s) = &self.session {
                        format!("artifact: {}", s.path().display())
                    } else {
                        "no artifact open".to_string()
                    });
                });
            });
        });

        // 4. Toolbar: back/forward, artifact search, meta.
        egui::TopBottomPanel::top("toolbar")
            .frame(egui::Frame::new().fill(design::DARK.surface))
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    let back = ui.button("◀").on_hover_text("back (Alt+←)");
                    if back.clicked() {
                        self.queue(Command::NavigateBack);
                    }
                    let fwd = ui.button("▶").on_hover_text("forward (Alt+→)");
                    if fwd.clicked() {
                        self.queue(Command::NavigateForward);
                    }
                    ui.separator();
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut self.search.input)
                            .hint_text("search artifact…")
                            .desired_width(280.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    if self.focus_search {
                        edit.request_focus();
                        self.focus_search = false;
                    }
                    if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.queue(Command::RunSearch);
                    }
                    if self.tasks.findrefs_running() {
                        ui.spinner();
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button("⌘P")
                            .on_hover_text("command palette (Ctrl+Shift+P)")
                            .clicked()
                        {
                            self.queue(Command::ToggleCommandPalette);
                        }
                        let pkg = self
                            .manifest
                            .as_ref()
                            .and_then(|m| m.package.clone())
                            .unwrap_or_else(|| {
                                self.session
                                    .as_ref()
                                    .map(|s| {
                                        s.path()
                                            .file_stem()
                                            .map(|f| f.to_string_lossy().into_owned())
                                            .unwrap_or_default()
                                    })
                                    .unwrap_or_else(|| "no artifact".to_string())
                            });
                        let ver = self
                            .manifest
                            .as_ref()
                            .and_then(|m| m.version_code)
                            .map(|v| format!(" v{v}"))
                            .unwrap_or_default();
                        ui.monospace(
                            egui::RichText::new(format!("{pkg}{ver}"))
                                .small()
                                .color(design::DARK.text_secondary),
                        );
                    });
                });
            });

        // 5. Bottom panel.
        if self.show_bottom {
            egui::TopBottomPanel::bottom("bottom_panel")
                .resizable(true)
                .default_height(design::DARK.bottom_default)
                .frame(egui::Frame::new().fill(design::DARK.panel_bg))
                .show(ctx, |ui| {
                    self.draw_bottom_panel(ui);
                });
        }

        // 6. Status bar.
        egui::TopBottomPanel::bottom("statusbar")
            .frame(egui::Frame::new().fill(design::DARK.panel_bg))
            .show(ctx, |ui| {
                self.draw_status_bar(ui);
            });

        // 7. Inspector (right).
        if self.show_inspector {
            egui::SidePanel::right("inspector")
                .resizable(true)
                .default_width(design::DARK.inspector_default)
                .frame(egui::Frame::new().fill(design::DARK.panel_bg))
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.draw_inspector(ui);
                    });
                });
        }

        // 7b. Activity bar (far left): Explorer / Search / Tasks.
        {
            egui::SidePanel::left("activity_bar")
                .exact_width(36.0)
                .frame(egui::Frame::new().fill(design::DARK.panel_bg))
                .show(ctx, |ui| {
                    ui.with_layout(
                        egui::Layout::top_down_justified(egui::Align::Center),
                        |ui| {
                            ui.add_space(4.0);
                            let toggle = |ui: &mut egui::Ui,
                                          label: &'static str,
                                          active: bool,
                                          hint: &'static str|
                             -> bool {
                                let rich = egui::RichText::new(label).size(15.0).color(if active {
                                    design::DARK.accent
                                } else {
                                    design::DARK.text_secondary
                                });
                                let btn = egui::Button::new(rich).frame(false);
                                let resp = ui
                                    .add(btn)
                                    .on_hover_text(hint)
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                                resp.clicked()
                            };
                            if toggle(ui, "▤", self.show_explorer, "Explorer (Ctrl+1)") {
                                self.show_explorer = !self.show_explorer;
                            }
                            if toggle(
                                ui,
                                "🔍",
                                self.show_bottom && self.bottom_tab == BottomTab::Results,
                                "Search (Ctrl+Shift+F)",
                            ) {
                                self.show_bottom = true;
                                self.bottom_tab = BottomTab::Results;
                                self.focus_search = true;
                            }
                            if toggle(
                                ui,
                                "☰",
                                self.show_bottom && self.bottom_tab == BottomTab::Tasks,
                                "Tasks (Ctrl+3)",
                            ) {
                                self.show_bottom = true;
                                self.bottom_tab = BottomTab::Tasks;
                            }
                        },
                    );
                });
        }

        // 8. Explorer (left).
        if self.show_explorer {
            egui::SidePanel::left("explorer")
                .resizable(true)
                .default_width(design::DARK.explorer_default)
                .frame(egui::Frame::new().fill(design::DARK.panel_bg))
                .show(ctx, |ui| {
                    self.draw_explorer(ui);
                });
        }

        // 9. Editor (center).
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(design::DARK.app_bg))
            .show(ctx, |ui| {
                self.draw_editor(ui);
            });

        // 10. Palette overlay.
        self.draw_palette(ctx);

        // 11. Dispatch everything queued this frame.
        let commands = std::mem::take(&mut self.commands);
        for cmd in commands {
            self.dispatch(cmd, ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::App as _;

    fn corpus() -> Option<PathBuf> {
        let apk = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/apk/workload.apk");
        apk.exists().then_some(apk)
    }

    fn empty_app() -> AscApp {
        AscApp::new(None)
    }

    fn fake_task(id: u64, descriptor: &str, outcome: TaskOutcome) -> CompletedTask {
        CompletedTask {
            id: crate::task::TaskId(id),
            generation: crate::task::SessionGeneration::INITIAL,
            kind: TaskKind::DecompileClass,
            label: descriptor.to_string(),
            outcome,
            elapsed: std::time::Duration::from_millis(1),
            stale: false,
        }
    }

    fn decompiled(descriptor: &str) -> TaskOutcome {
        TaskOutcome::Decompiled(Arc::new(Document::new(
            descriptor.to_string(),
            "classes.dex".into(),
            format!("class {} {{}}\n", descriptor.trim_matches(['L', ';'])),
        )))
    }

    fn active(app: &AscApp) -> Option<String> {
        app.tabs.active_descriptor().map(str::to_string)
    }

    /// click A, click B (preview), B first, A late → B stays active,
    /// one preview tab, both documents cached.
    #[test]
    fn late_result_cannot_steal_newer_activation() {
        let mut app = empty_app();
        app.tabs.open_preview("LA;");
        app.tabs.open_preview("LB;");
        assert_eq!(active(&app).as_deref(), Some("LB;"));
        // B lands first.
        app.apply_task(fake_task(2, "LB;", decompiled("LB;")));
        assert_eq!(
            app.active_doc.as_ref().map(|d| d.descriptor.as_str()),
            Some("LB;")
        );
        // A lands late: cached, but cannot steal the view.
        app.apply_task(fake_task(1, "LA;", decompiled("LA;")));
        assert_eq!(active(&app).as_deref(), Some("LB;"), "preview slot still B");
        assert_eq!(
            app.active_doc.as_ref().map(|d| d.descriptor.as_str()),
            Some("LB;"),
            "late older result must not steal the view"
        );
        assert_eq!(
            app.documents.len(),
            2,
            "A filled the cache in the background"
        );
        assert_eq!(app.tabs.tabs().len(), 1, "single preview tab");
    }

    /// click A (fails), click B (succeeds) → B active and visible
    /// (regression for audit F1: A's failure used to clear B's
    /// intent).
    #[test]
    fn older_failure_does_not_clear_newer_intent() {
        let mut app = empty_app();
        app.tabs.open_preview("LA;");
        app.tabs.open_preview("LB;");
        // A fails: B's tab is untouched.
        app.apply_task(fake_task(1, "LA;", TaskOutcome::Failed("not found".into())));
        assert_eq!(active(&app).as_deref(), Some("LB;"));
        assert!(app.active_doc.is_none(), "B still loading");
        // B succeeds → visible.
        app.apply_task(fake_task(2, "LB;", decompiled("LB;")));
        assert_eq!(active(&app).as_deref(), Some("LB;"));
        assert_eq!(
            app.active_doc.as_ref().map(|d| d.descriptor.as_str()),
            Some("LB;")
        );
    }

    /// Old-APK job completes after a new artifact loaded → ignored
    /// (generation gate).
    #[test]
    fn old_generation_result_ignored() {
        let mut app = empty_app();
        let mut stale = fake_task(1, "LOLD;", decompiled("LOLD;"));
        stale.generation = crate::task::SessionGeneration::INITIAL;
        app.tasks.bump_generation();
        stale.stale = true;
        app.apply_task(stale);
        assert!(app.documents.is_empty(), "stale result must not cache");
        assert!(app.tabs.tabs().is_empty());
    }

    /// Preview/pinned semantics through the shell: preview A, pin A,
    /// preview B.
    #[test]
    fn preview_pin_preview_flow() {
        let mut app = empty_app();
        app.tabs.open_preview("LA;");
        app.tabs.pin(None);
        app.tabs.open_preview("LB;");
        assert_eq!(app.tabs.tabs().len(), 2);
        assert_eq!(app.tabs.tabs()[0].kind, crate::state::TabKind::Pinned);
        assert_eq!(app.tabs.tabs()[0].descriptor, "LA;");
        assert_eq!(app.tabs.tabs()[1].descriptor, "LB;");
        assert_eq!(active(&app).as_deref(), Some("LB;"));
    }

    /// Navigation pushes locations; back/forward restore descriptor
    /// and line deterministically through the shell.
    #[test]
    fn navigation_restores_locations() {
        let Some(apk) = corpus() else {
            eprintln!("corpus fixture missing; skipping");
            return;
        };
        let session = WorkspaceSession::open(&apk).expect("open");
        let mut app = AscApp::from_session(session);
        let ctx = egui::Context::default();
        // Seed documents so navigation doesn't spawn jobs.
        for d in ["LA;", "LB;"] {
            app.documents.put(Arc::new(Document::new(
                d.to_string(),
                "classes.dex".into(),
                "class X {}\n".into(),
            )));
        }
        app.navigate_to("LA;", false, None, NavOrigin::Tree, &ctx);
        app.navigate_to("LB;", false, Some(7), NavOrigin::Outline, &ctx);
        assert_eq!(app.nav.len(), 2);
        app.nav_back(&ctx);
        assert_eq!(active(&app).as_deref(), Some("LA;"));
        assert_eq!(app.pending_scroll, Some(0), "back to A restores top");
        app.nav_forward(&ctx);
        assert_eq!(active(&app).as_deref(), Some("LB;"));
        assert_eq!(app.pending_scroll, Some(7), "forward restores line");
    }

    /// End-to-end queue: two real decompile jobs land as documents;
    /// the last-clicked class stays the active preview.
    #[test]
    fn getclass_jobs_open_documents_latest_click_wins() {
        let Some(apk) = corpus() else {
            eprintln!("corpus fixture missing; skipping");
            return;
        };
        let session = WorkspaceSession::open(&apk).expect("open");
        let mut app = AscApp::from_session(session);
        let ctx = egui::Context::default();
        let target = "Lcom/google/android/material/timepicker/ClockFaceView;".to_string();
        let other = app.tree.entry(0).descriptor.clone();

        app.navigate_to(&target, false, None, NavOrigin::Tree, &ctx);
        app.navigate_to(&other, false, None, NavOrigin::Tree, &ctx);
        assert_eq!(app.tasks.in_flight_count(), 2, "both jobs queued");

        for _ in 0..600 {
            app.poll_workers(&ctx);
            if app.documents.len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(app.documents.len(), 2, "both documents landed");
        assert!(
            app.documents
                .peek(&target)
                .is_some_and(|d| !d.source.is_empty())
        );
        assert!(
            app.documents
                .peek(&other)
                .is_some_and(|d| !d.source.is_empty())
        );
        assert_eq!(
            active(&app).as_deref(),
            Some(other.as_str()),
            "latest click active"
        );
        assert!(app.last_error.is_none(), "{:?}", app.last_error);
    }

    /// Dedup: clicking an in-flight class re-targets the same task.
    #[test]
    fn repeated_click_dedups_to_inflight_task() {
        let Some(apk) = corpus() else {
            eprintln!("corpus fixture missing; skipping");
            return;
        };
        let session = WorkspaceSession::open(&apk).expect("open");
        let mut app = AscApp::from_session(session);
        let ctx = egui::Context::default();
        app.navigate_to(
            "Lcom/example/SomeClass;",
            false,
            None,
            NavOrigin::Tree,
            &ctx,
        );
        app.navigate_to(
            "Lcom/example/SomeClass;",
            false,
            None,
            NavOrigin::Tree,
            &ctx,
        );
        assert_eq!(app.tasks.in_flight_count(), 1);
    }

    /// Search application: full SearchReport retained as rows.
    #[test]
    fn search_results_retained_and_navigable() {
        use asc_core::{DexResults, RenderedMatch};
        let mut app = empty_app();
        let mut report = asc_core::SearchReport::empty();
        report.results.push(DexResults {
            dex_name: "classes.dex".into(),
            matches: vec![RenderedMatch {
                caller: "Lcom/foo/Bar;->onCreate".into(),
                matched: vec!["\"lit\"".into()],
            }],
            errors: Vec::new(),
            complete: true,
        });
        app.apply_task(CompletedTask {
            id: crate::task::TaskId(9),
            generation: crate::task::SessionGeneration::INITIAL,
            kind: TaskKind::FindRefs,
            label: "string \"lit\"".into(),
            outcome: TaskOutcome::Search(report),
            elapsed: std::time::Duration::from_millis(2),
            stale: false,
        });
        let r = app.search.results().expect("retained");
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0].caller_class, "Lcom/foo/Bar;");
        assert_eq!(r.rows[0].caller_member, "onCreate");
        assert!(matches!(app.bottom_tab, BottomTab::Results));
    }

    /// Full-render smoke: load the corpus artifact, open a class,
    /// run a search, then drive every panel draw function inside a
    /// headless `egui::Context::run` — catches render-path panics
    /// without a native window.
    #[test]
    fn render_all_panels_smoke() {
        let Some(apk) = corpus() else {
            eprintln!("corpus fixture missing; skipping");
            return;
        };
        let ctx = egui::Context::default();
        let mut app = AscApp::new(Some(apk));
        // Drive the startup open to completion.
        for _ in 0..600 {
            let _ = ctx.run(Default::default(), |ctx| {
                app.update(ctx, &mut eframe::Frame::_new_kittest());
            });
            if app.session.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(app.session.is_some(), "artifact loaded");

        // Open a class and run a search.
        let _ = ctx.run(Default::default(), |ctx| {
            app.dispatch(
                Command::OpenClass {
                    descriptor: "Lcom/google/android/material/timepicker/ClockFaceView;".into(),
                    pin: false,
                    line: None,
                    origin: NavOrigin::Tree,
                },
                ctx,
            );
            app.search.input = "ClockFace".into();
            app.dispatch(Command::RunSearch, ctx);
        });
        for _ in 0..600 {
            let _ = ctx.run(Default::default(), |ctx| {
                app.update(ctx, &mut eframe::Frame::_new_kittest());
            });
            if !app.documents.is_empty() && app.search.results().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!app.documents.is_empty(), "class decompiled");
        assert!(app.search.results().is_some(), "search landed");

        // Render several frames (panels + palette + find bar).
        app.palette = Some(crate::ui::palette::PaletteMode::Commands);
        app.show_find = true;
        app.find_input = "class".into();
        for _ in 0..5 {
            let _ = ctx.run(Default::default(), |ctx| {
                app.update(ctx, &mut eframe::Frame::_new_kittest());
            });
        }
        assert!(app.last_error.is_none(), "{:?}", app.last_error);
    }

    /// Render full-workspace reference screenshots to
    /// `target/shots/*.png` via egui_kittest (software rasterizer —
    /// pixels as the user sees them, no GPU needed). Opt-in:
    /// `ASC_GUI_SHOTS=1 cargo test -p asc-gui --lib visual_shots`.
    #[test]
    fn visual_shots() {
        if std::env::var("ASC_GUI_SHOTS").is_err() {
            eprintln!("ASC_GUI_SHOTS not set; skipping");
            return;
        }
        let Some(apk) = corpus() else {
            eprintln!("corpus fixture missing; skipping");
            return;
        };
        let shots = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/shots");
        let _ = std::fs::remove_dir_all(&shots);
        std::fs::create_dir_all(&shots).unwrap();
        let save = |h: &mut egui_kittest::Harness<'_, AscApp>, name: &str| {
            let img = h.render().expect("render");
            let path = shots.join(format!("{name}.png"));
            img.save(&path).unwrap();
            eprintln!("shot: {}", path.display());
        };

        // Boot + load.
        let mut h = egui_kittest::Harness::builder()
            .with_size(egui::vec2(1440.0, 900.0))
            .wgpu()
            .build_state(
                |ctx, app: &mut AscApp| {
                    let mut frame = eframe::Frame::_new_kittest();
                    app.update(ctx, &mut frame);
                },
                AscApp::new(None),
            );
        crate::design::apply(&h.ctx);
        for _ in 0..5 {
            h.step();
        }
        save(&mut h, "01_boot_empty");

        // Load artifact as a background task.
        let ctx0 = h.ctx.clone();
        h.state_mut().open_path(&apk, &ctx0);
        for _ in 0..300 {
            h.step();
            if h.state().session.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for _ in 0..3 {
            h.step();
        }
        assert!(h.state().session.is_some(), "artifact loaded");
        save(&mut h, "02_loaded");

        // Open a class (preview) — syntax-highlighted source + inspector.
        h.state_mut().queue(Command::OpenClass {
            descriptor: "Lcom/google/android/material/timepicker/ClockFaceView;".into(),
            pin: false,
            line: None,
            origin: NavOrigin::Tree,
        });
        for _ in 0..300 {
            h.step();
            if h.state().active_doc.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for _ in 0..3 {
            h.step();
        }
        assert!(h.state().active_doc.is_some(), "class open");
        save(&mut h, "03_class_open");

        // String search with results in the bottom panel.
        {
            let app = h.state_mut();
            app.search.input = "onCreate".into();
            app.queue(Command::RunSearch);
        }
        for _ in 0..300 {
            h.step();
            if h.state().search.results().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for _ in 0..3 {
            h.step();
        }
        save(&mut h, "04_search_results");

        // Find-in-document.
        {
            let app = h.state_mut();
            app.show_find = true;
            app.find_input = "view".into();
            app.recompute_find_matches();
        }
        for _ in 0..2 {
            h.step();
        }
        save(&mut h, "05_find");

        // Quick-open palette with input + selection.
        h.state_mut().queue(Command::QuickOpen);
        for _ in 0..2 {
            h.step();
        }
        h.state_mut().palette_input = "clock".into();
        for _ in 0..2 {
            h.step();
        }
        save(&mut h, "06_palette");

        // Command palette.
        h.state_mut().queue(Command::ToggleCommandPalette);
        for _ in 0..2 {
            h.step();
        }
        save(&mut h, "07_commands");

        // References to the active class (Analysis ▸ Find references).
        h.state_mut().queue(Command::FindReferences);
        for _ in 0..300 {
            h.step();
            if h.state().references.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for _ in 0..3 {
            h.step();
        }
        assert!(h.state().references.is_some(), "references landed");
        save(&mut h, "08_references");
    }

    /// Objective font-coverage audit via egui's own font atlas
    /// (`FontsView::has_glyph`). Any glyph the UI uses must be covered
    /// by the default font stack — otherwise it renders as tofu.
    #[test]
    fn glyph_coverage() {
        // The full inventory of glyphs the UI renders (keep in sync
        // with src/*: grep non-ASCII string literals).
        const USED: &[&str] = &[
            "◀", "▶", "←", "→", "↑", "↓", "◆", "▾", "▸", "×", "●", "⌘", "▲", "▼", "✔", "⚠", "🔍",
            "▤", "☰", "·", "…", "≡", "⚙", "A", "b", "1",
        ];
        // Known-uncovered in egui default fonts — never use these.
        // (◇ IS covered but reads as a stray square outline at small
        // sizes — avoided for legibility, not coverage.)
        const BANNED: &[&str] = &["✕", "⌕", "✓", "⧉", "⋮"];
        let ctx = egui::Context::default();
        // Fonts exist only after a run() — do one empty pass.
        let _ = ctx.run(Default::default(), |_| {});
        let mut missing: Vec<char> = Vec::new();
        ctx.fonts_mut(|f| {
            for cand in USED.iter().chain(BANNED) {
                let ch = cand.chars().next().unwrap();
                let covered = f.has_glyph(&egui::FontId::monospace(20.0), ch);
                let banned = BANNED.contains(cand);
                if banned && covered {
                    panic!("banned glyph {ch:?} is now covered — move it to USED");
                }
                if !banned && !covered {
                    missing.push(ch);
                }
            }
        });
        let tofu = missing;
        for c in &tofu {
            eprintln!("TOFU: {c:?} U+{:04X}", *c as u32);
        }
        assert!(tofu.is_empty(), "uncovered glyphs present: {tofu:?}");
    }

    /// Pixel-level tofu detection: render each glyph ISOLATED at 48px
    /// monospace (the exact tree-row style family). Tofu glyphs all
    /// rasterize to the identical box — so any candidate whose PNG is
    /// byte-identical to a known-tofu control (⌕) is tofu. This
    /// catches what `has_glyph` chain semantics might hide.
    #[test]
    fn glyph_pixel_audit() {
        if std::env::var("ASC_GUI_SHOTS").is_err() {
            eprintln!("ASC_GUI_SHOTS not set; skipping");
            return;
        }
        const GLYPHS: &[&str] = &["◇", "◆", "▸", "▾", "×", "◀", "▶", "⌘", "●", "⌕"];
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/shots");
        std::fs::create_dir_all(&dir).unwrap();
        for (i, g) in GLYPHS.iter().enumerate() {
            let mut h = egui_kittest::Harness::builder()
                .with_size(egui::vec2(64.0, 64.0))
                .build_ui(|ui| {
                    ui.centered_and_justified(|ui| {
                        ui.monospace(egui::RichText::new(*g).size(48.0));
                    });
                });
            h.run();
            let img = h.render().expect("render");
            let path = dir.join(format!("glyph_{i:02}.png"));
            img.save(&path).unwrap();
            eprintln!("px: {}", path.display());
        }
    }

    /// Rasterize candidate glyphs so font coverage can be verified by
    /// eye: `ASC_GUI_SHOTS=1 cargo test -p asc-gui --lib glyph_probe`.
    /// Each row is `NNN` + one candidate glyph.
    #[test]
    fn glyph_probe() {
        if std::env::var("ASC_GUI_SHOTS").is_err() {
            eprintln!("ASC_GUI_SHOTS not set; skipping");
            return;
        }
        const GLYPHS: &[&str] = &[
            "🔍", "🔎", "⌖", "⌾", "⊙", "◎", "◉", "○", "■", "□", "✔", "✗", "⇄", "↻", "⟳", "ℹ", "⚡",
            "☰", "▤", "⚙", "≡", "▰", "▣", "⏵", "⚠",
        ];
        let mut h = egui_kittest::Harness::builder()
            .with_size(egui::vec2(420.0, 720.0))
            .build_ui(|ui| {
                egui::Grid::new("glyphs").num_columns(2).show(ui, |ui| {
                    for (i, g) in GLYPHS.iter().enumerate() {
                        ui.monospace(format!("{:03}", i));
                        ui.monospace(egui::RichText::new(*g).size(22.0));
                        ui.end_row();
                    }
                });
            });
        h.run();
        let img = h.render().expect("render");
        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/shots/09_glyph_probe.png");
        img.save(&out).unwrap();
        eprintln!("probe: {}", out.display());
    }
}
