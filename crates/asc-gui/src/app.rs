//! eframe `App` implementation — jadx-style IDE layout.
//!
//! ```text
//! +----------------------------------------------------------------------+
//! | File  View  Help                                                     |
//! +----------------------------------------------------------------------+
//! | [Open…] [◀ Back] [▶ Forward]                    pkg vN · N classes   |
//! +------------------+----------------------------------+---------------+
//! | Source           | Foo ×  Bar ×                     | Outline       |
//! | [filter box…]    |  1 | package com.foo;             |  fields       |
//! | ▾ com            |  2 |                               |  methods      |
//! |   ▾ google       |  3 | public class Foo {            |  (click =     |
//! |     Foo          |  4 |   …                            |   jump)       |
//! +------------------+----------------------------------+---------------+
//! | Findrefs: (kind) [query………] [Run] results / errors                  |
//! +----------------------------------------------------------------------+
//! | status: last op result · completeness (SearchReport) · tab count    |
//! +----------------------------------------------------------------------+
//! ```
//!
//! Interaction model (matching jadx habits):
//! - Single click on a class in the tree opens (and decompiles) it in
//!   a new tab; tabs are LRU-bounded by the session.
//! - Back/Forward (toolbar or Ctrl+←/→) walk the visited-class history.
//! - Outline entries jump the code view to their line.
//! - The class filter switches the tree to a flat match list.

use std::collections::BTreeSet;
use std::sync::mpsc::Receiver;

use eframe::egui;

use asc_query::{ClassConstraint, Query};

use crate::highlight::{self, OutlineEntry, Token};
use crate::package_tree::PackageTree;
use crate::session::{ClassEntry, MAX_OPEN_TABS, SessionError, SourceTab, WorkspaceSession};
use crate::worker::{Job, JobResult, spawn_job};

/// One syntax span: byte range + flavor (mirrors `highlight::Token`).
type Span = (usize, usize, Token);

/// Main GUI state. Owns the session and any pending worker
/// receivers; eframe calls `update` on every frame.
pub struct AscApp {
    session: WorkspaceSession,
    /// Package tree (left panel), built once per session.
    tree: PackageTree,
    /// Manifest summary for the toolbar (None when unparsable).
    manifest: Option<asc_manifest::ManifestInfo>,
    /// Class-name filter (tree switches to flat list while non-empty).
    tree_filter: String,
    /// Manually expanded package/class nodes (by node path).
    expanded: BTreeSet<String>,
    /// Findrefs query input text.
    query_input: String,
    /// Findrefs kind — selected via combo box.
    query_kind: QueryKind,
    /// Pending findrefs receiver (None when no job in flight).
    pending_findrefs: Option<Receiver<JobResult>>,
    /// Pending getclass receivers (multiple clicks may queue jobs).
    pub(crate) pending_getclass: Vec<Receiver<JobResult>>,
    /// Descriptor whose tab we are waiting to activate once it lands.
    want_active: Option<String>,
    /// Last completed findrefs report (displayed in the bottom panel).
    last_findrefs: Option<FindRefsView>,
    /// Currently selected class (highlighted in the tree).
    selected_class: Option<String>,
    /// Descriptor of the visible tab (one tab visible at a time).
    active_tab: Option<String>,
    /// Per-line syntax spans for the active tab (parallel to its lines).
    active_spans: Vec<Vec<Span>>,
    /// Outline of the active tab's source.
    active_outline: Vec<OutlineEntry>,
    /// Navigation history (descriptors) + cursor for Back/Forward.
    nav_history: Vec<String>,
    nav_pos: usize,
    /// Outline click target: scroll the code view to this line.
    pending_scroll: Option<usize>,
    /// View menu toggles.
    show_outline: bool,
    show_findrefs: bool,
    /// Findrefs error list visibility.
    show_errors: bool,
    /// Most-recent error message (status bar).
    last_error: Option<String>,
    /// Status bar content with an "ok" flag.
    status: Option<StatusLine>,
}

/// One-line status message with sentiment.
struct StatusLine {
    text: String,
    ok: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryKind {
    String,
    Type,
    Method,
    Field,
}

impl QueryKind {
    fn label(self) -> &'static str {
        match self {
            QueryKind::String => "string",
            QueryKind::Type => "type",
            QueryKind::Method => "method",
            QueryKind::Field => "field",
        }
    }
}

/// Cached view of a completed findrefs run, for the bottom panel.
struct FindRefsView {
    label: String,
    line_count: usize,
    complete: bool,
    error_count: usize,
    errors: Vec<String>,
}

impl AscApp {
    /// Build the app around an already-opened session.
    pub fn new(session: WorkspaceSession) -> Self {
        let manifest = asc_manifest::parse_from_apk(session.path()).ok();
        let tree = PackageTree::build(session.all_classes().unwrap_or_default());
        Self {
            session,
            tree,
            manifest,
            tree_filter: String::new(),
            expanded: BTreeSet::new(),
            query_input: String::from("ClockFace"),
            query_kind: QueryKind::String,
            pending_findrefs: None,
            pending_getclass: Vec::new(),
            want_active: None,
            last_findrefs: None,
            selected_class: None,
            active_tab: None,
            active_spans: Vec::new(),
            active_outline: Vec::new(),
            nav_history: Vec::new(),
            nav_pos: 0,
            pending_scroll: None,
            show_outline: true,
            show_findrefs: true,
            show_errors: false,
            last_error: None,
            status: None,
        }
    }

    /// Replace the whole session (Open… / Reload) and reset view state.
    fn load_session(&mut self, session: WorkspaceSession) {
        *self = AscApp::new(session);
    }

    /// Status bar setter.
    fn set_status(&mut self, text: impl Into<String>, ok: bool) {
        self.status = Some(StatusLine {
            text: text.into(),
            ok,
        });
    }

    /// Try to start a findrefs job on a worker thread.
    fn start_findrefs(&mut self, ctx: &egui::Context) {
        if self.pending_findrefs.is_some() {
            return;
        }
        let apk = self.session.path().to_path_buf();
        let query = match self.query_kind {
            QueryKind::String => Query::string(self.query_input.clone()),
            QueryKind::Type => Query::type_(self.query_input.clone()),
            QueryKind::Method => Query::method(
                Some(self.query_input.clone()),
                Some(ClassConstraint::new_exact(String::new())),
            ),
            QueryKind::Field => Query::field(
                Some(self.query_input.clone()),
                Some(ClassConstraint::new_exact(String::new())),
            ),
        };
        let label = format!("{} \"{}\"", self.query_kind.label(), self.query_input);
        let rx = spawn_job(Job::FindRefs { apk, query, label });
        self.pending_findrefs = Some(rx);
        self.set_status(format!("findrefs running: {}", self.query_input), true);
        ctx.request_repaint_after(std::time::Duration::from_millis(50));
    }

    /// Try to decompile the given class on a worker thread.
    fn start_getclass(&mut self, target: String, ctx: &egui::Context) {
        let apk = self.session.path().to_path_buf();
        let rx = spawn_job(Job::GetClass { apk, target });
        self.pending_getclass.push(rx);
        ctx.request_repaint_after(std::time::Duration::from_millis(50));
    }

    /// Open (and decompile if needed) a class tab. `push_nav` controls
    /// whether the visit enters the Back/Forward history (false while
    /// walking history itself).
    fn open_class(&mut self, descriptor: &str, ctx: &egui::Context, push_nav: bool) {
        self.selected_class = Some(descriptor.to_string());
        let open = self
            .session
            .open_tabs()
            .iter()
            .any(|t| t.descriptor == descriptor);
        if open {
            self.activate(descriptor);
        } else {
            self.want_active = Some(descriptor.to_string());
            self.set_status(format!("decompiling {descriptor}…"), true);
            self.start_getclass(descriptor.to_string(), ctx);
        }
        if push_nav {
            // Truncate the forward tail, then push.
            self.nav_history.truncate(self.nav_pos + 1);
            if self.nav_history.last().map(String::as_str) != Some(descriptor) {
                self.nav_history.push(descriptor.to_string());
            }
            self.nav_pos = self.nav_history.len() - 1;
        }
    }

    /// Make `descriptor` the visible tab, (re)computing its syntax
    /// spans and outline.
    fn activate(&mut self, descriptor: &str) {
        self.active_tab = Some(descriptor.to_string());
        let Some(tab) = self.tab_by_descriptor(descriptor) else {
            self.active_spans.clear();
            self.active_outline.clear();
            return;
        };
        let mut block = false;
        self.active_spans = tab
            .source
            .lines()
            .map(|line| {
                let mut spans = highlight::tokenize_line(line, &mut block);
                spans.retain(|(s, e, _)| e > s);
                spans
            })
            .collect();
        self.active_outline = highlight::outline(&tab.source);
        self.pending_scroll = Some(0);
    }

    /// Find the open tab for a descriptor (clone).
    fn tab_by_descriptor(&self, descriptor: &str) -> Option<SourceTab> {
        self.session
            .open_tabs()
            .into_iter()
            .find(|t| t.descriptor == descriptor)
    }

    /// Close a tab; activate a neighbor when the visible one closed.
    fn close_tab(&mut self, descriptor: &str) {
        self.session.close_tab(descriptor);
        if self.active_tab.as_deref() == Some(descriptor) {
            self.active_tab = None;
            self.active_spans.clear();
            self.active_outline.clear();
            if let Some(t) = self.session.open_tabs().pop() {
                self.activate(&t.descriptor);
            }
        }
        self.nav_history.retain(|d| d != descriptor);
        self.nav_pos = self.nav_pos.min(self.nav_history.len().saturating_sub(1));
    }

    /// Go back/forward in history.
    fn nav(&mut self, delta: isize, ctx: &egui::Context) {
        let target = self
            .nav_pos
            .checked_add_signed(delta)
            .filter(|&p| p < self.nav_history.len());
        if let Some(pos) = target {
            self.nav_pos = pos;
            let d = self.nav_history[pos].clone();
            self.open_class(&d, ctx, false);
        }
    }

    /// Poll pending workers (non-blocking); apply results when ready.
    fn poll_workers(&mut self, ctx: &egui::Context) {
        if let Some(rx) = self.pending_findrefs.as_ref() {
            match rx.try_recv() {
                Ok(JobResult::FindRefs { label, report }) => {
                    let view = match report {
                        Ok(r) => FindRefsView {
                            label,
                            line_count: r.total_lines(),
                            complete: r.complete,
                            error_count: r.errors.len(),
                            errors: r.errors.iter().map(|e| e.to_string()).collect(),
                        },
                        Err(e) => {
                            self.last_error = Some(format!("findrefs: {e}"));
                            FindRefsView {
                                label,
                                line_count: 0,
                                complete: false,
                                error_count: 1,
                                errors: vec![e.to_string()],
                            }
                        }
                    };
                    if view.complete && view.error_count == 0 {
                        self.set_status(
                            format!("findrefs: {} caller lines", view.line_count),
                            true,
                        );
                    } else {
                        self.set_status(
                            format!(
                                "findrefs INCOMPLETE: {} lines, {} errors",
                                view.line_count, view.error_count
                            ),
                            false,
                        );
                    }
                    self.last_findrefs = Some(view);
                    self.pending_findrefs = None;
                    ctx.request_repaint();
                }
                Ok(other) => {
                    self.last_error = Some(format!("unexpected findrefs result: {other:?}"));
                    self.pending_findrefs = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(50));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.pending_findrefs = None;
                    ctx.request_repaint();
                }
            }
        }
        let pending = std::mem::take(&mut self.pending_getclass);
        for rx in pending {
            match rx.try_recv() {
                Ok(JobResult::GetClass { target, result }) => {
                    match result {
                        Ok(r) => {
                            if let Err(e) =
                                self.session.open_tab(r.dex_name, target.clone(), r.source)
                            {
                                self.last_error = Some(format!("open_tab: {e}"));
                            }
                            // Activate if this is the tab the user is
                            // waiting for (or the first one).
                            if self.want_active.as_deref() == Some(target.as_str())
                                || self.active_tab.is_none()
                            {
                                self.want_active = None;
                                self.activate(&target);
                                self.set_status(format!("decompiled {target}"), true);
                            }
                        }
                        Err(e) => {
                            self.want_active = None;
                            self.last_error = Some(format!("getclass: {e}"));
                            self.set_status(format!("getclass failed: {e}"), false);
                        }
                    }
                    ctx.request_repaint();
                }
                Ok(other) => {
                    self.last_error = Some(format!("unexpected getclass result: {other:?}"));
                    ctx.request_repaint();
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending_getclass.push(rx);
                    ctx.request_repaint_after(std::time::Duration::from_millis(50));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    ctx.request_repaint();
                }
            }
        }
    }

    /// Left panel: jadx-style Source tree with filter.
    fn draw_source_tree(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Source");
        ui.add(
            egui::TextEdit::singleline(&mut self.tree_filter)
                .hint_text("🔍 Filter classes…")
                .desired_width(f32::INFINITY),
        );
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            let filter = self.tree_filter.trim().to_string();
            if filter.is_empty() {
                let children: Vec<usize> = self
                    .tree
                    .node(self.tree.root())
                    .children
                    .values()
                    .copied()
                    .collect();
                for idx in children {
                    self.draw_tree_node(ui, idx, 0, ctx);
                }
            } else {
                let hits = self.tree.filter(&filter);
                if hits.is_empty() {
                    ui.weak(format!("no classes matching “{filter}”"));
                } else {
                    ui.weak(format!("{} match(es)", hits.len()));
                    for leaf in hits.into_iter().take(500) {
                        let desc = self.tree.entry(leaf).descriptor.clone();
                        let label = short_name(&desc);
                        let selected = self.selected_class.as_deref() == Some(desc.as_str());
                        if class_row(ui, selected, &label) {
                            self.open_class(&desc, ctx, true);
                        }
                    }
                }
            }
        });
    }

    /// One package/class node in the tree.
    fn draw_tree_node(&mut self, ui: &mut egui::Ui, idx: usize, depth: usize, ctx: &egui::Context) {
        // Clone the small bits we need so `self` is free to mutate.
        let (label, path, is_class, has_children, own_desc) = {
            let n = self.tree.node(idx);
            (
                n.label.clone(),
                n.path.clone(),
                n.is_class,
                !n.children.is_empty(),
                n.class_leaves
                    .first()
                    .map(|&l| self.tree.entry(l).descriptor.clone()),
            )
        };
        let is_open = self.expanded.contains(&path);
        let mut toggled = false;
        ui.horizontal(|ui| {
            ui.add_space(depth as f32 * 14.0);
            if has_children {
                let glyph = if is_open { "▾" } else { "▸" };
                if ui.small_button(glyph).clicked() {
                    toggled = true;
                }
            } else {
                ui.label(" ");
            }
            if let Some(desc) = own_desc {
                let selected = self.selected_class.as_deref() == Some(desc.as_str());
                if class_row(ui, selected, &label) {
                    self.open_class(&desc, ctx, true);
                }
            } else if is_class {
                ui.weak(&label);
            } else {
                let text = egui::RichText::new(format!("📦 {label}")).strong();
                if ui.selectable_label(false, text).clicked() {
                    toggled = true;
                }
            }
        });
        if toggled {
            if is_open {
                self.expanded.remove(&path);
            } else {
                self.expanded.insert(path);
            }
        }
        let open_now = if toggled { !is_open } else { is_open };
        if has_children && open_now {
            let children: Vec<usize> = self.tree.node(idx).children.values().copied().collect();
            for child in children {
                self.draw_tree_node(ui, child, depth + 1, ctx);
            }
        }
    }

    /// Central panel: tab strip + code view.
    fn draw_code_area(&mut self, ui: &mut egui::Ui) {
        let tabs = self.session.open_tabs();
        // Reconcile active tab with eviction.
        if let Some(active) = self.active_tab.clone() {
            if !tabs.iter().any(|t| t.descriptor == active) {
                self.active_tab = tabs.last().map(|t| t.descriptor.clone());
            }
        }
        if self.active_tab.is_none() {
            self.active_tab = tabs.last().map(|t| t.descriptor.clone());
            if let Some(d) = self.active_tab.clone() {
                self.activate(&d);
            }
        }

        // --- tab strip ---
        let mut clicked: Option<String> = None;
        let mut close: Option<String> = None;
        let active = self.active_tab.clone();
        egui::ScrollArea::horizontal()
            .id_salt("tabstrip")
            .max_height(26.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for tab in &tabs {
                        let is_active = active.as_deref() == Some(tab.descriptor.as_str());
                        let title = egui::RichText::new(short_name(&tab.descriptor)).monospace();
                        let title = if is_active { title.strong() } else { title };
                        if ui
                            .selectable_label(is_active, title)
                            .on_hover_text(&tab.descriptor)
                            .clicked()
                        {
                            clicked = Some(tab.descriptor.clone());
                        }
                        if ui
                            .small_button("×")
                            .on_hover_text(format!("close {}", tab.descriptor))
                            .clicked()
                        {
                            close = Some(tab.descriptor.clone());
                        }
                        ui.separator();
                    }
                });
            });
        ui.separator();
        if let Some(d) = clicked {
            self.activate(&d);
        }
        if let Some(d) = close {
            self.close_tab(&d);
        }

        // --- code view ---
        let tab = active
            .or_else(|| tabs.last().map(|t| t.descriptor.clone()))
            .and_then(|d| tabs.iter().find(|t| t.descriptor == d).cloned());
        match tab {
            Some(tab) => self.draw_code(ui, &tab),
            None => {
                ui.centered_and_justified(|ui| {
                    ui.weak("No class open.\nClick a class in the Source tree to decompile it.")
                });
            }
        }
    }

    /// The code editor surface: gutter + highlighted lines.
    fn draw_code(&mut self, ui: &mut egui::Ui, tab: &SourceTab) {
        let lines: Vec<&str> = tab.source.lines().collect();
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace);

        let pending = self.pending_scroll.take();
        let mut scroll = egui::ScrollArea::both()
            .auto_shrink([false, false])
            .id_salt(("code", tab.key.as_str()));
        if let Some(line) = pending {
            scroll = scroll.vertical_scroll_offset(line as f32 * row_h);
        }
        scroll.show_rows(ui, row_h, lines.len(), |ui, range| {
            let (start, end) = (range.start, range.end);
            for (i, line) in lines[start..end].iter().enumerate() {
                let idx = start + i;
                let spans = self.active_spans.get(idx).cloned().unwrap_or_default();
                ui.horizontal(|ui| {
                    ui.set_min_height(row_h);
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(format!("{:>5}", idx + 1))
                                .monospace()
                                .weak(),
                        )
                        .selectable(false),
                    );
                    ui.add_space(6.0);
                    ui.add(
                        egui::Label::new(spans_to_job(line, &spans))
                            .selectable(true)
                            .wrap_mode(egui::TextWrapMode::Extend),
                    );
                });
            }
        });
    }

    /// Right panel: outline of the active class.
    fn draw_outline(&mut self, ui: &mut egui::Ui) {
        ui.heading("Outline");
        if self.active_outline.is_empty() {
            ui.weak("open a class to see its structure");
            return;
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut jump: Option<usize> = None;
            for e in &self.active_outline {
                let glyph = if e.is_field { "○" } else { "▶" };
                let text = egui::RichText::new(format!("{glyph} {}", e.text))
                    .monospace()
                    .size(12.5);
                if ui
                    .selectable_label(false, text)
                    .on_hover_text(format!("line {}", e.line + 1))
                    .clicked()
                {
                    jump = Some(e.line);
                }
            }
            if let Some(line) = jump {
                self.pending_scroll = Some(line);
            }
        });
    }

    /// Bottom panel: findrefs query + results (jadx "search" style).
    fn draw_findrefs(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.heading("Findrefs");
            egui::ComboBox::from_id_salt("query_kind")
                .selected_text(self.query_kind.label())
                .width(80.0)
                .show_ui(ui, |ui| {
                    for (kind, label) in [
                        (QueryKind::String, "string"),
                        (QueryKind::Type, "type"),
                        (QueryKind::Method, "method"),
                        (QueryKind::Field, "field"),
                    ] {
                        ui.selectable_value(&mut self.query_kind, kind, label);
                    }
                });
            let query_resp = ui.add(
                egui::TextEdit::singleline(&mut self.query_input)
                    .hint_text("pattern…")
                    .desired_width(220.0),
            );
            let run = ui.button("Run");
            let enter = query_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (run.clicked() || enter) && !self.query_input.trim().is_empty() {
                self.start_findrefs(ctx);
            }
            if self.pending_findrefs.is_some() {
                ui.spinner();
            }
            if let Some(fr) = &self.last_findrefs {
                let badge = if fr.complete && fr.error_count == 0 {
                    egui::RichText::new(format!("✓ {} caller lines", fr.line_count))
                        .color(egui::Color32::LIGHT_GREEN)
                } else {
                    egui::RichText::new(format!(
                        "⚠ {} lines, {} errors",
                        fr.line_count, fr.error_count
                    ))
                    .color(egui::Color32::YELLOW)
                };
                let badge_resp = ui.label(badge);
                badge_resp.on_hover_text(format!("query: {}", fr.label));
                if !fr.errors.is_empty() && ui.button("errors…").clicked() {
                    self.show_errors = !self.show_errors;
                }
            }
        });
        if self.show_errors {
            if let Some(fr) = &self.last_findrefs {
                ui.separator();
                egui::ScrollArea::vertical()
                    .max_height(90.0)
                    .show(ui, |ui| {
                        for e in &fr.errors {
                            ui.colored_label(egui::Color32::YELLOW, e);
                        }
                    });
            }
        }
    }

    /// Native file dialog → new session.
    fn pick_and_open(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Android package", &["apk"])
            .pick_file()
        else {
            return;
        };
        match WorkspaceSession::open(&path) {
            Ok(s) => self.load_session(s),
            Err(e) => {
                self.last_error = Some(format!("open: {e}"));
                self.set_status(format!("open failed: {e}"), false);
            }
        }
    }
}

/// A clickable class row in the tree; returns true when clicked.
fn class_row(ui: &mut egui::Ui, selected: bool, label: &str) -> bool {
    let text = egui::RichText::new(format!("◈ {label}"))
        .monospace()
        .size(13.0);
    ui.selectable_label(selected, text).clicked()
}

/// `Lcom/foo/Bar$Baz;` → `Bar$Baz`.
fn short_name(descriptor: &str) -> String {
    let d = descriptor.trim_start_matches('L');
    let d = d.strip_suffix(';').unwrap_or(d);
    match d.rfind('/') {
        Some(pos) => d[pos + 1..].to_string(),
        None => d.to_string(),
    }
}

fn spans_to_job(line: &str, spans: &[Span]) -> egui::text::LayoutJob {
    let font = egui::FontId::monospace(13.0);
    let plain = egui::TextFormat {
        font_id: font.clone(),
        color: highlight::token_color(Token::Plain),
        ..Default::default()
    };
    let mut job = egui::text::LayoutJob::default();
    let mut cursor = 0usize;
    for (start, end, tok) in spans {
        if *start > cursor {
            job.append(&line[cursor..*start], 0.0, plain.clone());
        }
        job.append(
            &line[*start..*end],
            0.0,
            egui::TextFormat {
                font_id: font.clone(),
                color: highlight::token_color(*tok),
                ..Default::default()
            },
        );
        cursor = *end;
    }
    if cursor < line.len() {
        job.append(&line[cursor..], 0.0, plain);
    }
    job.wrap = egui::text::TextWrapping {
        max_width: f32::INFINITY,
        max_rows: usize::MAX,
        break_anywhere: false,
        overflow_character: None,
    };
    job
}

/// Helper: list classes for a session as `Vec<ClassEntry>` (re-export
/// for use by tests that want to avoid the workspace-session type
/// directly).
pub fn list_classes(session: &WorkspaceSession) -> Result<Vec<ClassEntry>, SessionError> {
    session.all_classes()
}

impl eframe::App for AscApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Drain any in-flight workers first so the next paint sees
        //    their results.
        self.poll_workers(ctx);

        // 2. Menu bar.
        egui::TopBottomPanel::top("menubar").show(ctx, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open APK…  (Ctrl+O)").clicked() {
                        ui.close();
                        self.pick_and_open();
                    }
                    if ui.button("Reload APK").clicked() {
                        let p = self.session.path().to_path_buf();
                        match WorkspaceSession::open(&p) {
                            Ok(s) => self.load_session(s),
                            Err(e) => {
                                self.last_error = Some(format!("reload: {e}"));
                                self.set_status(format!("reload failed: {e}"), false);
                            }
                        }
                        ui.close();
                    }
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.toggle_value(&mut self.show_outline, "Outline panel");
                    ui.toggle_value(&mut self.show_findrefs, "Findrefs panel");
                });
                ui.menu_button("Help", |ui| {
                    ui.label("ASC-RS — native Rust APK analysis");
                    ui.weak(format!("open: {}", self.session.path().display()));
                    ui.weak(format!("{} classes", self.tree.len()));
                });
            });
        });

        // 3. Toolbar.
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .button("📂 Open")
                    .on_hover_text("open another APK (Ctrl+O)")
                    .clicked()
                {
                    self.pick_and_open();
                }
                let back = ui.button("◀ Back").on_hover_text("previous class (Ctrl+←)");
                if back.clicked() {
                    self.nav(-1, ctx);
                }
                let fwd = ui.button("Forward ▶").on_hover_text("next class (Ctrl+→)");
                if fwd.clicked() {
                    self.nav(1, ctx);
                }
                // Keyboard shortcuts.
                let ctrl_o = ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::O));
                let ctrl_left =
                    ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::ArrowLeft));
                let ctrl_right =
                    ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::ArrowRight));
                if ctrl_o {
                    self.pick_and_open();
                } else if ctrl_left {
                    self.nav(-1, ctx);
                } else if ctrl_right {
                    self.nav(1, ctx);
                }
                // Right-aligned APK meta.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let pkg = self
                        .manifest
                        .as_ref()
                        .and_then(|m| m.package.clone())
                        .unwrap_or_else(|| "unknown pkg".to_string());
                    let ver = self
                        .manifest
                        .as_ref()
                        .and_then(|m| m.version_code)
                        .map(|v| format!(" v{v}"))
                        .unwrap_or_default();
                    let tabs = self.session.open_tabs().len();
                    ui.weak(format!(
                        "{pkg}{ver} · {} classes · {} dex · {tabs}/{} tabs",
                        self.tree.len(),
                        self.session.dex_entries().len(),
                        MAX_OPEN_TABS
                    ));
                });
            });
        });

        // 4. Bottom: findrefs + status.
        if self.show_findrefs {
            egui::TopBottomPanel::bottom("findrefs")
                .resizable(true)
                .default_height(64.0)
                .show(ctx, |ui| {
                    self.draw_findrefs(ui, ctx);
                });
        }
        egui::TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
            ui.horizontal(|ui| match &self.status {
                Some(s) if s.ok => {
                    ui.colored_label(egui::Color32::LIGHT_GREEN, &s.text);
                }
                Some(s) => {
                    ui.colored_label(egui::Color32::YELLOW, &s.text);
                }
                None => {
                    if let Some(err) = &self.last_error {
                        ui.colored_label(egui::Color32::RED, format!("error: {err}"));
                    } else {
                        ui.weak("ready");
                    }
                }
            });
        });

        // 5. Right: outline.
        if self.show_outline {
            egui::SidePanel::right("outline")
                .resizable(true)
                .default_width(240.0)
                .show(ctx, |ui| {
                    self.draw_outline(ui);
                });
        }

        // 6. Left: source tree.
        egui::SidePanel::left("source_tree")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                self.draw_source_tree(ui, ctx);
            });

        // 7. Center: tabs + code.
        egui::CentralPanel::default().show(ctx, |ui| {
            self.draw_code_area(ui);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (user-reported): clicking a class in the left panel
    /// must lead to an open source tab. Exercises the exact queue →
    /// worker → poll → `open_tab` path `update` drives, headless
    /// (`egui::Context::default()` needs no window).
    #[test]
    fn getclass_job_opens_source_tab() {
        let apk =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/apk/workload.apk");
        if !apk.exists() {
            eprintln!("corpus fixture missing; skipping");
            return;
        }
        let session = WorkspaceSession::open(&apk).expect("open");
        let mut app = AscApp::new(session);
        let ctx = egui::Context::default();

        let target = "Lcom/google/android/material/timepicker/ClockFaceView;".to_string();
        // A second, different class to prove the queue drains both.
        let other = app
            .session
            .all_classes()
            .expect("classes")
            .into_iter()
            .map(|c| c.descriptor)
            .find(|d| d != &target)
            .expect("at least two distinct classes");

        app.start_getclass(target.clone(), &ctx);
        app.start_getclass(other.clone(), &ctx);
        assert_eq!(app.pending_getclass.len(), 2, "both jobs queued");

        // Poll until both workers reply (bounded wait).
        for _ in 0..600 {
            app.poll_workers(&ctx);
            if app.session.open_tabs().len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let tabs = app.session.open_tabs();
        for want in [&target, &other] {
            let tab = tabs
                .iter()
                .find(|t| &t.descriptor == want)
                .unwrap_or_else(|| panic!("tab for {want} must open; got {tabs:?}"));
            assert!(!tab.source.is_empty(), "source for {want} non-empty");
        }
        assert!(
            app.last_error.is_none(),
            "unexpected error: {:?}",
            app.last_error
        );
    }

    /// open_class on a class with an open tab activates immediately
    /// (no worker job queued) and builds outline + spans.
    #[test]
    fn open_class_with_existing_tab_activates_without_job() {
        let apk =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/apk/workload.apk");
        if !apk.exists() {
            eprintln!("corpus fixture missing; skipping");
            return;
        }
        let session = WorkspaceSession::open(&apk).expect("open");
        let mut app = AscApp::new(session);
        let ctx = egui::Context::default();
        let d = "Lcom/google/android/material/timepicker/ClockFaceView;";

        // Seed an open tab directly (bypassing the worker).
        app.session
            .open_tab(
                "classes.dex".to_string(),
                d.to_string(),
                "public class ClockFaceView {\n    int mClock;\n}\n".to_string(),
            )
            .expect("seed tab");
        app.open_class(d, &ctx, true);
        assert!(app.pending_getclass.is_empty(), "no job for open tab");
        assert_eq!(app.active_tab.as_deref(), Some(d));
        assert!(
            app.active_outline.iter().any(|e| e.text.contains("mClock")),
            "outline has the field: {:?}",
            app.active_outline
        );
        assert_eq!(app.active_spans.len(), 3, "one span-row per source line");
    }

    /// History: open_class pushes; nav(-1) walks back without pushing.
    #[test]
    fn navigation_history_back_forward() {
        let apk =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/apk/workload.apk");
        if !apk.exists() {
            eprintln!("corpus fixture missing; skipping");
            return;
        }
        let session = WorkspaceSession::open(&apk).expect("open");
        let mut app = AscApp::new(session);
        let ctx = egui::Context::default();

        // Nonexistent classes: jobs will fail later, but history must
        // still behave.
        app.open_class("La;", &ctx, true);
        app.open_class("Lb;", &ctx, true);
        assert_eq!(app.nav_history, vec!["La;".to_string(), "Lb;".to_string()]);
        assert_eq!(app.nav_pos, 1);
        app.nav(-1, &ctx);
        assert_eq!(app.nav_pos, 0, "back moved cursor");
        app.nav(1, &ctx);
        assert_eq!(app.nav_pos, 1, "forward restored cursor");
        // Push from the middle truncates the forward tail.
        app.nav(-1, &ctx);
        app.open_class("Lc;", &ctx, true);
        assert_eq!(app.nav_history, vec!["La;".to_string(), "Lc;".to_string()]);
    }

    /// spans_to_job covers the whole line (no dropped gaps).
    #[test]
    fn spans_to_job_covers_line() {
        let spans = vec![
            (0usize, 6usize, Token::Keyword),
            (7usize, 9usize, Token::Number),
        ];
        let job = spans_to_job("return 42;", &spans);
        assert_eq!(job.text, "return 42;");
        assert_eq!(job.sections.len(), 4, "keyword + gap + number + trailing ;");
        // Empty span list → single plain section.
        let job = spans_to_job("plain only", &[]);
        assert_eq!(job.text, "plain only");
        assert_eq!(job.sections.len(), 1);
    }
}
