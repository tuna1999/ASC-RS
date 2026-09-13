//! eframe `App` implementation: draws the panels, drives worker
//! threads, and applies results back into the [`WorkspaceSession`].
//!
//! ## Layout (single window, three regions)
//!
//! ```text
//! +----------------------+----------------------------+----------------------+
//! | Class tree           | Source tabs                | Findrefs             |
//! | (left panel)         | (center, top)              | query + results      |
//! |                      +----------------------------+ (right panel)        |
//! |                      | Manifest summary           |                      |
//! |                      | (center, bottom)           |                      |
//! +----------------------+----------------------------+----------------------+
//! | Status: search completeness (SearchReport.complete + errors).       |
//! +----------------------------------------------------------------------+
//! ```
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use eframe::egui;

use asc_query::{ClassConstraint, Query};

use crate::session::{ClassEntry, SessionError, SourceTab, WorkspaceSession};
use crate::worker::{spawn_job, Job, JobResult};

/// Main GUI state. Owns the session and any pending worker
/// receivers; eframe calls `update` on every frame.
pub struct AscApp {
    session: WorkspaceSession,
    /// Path input text (top bar — open / reopen APK).
    path_input: String,
    /// Findrefs query input text.
    query_input: String,
    /// Findrefs kind (string / type / method / field) — selected via
    /// a button group.
    query_kind: QueryKind,
    /// Pending findrefs receiver (None when no job in flight).
    pending_findrefs: Option<Receiver<JobResult>>,
    /// Pending getclass receiver.
    pending_getclass: Option<Receiver<JobResult>>,
    /// Last completed findrefs report (displayed in the right panel).
    last_findrefs: Option<FindRefsView>,
    /// Currently selected class (clicked in the left tree).
    selected_class: Option<String>,
    /// Most-recent error message to display in the status bar.
    last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryKind {
    String,
    Type,
    Method,
    Field,
}

/// Cached view of a completed findrefs run, for the right panel.
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
        Self {
            session,
            path_input: String::new(),
            query_input: String::from("ClockFace"),
            query_kind: QueryKind::String,
            pending_findrefs: None,
            pending_getclass: None,
            last_findrefs: None,
            selected_class: None,
            last_error: None,
        }
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
        let label = format!("{:?} {:?}", self.query_kind, self.query_input);
        let rx = spawn_job(Job::FindRefs { apk, query, label });
        self.pending_findrefs = Some(rx);
        ctx.request_repaint_after(std::time::Duration::from_millis(50));
    }

    /// Try to decompile the currently selected class.
    fn start_getclass(&mut self, target: String, ctx: &egui::Context) {
        if self.pending_getclass.is_some() {
            return;
        }
        let apk = self.session.path().to_path_buf();
        let rx = spawn_job(Job::GetClass { apk, target });
        self.pending_getclass = Some(rx);
        ctx.request_repaint_after(std::time::Duration::from_millis(50));
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
                    self.last_findrefs = Some(view);
                    self.pending_findrefs = None;
                    ctx.request_repaint();
                }
                Ok(other) => {
                    self.last_error = Some(format!(
                        "unexpected findrefs result: {other:?}"
                    ));
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
        if let Some(rx) = self.pending_getclass.as_ref() {
            match rx.try_recv() {
                Ok(JobResult::GetClass { target, result }) => {
                    match result {
                        Ok(r) => {
                            if let Err(e) = self.session.open_tab(
                                r.dex_name,
                                target.clone(),
                                r.source,
                            ) {
                                self.last_error = Some(format!("open_tab: {e}"));
                            }
                        }
                        Err(e) => {
                            self.last_error = Some(format!("getclass: {e}"));
                        }
                    }
                    self.pending_getclass = None;
                    ctx.request_repaint();
                }
                Ok(other) => {
                    self.last_error = Some(format!(
                        "unexpected getclass result: {other:?}"
                    ));
                    self.pending_getclass = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(50));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.pending_getclass = None;
                    ctx.request_repaint();
                }
            }
        }
    }
}

impl eframe::App for AscApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Drain any in-flight workers first so the next paint sees
        //    their results.
        self.poll_workers(ctx);

        egui::TopBottomPanel::top("topbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("APK:");
                let resp = ui.text_edit_singleline(&mut self.path_input);
                if resp.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter))
                {
                    let p = PathBuf::from(self.path_input.trim());
                    match WorkspaceSession::open(&p) {
                        Ok(s) => {
                            *self = AscApp::new(s);
                            self.path_input = p.display().to_string();
                        }
                        Err(e) => {
                            self.last_error = Some(format!("open: {e}"));
                        }
                    }
                }
                ui.label(format!("open: {}", self.session.path().display()));
            });
        });

        egui::TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(err) = &self.last_error {
                    ui.colored_label(egui::Color32::RED, format!("error: {err}"));
                } else if let Some(fr) = &self.last_findrefs {
                    if fr.complete && fr.error_count == 0 {
                        ui.colored_label(
                            egui::Color32::GREEN,
                            format!("findrefs complete: {} caller lines", fr.line_count),
                        );
                    } else {
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            format!(
                                "findrefs INCOMPLETE: {} lines, {} errors",
                                fr.line_count, fr.error_count
                            ),
                        );
                    }
                } else {
                    ui.label("idle — run a findrefs query in the right panel");
                }
            });
        });

        egui::SidePanel::left("class_tree")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                ui.heading("Classes");
                ui.label(format!(
                    "{} DEX(es), up to N open tabs",
                    self.session.dex_entries().len()
                ));
                let classes = self.session.all_classes();
                match classes {
                    Ok(list) => {
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for c in list.iter().take(2000) {
                                if ui
                                    .selectable_label(
                                        self.selected_class.as_deref() == Some(&c.descriptor),
                                        &c.descriptor,
                                    )
                                    .clicked()
                                {
                                    self.selected_class = Some(c.descriptor.clone());
                                }
                            }
                            if list.len() > 2000 {
                                ui.label(format!("… and {} more", list.len() - 2000));
                            }
                        });
                    }
                    Err(e) => {
                        ui.colored_label(egui::Color32::RED, format!("classes: {e}"));
                    }
                }
            });

        egui::SidePanel::right("findrefs")
            .resizable(true)
            .default_width(320.0)
            .show(ctx, |ui| {
                ui.heading("Findrefs");
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.query_kind, QueryKind::String, "string");
                    ui.selectable_value(&mut self.query_kind, QueryKind::Type, "type");
                    ui.selectable_value(&mut self.query_kind, QueryKind::Method, "method");
                    ui.selectable_value(&mut self.query_kind, QueryKind::Field, "field");
                });
                ui.text_edit_singleline(&mut self.query_input);
                if ui.button("Run").clicked() {
                    self.start_findrefs(ctx);
                }
                if let Some(fr) = &self.last_findrefs {
                    ui.separator();
                    ui.label(format!("query: {}", fr.label));
                    ui.label(format!("caller lines: {}", fr.line_count));
                    ui.label(format!("complete: {}", fr.complete));
                    ui.label(format!("errors: {}", fr.error_count));
                    if !fr.errors.is_empty() {
                        egui::ScrollArea::vertical()
                            .max_height(120.0)
                            .show(ui, |ui| {
                                for e in &fr.errors {
                                    ui.label(e);
                                }
                            });
                    }
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(sel) = &self.selected_class {
                    if ui.button(format!("Decompile {sel}")).clicked() {
                        self.start_getclass(sel.clone(), ctx);
                    }
                }
                ui.label(format!(
                    "{} tab(s) open",
                    self.session.open_tabs().len()
                ));
            });
            ui.separator();
            let tabs = self.session.open_tabs();
            if tabs.is_empty() {
                ui.label("No source tabs open — click a class on the left, then press Decompile.");
                return;
            }
            for tab in &tabs {
                draw_source_tab(ui, tab);
                ui.separator();
            }
        });
    }
}

fn draw_source_tab(ui: &mut egui::Ui, tab: &SourceTab) {
    ui.collapsing(
        format!("{} :: {}", tab.dex_name, tab.descriptor),
        |ui| {
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .show(ui, |ui| {
                    ui.monospace(&tab.source);
                });
        },
    );
}

/// Helper: list classes for a session as `Vec<ClassEntry>` (re-export
/// for use by tests that want to avoid the workspace-session type
/// directly).
pub fn list_classes(session: &WorkspaceSession) -> Result<Vec<ClassEntry>, SessionError> {
    session.all_classes()
}