//! Editor: tab strip (preview/pinned), code surface with gutter, and
//! the find-in-document bar.

use std::sync::Arc;

use eframe::egui;

use crate::app::AscApp;
use crate::command::Command;
use crate::design::DARK as T;
use crate::state::{Document, TabKind, TabStatus};

impl AscApp {
    pub(crate) fn draw_editor(&mut self, ui: &mut egui::Ui) {
        egui::TopBottomPanel::top("editor_tabs")
            .frame(egui::Frame::new().fill(T.surface))
            .show_inside(ui, |ui| {
                self.draw_tab_strip(ui);
            });
        egui::TopBottomPanel::top("editor_find")
            .frame(egui::Frame::new().fill(T.panel_bg))
            .show_inside(ui, |ui| {
                self.draw_find_bar(ui);
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(T.app_bg))
            .show_inside(ui, |ui| {
                self.draw_code_area(ui);
            });
    }

    /// Preview/pinned tab strip.
    fn draw_tab_strip(&mut self, ui: &mut egui::Ui) {
        let mut clicked: Option<String> = None;
        let mut closed: Option<String> = None;
        let mut pinned: Option<String> = None;
        let active = self.tabs.active_descriptor().map(str::to_string);
        let tabs: Vec<(String, TabKind, TabStatus)> = self
            .tabs
            .tabs()
            .iter()
            .map(|t| (t.descriptor.clone(), t.kind, t.status.clone()))
            .collect();
        egui::ScrollArea::horizontal()
            .max_height(T.tab_height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (descriptor, kind, status) in &tabs {
                        let is_active = active.as_deref() == Some(descriptor.as_str());
                        let mut title = egui::RichText::new(super::short_name(descriptor))
                            .monospace()
                            .size(12.0);
                        title = match kind {
                            TabKind::Preview => title.italics(),
                            TabKind::Pinned => title.color(T.text),
                        };
                        if !is_active && *kind == TabKind::Preview {
                            title = title.color(T.text_secondary);
                        }
                        if is_active {
                            title = title.strong();
                        }
                        let pin_glyph = match kind {
                            TabKind::Pinned => "◆ ",
                            TabKind::Preview => "",
                        };
                        let label = format!("{pin_glyph}{}", super::short_name(descriptor));
                        let rich = egui::RichText::new(label).monospace().size(12.0);
                        let rich = match kind {
                            TabKind::Preview => rich.italics(),
                            TabKind::Pinned => rich.color(T.text),
                        };
                        let rich = if is_active {
                            rich.strong().color(T.text)
                        } else {
                            rich.color(T.text_secondary)
                        };
                        let _ = title;
                        let resp = ui
                            .selectable_label(is_active, rich)
                            .on_hover_text(descriptor);
                        if resp.clicked() {
                            clicked = Some(descriptor.clone());
                        }
                        if resp.double_clicked() {
                            pinned = Some(descriptor.clone());
                        }
                        let close = ui
                            .small_button("×")
                            .on_hover_text(format!("close {descriptor}"));
                        if close.clicked() {
                            closed = Some(descriptor.clone());
                        }
                        match status {
                            TabStatus::Loading => {
                                ui.spinner();
                            }
                            TabStatus::Failed(_) => {
                                ui.label(egui::RichText::new("!").small().color(T.error));
                            }
                            TabStatus::Ready => {}
                        }
                        ui.separator();
                    }
                });
            });
        if let Some(d) = clicked {
            self.queue(Command::OpenClass {
                descriptor: d,
                pin: false,
                line: None,
                origin: crate::state::NavOrigin::Tab,
            });
        }
        if let Some(d) = pinned {
            self.tabs.pin(Some(&d));
        }
        if let Some(d) = closed {
            self.close_tab(&d);
        }
    }

    /// Find-in-document bar (Ctrl+F). Substring, case-insensitive,
    /// next/prev over cached match lines.
    fn draw_find_bar(&mut self, ui: &mut egui::Ui) {
        if !self.show_find {
            return;
        }
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("find").small().color(T.text_secondary));
            let changed = ui
                .add(
                    egui::TextEdit::singleline(&mut self.find_input)
                        .desired_width(220.0)
                        .font(egui::TextStyle::Monospace),
                )
                .changed();
            if changed {
                self.recompute_find_matches();
            }
            let total = self.find_matches.len();
            let pos = self.find_index.map(|i| i + 1).unwrap_or(0);
            ui.label(
                egui::RichText::new(format!("{pos}/{total}"))
                    .small()
                    .color(T.text_secondary),
            );
            if ui.button("▲").clicked() {
                self.find_step(false);
            }
            if ui.button("▼").clicked() {
                self.find_step(true);
            }
            let entered = ui.input(|i| i.key_pressed(egui::Key::Enter) && self.show_find);
            if entered {
                self.find_step(true);
            }
            if ui.button("✕").clicked() {
                self.show_find = false;
            }
        });
    }

    /// Code surface: gutter + virtualized highlighted lines. Reads
    /// the active document through one `Arc` — zero source copies.
    fn draw_code_area(&mut self, ui: &mut egui::Ui) {
        // Reconcile the active document with the active tab.
        if let Some(active) = self.tabs.active_descriptor().map(str::to_string) {
            let doc = self.documents.peek(&active);
            match doc {
                Some(d) => {
                    self.active_doc = Some(d);
                }
                None => {
                    // Document not cached (loading, evicted, or failed).
                    if self.active_doc.as_ref().map(|d| d.descriptor.as_str()) != Some(&active)
                        && !self.documents.contains(&active)
                        && !self.tasks.decompile_in_flight(&active).is_some()
                        && !matches!(
                            self.tabs.tabs().iter().find(|t| t.descriptor == active),
                            Some(t) if t.status == TabStatus::Loading || matches!(t.status, TabStatus::Failed(_))
                        )
                    {
                        // Evicted earlier: re-issue on demand.
                        let ctx = ui.ctx().clone();
                        self.spawn_decompile(&active, &ctx);
                    }
                }
            }
        } else {
            self.active_doc = None;
        }

        let doc = self.active_doc.clone();
        let Some(doc) = doc else {
            ui.centered_and_justified(|ui| {
                let msg = match self.tabs.active_descriptor() {
                    Some(d) => format!("decompiling {d}…"),
                    None => "no class open — click a class in the Explorer".to_string(),
                };
                ui.weak(msg);
            });
            return;
        };
        self.draw_code(ui, &doc);
    }

    fn draw_code(&mut self, ui: &mut egui::Ui, doc: &Arc<Document>) {
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace);

        // Highlight the find match / navigation target line.
        let scroll_target = self.nav_or_find_line();
        let pending = self.pending_scroll.take();
        let mut scroll = egui::ScrollArea::both()
            .auto_shrink([false, false])
            .id_salt(("code", doc.descriptor.as_str()));
        if let Some(line) = pending {
            scroll = scroll.vertical_scroll_offset(line as f32 * row_h);
        }
        scroll.show_rows(ui, row_h, doc.line_count(), |ui, range| {
            for idx in range {
                let line = doc.line(idx).unwrap_or("");
                let empty: Vec<crate::highlight::Span> = Vec::new();
                let spans = doc.spans.get(idx).unwrap_or(&empty);
                let is_target = scroll_target == Some(idx);
                let row_frame = if is_target {
                    egui::Frame::new().fill(T.accent.linear_multiply(0.12))
                } else if self.find_matches.contains(&idx) && self.show_find {
                    egui::Frame::new().fill(T.warning.linear_multiply(0.10))
                } else {
                    egui::Frame::new()
                };
                row_frame.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.set_min_height(row_h);
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("{:>5}", idx + 1))
                                    .monospace()
                                    .size(T.code_size)
                                    .color(T.text_disabled),
                            )
                            .selectable(false),
                        );
                        ui.add_space(6.0);
                        ui.add(
                            egui::Label::new(super::spans_to_job(line, spans))
                                .selectable(true)
                                .wrap_mode(egui::TextWrapMode::Extend),
                        );
                    });
                });
            }
        });
    }
}
