//! Editor: tab strip (preview/pinned), code surface with gutter, and
//! the find-in-document bar.

use std::sync::Arc;

use eframe::egui;

use crate::app::AscApp;
use crate::command::Command;
use crate::design::DARK as T;
use crate::state::{Document, NavOrigin, TabKind, TabStatus};

impl AscApp {
    pub(crate) fn draw_editor(&mut self, ui: &mut egui::Ui) {
        egui::TopBottomPanel::top("editor_tabs")
            .frame(egui::Frame::new().fill(T.surface))
            .show_inside(ui, |ui| {
                self.draw_tab_strip(ui);
            });
        if self.show_find {
            egui::TopBottomPanel::top("editor_find")
                .frame(egui::Frame::new().fill(T.panel_bg))
                .show_inside(ui, |ui| {
                    self.draw_find_bar(ui);
                });
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(T.app_bg))
            .show_inside(ui, |ui| {
                self.draw_code_area(ui);
            });
    }

    /// Preview/pinned tab strip. Active tab = surface fill + 2px accent
    /// underline; close button appears on hover; status glyph sits
    /// inside the tab, before the label.
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
            .max_height(T.tab_height + 4.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (descriptor, kind, status) in &tabs {
                        let is_active = active.as_deref() == Some(descriptor.as_str());
                        let short = super::short_name(descriptor);

                        // Status glyph inside the tab (spinner while
                        // loading, error dot on failure).
                        let status_glyph: Option<egui::RichText> = match status {
                            TabStatus::Loading => None, // spinner drawn after label
                            TabStatus::Failed(_) => {
                                Some(egui::RichText::new("!").small().color(T.error))
                            }
                            TabStatus::Ready => None,
                        };
                        let prefix = match kind {
                            TabKind::Pinned => "◆ ",
                            TabKind::Preview => "",
                        };
                        let mut label = egui::RichText::new(format!("{prefix}{short}"))
                            .monospace()
                            .size(12.0);
                        label = match kind {
                            TabKind::Preview => label.italics().color(T.text_secondary),
                            TabKind::Pinned => label.color(T.text),
                        };
                        if is_active {
                            label = label.color(T.text).strong();
                        }

                        let frame_fill = if is_active {
                            T.surface.linear_multiply(1.25)
                        } else {
                            T.surface
                        };
                        let tab_frame = egui::Frame::new()
                            .fill(frame_fill)
                            .inner_margin(egui::Margin::symmetric(8, 3));
                        let tab_resp = tab_frame
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.set_min_height(T.tab_height - 8.0);
                                    if let Some(glyph) = status_glyph.clone() {
                                        ui.label(glyph);
                                    }
                                    let resp = ui
                                        .add(egui::Button::new(label).frame(false))
                                        .on_hover_text(descriptor);
                                    if resp.clicked() {
                                        clicked = Some(descriptor.clone());
                                    }
                                    if resp.double_clicked() {
                                        pinned = Some(descriptor.clone());
                                    }
                                    if matches!(status, TabStatus::Loading) {
                                        ui.add(egui::Spinner::new().size(11.0));
                                    }
                                    // Close affordance: visible on tab hover.
                                    let hover = ui.rect_contains_pointer(ui.max_rect());
                                    if hover {
                                        let close = ui
                                            .add(
                                                egui::Button::new(
                                                    egui::RichText::new("×")
                                                        .small()
                                                        .color(T.text_secondary),
                                                )
                                                .frame(false),
                                            )
                                            .on_hover_text(format!("close {descriptor}"));
                                        if close.clicked() {
                                            closed = Some(descriptor.clone());
                                        }
                                    }
                                })
                                .response
                            })
                            .response
                            .interact(egui::Sense::click());
                        let _ = tab_resp;

                        // Active-tab accent underline (design §3).
                        // Drawn 1px inside the tab rect: the scroll
                        // area clips at its max_height, so an
                        // exactly-at-bottom line would be culled.
                        if is_active {
                            let rect = tab_resp.rect;
                            ui.painter().hline(
                                egui::Rangef::new(rect.left(), rect.right()),
                                rect.bottom() - 1.0,
                                egui::Stroke::new(2.0_f32, T.accent),
                            );
                        }

                        ui.add_space(1.0);
                    }
                });
            });
        if let Some(d) = clicked {
            self.queue(Command::OpenClass {
                descriptor: d,
                pin: false,
                line: None,
                origin: NavOrigin::Tab,
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
            // ▲/▼ only exist in the monospace family.
            let prev = egui::Button::new(egui::RichText::new("▲").monospace().size(11.0));
            if ui.add(prev).clicked() {
                self.find_step(false);
            }
            let next = egui::Button::new(egui::RichText::new("▼").monospace().size(11.0));
            if ui.add(next).clicked() {
                self.find_step(true);
            }
            let entered = ui.input(|i| i.key_pressed(egui::Key::Enter) && self.show_find);
            if entered {
                self.find_step(true);
            }
            if ui.button("×").clicked() {
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
            self.draw_editor_empty_state(ui);
            return;
        };
        self.draw_code(ui, &doc);
    }

    /// Empty-state hints. One composed block, secondary text — the
    /// editor never renders dead chrome.
    fn draw_editor_empty_state(&mut self, ui: &mut egui::Ui) {
        ui.centered_and_justified(|ui| {
            egui::Grid::new("empty_state")
                .num_columns(2)
                .spacing(egui::vec2(12.0, 6.0))
                .show(ui, |ui| {
                    let key = |ui: &mut egui::Ui, k: &str| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                            ui.monospace(egui::RichText::new(k).small().color(T.text_secondary));
                        });
                    };
                    let what = |ui: &mut egui::Ui, w: &str| {
                        ui.monospace(egui::RichText::new(w).small().color(T.text_disabled));
                    };
                    match self.tabs.active_descriptor() {
                        Some(d) => {
                            ui.vertical(|ui| {
                                ui.monospace(
                                    egui::RichText::new(format!(
                                        "decompiling {}…",
                                        super::short_name(d)
                                    ))
                                    .color(T.text_secondary),
                                );
                            });
                            ui.end_row();
                        }
                        None => {
                            if self.session.is_none() {
                                ui.vertical(|ui| {
                                    ui.label(
                                        egui::RichText::new("ASC Instant Workbench")
                                            .strong()
                                            .color(T.text),
                                    );
                                    ui.label(
                                        egui::RichText::new("no artifact open")
                                            .small()
                                            .color(T.text_secondary),
                                    );
                                    ui.add_space(8.0);
                                });
                                ui.end_row();
                            }
                            key(ui, "Ctrl+O");
                            what(ui, "open an APK");
                            ui.end_row();
                            key(ui, "Ctrl+P");
                            what(ui, "quick open a class");
                            ui.end_row();
                            key(ui, "Ctrl+Shift+F");
                            what(ui, "search the artifact");
                            ui.end_row();
                            key(ui, "Ctrl+1/2/3");
                            what(ui, "toggle panels");
                            ui.end_row();
                        }
                    }
                });
        });
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
                let is_find_match = self.show_find && self.find_matches.contains(&idx);
                let is_current = is_target && self.show_find;
                let row_frame = if is_current {
                    // Current find match: warning tint + accent left bar.
                    egui::Frame::new()
                        .fill(T.warning.linear_multiply(0.10))
                        .stroke(egui::Stroke::new(1.0_f32, T.accent.linear_multiply(0.4)))
                } else if is_find_match {
                    egui::Frame::new().fill(T.warning.linear_multiply(0.10))
                } else if is_target {
                    // Navigation target (search row / outline / history).
                    egui::Frame::new().fill(T.accent.linear_multiply(0.12))
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
