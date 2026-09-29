//! Editor: tab strip (preview/pinned), code surface with gutter, and
//! the find-in-document bar.

use std::sync::Arc;

use eframe::egui;

use crate::app::{AscApp, SymbolSelection};
use crate::command::Command;
use crate::state::{Document, NavOrigin, TabKind, TabStatus};

impl AscApp {
    pub(crate) fn draw_editor(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
        egui::Panel::top("editor_tabs")
            .frame(egui::Frame::new().fill(T.surface))
            .show(ui, |ui| {
                self.draw_tab_strip(ui);
            });
        if self.show_find {
            egui::Panel::top("editor_find")
                .frame(egui::Frame::new().fill(T.panel_bg))
                .show(ui, |ui| {
                    self.draw_find_bar(ui);
                });
        }
        if self.show_rename {
            egui::Panel::top("editor_rename")
                .frame(egui::Frame::new().fill(T.panel_bg))
                .show(ui, |ui| {
                    self.draw_rename_bar(ui);
                });
        }
        if self.comment_target.is_some() {
            egui::Panel::top("editor_comment")
                .frame(egui::Frame::new().fill(T.panel_bg))
                .show(ui, |ui| {
                    self.draw_comment_bar(ui);
                });
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(T.app_bg))
            .show(ui, |ui| {
                self.draw_code_area(ui);
            });
    }

    /// Preview/pinned tab strip. Active tab = surface fill + 2px accent
    /// underline; close button appears on hover; status glyph sits
    /// inside the tab, before the label.
    fn draw_tab_strip(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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
                            TabKind::Text => "≡ ",
                        };
                        let mut label = egui::RichText::new(format!("{prefix}{short}"))
                            .monospace()
                            .size(12.0);
                        label = match kind {
                            TabKind::Preview => label.italics().color(T.text_secondary),
                            TabKind::Pinned => label.color(T.text),
                            TabKind::Text => label.color(T.text),
                        };
                        if is_active {
                            label = label.color(T.text).strong();
                        }

                        let frame_fill = if is_active {
                            T.tab_active_bg
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
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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
                    // Never render another class's source under this tab.
                    if self
                        .active_doc
                        .as_ref()
                        .is_some_and(|d| d.descriptor != active)
                    {
                        self.active_doc = None;
                    }
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
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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

    /// Rename bar (F25): method-scoped rename of the clicked symbol.
    fn draw_rename_bar(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("rename")
                    .small()
                    .color(T.text_secondary),
            );
            if let Some(sel) = &self.symbol_sel {
                ui.label(
                    egui::RichText::new(format!(
                        "{} · {} refs in method",
                        sel.token,
                        sel.occurrences.len()
                    ))
                    .small()
                    .color(T.text_disabled),
                );
            }
            let edit = egui::TextEdit::singleline(&mut self.rename_input)
                .hint_text("new name")
                .desired_width(160.0);
            let resp = ui.add(edit);
            if !resp.has_focus() {
                resp.request_focus();
            }
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                let new_name = self.rename_input.trim().to_string();
                self.queue(Command::RenameSymbol { new_name });
            }
            ui.label(
                egui::RichText::new("Enter apply · Esc cancel")
                    .small()
                    .color(T.text_secondary),
            );
        });
    }

    /// Line-comment bar (F26): append a `// note` to the clicked line.
    fn draw_comment_bar(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
        let target = self.comment_target;
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("comment")
                    .small()
                    .color(T.text_secondary),
            );
            if let Some(line) = target {
                ui.label(
                    egui::RichText::new(format!("line {}", line + 1))
                        .small()
                        .color(T.text_disabled),
                );
            }
            let edit = egui::TextEdit::singleline(&mut self.comment_input)
                .hint_text("note")
                .desired_width(280.0);
            let resp = ui.add(edit);
            if !resp.has_focus() {
                resp.request_focus();
            }
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                let text = self.comment_input.clone();
                if let Some(line) = target {
                    self.queue(Command::SetLineComment { line, text });
                }
            }
            ui.label(
                egui::RichText::new("Enter save · Esc cancel")
                    .small()
                    .color(T.text_secondary),
            );
        });
    }

    fn draw_code(&mut self, ui: &mut egui::Ui, doc: &Arc<Document>) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
        let fid = egui::FontId::monospace(T.code_size);
        let advance = ui.fonts_mut(|f| f.glyph_width(&fid, 'M')).max(1.0);

        // Highlight the find match / navigation target line.
        let scroll_target = self.nav_or_find_line();
        let pending = self.pending_scroll.take();
        let mut scroll = egui::ScrollArea::both()
            .auto_shrink([false, false])
            .id_salt(("code", doc.descriptor.as_str()));
        if let Some(line) = pending {
            scroll = scroll.vertical_scroll_offset(line as f32 * row_h);
        }
        // Symbol selection (F24): byte offsets are valid only for
        // this document; clone out to release the borrow.
        let sym_occ: Vec<(usize, usize)> = self
            .symbol_sel
            .as_ref()
            .filter(|s| s.descriptor == doc.descriptor)
            .map(|s| s.occurrences.clone())
            .unwrap_or_default();
        let mut hovered = false;
        scroll.show_rows(ui, row_h, doc.line_count(), |ui, range| {
            for idx in range {
                let line = doc.line(idx).unwrap_or("");
                let line_abs = line.as_ptr() as usize - doc.source.as_ptr() as usize;
                let line_end = line_abs + line.len();
                let empty: Vec<crate::highlight::Span> = Vec::new();
                let spans = doc.spans.get(idx).unwrap_or(&empty);
                // Line-local slices of the symbol occurrence ranges.
                let sym_local: Vec<(usize, usize)> = sym_occ
                    .iter()
                    .filter_map(|&(s, e)| {
                        let a = s.max(line_abs) - line_abs;
                        let b = e.min(line_end) - line_abs;
                        (a < b).then_some((a, b))
                    })
                    .collect();
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
                        let resp = ui.add(
                            egui::Label::new(super::spans_to_job(line, spans, &sym_local))
                                .selectable(true)
                                .wrap_mode(egui::TextWrapMode::Extend),
                        );
                        if resp.clicked() {
                            self.last_clicked_line = Some(idx);
                            if let Some(pos) = resp.interact_pointer_pos() {
                                // Monospace: column from glyph advance.
                                let col = (((pos.x - resp.rect.left()) / advance).round() as i64)
                                    .clamp(0, line.chars().count() as i64)
                                    as usize;
                                let byte = line
                                    .char_indices()
                                    .nth(col)
                                    .map(|(b, _)| b)
                                    .unwrap_or(line.len());
                                self.symbol_sel = symbol_selection_for(
                                    &doc.descriptor,
                                    &doc.source,
                                    line_abs + byte,
                                );
                            }
                        }
                        hovered |= resp.hovered();
                    });
                });
            }
        });
        self.code_hovered = hovered;
    }
}

/// Selection model for the identifier at `byte` (F24): token,
/// enclosing-method byte range, code-state occurrences.
pub(crate) fn symbol_selection_for(
    descriptor: &str,
    source: &str,
    byte: usize,
) -> Option<SymbolSelection> {
    let (s, e) = crate::source_edit::token_at(source, byte)?;
    let token = source[s..e].to_string();
    let method = crate::source_edit::find_method_range(source, byte)?;
    let occurrences = crate::source_edit::occurrences_in_range(source, method.0, method.1, &token);
    Some(SymbolSelection {
        descriptor: descriptor.to_string(),
        token,
        method,
        occurrences,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `symbol_selection_for` returns the clicked identifier, the
    /// enclosing method's byte range, and every code-state
    /// occurrence inside that range. Covers ASC-GUI-019.
    #[test]
    fn symbol_selection_returns_method_occurrences() {
        let src = "\
class A {
  void m() {
    int foo = 0;
    int bar = foo + 1;
    bar = foo * 2;
  }
}
";
        // Click on the first `foo` (the declaration).
        let off = src.find("foo").unwrap();
        let sel = symbol_selection_for("LA;", src, off).expect("selection");
        assert_eq!(sel.token, "foo");
        // Every occurrence slice is exactly `foo`.
        for (s, e) in &sel.occurrences {
            assert_eq!(&src[*s..*e], "foo");
        }
        assert!(!sel.occurrences.is_empty(), "at least one occurrence");
    }
}
