//! Bottom panel: Search Results | References | Problems | Tasks. The
//! result set stays visible while browsing code (redesign §9).

use eframe::egui;

use crate::app::AscApp;
use crate::command::Command;
use crate::design::DARK as T;
use crate::state::{NavOrigin, SearchKind};

/// Which bottom view is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BottomTab {
    Results,
    References,
    Problems,
    Tasks,
}

impl BottomTab {
    fn title(self) -> &'static str {
        match self {
            BottomTab::Results => "SEARCH RESULTS",
            BottomTab::References => "REFERENCES",
            BottomTab::Problems => "PROBLEMS",
            BottomTab::Tasks => "TASKS",
        }
    }
}

const BOTTOM_TABS: [BottomTab; 4] = [
    BottomTab::Results,
    BottomTab::References,
    BottomTab::Problems,
    BottomTab::Tasks,
];

impl AscApp {
    pub(crate) fn draw_bottom_panel(&mut self, ui: &mut egui::Ui) {
        self.draw_search_bar(ui);
        ui.add_space(2.0);

        ui.horizontal(|ui| {
            for tab in BOTTOM_TABS {
                let selected = self.bottom_tab == tab;
                let label = egui::RichText::new(tab.title())
                    .small()
                    .strong()
                    .color(if selected { T.text } else { T.text_secondary });
                if ui.selectable_label(selected, label).clicked() {
                    self.bottom_tab = tab;
                }
                ui.add_space(4.0);
            }
            // Right-aligned result summary.
            let summary_source = if self.bottom_tab == BottomTab::References {
                self.references.as_ref()
            } else {
                self.search.results()
            };
            if let Some(r) = summary_source {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (color, glyph) = if r.complete && r.errors.is_empty() {
                        (T.success, "✔")
                    } else {
                        (T.warning, "⚠")
                    };
                    ui.monospace(
                        egui::RichText::new(format!(
                            "{glyph} {} · {}",
                            r.label,
                            human_count(r.rows.len())
                        ))
                        .small()
                        .color(color),
                    );
                });
            }
        });
        ui.separator();

        match self.bottom_tab {
            BottomTab::Results => self.draw_search_results(ui),
            BottomTab::References => self.draw_references(ui),
            BottomTab::Problems => self.draw_problems(ui),
            BottomTab::Tasks => self.draw_tasks(ui),
        }
    }

    /// Query input row: kind selector, pattern, optional class filter,
    /// run/cancel.
    fn draw_search_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("search_kind")
                .selected_text(self.search.kind.label())
                .width(78.0)
                .show_ui(ui, |ui| {
                    for kind in SearchKind::ALL {
                        ui.selectable_value(&mut self.search.kind, kind, kind.label());
                    }
                });
            let run_edit = ui.add(
                egui::TextEdit::singleline(&mut self.search.input)
                    .hint_text("search pattern…")
                    .desired_width(240.0)
                    .font(egui::TextStyle::Monospace),
            );
            if matches!(self.search.kind, SearchKind::Method | SearchKind::Field) {
                ui.add(
                    egui::TextEdit::singleline(&mut self.search.class_filter)
                        .hint_text("class filter (optional)")
                        .desired_width(180.0)
                        .font(egui::TextStyle::Monospace),
                );
            }
            if self.tasks.findrefs_running() {
                ui.spinner();
                if ui.button("cancel").clicked() {
                    self.queue(Command::CancelTask);
                }
            } else if ui.button("Run").clicked() {
                self.queue(Command::RunSearch);
            }
            let enter = run_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if enter && !self.search.input.trim().is_empty() {
                self.queue(Command::RunSearch);
            }
            if self.focus_search {
                run_edit.request_focus();
                self.focus_search = false;
            }
        });
    }

    /// REFERENCES tab: callers of the active class (Analysis ▸ Find
    /// references, or the palette).
    fn draw_references(&mut self, ui: &mut egui::Ui) {
        let rows: Vec<(String, String, String, String)> = self
            .references
            .as_ref()
            .map(|r| {
                r.rows
                    .iter()
                    .map(|row| {
                        (
                            row.dex_name.clone(),
                            format!(
                                "{}.{}",
                                super::short_name(&row.caller_class),
                                row.caller_member
                            ),
                            row.caller_class.clone(),
                            row.matched.join(" "),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        if rows.is_empty() {
            ui.weak(if self.tasks.findrefs_class_running() {
                "collecting references…"
            } else {
                "no references — Analysis ▸ Find references to the open class"
            });
            return;
        }
        self.draw_result_rows(ui, rows, false);
    }

    /// Virtualized search-result rows: DEX · caller · matched
    /// entities. Selection navigates (preview) and keeps the list.
    fn draw_search_results(&mut self, ui: &mut egui::Ui) {
        let rows: Vec<(String, String, String, String)> = self
            .search
            .results()
            .map(|r| {
                r.rows
                    .iter()
                    .map(|row| {
                        (
                            row.dex_name.clone(),
                            format!(
                                "{}.{}",
                                super::short_name(&row.caller_class),
                                row.caller_member
                            ),
                            row.caller_class.clone(),
                            row.matched.join(" "),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        if rows.is_empty() {
            ui.weak(if self.tasks.findrefs_running() {
                "searching…"
            } else {
                "no results — run a search (Ctrl+Shift+F)"
            });
            return;
        }
        self.draw_result_rows(ui, rows, true);
    }

    /// Shared virtualized result rows. `track_selection` keeps the
    /// clicked row highlighted in SEARCH RESULTS (the REFERENCES list
    /// is transient).
    fn draw_result_rows(
        &mut self,
        ui: &mut egui::Ui,
        rows: Vec<(String, String, String, String)>,
        track_selection: bool,
    ) {
        let row_h = T.row_list;
        let selected = self.search.selected();
        let mut activate: Option<(usize, String)> = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_h, rows.len(), |ui, range| {
                for idx in range {
                    let (dex, caller, descriptor, matched) = &rows[idx];
                    let is_sel = track_selection && selected == Some(idx);
                    let frame = if is_sel {
                        egui::Frame::new().fill(T.accent.linear_multiply(0.15))
                    } else {
                        egui::Frame::new().fill(T.panel_bg)
                    };
                    let resp = frame
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.set_min_height(row_h);
                                ui.monospace(
                                    egui::RichText::new(dex).small().color(T.text_disabled),
                                );
                                ui.monospace(egui::RichText::new(caller).color(if is_sel {
                                    T.text
                                } else {
                                    T.accent
                                }));
                                ui.monospace(
                                    egui::RichText::new(truncate(matched, 96))
                                        .small()
                                        .color(T.text_secondary),
                                );
                            });
                        })
                        .response
                        .interact(egui::Sense::click())
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    if resp.clicked() {
                        activate = Some((idx, descriptor.clone()));
                    }
                }
            });
        if let Some((idx, descriptor)) = activate {
            if track_selection {
                self.search.select(Some(idx));
            }
            self.queue(Command::OpenClass {
                descriptor,
                pin: false,
                line: None,
                origin: NavOrigin::Search,
            });
        }
    }

    /// Problems: engine errors from the last search / session.
    fn draw_problems(&mut self, ui: &mut egui::Ui) {
        let errors: Vec<String> = self
            .search
            .results()
            .map(|r| r.errors.clone())
            .unwrap_or_default();
        if errors.is_empty() && self.last_error.is_none() {
            ui.weak("no problems");
            return;
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            if let Some(e) = &self.last_error {
                ui.monospace(
                    egui::RichText::new(format!("session: {e}"))
                        .small()
                        .color(T.error),
                );
            }
            for e in &errors {
                ui.monospace(egui::RichText::new(e).small().color(T.warning));
            }
        });
    }

    /// Tasks: in-flight + recent completed tasks.
    fn draw_tasks(&mut self, ui: &mut egui::Ui) {
        let recent: Vec<(String, String, bool, bool, u64)> = self
            .tasks
            .recent()
            .map(|t| {
                (
                    t.kind.label().to_string(),
                    t.label.clone(),
                    t.ok,
                    t.discarded,
                    t.elapsed_ms,
                )
            })
            .collect();
        if !self.tasks.has_in_flight() && recent.is_empty() {
            ui.weak("no tasks");
            return;
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.tasks.has_in_flight() {
                ui.monospace(
                    egui::RichText::new(format!("{} running", self.tasks.in_flight_count()))
                        .small()
                        .color(T.accent),
                );
            }
            for (kind, label, ok, discarded, ms) in recent {
                let (state_name, state_color) = if discarded {
                    ("discarded", T.text_disabled)
                } else if ok {
                    ("done", T.success)
                } else {
                    ("failed", T.error)
                };
                ui.horizontal(|ui| {
                    ui.monospace(
                        egui::RichText::new(format!("{kind:>9}"))
                            .small()
                            .color(T.text_secondary),
                    );
                    ui.monospace(
                        egui::RichText::new(truncate(&label, 72))
                            .small()
                            .color(T.text),
                    );
                    ui.monospace(
                        egui::RichText::new(format!("{state_name} {ms} ms"))
                            .small()
                            .color(state_color),
                    );
                });
            }
        });
    }
}

fn human_count(n: usize) -> String {
    match n {
        0 => "no hits".to_string(),
        1 => "1 hit".to_string(),
        n => format!("{n} hits"),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}
