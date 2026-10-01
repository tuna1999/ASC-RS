//! Bottom panel: Search Results | References | Problems | Tasks. The
//! result set stays visible while browsing code (redesign §9).

use eframe::egui;

use crate::app::AscApp;
use crate::command::Command;
use crate::state::{NavOrigin, SearchKind, SearchRow};

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
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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
            let uses_class = matches!(
                self.search.kind,
                SearchKind::Method
                    | SearchKind::Field
                    | SearchKind::MemberMethod
                    | SearchKind::MemberField
            );
            if uses_class {
                ui.add(
                    egui::TextEdit::singleline(&mut self.search.class_filter)
                        .hint_text("class filter (optional)")
                        .desired_width(180.0)
                        .font(egui::TextStyle::Monospace),
                );
                ui.checkbox(
                    &mut self.search.fuzzy_class,
                    egui::RichText::new("fuzzy class").small(),
                )
                .on_hover_text("substring match on the class descriptor (off = exact)");
            }
            // Search history dropdown (ASC-GUI-036 / JADX-GUI-013):
            // entries filter on the current input as you type. Owned
            // clones — the popup closure mutates the controller.
            let history: Vec<_> = self
                .search
                .history_filtered(&self.search.input)
                .into_iter()
                .cloned()
                .collect();
            let history_button = egui::RichText::new(format!("hist ({})", history.len())).small();
            ui.menu_button(history_button, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(180.0)
                    .show(ui, |ui| {
                        for e in &history {
                            let text = if e.class_filter.is_empty() {
                                format!("{}  {}", e.kind.label(), e.input)
                            } else {
                                format!("{}  {}  in {}", e.kind.label(), e.input, e.class_filter)
                            };
                            if ui
                                .selectable_label(false, egui::RichText::new(text).small())
                                .clicked()
                            {
                                self.search.apply_history(e.clone());
                                ui.close();
                            }
                        }
                    });
            });
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
        let rows = self.references.as_ref().map_or(&[][..], |r| &r.rows[..]);
        if rows.is_empty() {
            ui.weak(if self.tasks.findrefs_class_running() {
                "collecting references…"
            } else {
                "no references — Analysis ▸ Find references to the open class"
            });
            return;
        }
        let activate = Self::result_rows_ui(ui, rows, None);
        self.activate_result_row(activate, false);
    }

    /// Virtualized search-result rows: DEX · caller · matched
    /// entities. Selection navigates (preview) and keeps the list.
    fn draw_search_results(&mut self, ui: &mut egui::Ui) {
        // Post-search filter (ASC-GUI-013): narrows visible rows only;
        // the retained results are untouched.
        let has_rows = self.search.results().is_some_and(|r| !r.rows.is_empty());
        if has_rows {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.search.results_filter)
                        .hint_text("filter results…")
                        .desired_width(180.0)
                        .font(egui::TextStyle::Monospace),
                );
                if !self.search.results_filter.is_empty() && ui.small_button("clear").clicked() {
                    self.search.results_filter.clear();
                }
            });
        }
        let needle = self.search.results_filter.trim().to_ascii_lowercase();
        let rows = self.search.results().map_or(&[][..], |r| &r.rows[..]);
        if rows.is_empty() {
            ui.weak(if self.tasks.findrefs_running() {
                "searching…"
            } else {
                "no results — run a search (Ctrl+Shift+F)"
            });
            return;
        }
        if needle.is_empty() {
            let activate = Self::result_rows_ui(ui, rows, self.search.selected());
            self.activate_result_row(activate, true);
            return;
        }
        // Filtered view: rows are cloned per frame (ponytail: fine at
        // UI frame rates; revisit if result sets reach 10⁵ rows).
        // Selection tracking is off here — indices refer to the
        // filtered list, not the retained rows.
        let filtered: Vec<crate::state::SearchRow> = rows
            .iter()
            .filter(|row| crate::state::SearchController::row_matches(row, &needle))
            .cloned()
            .collect();
        let shown = format!("{} / {} rows", filtered.len(), rows.len());
        let activate = Self::result_rows_ui(ui, &filtered, None);
        ui.weak(egui::RichText::new(shown).small());
        self.activate_result_row(activate, false);
    }

    /// Shared virtualized result rows; only the visible range is
    /// formatted. `selected` highlights the clicked row in SEARCH RESULTS
    /// (the REFERENCES list is transient). When the row carries a
    /// code-unit offset (`JADX-GUI-012`), clicking jumps to that line in
    /// the editor. Returns the clicked `(row, descriptor, line)`.
    fn result_rows_ui(
        ui: &mut egui::Ui,
        rows: &[SearchRow],
        selected: Option<usize>,
    ) -> Option<(usize, String, Option<usize>)> {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
        let row_h = T.row_list;
        let mut activate = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_h, rows.len(), |ui, range| {
                for idx in range {
                    let row = &rows[idx];
                    let caller = format!(
                        "{}.{}",
                        super::short_name(&row.caller_class),
                        row.caller_member
                    );
                    let matched = row.matched.join(" ");
                    let is_sel = selected == Some(idx);
                    let frame = if is_sel {
                        egui::Frame::new().fill(T.row_sel_bg)
                    } else {
                        egui::Frame::new().fill(T.panel_bg)
                    };
                    let resp = frame
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.set_min_height(row_h);
                                ui.monospace(
                                    egui::RichText::new(&row.dex_name)
                                        .small()
                                        .color(T.text_disabled),
                                );
                                ui.monospace(egui::RichText::new(caller).color(if is_sel {
                                    T.text
                                } else {
                                    T.accent
                                }));
                                ui.monospace(
                                    egui::RichText::new(truncate(&matched, 96))
                                        .small()
                                        .color(T.text_secondary),
                                );
                            });
                        })
                        .response
                        .interact(egui::Sense::click())
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    if resp.clicked() {
                        // Backend stores a 1-indexed line; navigation is 0-indexed.
                        let line = row.code_off.map(|n| n.saturating_sub(1) as usize);
                        activate = Some((idx, row.caller_class.clone(), line));
                    }
                }
            });
        activate
    }

    fn activate_result_row(
        &mut self,
        activate: Option<(usize, String, Option<usize>)>,
        track_selection: bool,
    ) {
        if let Some((idx, descriptor, line)) = activate {
            if track_selection {
                self.search.select(Some(idx));
            }
            self.queue(Command::OpenClass {
                descriptor,
                pin: false,
                line,
                origin: NavOrigin::Search,
            });
        }
    }

    /// Problems: engine errors from the last search / session.
    fn draw_problems(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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

#[cfg(test)]
mod tests {
    use super::*;
    /// `truncate` shortens strings longer than `max` characters with
    /// an ellipsis; shorter strings are returned unchanged.
    #[test]
    fn truncate_shortens_at_max_chars() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 5), "hello…");
        assert_eq!(truncate("", 5), "");
        // Multibyte safe: counts chars, not bytes.
        assert_eq!(truncate("αβγδεζ", 3), "αβγ…");
    }

    /// `BottomTab::title` covers all four variants. Alias for
    /// `ui::bottom_panel::tests::bottom_tabs_render`.
    #[test]
    fn bottom_tabs_render() {
        let titles = [
            BottomTab::Results.title(),
            BottomTab::References.title(),
            BottomTab::Problems.title(),
            BottomTab::Tasks.title(),
        ];
        // Every variant has a non-empty title (the renderer shows it).
        for t in titles {
            assert!(!t.is_empty(), "title for variant is non-empty");
        }
        // BOTTOM_TABS contains all four (the tab strip iterates it).
        assert_eq!(BOTTOM_TABS.len(), 4);
    }
}
