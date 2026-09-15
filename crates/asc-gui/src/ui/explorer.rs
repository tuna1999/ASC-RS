//! Explorer: the left panel — package tree, class filter, flat match
//! list. Single click previews, double click pins.

use eframe::egui;

use crate::app::AscApp;
use crate::command::Command;
use crate::design::DARK as T;
use crate::state::NavOrigin;

impl AscApp {
    pub(crate) fn draw_explorer(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("EXPLORER")
                    .small()
                    .strong()
                    .color(T.text_secondary),
            );
            if self.session.is_some() {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("{}", self.tree.len()))
                            .small()
                            .color(T.text_disabled),
                    );
                });
            }
        });
        ui.add_space(2.0);
        let filter_resp = ui.add(
            egui::TextEdit::singleline(&mut self.tree_filter)
                .hint_text("filter classes…")
                .desired_width(f32::INFINITY),
        );
        ui.add_space(2.0);

        let Some(_session) = self.session.as_ref() else {
            ui.with_layout(
                egui::Layout::top_down(egui::Align::Center).with_main_justify(true),
                |ui| {
                    ui.weak(if self.loading_artifact {
                        "opening artifact…"
                    } else {
                        "no artifact open — File ▸ Open (Ctrl+O)"
                    });
                },
            );
            return;
        };

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
                    self.draw_tree_node(ui, idx, 0);
                }
            } else {
                // Cached in the tree; copied out so the click loop can
                // mutate `self`.
                let hits: Vec<usize> = self.tree.filter(&filter).to_vec();
                if hits.is_empty() {
                    ui.weak(format!("no classes matching “{filter}”"));
                } else {
                    ui.label(
                        egui::RichText::new(format!("{} match(es)", hits.len()))
                            .small()
                            .color(T.text_disabled),
                    );
                    for leaf in hits.into_iter().take(500) {
                        let desc = self.tree.entry(leaf).descriptor.clone();
                        let label = super::short_name(&desc);
                        let selected = self.selected_class.as_deref() == Some(desc.as_str());
                        if self.class_row(ui, selected, &label) {
                            self.queue(Command::OpenClass {
                                descriptor: desc,
                                pin: false,
                                line: None,
                                origin: NavOrigin::Tree,
                            });
                        }
                    }
                }
            }
        });
        let _ = filter_resp;
    }

    /// One package/class node.
    fn draw_tree_node(&mut self, ui: &mut egui::Ui, idx: usize, depth: usize) {
        // Clone the small bits we need so `self` is free to mutate.
        let (label, path, has_children, own_desc) = {
            let n = self.tree.node(idx);
            (
                n.label.clone(),
                n.path.clone(),
                !n.children.is_empty(),
                n.class_leaves
                    .first()
                    .map(|&l| self.tree.entry(l).descriptor.clone()),
            )
        };
        let is_open = self.expanded.contains(&path);
        let mut toggled = false;
        ui.horizontal(|ui| {
            ui.set_min_height(T.row_tree);
            ui.add_space(depth as f32 * 12.0);
            if has_children {
                let glyph = if is_open { "▾" } else { "▸" };
                if ui
                    .small_button(glyph)
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                {
                    toggled = true;
                }
            } else {
                ui.label(" ");
            }
            if let Some(desc) = own_desc {
                let selected = self.selected_class.as_deref() == Some(desc.as_str());
                if self.class_row(ui, selected, &label) {
                    let pin = ui.input(|i| {
                        i.pointer
                            .button_double_clicked(egui::PointerButton::Primary)
                    }) || ui.input(|i| i.modifiers.shift);
                    self.queue(Command::OpenClass {
                        descriptor: desc,
                        pin,
                        line: None,
                        origin: NavOrigin::Tree,
                    });
                }
            } else {
                let text = egui::RichText::new(label).monospace().size(12.5);
                let text = if is_open {
                    text.color(T.text)
                } else {
                    text.color(T.text_secondary)
                };
                if ui
                    .selectable_label(false, text)
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                {
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
                self.draw_tree_node(ui, child, depth + 1);
            }
        }
    }

    /// A clickable class row; returns true when clicked. Filled
    /// diamond (class-leaf motif, design §3) — the hollow ◇ reads as
    /// a stray square outline at 12.5 px. Selected row gets the
    /// spec'd accent-tinted background.
    fn class_row(&self, ui: &mut egui::Ui, selected: bool, label: &str) -> bool {
        let row_frame = if selected {
            egui::Frame::new().fill(T.accent.linear_multiply(0.12))
        } else {
            egui::Frame::new()
        };
        let mut clicked = false;
        row_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.set_min_height(T.row_tree - 4.0);
                ui.label(
                    egui::RichText::new("◆")
                        .monospace()
                        .size(11.0)
                        .color(if selected { T.accent } else { T.text_disabled }),
                );
                clicked = ui
                    .selectable_label(
                        selected,
                        egui::RichText::new(label)
                            .monospace()
                            .size(12.5)
                            .color(if selected { T.text } else { T.text_secondary }),
                    )
                    .clicked();
            });
        });
        clicked
    }
}
