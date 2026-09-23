//! Status bar: state dot, session counters, engine mode, transient
//! operation.

use eframe::egui;

use crate::app::AscApp;

impl AscApp {
    pub(crate) fn draw_status_bar(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
        ui.horizontal(|ui| {
            // State dot.
            let (dot, color) = if self.tasks.has_in_flight() {
                ("●", T.accent)
            } else if self.last_error.is_some() {
                ("●", T.error)
            } else if let Some(s) = &self.status {
                ("●", if s.ok { T.success } else { T.warning })
            } else {
                ("●", T.success)
            };
            ui.label(egui::RichText::new(dot).color(color));

            match &self.status {
                Some(s) => {
                    ui.monospace(egui::RichText::new(&s.text).small().color(if s.ok {
                        T.text
                    } else {
                        T.warning
                    }));
                }
                None => {
                    ui.monospace(egui::RichText::new("ready").small().color(T.text_secondary));
                }
            }
            if self.last_error.is_some() && self.status.is_none() {
                if let Some(e) = &self.last_error {
                    ui.monospace(egui::RichText::new(e).small().color(T.error));
                }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.monospace(
                    egui::RichText::new(format!(
                        "{} docs · {}",
                        self.documents.len(),
                        human_bytes(self.documents.bytes())
                    ))
                    .small()
                    .color(T.text_disabled),
                );
                let (pos, len) = self.nav.position();
                if len > 0 {
                    ui.monospace(
                        egui::RichText::new(format!("{}/{}", pos + 1, len))
                            .small()
                            .color(T.text_disabled),
                    );
                }
                if let Some(session) = &self.session {
                    ui.monospace(
                        egui::RichText::new(format!(
                            "{} classes · {} dex",
                            self.tree.len(),
                            session.dex_entries().len()
                        ))
                        .small()
                        .color(T.text_disabled),
                    );
                }
                ui.monospace(
                    egui::RichText::new("ASC Direct")
                        .small()
                        .color(T.text_disabled),
                );
            });
        });
    }
}

fn human_bytes(bytes: usize) -> String {
    let b = bytes as f64;
    if b < 1024.0 {
        format!("{bytes} B")
    } else if b < 1024.0 * 1024.0 {
        format!("{:.1} KiB", b / 1024.0)
    } else {
        format!("{:.1} MiB", b / (1024.0 * 1024.0))
    }
}
