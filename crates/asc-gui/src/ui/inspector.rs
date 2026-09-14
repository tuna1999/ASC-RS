//! Inspector: right panel — symbol, DEX, references, and metadata
//! sections. Engine-backed data only. (`CollapsingHeader` persists
//! its own open/closed state in egui memory by header id.)

use eframe::egui;

use crate::app::AscApp;
use crate::design::DARK as T;
use crate::state::TabStatus;

impl AscApp {
    pub(crate) fn draw_inspector(&mut self, ui: &mut egui::Ui) {
        ui.label(
            egui::RichText::new("INSPECTOR")
                .small()
                .strong()
                .color(T.text_secondary),
        );
        ui.add_space(2.0);

        self.inspector_symbol(ui);
        self.inspector_dex(ui);
        self.inspector_references(ui);
        self.inspector_metadata(ui);
    }

    fn inspector_symbol(&mut self, ui: &mut egui::Ui) {
        let active = self.tabs.active_descriptor().map(str::to_string);
        let status = self
            .tabs
            .tabs()
            .iter()
            .find(|t| Some(t.descriptor.as_str()) == active.as_deref())
            .map(|t| t.status.clone());
        egui::CollapsingHeader::new(
            egui::RichText::new("SYMBOL")
                .small()
                .strong()
                .color(T.text_secondary),
        )
        .default_open(true)
        .show(ui, |ui| match (&active, &status) {
            (Some(d), Some(st)) => {
                ui.monospace(
                    egui::RichText::new(super::short_name(d))
                        .color(T.text)
                        .strong(),
                );
                ui.monospace(egui::RichText::new(d).small().color(T.text_secondary));
                match st {
                    TabStatus::Loading => {
                        let _ = ui.spinner();
                    }
                    TabStatus::Ready => {
                        let _ = ui.label(egui::RichText::new("ready").small().color(T.success));
                        if let Some(doc) = &self.active_doc {
                            let _ = ui.monospace(
                                egui::RichText::new(format!(
                                    "{} lines · {} outline entries",
                                    doc.line_count(),
                                    doc.outline.len()
                                ))
                                .small()
                                .color(T.text_disabled),
                            );
                        }
                    }
                    TabStatus::Failed(e) => {
                        let _ = ui.label(egui::RichText::new(e).small().color(T.error));
                    }
                }
            }
            _ => {
                let _ = ui.weak("no symbol selected");
            }
        });
    }

    fn inspector_dex(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new(
            egui::RichText::new("DEX")
                .small()
                .strong()
                .color(T.text_secondary),
        )
        .default_open(true)
        .show(ui, |ui| {
            if self.dex_counts.is_empty() {
                ui.weak("no artifact");
                return;
            }
            for (name, count) in &self.dex_counts {
                let active_here = self
                    .active_doc
                    .as_ref()
                    .map(|d| &d.dex_name == name)
                    .unwrap_or(false);
                let text = format!("{name} · {count} classes");
                let rich = if active_here {
                    egui::RichText::new(text).color(T.accent).monospace()
                } else {
                    egui::RichText::new(text)
                        .color(T.text_secondary)
                        .monospace()
                };
                ui.label(rich);
            }
        });
    }

    fn inspector_references(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new(
            egui::RichText::new("REFERENCES")
                .small()
                .strong()
                .color(T.text_secondary),
        )
        .default_open(true)
        .show(ui, |ui| match self.search.results() {
            Some(r) if !r.rows.is_empty() => {
                let _ = ui.monospace(
                    egui::RichText::new(&r.label)
                        .small()
                        .color(T.text_secondary),
                );
                let _ = ui.monospace(
                    egui::RichText::new(format!("{} callers", r.rows.len())).color(T.text),
                );
                let _ = ui.weak("browse hits in SEARCH RESULTS");
            }
            _ => {
                let _ = ui.weak("run a search to collect references");
            }
        });
    }

    fn inspector_metadata(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new(
            egui::RichText::new("METADATA")
                .small()
                .strong()
                .color(T.text_secondary),
        )
        .default_open(false)
        .show(ui, |ui| match &self.manifest {
            Some(m) => {
                let pkg = m.package.clone().unwrap_or_default();
                if pkg.is_empty() {
                    let _ = ui.weak("manifest present, no package name");
                } else {
                    let ver = m.version_code.map(|v| format!(" v{v}")).unwrap_or_default();
                    let _ = ui.monospace(format!("{pkg}{ver}"));
                }
            }
            None => {
                let _ = ui.weak("no manifest (synthetic corpus?)");
            }
        });
    }
}
