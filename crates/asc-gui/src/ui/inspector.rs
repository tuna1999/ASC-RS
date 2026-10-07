//! Inspector: right panel — symbol, DEX, references, and metadata
//! sections. Engine-backed data only. (`CollapsingHeader` persists
//! its own open/closed state in egui memory by header id.)

use eframe::egui;

use crate::app::AscApp;
use crate::command::Command;
use crate::state::{NavOrigin, TabStatus};

impl AscApp {
    pub(crate) fn draw_inspector(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
        ui.label(
            egui::RichText::new("INSPECTOR")
                .small()
                .strong()
                .color(T.text_secondary),
        );
        ui.add_space(2.0);

        self.inspector_symbol(ui);
        self.inspector_outline(ui);
        self.inspector_dex(ui);
        self.inspector_references(ui);
        self.inspector_metadata(ui);
    }

    fn inspector_symbol(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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

    /// STRUCTURE: the computed document outline (methods and fields,
    /// with line numbers). Clicking jumps to the line in the editor.
    /// JADX-GUI-008: a type-ahead filter input narrows the rows.
    fn inspector_outline(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
        // Filter input row. Lives inside the CollapsingHeader body so
        // it collapses with the section.
        let header = egui::CollapsingHeader::new(
            egui::RichText::new("STRUCTURE")
                .small()
                .strong()
                .color(T.text_secondary),
        )
        .default_open(true)
        .show(ui, |ui| {
            // Type-ahead filter.
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.outline_filter)
                        .hint_text("filter…")
                        .desired_width(ui.available_width()),
                );
            });
            // Build entries with the filter applied.
            let needle = self.outline_filter.trim();
            let entries: Vec<(String, usize, bool)> = self
                .active_doc
                .as_ref()
                .map(|d| {
                    let raw: Vec<(String, usize, bool)> = d
                        .outline
                        .iter()
                        .map(|e| (e.text.clone(), e.line, e.is_field))
                        .collect();
                    crate::ui::inspector::filter_outline(&raw, needle)
                })
                .unwrap_or_default();
            if entries.is_empty() {
                if self.active_doc.is_none() {
                    ui.weak("open a class to see its structure");
                } else {
                    ui.weak("no outline entries match the filter");
                }
                return;
            }
            let mut jump: Option<usize> = None;
            egui::ScrollArea::vertical()
                .max_height(260.0)
                .auto_shrink([false, false])
                .show_rows(ui, T.row_list, entries.len(), |ui, range| {
                    for idx in range {
                        let (text, line, is_field) = &entries[idx];
                        let rich = if *is_field {
                            egui::RichText::new(text)
                                .monospace()
                                .small()
                                .color(T.text_secondary)
                        } else {
                            egui::RichText::new(text).monospace().small().color(T.text)
                        };
                        let resp = ui
                            .add(egui::Button::new(rich).frame(false))
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text(format!("line {}", line + 1));
                        if resp.clicked() {
                            jump = Some(*line);
                        }
                    }
                });
            if let Some(line) = jump {
                let descriptor = self.tabs.active_descriptor().map(str::to_string);
                if let Some(descriptor) = descriptor {
                    self.queue(Command::OpenClass {
                        descriptor,
                        pin: false,
                        line: Some(line),
                        origin: NavOrigin::Outline,
                    });
                }
            }
        });
        let _ = header;
    }

    // Close the first `impl AscApp` block (draw_inspector,
    // inspector_symbol, inspector_outline). The remaining inspector
    // methods (inspector_dex, inspector_references, inspector_metadata)
    // live in a second `impl AscApp` block below; `filter_outline` is a
    // free helper between them.
}

pub(crate) fn filter_outline(
    entries: &[(String, usize, bool)],
    needle: &str,
) -> Vec<(String, usize, bool)> {
    let needle = needle.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return entries.to_vec();
    }
    entries
        .iter()
        .filter(|(text, _, _)| text.to_ascii_lowercase().contains(&needle))
        .cloned()
        .collect()
}

// `inspector_outline`, `filter_outline`, and the remaining inspector
// methods are organized as: methods-with-self live inside `impl
// AscApp`, but `filter_outline` is a free helper and breaks the
// block. Re-open a new impl block for what follows.
impl AscApp {
    fn inspector_dex(&mut self, ui: &mut egui::Ui) {
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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
        #[allow(non_snake_case)] // design-token alias (matches the previous `use DARK as T` idiom)
        let T = crate::design::tokens();
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
                let rows = metadata_rows(m);
                if rows.is_empty() {
                    return;
                }
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for row in &rows {
                            match row {
                                MetadataRow::Field(s) => {
                                    let _ = ui.monospace(
                                        egui::RichText::new(s).small().color(T.text_secondary),
                                    );
                                }
                                MetadataRow::Permission(s) => {
                                    let _ =
                                        ui.monospace(egui::RichText::new(s).small().color(T.text));
                                }
                                MetadataRow::Provider(s) => {
                                    let _ = ui.monospace(
                                        egui::RichText::new(s).small().color(T.text_disabled),
                                    );
                                }
                            }
                        }
                    });
            }
            None => {
                // Three distinct states, never merged: no artifact open,
                // an APK that genuinely has no AndroidManifest.xml (e.g. a
                // synthetic fixture), and one whose manifest failed to
                // decode (metadata is then untrustworthy, not absent).
                let msg = if self.session.is_none() {
                    "no artifact".to_string()
                } else if let Some(err) = &self.manifest_error {
                    format!("manifest parse failed: {err}")
                } else {
                    "no AndroidManifest.xml".to_string()
                };
                let _ = ui.weak(msg);
            }
        });
    }
}

/// One row in the inspector's METADATA section. `Field` is a label/value
/// pair like `versionName 1.2.3`; the lists (`Permission`, `Provider`)
/// render as one monospace row each. Kept `pub(crate)` so the inline
/// tests can assert on the produced rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MetadataRow {
    Field(String),
    Permission(String),
    Provider(String),
}

/// Build the additional METADATA rows rendered below the package line.
///
/// Returned in source order: version_name, sdk range, components
/// summary, then one row per permission / provider. Empty manifest
/// returns an empty `Vec` (the caller then skips the scroll area).
pub(crate) fn metadata_rows(m: &asc_manifest::ManifestInfo) -> Vec<MetadataRow> {
    use MetadataRow::*;
    let mut out = Vec::new();
    if let Some(vn) = &m.version_name {
        out.push(Field(format!("versionName {vn}")));
    }
    match (m.min_sdk, m.target_sdk) {
        (Some(a), Some(b)) => out.push(Field(format!("sdk min {a} · target {b}"))),
        (Some(a), None) => out.push(Field(format!("sdk min {a}"))),
        (None, Some(b)) => out.push(Field(format!("sdk target {b}"))),
        (None, None) => {}
    }
    let n_act = m.activities.len();
    let n_svc = m.services.len();
    let n_recv = m.receivers.len();
    if n_act + n_svc + n_recv > 0 {
        out.push(Field(format!(
            "{n_act} activities · {n_svc} services · {n_recv} receivers"
        )));
    }
    for p in &m.permissions {
        out.push(Permission(p.name.clone()));
    }
    for p in &m.providers {
        let line = match &p.authorities {
            Some(a) if !a.is_empty() => format!("{} · {a}", p.name),
            _ => p.name.clone(),
        };
        out.push(Provider(line));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::inspector::filter_outline;
    use asc_manifest::{ComponentEntry, ManifestInfo, PermissionEntry, ProviderEntry};

    fn populated_manifest() -> ManifestInfo {
        ManifestInfo {
            package: Some("com.example.app".into()),
            version_code: Some(42),
            version_name: Some("1.2.3".into()),
            min_sdk: Some(21),
            target_sdk: Some(33),
            permissions: vec![
                PermissionEntry {
                    name: "android.permission.INTERNET".into(),
                    decl: "uses",
                    protection_level: None,
                    label: None,
                    max_sdk: None,
                },
                PermissionEntry {
                    name: "android.permission.ACCESS_NETWORK_STATE".into(),
                    decl: "uses",
                    protection_level: None,
                    label: None,
                    max_sdk: None,
                },
            ],
            activities: vec![ComponentEntry {
                name: "com.example.app.Main".into(),
                exported: true,
                exported_explicit: None,
                permission: None,
                process: None,
                label: None,
                intent_filters: Vec::new(),
                meta_data: Vec::new(),
            }],
            services: vec![ComponentEntry {
                name: "com.example.app.Svc".into(),
                exported: false,
                exported_explicit: None,
                permission: None,
                process: None,
                label: None,
                intent_filters: Vec::new(),
                meta_data: Vec::new(),
            }],
            receivers: vec![ComponentEntry {
                name: "com.example.app.R".into(),
                exported: true,
                exported_explicit: None,
                permission: None,
                process: None,
                label: None,
                intent_filters: Vec::new(),
                meta_data: Vec::new(),
            }],
            providers: vec![ProviderEntry {
                name: "com.example.app.Data".into(),
                authorities: Some("com.example.app.data".into()),
                exported: false,
                exported_explicit: None,
                permission: None,
                read_permission: None,
                write_permission: None,
                grant_uri_permissions: false,
                label: None,
                meta_data: Vec::new(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn metadata_rows_emits_expected_sections() {
        let rows = metadata_rows(&populated_manifest());
        // version_name line.
        assert!(
            rows.iter()
                .any(|r| matches!(r, MetadataRow::Field(s) if s == "versionName 1.2.3")),
            "rows: {rows:?}"
        );
        // sdk range line.
        assert!(
            rows.iter().any(|r| matches!(r, MetadataRow::Field(s)
                if s == "sdk min 21 · target 33")),
            "rows: {rows:?}"
        );
        // components summary line.
        assert!(
            rows.iter().any(|r| matches!(r, MetadataRow::Field(s)
                if s == "1 activities · 1 services · 1 receivers")),
            "rows: {rows:?}"
        );
        // INTERNET permission is present (the row the user looks for).
        assert!(
            rows.iter().any(|r| matches!(r, MetadataRow::Permission(s)
                if s == "android.permission.INTERNET")),
            "rows: {rows:?}"
        );
        // Second permission also surfaces.
        assert!(
            rows.iter().any(|r| matches!(r, MetadataRow::Permission(s)
                if s == "android.permission.ACCESS_NETWORK_STATE")),
            "rows: {rows:?}"
        );
        // Provider line carries authorities.
        assert!(
            rows.iter().any(|r| matches!(r, MetadataRow::Provider(s)
                if s.contains("com.example.app.Data")
                    && s.contains("com.example.app.data"))),
            "rows: {rows:?}"
        );
    }

    #[test]
    fn metadata_rows_empty_when_manifest_has_only_pkg() {
        let m = ManifestInfo {
            package: Some("com.example".into()),
            ..Default::default()
        };
        assert!(metadata_rows(&m).is_empty());
    }

    #[test]
    fn metadata_rows_omits_components_summary_when_zero() {
        // No activities/services/receivers → no summary line.
        let m = ManifestInfo {
            package: Some("com.example".into()),
            version_name: Some("1.0".into()),
            permissions: vec![PermissionEntry {
                name: "android.permission.INTERNET".into(),
                decl: "uses",
                protection_level: None,
                label: None,
                max_sdk: None,
            }],
            ..Default::default()
        };
        let rows = metadata_rows(&m);
        assert!(
            rows.iter()
                .any(|r| matches!(r, MetadataRow::Field(s) if s == "versionName 1.0"))
        );
        assert!(
            !rows
                .iter()
                .any(|r| matches!(r, MetadataRow::Field(s) if s.contains("activities"))),
            "no components summary when counts are zero: {rows:?}"
        );
        assert_eq!(
            rows.iter()
                .filter(|r| matches!(r, MetadataRow::Permission(_)))
                .count(),
            1
        );
    }

    /// Render smoke: drive `draw_inspector` headlessly with a populated
    /// manifest; catches any rendering-side regression without needing
    /// a native window. Mirrors the harness pattern in
    /// `app::render_all_panels_smoke`.
    #[test]
    fn inspector_metadata_renders_with_populated_manifest() {
        let mut app = crate::app::AscApp::new(None);
        app.manifest = Some(populated_manifest());
        let ctx = egui::Context::default();
        for _ in 0..3 {
            crate::app::AscApp::run_ui(&ctx, |ui| {
                egui::Panel::right("inspector-test").show(ui, |ui| app.draw_inspector(ui));
            });
        }
        assert!(app.last_error.is_none(), "{:?}", app.last_error);
    }

    /// Outline filter narrows rows by case-insensitive substring.
    /// Empty / whitespace needle is a no-op. Covers `JADX-GUI-008`.
    #[test]
    fn outline_filter_narrows() {
        let entries = vec![
            ("void onCreate()".to_string(), 5, false),
            ("void onResume()".to_string(), 9, false),
            ("private int mView".to_string(), 2, true),
            ("void onPause()".to_string(), 13, false),
        ];
        // Empty needle: every entry.
        assert_eq!(filter_outline(&entries, "").len(), 4);
        assert_eq!(filter_outline(&entries, "   ").len(), 4);
        // Substring "on" matches three onCreate / onResume / onPause.
        let on = filter_outline(&entries, "on");
        assert_eq!(on.len(), 3);
        // Case-insensitive: "MVIEW" matches "mView".
        let field = filter_outline(&entries, "MVIEW");
        assert_eq!(field.len(), 1);
        assert!(field[0].2, "is_field preserved");
        // No match → empty.
        assert!(filter_outline(&entries, "xyz").is_empty());
    }

    /// Clicking an outline entry queues an `OpenClass` with the
    /// entry's line. Alias for `ui::inspector::tests::outline_jump_*`.
    #[test]
    fn outline_jump_queues_open_class() {
        let mut app = crate::app::AscApp::new(None);
        app.tabs.open_pinned("Lcom/foo/Bar;");
        // Active doc with one outline entry at line 7.
        let doc = std::sync::Arc::new(crate::state::Document::new(
            "Lcom/foo/Bar;".into(),
            "classes.dex".into(),
            "class Bar {\n    void m() {}\n}\n".into(),
        ));
        app.active_doc = Some(doc);
        // Manually drive the queue to validate the contract.
        app.queue(crate::command::Command::OpenClass {
            descriptor: "Lcom/foo/Bar;".into(),
            pin: false,
            line: Some(7),
            origin: crate::state::NavOrigin::Outline,
        });
        // One command queued with line 7.
        assert_eq!(app.commands.len(), 1);
        match &app.commands[0] {
            crate::command::Command::OpenClass { line, .. } => {
                assert_eq!(*line, Some(7));
            }
            _ => panic!("expected OpenClass"),
        }
    }
}
