//! Frame rendering for the application shell: the eframe `App` impl
//! (menu bar, side panels, editor, overlays) lives here.

use super::*;

impl eframe::App for AscApp {
    /// Non-UI work. eframe (0.35+) forbids painting from here, so the
    /// texture upload — which needs a live `Context` — moved into
    /// [`App::ui`] behind the same `get_or_insert_with` guard.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.initial_path.is_some() {
            let path = self.initial_path.take().unwrap();
            self.open_path(&path, ctx);
        }

        // Drain worker results before the UI pass so this frame sees
        // freshly-completed tasks.
        self.poll_workers(ctx);
        let want_title = self.window_title.clone();
        if want_title != "asc-gui" {
            let current = ctx.input(|i| i.viewport().title.clone());
            if current.as_deref() != Some(want_title.as_str()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Title(want_title));
            }
        }

        // Frame-level shortcuts.
        self.frame_shortcuts(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let tokens = design::tokens();

        // Upload workspace icon textures once (folders / source
        // files; see `icons.rs`).
        self.icons
            .get_or_insert_with(|| crate::icons::Icons::load(ui.ctx()));

        // 1. Menu bar.
        egui::Panel::top("menubar").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open artifact…  (Ctrl+O)").clicked() {
                        ui.close();
                        self.queue(Command::OpenArtifact);
                    }
                    if ui.button("Reload artifact").clicked() {
                        ui.close();
                        self.queue(Command::ReloadArtifact);
                    }
                    // Recent artifacts (JADX-GUI-007): most recent
                    // first; click re-opens (missing paths are
                    // reported, not fatal).
                    let recents: Vec<std::path::PathBuf> = self.tabs.recent_artifacts().to_vec();
                    if recents.is_empty() {
                        ui.weak(egui::RichText::new("no recent artifacts").small());
                    } else {
                        for p in &recents {
                            let name = p
                                .file_name()
                                .map(|f| f.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            if ui
                                .selectable_label(false, egui::RichText::new(name).small())
                                .on_hover_text(p.display().to_string())
                                .clicked()
                            {
                                ui.close();
                                let path = p.clone();
                                self.queue(Command::OpenRecent { path });
                            }
                        }
                    }
                    ui.separator();
                    if ui.button("Quit").clicked() {
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Navigate", |ui| {
                    if ui
                        .button(egui::RichText::new("Back  (Alt+←)").monospace().size(12.5))
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::NavigateBack);
                    }
                    if ui
                        .button(
                            egui::RichText::new("Forward  (Alt+→)")
                                .monospace()
                                .size(12.5),
                        )
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::NavigateForward);
                    }
                });
                ui.menu_button("Search", |ui| {
                    if ui.button("Search artifact  (Ctrl+Shift+F)").clicked() {
                        ui.close();
                        self.queue(Command::GlobalSearch);
                    }
                    if ui.button("Find in document  (Ctrl+F)").clicked() {
                        ui.close();
                        self.queue(Command::FindInDocument);
                    }
                    if ui.button("Quick open class  (Ctrl+P)").clicked() {
                        ui.close();
                        self.queue(Command::QuickOpen);
                    }
                });
                ui.menu_button("Analysis", |ui| {
                    let target = self
                        .active_class_descriptor()
                        .map(crate::ui::short_name)
                        .unwrap_or_else(|| "—".to_string());
                    let has_target = self.active_class_descriptor().is_some();
                    if ui
                        .add_enabled(
                            has_target,
                            egui::Button::new(format!("Find references to {target}")),
                        )
                        .on_disabled_hover_text("open a class first")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::FindReferences);
                    }
                    if ui
                        .add_enabled(
                            has_target,
                            egui::Button::new(format!("Show Smali of {target}")),
                        )
                        .on_disabled_hover_text("open a class first")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::ShowSmali);
                    }
                    let sel_ok = self.active_symbol_sel().is_some();
                    if ui
                        .add_enabled(sel_ok, egui::Button::new("Show Smali of clicked method"))
                        .on_disabled_hover_text("click a method identifier first")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::ShowSmaliMethod);
                    }
                    if ui
                        .add_enabled(sel_ok, egui::Button::new("Show callees of clicked method"))
                        .on_disabled_hover_text("click a method identifier first")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::ShowCallees);
                    }
                    let class_ok = self.active_symbol_sel().is_some()
                        || self.active_class_descriptor().is_some();
                    if ui
                        .add_enabled(class_ok, egui::Button::new("Strings used by this class"))
                        .on_disabled_hover_text("select a class first")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::ShowClassStrings);
                    }
                    let sel_ok = self.active_symbol_sel().is_some();
                    if ui
                        .add_enabled(sel_ok, egui::Button::new("Rename symbol  (n)"))
                        .on_disabled_hover_text("click an identifier in the editor first")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::BeginRenameSymbol);
                    }
                    let line_ok = self.clicked_line().is_some();
                    if ui
                        .add_enabled(line_ok, egui::Button::new("Comment line  (;)"))
                        .on_disabled_hover_text("click a code line first")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::BeginLineComment);
                    }
                });
                ui.menu_button("View", |ui| {
                    ui.toggle_value(&mut self.show_explorer, "Explorer  (Ctrl+1)");
                    ui.toggle_value(&mut self.show_inspector, "Inspector  (Ctrl+2)");
                    ui.toggle_value(&mut self.show_bottom, "Bottom panel  (Ctrl+3)");
                    ui.separator();
                    let mut paranoid = self.paranoid;
                    if ui
                        .toggle_value(&mut paranoid, "Decode Paranoid strings")
                        .on_hover_text("Show Paranoid/LSParanoid-obfuscated literals in decompiled code and match them in string searches")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::ToggleParanoid);
                    }
                    ui.separator();
                    let next = if design::theme() == design::Theme::Dark {
                        "light"
                    } else {
                        "dark"
                    };
                    if ui.button(format!("Switch to {next} theme")).clicked() {
                        ui.close();
                        self.queue(Command::ToggleTheme);
                    }
                    if ui.button("Settings…").clicked() {
                        ui.close();
                        self.queue(Command::OpenSettings);
                    }
                });
                ui.menu_button("Help", |ui| {
                    ui.label("ASC Instant Workbench");
                    ui.weak(if let Some(s) = &self.session {
                        format!("artifact: {}", s.path().display())
                    } else {
                        "no artifact open".to_string()
                    });
                });
            });
        });

        // 4. Toolbar: back/forward, artifact search, meta.
        egui::Panel::top("toolbar")
            .frame(egui::Frame::new().fill(tokens.surface))
            .show(ui, |ui| {
                ui.horizontal_centered(|ui| {
                    // ◀/▶ exist in both families; monospace keeps the
                    // toolbar's code-face consistent.
                    let back = ui
                        .button(egui::RichText::new("◀").monospace().size(12.0))
                        .on_hover_text(egui::RichText::new("back (Alt+←)").monospace().size(12.0));
                    if back.clicked() {
                        self.queue(Command::NavigateBack);
                    }
                    let fwd = ui
                        .button(egui::RichText::new("▶").monospace().size(12.0))
                        .on_hover_text(
                            egui::RichText::new("forward (Alt+→)")
                                .monospace()
                                .size(12.0),
                        );
                    if fwd.clicked() {
                        self.queue(Command::NavigateForward);
                    }
                    ui.separator();
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut self.search.input)
                            .hint_text("search artifact…")
                            .desired_width(280.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    if self.focus_search {
                        edit.request_focus();
                        self.focus_search = false;
                    }
                    if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.queue(Command::RunSearch);
                    }
                    // Live only: a cancelled/superseded scan keeps running
                    // but its result is discarded, so it must not spin here.
                    if self.tasks.findrefs_live() {
                        ui.spinner();
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button("⌘P")
                            .on_hover_text("command palette (Ctrl+Shift+P)")
                            .clicked()
                        {
                            self.queue(Command::ToggleCommandPalette);
                        }
                        let pkg = self
                            .manifest
                            .as_ref()
                            .and_then(|m| m.package.clone())
                            .unwrap_or_else(|| {
                                self.session
                                    .as_ref()
                                    .map(|s| {
                                        s.path()
                                            .file_stem()
                                            .map(|f| f.to_string_lossy().into_owned())
                                            .unwrap_or_default()
                                    })
                                    .unwrap_or_else(|| "no artifact".to_string())
                            });
                        let ver = self
                            .manifest
                            .as_ref()
                            .and_then(|m| m.version_code)
                            .map(|v| format!(" v{v}"))
                            .unwrap_or_default();
                        ui.monospace(
                            egui::RichText::new(format!("{pkg}{ver}"))
                                .small()
                                .color(tokens.text_secondary),
                        );
                    });
                });
            });

        // 5. Bottom panel.
        if self.show_bottom {
            egui::Panel::bottom("bottom_panel")
                .resizable(true)
                .default_size(tokens.bottom_default)
                .frame(egui::Frame::new().fill(tokens.panel_bg))
                .show(ui, |ui| {
                    self.draw_bottom_panel(ui);
                });
        }

        // 6. Status bar.
        egui::Panel::bottom("statusbar")
            .frame(egui::Frame::new().fill(tokens.panel_bg))
            .show(ui, |ui| {
                self.draw_status_bar(ui);
            });

        // 7. Inspector (right).
        if self.show_inspector {
            egui::Panel::right("inspector")
                .resizable(true)
                .default_size(tokens.inspector_default)
                .frame(egui::Frame::new().fill(tokens.panel_bg))
                .show(ui, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.draw_inspector(ui);
                    });
                });
        }

        // 7b. Activity bar (far left): Explorer / Search / Tasks.
        {
            egui::Panel::left("activity_bar")
                .exact_size(36.0)
                .frame(egui::Frame::new().fill(tokens.panel_bg))
                .show(ui, |ui| {
                    ui.with_layout(
                        egui::Layout::top_down_justified(egui::Align::Center),
                        |ui| {
                            ui.add_space(4.0);
                            let toggle = |ui: &mut egui::Ui,
                                          label: &'static str,
                                          active: bool,
                                          hint: &'static str|
                             -> bool {
                                let rich = egui::RichText::new(label).monospace().size(15.0).color(
                                    if active {
                                        tokens.accent
                                    } else {
                                        tokens.text_secondary
                                    },
                                );
                                let btn = egui::Button::new(rich).frame(false);
                                let resp = ui
                                    .add(btn)
                                    .on_hover_text(hint)
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                                resp.clicked()
                            };
                            if toggle(ui, "▤", self.show_explorer, "Explorer (Ctrl+1)") {
                                self.show_explorer = !self.show_explorer;
                            }
                            if toggle(
                                ui,
                                "🔍",
                                self.show_bottom && self.bottom_tab == BottomTab::Results,
                                "Search (Ctrl+Shift+F)",
                            ) {
                                self.show_bottom = true;
                                self.bottom_tab = BottomTab::Results;
                                self.focus_search = true;
                                self.pin_bottom_focus();
                            }
                            if toggle(
                                ui,
                                "☰",
                                self.show_bottom && self.bottom_tab == BottomTab::Tasks,
                                "Tasks (Ctrl+3)",
                            ) {
                                self.show_bottom = true;
                                self.bottom_tab = BottomTab::Tasks;
                                self.pin_bottom_focus();
                            }
                        },
                    );
                });
        }

        // 8. Explorer (left).
        if self.show_explorer {
            egui::Panel::left("explorer")
                .resizable(true)
                .default_size(tokens.explorer_default)
                .frame(egui::Frame::new().fill(tokens.panel_bg))
                .show(ui, |ui| {
                    self.draw_explorer(ui);
                });
        }

        // 9a. Overlay strips (panels — before the central panel).
        self.draw_open_tabs_strip(ui);
        self.draw_settings_strip(ui);
        self.draw_goto_bar(ui);

        // 9. Editor (center).
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(tokens.app_bg))
            .show(ui, |ui| {
                self.draw_editor(ui);
            });

        // 10. Palette overlay.
        self.draw_palette(ui.ctx());

        // 11. Dispatch everything queued this frame.

        // 11. Dispatch everything queued this frame.
        let commands = std::mem::take(&mut self.commands);
        for cmd in commands {
            self.dispatch(cmd, ui.ctx());
        }
    }
}

impl AscApp {
    /// Open-tabs picker (ASC-GUI-029 / JADX-GUI-004): filterable
    /// list of open tabs, click activates. Ctrl+Shift+H.
    fn draw_open_tabs_strip(&mut self, ui: &mut egui::Ui) {
        if !self.show_open_tabs {
            return;
        }
        #[allow(non_snake_case)]
        let T = design::tokens();
        let mut activate: Option<String> = None;
        // Snapshot before the mutable closure.
        let tabs: Vec<(String, bool)> = self
            .tabs
            .tabs()
            .iter()
            .map(|t| {
                let active = self.tabs.active_descriptor() == Some(t.descriptor.as_str());
                (t.descriptor.clone(), active)
            })
            .collect();
        let needle = self.open_tabs_filter.trim().to_ascii_lowercase();
        let shown: Vec<_> = tabs
            .iter()
            .filter(|(d, _)| d.to_ascii_lowercase().contains(&needle))
            .collect();
        egui::Panel::top("open_tabs_strip")
            .frame(egui::Frame::new().fill(T.panel_bg).inner_margin(6))
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.open_tabs_filter)
                        .hint_text("filter open tabs…")
                        .font(egui::TextStyle::Monospace),
                );
                egui::ScrollArea::vertical()
                    .max_height(160.0)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (d, is_active) in &shown {
                            let star = if self.tabs.bookmark(d).is_some() {
                                "★ "
                            } else {
                                ""
                            };
                            let label = format!("{star}{}", crate::ui::short_name(d));
                            let resp = ui
                                .selectable_label(*is_active, egui::RichText::new(label).small())
                                .on_hover_text(d);
                            if resp.clicked() {
                                activate = Some(d.clone());
                            }
                        }
                    });
                ui.weak(
                    egui::RichText::new(format!(
                        "{} / {} tabs · Esc close",
                        shown.len(),
                        tabs.len()
                    ))
                    .small(),
                );
            });
        if let Some(d) = activate {
            self.show_open_tabs = false;
            self.tabs.activate(&d);
            if self.documents.contains(&d) {
                self.active_doc = self.documents.get(&d);
            }
        }
    }

    /// Settings dialog (ASC-GUI-025 / JADX-GUI-009): theme picker.
    fn draw_settings_strip(&mut self, ui: &mut egui::Ui) {
        if !self.show_settings {
            return;
        }
        #[allow(non_snake_case)]
        let T = design::tokens();
        let mut close = false;
        egui::Panel::top("settings_strip")
            .frame(egui::Frame::new().fill(T.panel_bg).inner_margin(6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("settings · theme:");
                    if ui
                        .selectable_label(matches!(design::theme(), design::Theme::Dark), "dark")
                        .clicked()
                    {
                        self.queue(Command::ToggleTheme);
                    }
                    if ui
                        .selectable_label(matches!(design::theme(), design::Theme::Light), "light")
                        .clicked()
                    {
                        self.queue(Command::ToggleTheme);
                    }
                    if ui.small_button("close").clicked() {
                        close = true;
                    }
                });
            });
        if close {
            self.show_settings = false;
        }
    }

    /// Goto-line bar (JADX-GUI-020): Ctrl+G, Enter applies.
    fn draw_goto_bar(&mut self, ui: &mut egui::Ui) {
        let Some(input) = self.goto_line_input.as_mut() else {
            return;
        };
        #[allow(non_snake_case)]
        let T = design::tokens();
        let mut apply = None;
        egui::Panel::top("goto_line_strip")
            .frame(egui::Frame::new().fill(T.panel_bg).inner_margin(6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("goto line:");
                    let resp = ui.add(
                        egui::TextEdit::singleline(input)
                            .hint_text("1-indexed")
                            .font(egui::TextStyle::Monospace)
                            .desired_width(120.0),
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        apply = input.trim().parse::<usize>().ok();
                    }
                });
            });
        if let Some(line) = apply {
            self.apply_goto_line(line);
        }
    }
}
