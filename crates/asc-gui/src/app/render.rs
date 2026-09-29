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
                        .tabs
                        .active_descriptor()
                        .or(self.selected_class.as_deref())
                        .map(crate::ui::short_name)
                        .unwrap_or_else(|| "—".to_string());
                    let has_target = self
                        .tabs
                        .active_descriptor()
                        .or(self.selected_class.as_deref())
                        .is_some();
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
                    ui.separator();
                    let sel_ok = self.symbol_sel.is_some();
                    if ui
                        .add_enabled(sel_ok, egui::Button::new("Rename symbol  (n)"))
                        .on_disabled_hover_text("click an identifier in the editor first")
                        .clicked()
                    {
                        ui.close();
                        self.queue(Command::BeginRenameSymbol);
                    }
                    let line_ok = self.last_clicked_line.is_some();
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
                    let next = if design::theme() == design::Theme::Dark {
                        "light"
                    } else {
                        "dark"
                    };
                    if ui.button(format!("Switch to {next} theme")).clicked() {
                        ui.close();
                        self.queue(Command::ToggleTheme);
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
                    if self.tasks.findrefs_running() {
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
                            }
                            if toggle(
                                ui,
                                "☰",
                                self.show_bottom && self.bottom_tab == BottomTab::Tasks,
                                "Tasks (Ctrl+3)",
                            ) {
                                self.show_bottom = true;
                                self.bottom_tab = BottomTab::Tasks;
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

        // 9. Editor (center).
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(tokens.app_bg))
            .show(ui, |ui| {
                self.draw_editor(ui);
            });

        // 10. Palette overlay.
        self.draw_palette(ui.ctx());

        // 11. Dispatch everything queued this frame.
        let commands = std::mem::take(&mut self.commands);
        for cmd in commands {
            self.dispatch(cmd, ui.ctx());
        }
    }
}
