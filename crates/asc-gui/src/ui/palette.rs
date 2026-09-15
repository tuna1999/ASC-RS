//! Command palette + quick open (Ctrl+Shift+P / Ctrl+P).

use eframe::egui;

use crate::app::AscApp;
use crate::command::Command;
use crate::design::DARK as T;
use crate::state::NavOrigin;

/// Palette mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteMode {
    /// Fuzzy class open (Ctrl+P).
    QuickOpen,
    /// Command list (Ctrl+Shift+P).
    Commands,
}

/// What running a palette row does.
enum PaletteAction {
    Dispatch(Command),
    OpenClass(String),
}

impl AscApp {
    pub(crate) fn draw_palette(&mut self, ctx: &egui::Context) {
        let Some(mode) = self.palette else { return };

        // Build entries once from the current input.
        let needle = self.palette_input.trim().to_ascii_lowercase();
        let entries: Vec<(String, String, PaletteAction)> = match mode {
            PaletteMode::Commands => palette_commands()
                .into_iter()
                .filter(|(name, _)| needle.is_empty() || name.to_lowercase().contains(&needle))
                .map(|(name, c)| (name.to_string(), String::new(), PaletteAction::Dispatch(c)))
                .collect(),
            PaletteMode::QuickOpen => self
                .tree
                .filter(&needle)
                .to_vec()
                .into_iter()
                .take(50)
                .map(|leaf| {
                    let d = self.tree.entry(leaf).descriptor.clone();
                    let package = package_of(&d);
                    (super::short_name(&d), package, PaletteAction::OpenClass(d))
                })
                .collect(),
        };

        let count = entries.len();
        if self.palette_sel >= count {
            self.palette_sel = count.saturating_sub(1);
        }

        let mut close = false;
        let mut run: Option<PaletteAction> = None;

        let frame = egui::Frame::new()
            .fill(T.surface)
            .stroke(egui::Stroke::new(1.0_f32, T.border))
            .corner_radius(4.0)
            .inner_margin(egui::Margin::same(T.panel_padding as i8))
            .outer_margin(egui::Margin::symmetric(0, 4));

        egui::Window::new("palette")
            .title_bar(false)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 72.0))
            .min_width(560.0)
            .max_width(560.0)
            .frame(frame)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.set_min_width(544.0);

                let input = ui.add(
                    egui::TextEdit::singleline(&mut self.palette_input)
                        .hint_text(match mode {
                            PaletteMode::QuickOpen => "class name…",
                            PaletteMode::Commands => "command…",
                        })
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
                let input_changed = input.changed();
                if self.focus_palette {
                    input.request_focus();
                    self.focus_palette = false;
                }

                // Keyboard navigation.
                let move_sel = |delta: i32, app: &mut Self| {
                    if count == 0 {
                        return;
                    }
                    let n = count as i32;
                    let cur = app.palette_sel as i32;
                    app.palette_sel = ((cur + delta).rem_euclid(n)) as usize;
                };
                if ui.input(|i| i.key_pressed(egui::Key::ArrowDown)) {
                    move_sel(1, self);
                }
                if ui.input(|i| i.key_pressed(egui::Key::ArrowUp)) {
                    move_sel(-1, self);
                }
                if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if let Some((_, _, action)) = entries.get(self.palette_sel) {
                        run = Some(match action {
                            PaletteAction::Dispatch(c) => PaletteAction::Dispatch(c.clone()),
                            PaletteAction::OpenClass(d) => PaletteAction::OpenClass(d.clone()),
                        });
                    }
                }
                if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    close = true;
                }
                if input_changed {
                    self.palette_sel = 0;
                }

                if entries.is_empty() {
                    ui.add_space(2.0);
                    ui.label(
                        egui::RichText::new(match mode {
                            PaletteMode::QuickOpen => "no matching classes",
                            PaletteMode::Commands => "no matching commands",
                        })
                        .small()
                        .color(T.text_secondary),
                    );
                    return;
                }

                ui.add_space(2.0);
                let row_h = T.row_list;
                let list_height = (count as f32 * row_h).min(300.0);
                egui::ScrollArea::vertical()
                    .max_height(list_height)
                    .auto_shrink([false, false])
                    .show_rows(ui, row_h, count, |ui, range| {
                        for idx in range {
                            let (label, sub, action) = &entries[idx];
                            let is_sel = idx == self.palette_sel;
                            let row_frame = if is_sel {
                                egui::Frame::new().fill(T.accent.linear_multiply(0.16))
                            } else {
                                egui::Frame::new()
                            };
                            let resp = row_frame
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.set_min_height(row_h - 2.0);
                                        ui.monospace(
                                            egui::RichText::new(label).size(12.5).color(T.text),
                                        );
                                        if !sub.is_empty() {
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    ui.monospace(
                                                        egui::RichText::new(sub)
                                                            .small()
                                                            .color(T.text_secondary),
                                                    );
                                                },
                                            );
                                        }
                                    });
                                })
                                .response
                                .interact(egui::Sense::click());
                            if resp.hovered() {
                                self.palette_sel = idx;
                            }
                            if resp.clicked() {
                                run = Some(match action {
                                    PaletteAction::Dispatch(c) => {
                                        PaletteAction::Dispatch(c.clone())
                                    }
                                    PaletteAction::OpenClass(d) => {
                                        PaletteAction::OpenClass(d.clone())
                                    }
                                });
                            }
                        }
                    });

                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(format!(
                        "{} {} · ▲▼ select · Enter open · Esc close",
                        count,
                        if mode == PaletteMode::QuickOpen {
                            "classes"
                        } else {
                            "commands"
                        }
                    ))
                    .small()
                    .monospace()
                    .color(T.text_disabled),
                );
            });

        if let Some(action) = run {
            match action {
                PaletteAction::Dispatch(c) => self.queue(c),
                PaletteAction::OpenClass(d) => self.queue(Command::OpenClass {
                    descriptor: d,
                    pin: false,
                    line: None,
                    origin: NavOrigin::Tree,
                }),
            }
            close = true;
        }
        if close {
            self.palette = None;
            self.palette_input.clear();
            self.palette_sel = 0;
        }
    }
}

/// `Lcom/foo/Bar;` → `com.foo` (empty when default package).
fn package_of(descriptor: &str) -> String {
    let d = descriptor.trim_start_matches('L');
    let d = d.strip_suffix(';').unwrap_or(d);
    match d.rfind('/') {
        Some(pos) => d[..pos].replace('/', "."),
        None => String::new(),
    }
}

/// Static command list for the palette.
fn palette_commands() -> Vec<(&'static str, Command)> {
    vec![
        ("Open artifact… (Ctrl+O)", Command::OpenArtifact),
        ("Reload artifact", Command::ReloadArtifact),
        ("Global search (Ctrl+Shift+F)", Command::GlobalSearch),
        ("Find in document (Ctrl+F)", Command::FindInDocument),
        ("Quick open class (Ctrl+P)", Command::QuickOpen),
        ("Find references to selected class", Command::FindReferences),
        ("Close tab (Ctrl+W)", Command::CloseTab),
        ("Pin tab", Command::PinTab),
        ("Next tab (Ctrl+Tab)", Command::NextTab),
        ("Previous tab (Ctrl+Shift+Tab)", Command::PreviousTab),
        ("Back (Alt+←)", Command::NavigateBack),
        ("Forward (Alt+→)", Command::NavigateForward),
        ("Toggle Explorer (Ctrl+1)", Command::ToggleExplorer),
        ("Toggle Inspector (Ctrl+2)", Command::ToggleInspector),
        ("Toggle bottom panel (Ctrl+3)", Command::ToggleBottomPanel),
        ("Cancel running task (Esc)", Command::CancelTask),
    ]
}
