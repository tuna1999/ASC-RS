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
        let entries: Vec<(String, PaletteAction)> = match mode {
            PaletteMode::Commands => palette_commands()
                .into_iter()
                .filter(|(name, _)| needle.is_empty() || name.to_lowercase().contains(&needle))
                .map(|(name, c)| (name.to_string(), PaletteAction::Dispatch(c)))
                .collect(),
            PaletteMode::QuickOpen => {
                let hits: Vec<usize> = self.tree.filter(&needle).to_vec();
                hits.into_iter()
                    .take(50)
                    .map(|leaf| {
                        let d = self.tree.entry(leaf).descriptor.clone();
                        (d.clone(), PaletteAction::OpenClass(d))
                    })
                    .collect()
            }
        };

        let mut close = false;
        let mut run: Option<PaletteAction> = None;

        egui::Window::new(match mode {
            PaletteMode::QuickOpen => "quick open",
            PaletteMode::Commands => "commands",
        })
        .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 80.0))
        .fixed_size(egui::vec2(520.0, 0.0))
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            let input = ui.add(
                egui::TextEdit::singleline(&mut self.palette_input)
                    .hint_text(match mode {
                        PaletteMode::QuickOpen => "class name…",
                        PaletteMode::Commands => "command…",
                    })
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            );
            if self.focus_palette {
                input.request_focus();
                self.focus_palette = false;
            }
            let entered = ui.input(|i| i.key_pressed(egui::Key::Enter));

            let list_height = (entries.len() as f32 * T.row_list).min(320.0);
            egui::ScrollArea::vertical()
                .max_height(list_height)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (label, action) in &entries {
                        let rich = egui::RichText::new(label)
                            .monospace()
                            .size(12.5)
                            .color(T.text);
                        if ui
                            .selectable_label(false, rich)
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            run = Some(match action {
                                PaletteAction::Dispatch(c) => PaletteAction::Dispatch(c.clone()),
                                PaletteAction::OpenClass(d) => PaletteAction::OpenClass(d.clone()),
                            });
                        }
                    }
                });
            if entered {
                if let Some((_, action)) = entries.into_iter().next() {
                    run = Some(action);
                }
            }
            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                close = true;
            }
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
        }
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
