//! Workspace rendering modules. Each module draws one workspace
//! surface; all engine work and state mutation flows through
//! [`crate::app`]'s command dispatch — these files only read state
//! and queue [`crate::command::Command`]s.

pub mod bottom_panel;
pub mod editor;
pub mod explorer;
pub mod inspector;
pub mod palette;
pub mod status_bar;

use eframe::egui;

use crate::design::DARK as T;

/// `Lcom/foo/Bar$Baz;` → `Bar$Baz`.
pub(crate) fn short_name(descriptor: &str) -> String {
    let d = descriptor.trim_start_matches('L');
    let d = d.strip_suffix(';').unwrap_or(d);
    match d.rfind('/') {
        Some(pos) => d[pos + 1..].to_string(),
        None => d.to_string(),
    }
}

/// Convert per-line syntax spans + text into an egui `LayoutJob`.
pub(crate) fn spans_to_job(line: &str, spans: &[crate::highlight::Span]) -> egui::text::LayoutJob {
    use crate::highlight::Token;
    let font = egui::FontId::monospace(T.code_size);
    let plain = egui::TextFormat {
        font_id: font.clone(),
        color: crate::design::token_color(Token::Plain),
        ..Default::default()
    };
    let mut job = egui::text::LayoutJob::default();
    let mut cursor = 0usize;
    for (start, end, tok) in spans {
        if *start > cursor {
            job.append(&line[cursor..*start], 0.0, plain.clone());
        }
        job.append(
            &line[*start..*end],
            0.0,
            egui::TextFormat {
                font_id: font.clone(),
                color: crate::design::token_color(*tok),
                ..Default::default()
            },
        );
        cursor = *end;
    }
    if cursor < line.len() {
        job.append(&line[cursor..], 0.0, plain);
    }
    job.wrap = egui::text::TextWrapping {
        max_width: f32::INFINITY,
        max_rows: usize::MAX,
        break_anywhere: false,
        overflow_character: None,
    };
    job
}
