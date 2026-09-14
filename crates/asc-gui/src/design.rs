//! Centralized design tokens — the single source of truth for colors
//! and metrics (design language: "ASC Instant Workbench"; see
//! `docs/design-language.md`). Rendering code references semantic
//! tokens only; raw `Color32`/size literals live here.

use eframe::egui::{Color32, Style, Visuals};

/// All visual constants. Dark-first.
#[derive(Debug, Clone, Copy)]
pub struct Tokens {
    // --- backgrounds ---
    pub app_bg: Color32,
    pub panel_bg: Color32,
    pub surface: Color32,
    pub hover: Color32,
    pub border: Color32,

    // --- text ---
    pub text: Color32,
    pub text_secondary: Color32,
    pub text_disabled: Color32,

    // --- semantic ---
    pub accent: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub error: Color32,
    pub info: Color32,

    // --- syntax (line tokenizer output → color) ---
    pub syn_keyword: Color32,
    pub syn_type: Color32,
    pub syn_annotation: Color32,
    pub syn_string: Color32,
    pub syn_number: Color32,
    pub syn_comment: Color32,
    pub syn_plain: Color32,

    // --- metrics (px) ---
    pub row_tree: f32,
    pub row_list: f32,
    pub tab_height: f32,
    pub toolbar_height: f32,
    pub status_height: f32,
    pub code_size: f32,
    pub ui_size: f32,
    pub small_size: f32,
    pub panel_padding: f32,
    pub spacing: f32,
    pub spacing_tight: f32,
    pub explorer_default: f32,
    pub inspector_default: f32,
    pub bottom_default: f32,
}

/// The reference dark palette.
pub const DARK: Tokens = Tokens {
    app_bg: Color32::from_rgb(0x0F, 0x11, 0x15),
    panel_bg: Color32::from_rgb(0x14, 0x17, 0x1D),
    surface: Color32::from_rgb(0x19, 0x1D, 0x24),
    hover: Color32::from_rgb(0x20, 0x26, 0x31),
    border: Color32::from_rgb(0x2A, 0x31, 0x3C),

    text: Color32::from_rgb(0xE6, 0xEA, 0xF0),
    text_secondary: Color32::from_rgb(0x90, 0x99, 0xA7),
    text_disabled: Color32::from_rgb(0x5C, 0x66, 0x74),

    accent: Color32::from_rgb(0x4C, 0x8D, 0xFF),
    success: Color32::from_rgb(0x3F, 0xB9, 0x50),
    warning: Color32::from_rgb(0xD2, 0x99, 0x22),
    error: Color32::from_rgb(0xF8, 0x51, 0x49),
    info: Color32::from_rgb(0x58, 0xA6, 0xFF),

    syn_keyword: Color32::from_rgb(0xCC, 0x88, 0x44),
    syn_type: Color32::from_rgb(0xA9, 0xB7, 0xC6),
    syn_annotation: Color32::from_rgb(0xBB, 0xB5, 0x29),
    syn_string: Color32::from_rgb(0x7C, 0xBF, 0x6B),
    syn_number: Color32::from_rgb(0x2A, 0xA1, 0x98),
    syn_comment: Color32::from_rgb(0x6E, 0x76, 0x81),
    syn_plain: Color32::from_rgb(0xC8, 0xCE, 0xDA),

    row_tree: 20.0,
    row_list: 20.0,
    tab_height: 26.0,
    toolbar_height: 30.0,
    status_height: 24.0,
    code_size: 13.0,
    ui_size: 13.0,
    small_size: 11.5,
    panel_padding: 8.0,
    spacing: 8.0,
    spacing_tight: 4.0,
    explorer_default: 260.0,
    inspector_default: 240.0,
    bottom_default: 180.0,
};

/// Apply the workbench dark style to an egui context. Called once at
/// startup (and on theme change later — light theme is future work).
pub fn apply(ctx: &eframe::egui::Context) {
    let t = DARK;
    let mut style = Style::default();
    let mut v = Visuals::dark();
    v.panel_fill = t.app_bg;
    v.window_fill = t.surface;
    v.extreme_bg_color = t.app_bg;
    v.faint_bg_color = t.surface;
    v.widgets.noninteractive.bg_fill = t.panel_bg;
    v.widgets.inactive.bg_fill = t.surface;
    v.widgets.hovered.bg_fill = t.hover;
    v.widgets.active.bg_fill = t.hover;
    v.widgets.open.bg_fill = t.hover;
    v.selection.bg_fill = t.accent.linear_multiply(0.25);
    v.selection.stroke.color = t.text;
    v.widgets.noninteractive.fg_stroke.color = t.text_secondary;
    v.widgets.inactive.fg_stroke.color = t.text;
    v.widgets.hovered.fg_stroke.color = t.text;
    v.widgets.active.fg_stroke.color = t.text;
    v.widgets.noninteractive.bg_stroke.color = t.border;
    v.widgets.inactive.bg_stroke.color = t.border;
    style.visuals = v;
    style.spacing.item_spacing = eframe::egui::vec2(t.spacing_tight, t.spacing_tight);
    style.spacing.menu_margin = eframe::egui::Margin::same(6);
    ctx.set_style(style);
}

use crate::highlight::Token;

/// Syntax token → color (replaces `highlight::token_color`'s local
/// palette; kept as a token-domain mapping).
pub fn token_color(tok: Token) -> Color32 {
    let t = &DARK;
    match tok {
        Token::Keyword | Token::Modifier => t.syn_keyword,
        Token::Type => t.syn_type,
        Token::Annotation => t.syn_annotation,
        Token::String => t.syn_string,
        Token::Number => t.syn_number,
        Token::Comment => t.syn_comment,
        Token::Plain => t.syn_plain,
    }
}
