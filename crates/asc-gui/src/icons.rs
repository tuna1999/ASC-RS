//! Jadx-style workspace raster icons (folders + source files by class
//! kind), embedded as 32×32 RGBA blobs and uploaded to egui textures
//! once per app. The assets are generated (PowerShell System.Drawing)
//! into `assets/ic_*.rgba`; see `docs/gui-redesign-plan.md`.

use eframe::egui;

use crate::session::ClassKind;

macro_rules! icon_asset {
    ($name:literal) => {
        include_bytes!(concat!("../assets/ic_", $name, ".rgba"))
    };
}

/// Loaded icon textures (one `TextureHandle` each).
pub(crate) struct Icons {
    pub folder_closed: egui::TextureHandle,
    pub folder_open: egui::TextureHandle,
    doc_class: egui::TextureHandle,
    doc_interface: egui::TextureHandle,
    doc_enum: egui::TextureHandle,
    doc_annotation: egui::TextureHandle,
}

const ICON_PX: f32 = 15.0;

impl Icons {
    /// Upload every icon texture. Cheap (six 32×32 uploads, once).
    pub fn load(ctx: &egui::Context) -> Self {
        let tex = |name: &str, bytes: &'static [u8]| {
            let image = egui::ColorImage::from_rgba_unmultiplied([32, 32], bytes);
            ctx.load_texture(name, image, egui::TextureOptions::LINEAR)
        };
        Icons {
            folder_closed: tex("ic_folder_closed", icon_asset!("folder_closed")),
            folder_open: tex("ic_folder_open", icon_asset!("folder_open")),
            doc_class: tex("ic_doc_class", icon_asset!("doc_class")),
            doc_interface: tex("ic_doc_interface", icon_asset!("doc_interface")),
            doc_enum: tex("ic_doc_enum", icon_asset!("doc_enum")),
            doc_annotation: tex("ic_doc_annotation", icon_asset!("doc_annotation")),
        }
    }

    /// Source-file icon for a class kind.
    pub fn doc(&self, kind: ClassKind) -> &egui::TextureHandle {
        match kind {
            ClassKind::Class => &self.doc_class,
            ClassKind::Interface => &self.doc_interface,
            ClassKind::Enum => &self.doc_enum,
            ClassKind::Annotation => &self.doc_annotation,
        }
    }
}

/// Draw an icon at the standard row size, vertically centered on the
/// current row.
pub(crate) fn icon_ui(ui: &mut egui::Ui, tex: &egui::TextureHandle) -> egui::Response {
    ui.add(
        egui::Image::from_texture(tex)
            .fit_to_exact_size(egui::vec2(ICON_PX, ICON_PX))
            .corner_radius(2.0),
    )
}
