//! `asc-gui` binary entry point.
//!
//! Two modes:
//!
//! - `--selfcheck <apk>`: runs [`asc_gui::run_selfcheck`] and prints a
//!   one-line summary of every step. Exits 0 on success, non-zero on
//!   engine / IO errors.
//! - (no flag): launches the eframe desktop GUI immediately — no APK
//!   open happens before the window exists. A path argument (or the
//!   native open dialog) is opened as a background task on the first
//!   frame; the workspace shows an empty state until it lands.

use std::path::PathBuf;
use std::process::ExitCode;

use asc_gui::{AscApp, run_selfcheck};
use eframe::egui;

/// 32×32 RGBA window icon (same design as `assets/icon.ico`, which
/// the build script embeds into the executable resource section for
/// the shell/taskbar).
const ICON_32_RGBA: &[u8] = include_bytes!("../assets/icon_32.rgba");

/// Stamped from `Cargo.toml` at build time via `env!("CARGO_PKG_VERSION")`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--selfcheck") {
        return run_selfcheck_mode(&args);
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("asc-gui {VERSION}");
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return ExitCode::SUCCESS;
    }
    run_gui_mode(&args)
}

fn print_help() {
    println!("asc-gui {VERSION} — ASC-RS desktop workbench");
    println!();
    println!("USAGE:");
    println!(
        "  asc-gui [path.apk]            Open the GUI on the given APK (loaded in the background)."
    );
    println!("  asc-gui --selfcheck <apk>     Run the headless selfcheck and exit.");
    println!("  asc-gui --version             Print version and exit.");
    println!("  asc-gui --help                Print this help.");
}

fn run_selfcheck_mode(args: &[String]) -> ExitCode {
    // Find the apk path (the non-flag arg after --selfcheck).
    let apk = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--") && *a != "--selfcheck")
        .map(PathBuf::from);
    let Some(apk) = apk else {
        eprintln!("--selfcheck requires an APK path argument");
        return ExitCode::from(2);
    };
    match run_selfcheck(&apk) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("selfcheck failed: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_gui_mode(args: &[String]) -> ExitCode {
    let initial = args
        .iter()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .map(PathBuf::from);

    let viewport = egui::ViewportBuilder::default()
        .with_title(format!("asc-gui {VERSION}"))
        .with_inner_size([1280.0, 820.0])
        .with_icon(std::sync::Arc::new(egui::IconData {
            rgba: ICON_32_RGBA.to_vec(),
            width: 32,
            height: 32,
        }));
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    if let Err(e) = eframe::run_native(
        "asc-gui",
        options,
        Box::new(move |cc| {
            asc_gui::design::apply(&cc.egui_ctx);
            Ok(Box::new(AscApp::new(initial)))
        }),
    ) {
        eprintln!("eframe failed: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
