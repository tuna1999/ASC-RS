//! `asc-gui` binary entry point.
//!
//! Two modes:
//!
//! - `--selfcheck <apk>`: runs [`asc_gui::run_selfcheck`] and prints a
//!   one-line summary of every step. Exits 0 on success, non-zero on
//!   engine / IO errors.
//! - (no flag): launches the eframe desktop GUI. The window opens
//!   with the standard panel layout (class tree left, source tabs
//!   center, findrefs right, status bar at the bottom).

use std::path::PathBuf;
use std::process::ExitCode;

use asc_gui::{AscApp, WorkspaceSession, run_selfcheck};
use eframe::egui;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--selfcheck") {
        return run_selfcheck_mode(&args);
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return ExitCode::SUCCESS;
    }
    run_gui_mode(&args)
}

fn print_help() {
    println!("asc-gui — ASC-RS desktop UI");
    println!();
    println!("USAGE:");
    println!("  asc-gui [path.apk]            Open the GUI on the given APK (default: prompt).");
    println!("  asc-gui --selfcheck <apk>     Run the headless selfcheck and exit.");
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
    let apk_arg = args.iter().skip(1).find(|a| !a.starts_with("--"));
    let session = match apk_arg {
        Some(path) => match WorkspaceSession::open(&PathBuf::from(path)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("asc-gui: cannot open {}: {e}", path);
                return ExitCode::from(1);
            }
        },
        None => {
            eprintln!("asc-gui: pass an APK path, or use --selfcheck <apk>");
            return ExitCode::from(2);
        }
    };

    let viewport = egui::ViewportBuilder::default()
        .with_title(format!("asc-gui — {}", session.path().display()))
        .with_inner_size([1200.0, 800.0]);
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    if let Err(e) = eframe::run_native(
        "asc-gui",
        options,
        Box::new(move |_cc| Ok(Box::new(AscApp::new(session)))),
    ) {
        eprintln!("eframe failed: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
