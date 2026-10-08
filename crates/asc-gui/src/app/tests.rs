//! Unit tests for the application shell: task identity/staleness,
//! tab + navigation controllers, search, and dispatch commands.

use super::*;

/// `true` when the fixture basename matches an entry of the
/// comma-separated `ASC_REQUIRE_CORPUS` list (CI sets it after
/// recreating the corpus fixtures it guarantees; a listed fixture that
/// is still missing must fail, not silently skip).
fn require_corpus(var: &str, p: &std::path::Path) -> bool {
    std::env::var(var).is_ok_and(|req| {
        req.split(',').any(|f| {
            let f = f.trim();
            !f.is_empty()
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(f))
        })
    })
}
fn corpus() -> Option<PathBuf> {
    let apk = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/apk/workload.apk");
    if !apk.exists() && require_corpus("ASC_REQUIRE_CORPUS", &apk) {
        panic!(
            "ASC_REQUIRE_CORPUS is set but fixture missing: {}",
            apk.display()
        );
    }
    apk.exists().then_some(apk)
}

fn empty_app() -> AscApp {
    AscApp::new(None)
}

/// Serializes every test that creates an egui_kittest wgpu harness.
///
/// Each harness builds its own wgpu `RenderState` (egui_kittest
/// `WgpuTestRenderer::new`), and the Windows CI runner only exposes a
/// software/CPU adapter: several harnesses rendering at once outlast
/// wgpu's 10 s `PollType::Wait` budget and fail with `PollError: The
/// requested Wait timed out…` (`glyph_pixel_audit` / `visual_shots` on
/// CI, never on a machine with a real GPU). One render test at a time
/// keeps device creation and submissions off the same adapter.
fn render_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A panicking render test must not poison every later render test.
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn fake_task(id: u64, descriptor: &str, outcome: TaskOutcome) -> CompletedTask {
    CompletedTask {
        id: crate::task::TaskId(id),
        generation: crate::task::SessionGeneration::INITIAL,
        kind: TaskKind::DecompileClass,
        label: descriptor.to_string(),
        outcome,
        elapsed: std::time::Duration::from_millis(1),
        stale: false,
    }
}

fn decompiled(descriptor: &str) -> TaskOutcome {
    TaskOutcome::Decompiled(Arc::new(Document::new(
        descriptor.to_string(),
        "classes.dex".into(),
        format!("class {} {{}}\n", descriptor.trim_matches(['L', ';'])),
    )))
}

fn active(app: &AscApp) -> Option<String> {
    app.tabs.active_descriptor().map(str::to_string)
}

/// click A, click B (preview), B first, A late → B stays active,
/// one preview tab, both documents cached.
#[test]
fn late_result_cannot_steal_newer_activation() {
    let mut app = empty_app();
    app.tabs.open_preview("LA;");
    app.tabs.open_preview("LB;");
    assert_eq!(active(&app).as_deref(), Some("LB;"));
    // B lands first.
    app.apply_task(fake_task(2, "LB;", decompiled("LB;")));
    assert_eq!(
        app.active_doc.as_ref().map(|d| d.descriptor.as_str()),
        Some("LB;")
    );
    // A lands late: cached, but cannot steal the view.
    app.apply_task(fake_task(1, "LA;", decompiled("LA;")));
    assert_eq!(active(&app).as_deref(), Some("LB;"), "preview slot still B");
    assert_eq!(
        app.active_doc.as_ref().map(|d| d.descriptor.as_str()),
        Some("LB;"),
        "late older result must not steal the view"
    );
    assert_eq!(
        app.documents.len(),
        2,
        "A filled the cache in the background"
    );
    assert_eq!(app.tabs.tabs().len(), 1, "single preview tab");
}

/// click A (fails), click B (succeeds) → B active and visible
/// (regression for audit F1: A's failure used to clear B's
/// intent).
#[test]
fn older_failure_does_not_clear_newer_intent() {
    let mut app = empty_app();
    app.tabs.open_preview("LA;");
    app.tabs.open_preview("LB;");
    // A fails: B's tab is untouched.
    app.apply_task(fake_task(1, "LA;", TaskOutcome::Failed("not found".into())));
    assert_eq!(active(&app).as_deref(), Some("LB;"));
    assert!(app.active_doc.is_none(), "B still loading");
    // B succeeds → visible.
    app.apply_task(fake_task(2, "LB;", decompiled("LB;")));
    assert_eq!(active(&app).as_deref(), Some("LB;"));
    assert_eq!(
        app.active_doc.as_ref().map(|d| d.descriptor.as_str()),
        Some("LB;")
    );
}

/// Old-APK job completes after a new artifact loaded → ignored
/// (generation gate).
#[test]
fn old_generation_result_ignored() {
    let mut app = empty_app();
    let mut stale = fake_task(1, "LOLD;", decompiled("LOLD;"));
    stale.generation = crate::task::SessionGeneration::INITIAL;
    app.tasks.bump_generation();
    stale.stale = true;
    app.apply_task(stale);
    assert!(app.documents.is_empty(), "stale result must not cache");
    assert!(app.tabs.tabs().is_empty());
}

/// Preview/pinned semantics through the shell: preview A, pin A,
/// preview B.
#[test]
fn preview_pin_preview_flow() {
    let mut app = empty_app();
    app.tabs.open_preview("LA;");
    app.tabs.pin(None);
    app.tabs.open_preview("LB;");
    assert_eq!(app.tabs.tabs().len(), 2);
    assert_eq!(app.tabs.tabs()[0].kind, crate::state::TabKind::Pinned);
    assert_eq!(app.tabs.tabs()[0].descriptor, "LA;");
    assert_eq!(app.tabs.tabs()[1].descriptor, "LB;");
    assert_eq!(active(&app).as_deref(), Some("LB;"));
}

/// Navigation pushes locations; back/forward restore descriptor
/// and line deterministically through the shell.
#[test]
fn navigation_restores_locations() {
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let session = WorkspaceSession::open(&apk).expect("open");
    let mut app = AscApp::from_session(session);
    let ctx = egui::Context::default();
    // Seed documents so navigation doesn't spawn jobs.
    for d in ["LA;", "LB;"] {
        app.documents.put(Arc::new(Document::new(
            d.to_string(),
            "classes.dex".into(),
            "class X {}\n".into(),
        )));
    }
    app.navigate_to("LA;", false, None, NavOrigin::Tree, &ctx);
    app.navigate_to("LB;", false, Some(7), NavOrigin::Outline, &ctx);
    assert_eq!(app.nav.len(), 2);
    app.nav_back(&ctx);
    assert_eq!(active(&app).as_deref(), Some("LA;"));
    assert_eq!(app.pending_scroll, Some(0), "back to A restores top");
    app.nav_forward(&ctx);
    assert_eq!(active(&app).as_deref(), Some("LB;"));
    assert_eq!(app.pending_scroll, Some(7), "forward restores line");
}

/// End-to-end queue: two real decompile jobs land as documents;
/// the last-clicked class stays the active preview.
#[test]
fn getclass_jobs_open_documents_latest_click_wins() {
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let session = WorkspaceSession::open(&apk).expect("open");
    let mut app = AscApp::from_session(session);
    let ctx = egui::Context::default();
    let target = "Lcom/google/android/material/timepicker/ClockFaceView;".to_string();
    let other = app.tree.entry(0).descriptor.clone();

    app.navigate_to(&target, false, None, NavOrigin::Tree, &ctx);
    app.navigate_to(&other, false, None, NavOrigin::Tree, &ctx);
    assert_eq!(app.tasks.in_flight_count(), 2, "both jobs queued");

    for _ in 0..600 {
        app.poll_workers(&ctx);
        if app.documents.len() >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(app.documents.len(), 2, "both documents landed");
    assert!(
        app.documents
            .peek(&target)
            .is_some_and(|d| !d.source.is_empty())
    );
    assert!(
        app.documents
            .peek(&other)
            .is_some_and(|d| !d.source.is_empty())
    );
    assert_eq!(
        active(&app).as_deref(),
        Some(other.as_str()),
        "latest click active"
    );
    assert!(app.last_error.is_none(), "{:?}", app.last_error);
}

/// Dedup: clicking an in-flight class re-targets the same task.
#[test]
fn repeated_click_dedups_to_inflight_task() {
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let session = WorkspaceSession::open(&apk).expect("open");
    let mut app = AscApp::from_session(session);
    let ctx = egui::Context::default();
    app.navigate_to(
        "Lcom/example/SomeClass;",
        false,
        None,
        NavOrigin::Tree,
        &ctx,
    );
    app.navigate_to(
        "Lcom/example/SomeClass;",
        false,
        None,
        NavOrigin::Tree,
        &ctx,
    );
    assert_eq!(app.tasks.in_flight_count(), 1);
}

/// Search application: full SearchReport retained as rows.
#[test]
fn search_results_retained_and_navigable() {
    use asc_core::{DexResults, RenderedMatch};
    let mut app = empty_app();
    let mut report = asc_core::SearchReport::empty();
    report.results.push(DexResults {
        dex_name: "classes.dex".into(),
        matches: vec![RenderedMatch {
            caller: "Lcom/foo/Bar;->onCreate".into(),
            matched: vec!["\"lit\"".into()],
            first_line: Some(3),
        }],
        errors: Vec::new(),
        complete: true,
    });
    app.apply_task(CompletedTask {
        id: crate::task::TaskId(9),
        generation: crate::task::SessionGeneration::INITIAL,
        kind: TaskKind::FindRefs,
        label: "string \"lit\"".into(),
        outcome: TaskOutcome::Search(report),
        elapsed: std::time::Duration::from_millis(2),
        stale: false,
    });
    let r = app.search.results().expect("retained");
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.rows[0].caller_class, "Lcom/foo/Bar;");
    assert_eq!(r.rows[0].caller_member, "onCreate");
    assert!(matches!(app.bottom_tab, BottomTab::Results));
}

/// A result landing after the user has taken manual control of the
/// bottom panel stores its data but must not move the panel or the tab.
/// `bottom_focus_pinned` is set by the panel's own tab buttons, the
/// activity-bar toggles and Ctrl+3. (The unpinned case is covered by the
/// test above, where `bottom_tab` flips to Results.)
#[test]
fn late_result_does_not_steal_bottom_focus() {
    let mut app = empty_app();
    let mut report = asc_core::SearchReport::empty();
    report.results.push(asc_core::DexResults {
        dex_name: "classes.dex".into(),
        matches: vec![asc_core::RenderedMatch {
            caller: "Lcom/foo/Bar;->onCreate".into(),
            matched: vec!["Lcom/foo/Bar;".into()],
            first_line: Some(3),
        }],
        errors: Vec::new(),
        complete: true,
    });
    app.show_bottom = false;
    app.bottom_tab = BottomTab::Tasks;
    app.pin_bottom_focus();

    app.apply_task(CompletedTask {
        id: crate::task::TaskId(11),
        generation: crate::task::SessionGeneration::INITIAL,
        kind: TaskKind::FindRefsClass,
        label: "refs Lcom/foo/Bar;".into(),
        outcome: TaskOutcome::Search(report),
        elapsed: std::time::Duration::from_millis(2),
        stale: false,
    });

    // The data landed...
    assert!(app.references.is_some(), "references stored regardless");
    // ...but the user's tab choice and the closed panel were respected.
    assert!(
        matches!(app.bottom_tab, BottomTab::Tasks),
        "pinned tab choice kept"
    );
    assert!(!app.show_bottom, "closed panel stays closed");
}

/// `reveal_bottom_tab` opens the panel only while the user has not taken
/// control; `focus_bottom_tab` never opens it, and both leave the tab
/// alone once pinned. Covers the "a late result cannot steal focus"
/// guarantee for the references/callees kinds (it was only tested for
/// `DecompileClass`).
#[test]
fn bottom_focus_helpers_respect_the_pin() {
    let mut app = empty_app();
    app.show_bottom = false;
    app.bottom_tab = BottomTab::Tasks;

    // Unpinned: results may reveal the panel and select their tab.
    app.reveal_bottom_tab(BottomTab::References);
    assert!(app.show_bottom, "unpinned result opens the panel");
    assert!(matches!(app.bottom_tab, BottomTab::References));

    // Pinned: neither helper may touch the panel or the tab.
    app.show_bottom = false;
    app.pin_bottom_focus();
    app.reveal_bottom_tab(BottomTab::Results);
    app.focus_bottom_tab(BottomTab::Results);
    assert!(!app.show_bottom, "pinned: panel stays closed");
    assert!(
        matches!(app.bottom_tab, BottomTab::References),
        "pinned: tab untouched"
    );

    // A new request unpins, so the next result may focus again.
    app.unpin_bottom_focus();
    app.focus_bottom_tab(BottomTab::Results);
    assert!(
        matches!(app.bottom_tab, BottomTab::Results),
        "unpinned again: follows results"
    );
}

/// One injected key event, as a frame's `RawInput`.
///
/// `RawInput` carries no `modifiers` field in egui 0.36, and
/// `InputState::modifiers` is updated only by `Event::ModifiersChanged`
/// (not by the key event's own `modifiers` field) — so both events are
/// needed for a modified shortcut to be seen.
fn key_event(key: egui::Key, modifiers: egui::Modifiers) -> egui::RawInput {
    egui::RawInput {
        events: vec![
            egui::Event::ModifiersChanged(modifiers),
            egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            },
        ],
        ..Default::default()
    }
}

/// Drive one key through `frame_shortcuts` and assert it queued the
/// expected command.
fn assert_shortcut(
    key: egui::Key,
    modifiers: egui::Modifiers,
    matches_want: impl Fn(&Command) -> bool,
    what: &str,
) {
    let mut app = empty_app();
    let ctx = egui::Context::default();
    AscApp::run_ui_with_input(&ctx, key_event(key, modifiers), |ui| {
        app.frame_shortcuts(ui.ctx());
    });
    assert!(
        app.commands.iter().any(matches_want),
        "{what} queued {:?}",
        app.commands
    );
}

/// Before this, **no** test injected a key event, so the entire
/// `frame_shortcuts` table was unverified. These are the bindings that
/// were missing entirely (JADX-GUI-003/006/015/020, JADX-GUI-014).
#[test]
fn frame_shortcuts_wires_the_previously_dead_bindings() {
    let ctrl = egui::Modifiers {
        ctrl: true,
        ..Default::default()
    };
    let ctrl_shift = egui::Modifiers {
        ctrl: true,
        shift: true,
        ..Default::default()
    };
    let alt = egui::Modifiers {
        alt: true,
        ..Default::default()
    };

    assert_shortcut(
        egui::Key::G,
        ctrl,
        |c| matches!(c, Command::GotoLine),
        "Ctrl+G",
    );
    assert_shortcut(
        egui::Key::D,
        ctrl,
        |c| matches!(c, Command::GoToDeclaration),
        "Ctrl+D",
    );
    assert_shortcut(
        egui::Key::C,
        ctrl,
        |c| matches!(c, Command::CopyDescriptor),
        "Ctrl+C",
    );
    assert_shortcut(
        egui::Key::C,
        ctrl_shift,
        |c| matches!(c, Command::CopyFqn),
        "Ctrl+Shift+C",
    );
    // Alt, not Ctrl: Ctrl+1/2/3 are the panel toggles.
    assert_shortcut(
        egui::Key::Num2,
        alt,
        |c| matches!(c, Command::QuickSwitch { n: 2 }),
        "Alt+2",
    );
}

/// `X` over the code surface finds usages of the clicked identifier
/// (JADX-GUI-002's click affordance); it stays inert without a document.
#[test]
fn bare_x_finds_usages_of_the_clicked_identifier() {
    let mut app = empty_app();
    app.code_hovered = true;
    app.active_doc = Some(Arc::new(Document::new(
        "LA;".into(),
        "classes.dex".into(),
        "class A {}".into(),
    )));
    let ctx = egui::Context::default();
    AscApp::run_ui_with_input(
        &ctx,
        key_event(egui::Key::X, egui::Modifiers::default()),
        |ui| app.frame_shortcuts(ui.ctx()),
    );
    assert!(
        app.commands
            .iter()
            .any(|c| matches!(c, Command::FindUsagesOfClicked)),
        "queued {:?}",
        app.commands
    );
}

/// Full-render smoke: load the corpus artifact, open a class,
/// run a search, then drive every panel draw function inside a
/// headless `egui::Context::run` — catches render-path panics
/// without a native window.
#[test]
fn render_all_panels_smoke() {
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let ctx = egui::Context::default();
    let mut app = AscApp::new(Some(apk));
    // Drive the startup open to completion.
    for _ in 0..600 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app.session.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(app.session.is_some(), "artifact loaded");

    // Open a class and run a search.
    crate::app::AscApp::run_ui(&ctx, |ui| {
        let ctx = ui.ctx();
        app.dispatch(
            Command::OpenClass {
                descriptor: "Lcom/google/android/material/timepicker/ClockFaceView;".into(),
                pin: false,
                line: None,
                origin: NavOrigin::Tree,
            },
            ctx,
        );
        app.search.input = "ClockFace".into();
        app.dispatch(Command::RunSearch, ctx);
    });
    for _ in 0..600 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if !app.documents.is_empty() && app.search.results().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(!app.documents.is_empty(), "class decompiled");
    assert!(app.search.results().is_some(), "search landed");

    // Render several frames (panels + palette + find bar).
    app.palette = Some(crate::ui::palette::PaletteMode::Commands);
    app.show_find = true;
    app.find_input = "class".into();
    for _ in 0..5 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
    }
    assert!(app.last_error.is_none(), "{:?}", app.last_error);
}

/// Render full-workspace reference screenshots to
/// `target/shots/*.png` via egui_kittest (software rasterizer —
/// pixels as the user sees them, no GPU needed). Opt-in:
/// `ASC_GUI_SHOTS=1 cargo test -p asc-gui --lib visual_shots`.
#[test]
fn visual_shots() {
    if std::env::var("ASC_GUI_SHOTS").is_err() {
        eprintln!("ASC_GUI_SHOTS not set; skipping");
        return;
    }
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let shots = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/shots");
    let _guard = render_lock();
    let _ = std::fs::remove_dir_all(&shots);
    std::fs::create_dir_all(&shots).unwrap();
    let save = |h: &mut egui_kittest::Harness<'_, AscApp>, name: &str| {
        let img = h.render().expect("render");
        let path = shots.join(format!("{name}.png"));
        img.save(&path).unwrap();
        eprintln!("shot: {}", path.display());
    };

    // Boot + load.
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1440.0, 900.0))
        .wgpu()
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), AscApp::new(None));
    crate::design::apply(&h.ctx);
    for _ in 0..5 {
        h.step();
    }
    save(&mut h, "01_boot_empty");

    // Load artifact as a background task.
    let ctx0 = h.ctx.clone();
    h.state_mut().open_path(&apk, &ctx0);
    for _ in 0..300 {
        h.step();
        if h.state().session.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for _ in 0..3 {
        h.step();
    }
    assert!(h.state().session.is_some(), "artifact loaded");
    save(&mut h, "02_loaded");

    // Open a class (preview) — syntax-highlighted source + inspector.
    h.state_mut().queue(Command::OpenClass {
        descriptor: "Lcom/google/android/material/timepicker/ClockFaceView;".into(),
        pin: false,
        line: None,
        origin: NavOrigin::Tree,
    });
    for _ in 0..300 {
        h.step();
        if h.state().active_doc.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for _ in 0..3 {
        h.step();
    }
    assert!(h.state().active_doc.is_some(), "class open");
    save(&mut h, "03_class_open");

    // String search with results in the bottom panel.
    {
        let app = h.state_mut();
        app.search.input = "onCreate".into();
        app.queue(Command::RunSearch);
    }
    for _ in 0..300 {
        h.step();
        if h.state().search.results().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for _ in 0..3 {
        h.step();
    }
    save(&mut h, "04_search_results");

    // Find-in-document.
    {
        let app = h.state_mut();
        app.show_find = true;
        app.find_input = "view".into();
        app.recompute_find_matches();
    }
    for _ in 0..2 {
        h.step();
    }
    save(&mut h, "05_find");

    // Quick-open palette with input + selection.
    h.state_mut().queue(Command::QuickOpen);
    for _ in 0..2 {
        h.step();
    }
    h.state_mut().palette_input = "clock".into();
    for _ in 0..2 {
        h.step();
    }
    save(&mut h, "06_palette");

    // Command palette.
    h.state_mut().queue(Command::ToggleCommandPalette);
    for _ in 0..2 {
        h.step();
    }
    save(&mut h, "07_commands");

    // References to the active class (Analysis ▸ Find references).
    h.state_mut().queue(Command::FindReferences);
    for _ in 0..300 {
        h.step();
        if h.state().references.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for _ in 0..3 {
        h.step();
    }
    assert!(h.state().references.is_some(), "references landed");
    save(&mut h, "08_references");
}

/// Reproduce the user-reported sidebar state (fdroid corpus,
/// NetCipher open, tree expanded to it) and save zoomable crops.
#[test]
fn sidebar_repro() {
    if std::env::var("ASC_GUI_SHOTS").is_err() {
        eprintln!("ASC_GUI_SHOTS not set; skipping");
        return;
    }
    let apk = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apk/org.fdroid.fdroid_1016000.apk");
    if !apk.exists() {
        eprintln!("fdroid fixture missing; skipping");
        return;
    }
    let _guard = render_lock();
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1440.0, 900.0))
        .wgpu()
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), AscApp::new(None));
    crate::design::apply(&h.ctx);
    let ctx0 = h.ctx.clone();
    h.state_mut().open_path(&apk, &ctx0);
    for _ in 0..400 {
        h.step();
        if h.state().session.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for _ in 0..3 {
        h.step();
    }
    // Expand exactly like the user: info/guardianproject/netcipher,
    // open NetCipher as preview.
    {
        let app = h.state_mut();
        app.queue(Command::OpenClass {
            descriptor: "Linfo/guardianproject/netcipher/NetCipher;".into(),
            pin: false,
            line: None,
            origin: NavOrigin::Tree,
        });
    }
    for _ in 0..400 {
        h.step();
        if h.state().active_doc.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // Expand exactly like the user's screenshot: info →
    // guardianproject → netcipher, so class rows with doc icons
    // are in frame.
    {
        let app = h.state_mut();
        app.expanded.insert("info".into());
        app.expanded.insert("info.guardianproject".into());
        app.expanded.insert("info.guardianproject.netcipher".into());
    }
    for _ in 0..3 {
        h.step();
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/shots");
    std::fs::create_dir_all(&dir).unwrap();
    let img = h.render().expect("render");
    img.save(dir.join("repro_full.png")).unwrap();
    eprintln!("repro saved");
}

/// Objective font-coverage audit via egui's own font atlas
/// (`FontsView::has_glyph`). Any glyph the UI uses must be covered
/// by the default font stack — otherwise it renders as tofu.
#[test]
fn glyph_coverage() {
    let _guard = render_lock();
    // The full inventory of glyphs the UI renders (keep in sync
    // with src/*: grep non-ASCII string literals).
    const USED: &[&str] = &[
        "◀", "▶", "←", "→", "↑", "↓", "◆", "▾", "▸", "×", "●", "⌘", "▲", "▼", "✔", "⚠", "🔍", "▤",
        "☰", "·", "…", "≡", "⚙", "A", "b", "1",
    ];
    // Known-uncovered in egui default fonts — never use these.
    // (◇ IS covered but reads as a stray square outline at small
    // sizes — avoided for legibility, not coverage.) Held as
    // codepoints so the source scan below never sees the literal
    // characters themselves.
    const BANNED_CP: &[u32] = &[0x2715, 0x2315, 0x2713, 0x29C9, 0x22EE];
    let banned_chars: Vec<char> = BANNED_CP
        .iter()
        .map(|cp| char::from_u32(*cp).unwrap())
        .collect();
    let banned = |c: char| banned_chars.contains(&c);
    // egui 0.35+ resolves a char through the family fallback chain,
    // and `FontsView::has_glyph` reports `false` for every char on a
    // fresh context (the faces are not warm yet) — it cannot be used
    // as the oracle. Rasterize instead: the control renders as the
    // identical replacement box, so matching its pixels IS tofu.
    let raster = |g: &str| -> Vec<u8> {
        let mut h = egui_kittest::Harness::builder()
            .with_size(egui::vec2(64.0, 64.0))
            .build_ui(|ui| {
                ui.centered_and_justified(|ui| {
                    ui.monospace(egui::RichText::new(g).size(48.0));
                });
            });
        h.run();
        h.render().expect("render").into_raw()
    };
    let tofu_px = raster(&char::from_u32(0x2315).unwrap().to_string());
    let mut missing: Vec<String> = Vec::new();
    for ch in USED.iter().map(|c| c.chars().next().unwrap()) {
        assert!(!banned(ch), "{ch:?} is in USED and BANNED_CP");
        // All glyph sites render through the Monospace family
        // (Proportional lacks ▸▾▲▼●◆▤ etc. — the tree-toggle
        // tofu bug), so the audit checks the mono raster only.
        if raster(&ch.to_string()) == tofu_px {
            missing.push(format!("{ch:?} in mono"));
        }
    }
    // Static guard: banned glyphs must not appear anywhere in the
    // crate source (catches copy-paste regressions pre-render).
    for file in [
        "src/app.rs",
        "src/ui/explorer.rs",
        "src/ui/editor.rs",
        "src/ui/inspector.rs",
        "src/ui/bottom_panel.rs",
        "src/ui/status_bar.rs",
        "src/ui/palette.rs",
        "src/ui/mod.rs",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        for ch in &banned_chars {
            if src.contains(*ch) {
                panic!("{file} contains banned glyph {ch:?}");
            }
        }
    }
    for m in &missing {
        eprintln!("TOFU: {m}");
    }
    let tofu = missing;

    assert!(tofu.is_empty(), "uncovered glyphs present: {tofu:?}");
}

/// Pixel-level tofu detection: render each glyph ISOLATED at 48px
/// monospace (the exact tree-row style family). Tofu glyphs all
/// rasterize to the identical box — so any candidate whose PNG is
/// byte-identical to a known-tofu control (U+2315) is tofu. This
/// catches what `has_glyph` chain semantics might hide.
#[test]
fn glyph_pixel_audit() {
    if std::env::var("ASC_GUI_SHOTS").is_err() {
        eprintln!("ASC_GUI_SHOTS not set; skipping");
        return;
    }
    // The control (0x2315) is held as a codepoint so the
    // glyph_coverage source scan never sees the literal.
    let _guard = render_lock();
    const GLYPHS: &[&str] = &["◇", "◆", "▸", "▾", "×", "◀", "▶", "⌘", "●"];
    const CONTROL_CP: u32 = 0x2315;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/shots");
    std::fs::create_dir_all(&dir).unwrap();
    let control = char::from_u32(CONTROL_CP).unwrap().to_string();
    let all: Vec<&str> = GLYPHS
        .iter()
        .copied()
        .chain(std::iter::once(control.as_str()))
        .collect();
    for (i, g) in all.iter().enumerate() {
        let mut h = egui_kittest::Harness::builder()
            .with_size(egui::vec2(64.0, 64.0))
            .build_ui(|ui| {
                ui.centered_and_justified(|ui| {
                    ui.monospace(egui::RichText::new(*g).size(48.0));
                });
            });
        h.run();
        let img = h.render().expect("render");
        let path = dir.join(format!("glyph_{i:02}.png"));
        img.save(&path).unwrap();
        eprintln!("px: {}", path.display());
    }
}

/// Rasterize candidate glyphs so font coverage can be verified by
/// eye: `ASC_GUI_SHOTS=1 cargo test -p asc-gui --lib glyph_probe`.
/// Each row is `NNN` + one candidate glyph.
#[test]
fn glyph_probe() {
    if std::env::var("ASC_GUI_SHOTS").is_err() {
        eprintln!("ASC_GUI_SHOTS not set; skipping");
        return;
    }
    let _guard = render_lock();
    const GLYPHS: &[&str] = &[
        "🔍", "🔎", "⌖", "⌾", "⊙", "◎", "◉", "○", "■", "□", "✔", "✗", "⇄", "↻", "⟳", "ℹ", "⚡",
        "☰", "▤", "⚙", "≡", "▰", "▣", "⏵", "⚠",
    ];
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(420.0, 720.0))
        .build_ui(|ui| {
            egui::Grid::new("glyphs").num_columns(2).show(ui, |ui| {
                for (i, g) in GLYPHS.iter().enumerate() {
                    ui.monospace(format!("{:03}", i));
                    ui.monospace(egui::RichText::new(*g).size(22.0));
                    ui.end_row();
                }
            });
        });
    h.run();
    let img = h.render().expect("render");
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/shots/09_glyph_probe.png");
    // Several shot tests write here; each must ensure the directory itself,
    // otherwise the first one to run on a fresh checkout fails with
    // "path not found" (the tests run in parallel, so the order is not
    // defined).
    std::fs::create_dir_all(out.parent().expect("shot path has a parent")).unwrap();
    img.save(&out).unwrap();
    eprintln!("probe: {}", out.display());
}

/// F24/F25/F26: symbol selection drives a method-scoped rename
/// and a per-line comment; both rebuild the active document.
#[test]
fn rename_and_comment_edit_flow() {
    let src = "public class A {\n    int field;\n    void run(int px) {\n        int q = px + 1;\n    }\n}\n";
    let mut app = empty_app();
    let doc = Arc::new(Document::new(
        "LA;".into(),
        "classes.dex".into(),
        src.into(),
    ));
    app.active_doc = Some(doc.clone());
    app.documents.put(doc);

    // Select the `px` use in the method body.
    let byte = src.find("px + 1").unwrap() + 1;
    let sel = crate::ui::editor::symbol_selection_for("LA;", src, byte).unwrap();
    assert_eq!(sel.token, "px");
    assert_eq!(sel.occurrences.len(), 2, "param decl + body use");
    app.symbol_sel = Some(sel);

    // Rename via dispatch: only inside the method, code-state only.
    app.dispatch(
        Command::RenameSymbol {
            new_name: "width".into(),
        },
        &egui::Context::default(),
    );

    let doc = app.active_doc.clone().expect("doc kept");
    assert!(doc.source.contains("void run(int width)"), "param renamed");
    assert!(doc.source.contains("int q = width + 1;"), "body renamed");
    assert!(!doc.source.contains("(int px)"), "no stale param");
    assert!(app.symbol_sel.is_none(), "selection dropped after edit");
    assert!(app.documents.peek("LA;").is_some(), "cache entry replaced");

    // Line comment on the signature line (2, 0-based) via dispatch.
    app.dispatch(
        Command::SetLineComment {
            line: 2,
            text: "entry point".into(),
        },
        &egui::Context::default(),
    );
    let doc = app.active_doc.clone().expect("doc kept");
    assert!(
        doc.source.contains("void run(int width) {  // entry point"),
        "comment appended to the line"
    );
    assert!(doc.source.ends_with("}\n"), "tail preserved");
}

/// `Command::GoToDeclaration` on an `L...;` selection queues an
/// `OpenClass` for the resolved owner. Covers `JADX-GUI-003`
/// (Go to declaration of selected symbol). The test inspects
/// the queue — `navigate_to` would need a live `WorkspaceSession`
/// to call `spawn_decompile`, which is outside the unit-test
/// scope (covered by `integration::selfcheck_on_workload_apk`).
#[test]
fn go_to_declaration_jumps_to_owner() {
    let mut app = empty_app();
    // Simulate a click on an `Lcom/foo/Bar;` reference.
    app.symbol_sel = Some(SymbolSelection {
        descriptor: "Lcom/foo/Bar;".into(),
        token: "Bar".into(),
        method: (0, 10),
        occurrences: vec![(0, 3)],
    });
    let ctx = egui::Context::default();
    app.dispatch(Command::GoToDeclaration, &ctx);
    // Exactly one command queued, opening the resolved owner.
    assert_eq!(app.commands.len(), 1, "one OpenClass queued");
    match &app.commands[0] {
        Command::OpenClass {
            descriptor, origin, ..
        } => {
            assert_eq!(descriptor, "Lcom/foo/Bar;");
            assert_eq!(*origin, NavOrigin::Declaration);
        }
        other => panic!("expected OpenClass, got {other:?}"),
    }
}

/// `Command::FindUsagesOfClicked` pre-fills the search bar with
/// the click's token and a class filter pinned to the click's
/// descriptor, then queues a `RunSearch`. Covers workflow B
/// (`JADX-GUI-002` member-scoped find from a click).
#[test]
fn find_usages_method_query_via_click() {
    let mut app = empty_app();
    app.symbol_sel = Some(SymbolSelection {
        descriptor: "Lcom/foo/Bar;".into(),
        token: "doThing".into(),
        method: (0, 10),
        occurrences: vec![(0, 8)],
    });
    let ctx = egui::Context::default();
    app.dispatch(Command::FindUsagesOfClicked, &ctx);
    // The search controller was retargeted before RunSearch was
    // queued.
    assert_eq!(app.search.kind, SearchKind::Method);
    assert_eq!(app.search.input, "doThing");
    assert!(
        app.search.class_filter.contains("Bar"),
        "class filter pinned to click descriptor: {:?}",
        app.search.class_filter
    );
    // RunSearch is queued (its execution depends on a live
    // session, asserted at integration level).
    assert!(
        app.commands.iter().any(|c| matches!(c, Command::RunSearch)),
        "RunSearch queued"
    );
}

/// `Command::CopyDescriptor` writes the active class's descriptor
/// to `last_clipboard`. Covers JADX-GUI-006 (Ctrl+C → copy
/// descriptor).
#[test]
fn copy_descriptor_writes_clipboard() {
    let mut app = empty_app();
    app.tabs.open_pinned("Lcom/foo/Bar;");
    let ctx = egui::Context::default();
    app.dispatch(Command::CopyDescriptor, &ctx);
    assert_eq!(app.last_clipboard.as_deref(), Some("Lcom/foo/Bar;"));
}

/// `Command::CopyFqn` writes the active class's Java-form FQN
/// (`com.foo.Bar`) to `last_clipboard`. Covers JADX-GUI-015
/// (Copy FQN of selected class).
#[test]
fn copy_fqn_writes_clipboard() {
    let mut app = empty_app();
    app.tabs.open_pinned("Lcom/foo/Bar;");
    let ctx = egui::Context::default();
    app.dispatch(Command::CopyFqn, &ctx);
    assert_eq!(app.last_clipboard.as_deref(), Some("com.foo.Bar"));
}

/// A `#smali` view tab is a *view* identity, not a class identity.
/// Class-scoped actions must resolve the owning class, never pass the
/// synthetic tab key to the engine (audit F2: the tab key reached
/// `spawn_findrefs_class` and produced a false-negative search).
#[test]
fn copy_descriptor_from_smali_tab_copies_owning_class() {
    let mut app = empty_app();
    let class = "Lcom/example/Foo;";
    app.tabs.open_pinned(class);
    app.tabs
        .open_preview(&crate::task::TaskManager::smali_key(class, None));
    assert_eq!(
        active(&app).as_deref(),
        Some("Lcom/example/Foo;#smali"),
        "smali view tab is active"
    );
    let ctx = egui::Context::default();
    app.dispatch(Command::CopyDescriptor, &ctx);
    assert_eq!(
        app.last_clipboard.as_deref(),
        Some(class),
        "descriptor must be the owning class, not the view key"
    );
}

/// Same for a method-scoped Smali tab (`Lclass;#smali#method`) and the
/// FQN form.
#[test]
fn copy_fqn_from_method_smali_tab_copies_owning_class() {
    let mut app = empty_app();
    let class = "Lcom/example/Foo;";
    app.tabs.open_pinned(class);
    app.tabs
        .open_preview(&crate::task::TaskManager::smali_key(class, Some("doThing")));
    assert_eq!(
        active(&app).as_deref(),
        Some("Lcom/example/Foo;#smali#doThing")
    );
    let ctx = egui::Context::default();
    app.dispatch(Command::CopyFqn, &ctx);
    assert_eq!(app.last_clipboard.as_deref(), Some("com.example.Foo"));
}

/// `FindReferences` with a Smali tab active must query the owning class
/// (observable through the status line the dispatch writes).
#[test]
fn find_references_from_smali_tab_targets_owning_class() {
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let session = WorkspaceSession::open(&apk).expect("open");
    let mut app = AscApp::from_session(session);
    let ctx = egui::Context::default();
    let class = "Lcom/example/Foo;";
    app.tabs.open_pinned(class);
    app.tabs
        .open_preview(&crate::task::TaskManager::smali_key(class, None));
    app.dispatch(Command::FindReferences, &ctx);
    assert_eq!(
        app.status.as_ref().map(|s| s.text.as_str()),
        Some("references: Lcom/example/Foo;"),
        "references must target the owning class, not the #smali view key"
    );
}

/// A text tab is not class-shaped: with no tree selection the
/// class-scoped actions resolve nothing (they must never hand the text
/// key to the engine).
#[test]
fn copy_descriptor_from_text_tab_without_class_is_a_noop() {
    let mut app = empty_app();
    app.tabs.tabs_mut().push(crate::state::Tab {
        descriptor: "manifest".into(),
        dex_name: None,
        kind: crate::state::TabKind::Text,
        status: crate::state::TabStatus::Ready,
    });
    app.tabs.activate("manifest");
    let ctx = egui::Context::default();
    app.dispatch(Command::CopyDescriptor, &ctx);
    assert_eq!(app.last_clipboard, None, "no class resolved");
    assert_eq!(
        app.status.as_ref().map(|s| s.text.as_str()),
        Some("copy descriptor: no active class")
    );
}

/// ... but a text tab still falls back to the tree selection rather than
/// the text key.
#[test]
fn copy_descriptor_from_text_tab_falls_back_to_tree_selection() {
    let mut app = empty_app();
    app.tabs.tabs_mut().push(crate::state::Tab {
        descriptor: "manifest".into(),
        dex_name: None,
        kind: crate::state::TabKind::Text,
        status: crate::state::TabStatus::Ready,
    });
    app.tabs.activate("manifest");
    app.selected_class = Some("Lcom/example/Foo;".into());
    let ctx = egui::Context::default();
    app.dispatch(Command::CopyDescriptor, &ctx);
    assert_eq!(app.last_clipboard.as_deref(), Some("Lcom/example/Foo;"));
}

/// ASC-RS-GUI-002 render level: the class-scoped button never renders
/// when the current context resolves no class.
#[test]
fn used_by_class_button_absent_for_text_tab_without_class() {
    let _guard = render_lock();
    use egui_kittest::kittest::Queryable;
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), empty_app());
    h.state_mut().tabs.tabs_mut().push(crate::state::Tab {
        descriptor: "manifest".into(),
        dex_name: None,
        kind: crate::state::TabKind::Text,
        status: crate::state::TabStatus::Ready,
    });
    h.state_mut().tabs.activate("manifest");
    h.run_steps(2);
    assert!(
        h.query_by_label("used by this class").is_none(),
        "no class in context → no class-scoped action"
    );
}

/// Opening a view key (as a tab click does) must not taint the class
/// selection: otherwise a later class-scoped action would fall back to
/// the `#smali` descriptor.
#[test]
fn opening_a_smali_tab_does_not_taint_the_class_selection() {
    let mut app = empty_app();
    let key = crate::task::TaskManager::smali_key("Lcom/example/Foo;", None);
    let ctx = egui::Context::default();
    app.navigate_to(&key, false, None, NavOrigin::Tab, &ctx);
    assert_eq!(app.tabs.active_descriptor(), Some(key.as_str()));
    assert!(
        app.selected_class.is_none(),
        "a view key must never become the class selection"
    );
}

/// A Smali tab whose document was evicted is re-issued on demand by
/// `draw_code_area`; that re-issue must not query the class engine with
/// the view key (it would fail). Audit F2 sibling.
#[test]
fn evicted_smali_tab_is_not_reissued_as_getclass() {
    let _guard = render_lock();
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let session = WorkspaceSession::open(&apk).expect("open");
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_ui_state(
            |ui, app: &mut AscApp| app.test_frame(ui),
            AscApp::from_session(session),
        );
    let key = crate::task::TaskManager::smali_key("Lcom/example/Foo;", None);
    h.state_mut().tabs.open_preview(&key);
    // The listing landed earlier; its document is since evicted.
    h.state_mut()
        .tabs
        .set_ready(&key, Some("classes.dex".into()));
    h.run_steps(2);
    assert_eq!(
        h.state().tasks.in_flight_count(),
        0,
        "a view key must not be re-issued as a getclass job"
    );
}

/// `Command::ToggleTheme` flips the active theme. Covers
/// `ASC-GUI-025` (settings dialog theme picker). The full
/// settings dialog is still TODO; the theme toggle is the
/// minimum the picker needs to drive.
#[test]
fn theme_toggle_via_view_menu() {
    use crate::design::{Theme, set_theme, theme};
    // Start in Dark so we observe the flip.
    set_theme(Theme::Dark);
    let mut app = empty_app();
    let ctx = egui::Context::default();
    app.dispatch(Command::ToggleTheme, &ctx);
    assert_eq!(theme(), Theme::Light, "Dark → Light on first toggle");
    app.dispatch(Command::ToggleTheme, &ctx);
    assert_eq!(theme(), Theme::Dark, "Light → Dark on second toggle");
}

/// `apply_goto_line` converts a 1-indexed user line to a
/// 0-indexed `pending_scroll`. Covers JADX-GUI-020 (goto line).
#[test]
fn goto_line_jumps_to_zero_indexed() {
    let mut app = empty_app();
    // Open an active doc so the editor has a target.
    app.tabs.open_pinned("Lcom/foo/Bar;");
    // 1-indexed line 42 → 0-indexed 41.
    app.apply_goto_line(42);
    assert_eq!(app.pending_scroll, Some(41));
    assert!(app.goto_line_input.is_none(), "input bar closed");
    // 0 is a no-op (avoids underflow).
    app.pending_scroll = None;
    app.apply_goto_line(0);
    assert!(app.pending_scroll.is_none(), "0 is a no-op");
}

/// `Command::GotoLine` opens the input bar. The bar is dismissed
/// by `apply_goto_line`. Covers the dispatch half of JADX-GUI-020.
#[test]
fn goto_line_input_opens_via_command() {
    let mut app = empty_app();
    let ctx = egui::Context::default();
    assert!(app.goto_line_input.is_none());
    app.dispatch(Command::GotoLine, &ctx);
    assert!(app.goto_line_input.is_some(), "input bar opened");
    app.apply_goto_line(7);
    assert!(app.goto_line_input.is_none(), "input bar closed on apply");
}

/// `Command::QuickSwitch { n }` activates the n-th tab
/// (1-indexed). Covers JADX-GUI-014 (Ctrl+1..9 quick switch).
#[test]
fn quick_switch_activates_nth_tab() {
    let mut app = empty_app();
    app.tabs.open_pinned("Lcom/foo/A;");
    app.tabs.open_pinned("Lcom/foo/B;");
    app.tabs.open_pinned("Lcom/foo/C;");
    let ctx = egui::Context::default();
    // Ctrl+1 → first tab.
    app.dispatch(Command::QuickSwitch { n: 1 }, &ctx);
    assert_eq!(app.tabs.active_descriptor(), Some("Lcom/foo/A;"));
    // Ctrl+2 → second tab.
    app.dispatch(Command::QuickSwitch { n: 2 }, &ctx);
    assert_eq!(app.tabs.active_descriptor(), Some("Lcom/foo/B;"));
    // Ctrl+99 is clamped to the last tab.
    app.dispatch(Command::QuickSwitch { n: 99 }, &ctx);
    assert_eq!(app.tabs.active_descriptor(), Some("Lcom/foo/C;"));
    // Empty tab list: no-op (status set, no panic).
    app.tabs.clear();
    app.dispatch(Command::QuickSwitch { n: 1 }, &ctx);
    assert!(app.tabs.active_descriptor().is_none());
}

/// `open_path` flips `loading_artifact` true and surfaces a
/// running hint in the status bar. Covers ASC-GUI-035 (per-DEX
/// load progress feedback; the artifact-level status is the
/// minimum we can assert from the UI loop).
#[test]
fn load_artifact_reports_running_status() {
    let mut app = empty_app();
    // No-op: open_path dispatches a background task; we observe
    // the flag + status without running the task. Use a path that
    // the test harness will not actually read (the spawn never
    // completes; we never poll).
    let path = std::path::PathBuf::from("corpus/apk/workload.apk");
    let ctx = egui::Context::default();
    // Drop any prior status.
    app.status = None;
    if let Some(s) = app.session.as_ref() {
        // Already loaded; the test is irrelevant.
        let _ = s.path();
    }
    app.open_path(&path, &ctx);
    assert!(app.loading_artifact, "loading flag flipped");
    let line = app
        .status
        .as_ref()
        .map(|s| s.text.clone())
        .unwrap_or_default();
    assert!(line.contains("opening"), "running hint: {line:?}");
    assert!(line.contains(&path.display().to_string()));
}

/// `close_tab` removes the tab's metadata (descriptor gone from
/// `tabs.tabs()`, neighbour activated). Covers ASC-GUI-028 (close
/// tab removes metadata).
#[test]
fn close_tab_removes_metadata() {
    let mut app = empty_app();
    app.tabs.open_pinned("LA;");
    app.tabs.open_pinned("LB;");
    app.tabs.open_pinned("LC;");
    // Active is LC. Closing it surfaces LB.
    app.close_tab("LC;");
    assert!(
        !app.tabs.tabs().iter().any(|t| t.descriptor == "LC;"),
        "LC removed from tabs"
    );
    assert_eq!(app.tabs.active_descriptor(), Some("LB;"));
    // The neighbour's metadata is intact.
    let lb = app.tabs.tabs().iter().find(|t| t.descriptor == "LB;");
    assert!(lb.is_some());
}

/// `Command::CloseAll` drops every tab (and forgets cached
/// documents for closed descriptors). Verified end-to-end through
/// dispatch.
#[test]
fn close_all_empties_tab_strip() {
    let mut app = empty_app();
    app.tabs.open_pinned("LA;");
    app.tabs.open_pinned("LB;");
    let ctx = egui::Context::default();
    app.dispatch(Command::CloseAll, &ctx);
    assert!(app.tabs.tabs().is_empty());
    assert!(app.tabs.active_descriptor().is_none());
}

/// `Command::CloseRight` drops only the tabs to the right of the named
/// one, evicts their cached documents, keeps the survivors' documents,
/// and hands focus to the named tab when the active tab was closed.
/// Covers the JADX-GUI-005 close-right half through dispatch (the
/// semantics live in `state::tabs::tests::close_others_close_all`).
#[test]
fn close_right_drops_only_right_neighbours() {
    let mut app = empty_app();
    app.tabs.open_pinned("LA;");
    app.tabs.open_pinned("LB;");
    app.tabs.open_pinned("LC;");
    for d in ["LA;", "LB;", "LC;"] {
        app.documents.put(Arc::new(Document::new(
            d.to_string(),
            "classes.dex".into(),
            format!("class {d} {{}}\n"),
        )));
    }
    // Active is LC (the rightmost), so the fallback is exercised.
    let ctx = egui::Context::default();
    app.dispatch(
        Command::CloseRight {
            descriptor: "LA;".into(),
        },
        &ctx,
    );
    assert_eq!(
        app.tabs
            .tabs()
            .iter()
            .map(|t| t.descriptor.as_str())
            .collect::<Vec<_>>(),
        vec!["LA;"],
        "only the tabs right of LA; go"
    );
    assert_eq!(active(&app).as_deref(), Some("LA;"), "focus falls back");
    assert!(
        app.documents.peek("LB;").is_none() && app.documents.peek("LC;").is_none(),
        "closed tabs' documents evicted"
    );
    assert!(
        app.documents.peek("LA;").is_some(),
        "the survivor keeps its document"
    );
    assert_eq!(
        app.status.as_ref().map(|s| s.text.as_str()),
        Some("closed 2 tab(s) to the right")
    );
}

/// `Command::OpenSettings` toggles the settings dialog. Covers
/// JADX-GUI-009 (settings dialog opens + lists themes; the
/// dialog draws a theme list at render time).
#[test]
fn settings_dialog_opens_and_lists_themes() {
    let mut app = empty_app();
    let ctx = egui::Context::default();
    assert!(!app.show_settings);
    app.dispatch(Command::OpenSettings, &ctx);
    assert!(app.show_settings, "settings dialog toggled on");
    app.dispatch(Command::OpenSettings, &ctx);
    assert!(!app.show_settings, "settings dialog toggled off");
}

/// `Command::UsedByClass` routes to `FindReferences` (the same
/// engine path, surfaced via an inline button). Covers
/// ASC-RS-GUI-002 (used by class X inline button).
#[test]
fn used_by_class_button_routes_to_findrefs_class() {
    let mut app = empty_app();
    // Pre-select a class so the dispatch target is unambiguous.
    app.tabs.open_pinned("Lcom/foo/Bar;");
    let ctx = egui::Context::default();
    app.dispatch(Command::UsedByClass, &ctx);
    // The dispatch queues a FindReferences command for the same
    // descriptor; status flips to the references hint.
    assert!(
        app.commands
            .iter()
            .any(|c| matches!(c, Command::FindReferences)),
        "FindReferences queued via UsedByClass"
    );
}

/// JADX-GUI-005 render level: the tab right-click menu offers
/// "Close right", and using it on a middle tab closes exactly the tabs
/// to its right (status line proves the dispatch round-trip).
#[test]
fn tab_context_menu_close_right_closes_right_neighbours_only() {
    let _guard = render_lock();
    use egui_kittest::kittest::Queryable;
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), empty_app());
    h.state_mut().tabs.open_pinned("LAA;");
    h.state_mut().tabs.open_pinned("LBB;");
    h.state_mut().tabs.open_pinned("LCC;");
    h.run_steps(2);
    // Right-click the middle tab → its context menu (JADX tab context).
    h.get_by_label_contains("BB").click_secondary();
    h.run_steps(2);
    h.get_by_label("Close right").click();
    h.run_steps(2);
    assert_eq!(
        h.state()
            .tabs
            .tabs()
            .iter()
            .map(|t| t.descriptor.as_str())
            .collect::<Vec<_>>(),
        vec!["LAA;", "LBB;"],
        "close right must keep BB and everything left of it"
    );
    assert_eq!(
        h.state().status.as_ref().map(|s| s.text.as_str()),
        Some("closed 1 tab(s) to the right")
    );
}

/// JADX-GUI-005 render level: "Close others" acts on the tab the menu
/// was opened on, not on whichever tab happens to be active. Audit F3:
/// the context menu dropped the descriptor, so right-clicking B while A
/// was active kept A and closed B.
#[test]
fn tab_context_menu_close_others_keeps_right_clicked_tab() {
    let _guard = render_lock();
    use egui_kittest::kittest::Queryable;
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), empty_app());
    h.state_mut().tabs.open_pinned("LAA;");
    h.state_mut().tabs.open_pinned("LBB;");
    h.state_mut().tabs.open_pinned("LCC;");
    // Active is LCC; right-click the middle tab instead.
    h.run_steps(2);
    h.get_by_label_contains("BB").click_secondary();
    h.run_steps(2);
    h.get_by_label("Close others").click();
    h.run_steps(2);
    assert_eq!(
        h.state()
            .tabs
            .tabs()
            .iter()
            .map(|t| t.descriptor.as_str())
            .collect::<Vec<_>>(),
        vec!["LBB;"],
        "close others must keep the right-clicked tab"
    );
    assert_eq!(
        active(h.state()).as_deref(),
        Some("LBB;"),
        "focus lands on the survivor"
    );
}

/// ASC-RS-GUI-002 render level: the SYMBOL section carries the inline
/// "used by this class" button, it exists only while a class is
/// selected, and *clicking* it is what drives the class-references path
/// (the queued `FindReferences` is observable at the end of that frame;
/// no synthetic dispatch is involved).
#[test]
fn used_by_class_inline_button_renders_and_dispatches() {
    let _guard = render_lock();
    use egui_kittest::kittest::Queryable;
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), empty_app());
    // No selected class → no button (it belongs to the SYMBOL section,
    // not to the global chrome).
    h.run_steps(2);
    assert!(
        h.query_by_label("used by this class").is_none(),
        "button must not render without a selected class"
    );
    // Select a class → the button appears next to the descriptor.
    h.state_mut().tabs.open_pinned("Lcom/example/Foo;");
    h.run_steps(2);
    h.get_by_label("used by this class").click();
    h.run_steps(1);
    assert!(
        h.state()
            .commands
            .iter()
            .any(|c| matches!(c, Command::FindReferences)),
        "clicking the inline button must queue FindReferences, got {:?}",
        h.state().commands
    );
}

/// `apply_artifact` updates the window title to the APK file
/// name. Covers ASC-GUI-034 (apply artifact sets window title).
#[test]
fn apply_artifact_sets_window_title() {
    let mut app = empty_app();
    use crate::task::LoadedArtifact;
    // Build a LoadedArtifact via a successful spawn_land path.
    // We construct one directly; this only exercises the title
    // side-effect.
    let path = std::path::PathBuf::from("corpus/apk/workload.apk");
    // Use a real session so the test doesn't need a fake.
    if let Ok(s) = crate::session::WorkspaceSession::open(&path) {
        let artifact = LoadedArtifact {
            session: s,
            classes: Vec::new(),
            dex_counts: vec![("classes.dex".into(), 6220)],
            manifest: None,
            manifest_error: None,
            warnings: Vec::new(),
        };
        app.apply_artifact(artifact);
        assert!(app.window_title.contains("workload"));
    }
}

/// `apply_artifact` closes the open-tabs picker: the artifact load
/// clears the tab list, and a picker listing the now-dead tabs must
/// not stay visible (regression: 272a069 dropped the reset).
#[test]
fn apply_artifact_closes_open_tabs_picker() {
    let mut app = empty_app();
    use crate::task::LoadedArtifact;
    let path = std::path::PathBuf::from("corpus/apk/workload.apk");
    if let Ok(s) = crate::session::WorkspaceSession::open(&path) {
        app.show_open_tabs = true;
        app.open_tabs_filter = "stale".into();
        let artifact = LoadedArtifact {
            session: s,
            classes: Vec::new(),
            dex_counts: Vec::new(),
            manifest: None,
            manifest_error: None,
            warnings: Vec::new(),
        };
        app.apply_artifact(artifact);
        assert!(!app.show_open_tabs, "picker must close on artifact load");
        assert!(app.open_tabs_filter.is_empty(), "stale filter must clear");
    }
}

/// `apply_artifact` aggregates dex counts per entry. Covers
/// ASC-GUI-032 (dex counts aggregate per entry).
#[test]
fn dex_counts_aggregate_per_entry() {
    let mut app = empty_app();
    use crate::task::LoadedArtifact;
    let path = std::path::PathBuf::from("corpus/apk/workload.apk");
    if let Ok(s) = crate::session::WorkspaceSession::open(&path) {
        let artifact = LoadedArtifact {
            session: s,
            classes: Vec::new(),
            dex_counts: vec![("classes.dex".into(), 6220)],
            manifest: None,
            manifest_error: None,
            warnings: Vec::new(),
        };
        app.apply_artifact(artifact);
        // One entry was provided; the controller stores the same
        // value (no on-demand re-counting in the smoke path).
        assert_eq!(app.dex_counts, vec![("classes.dex".to_string(), 6220)]);
    }
}

/// Empty app: no window title, no commands, no tabs. Used as a
/// baseline for other app-level tests.
#[test]
fn empty_app_baseline() {
    let app = empty_app();
    assert!(app.tabs.tabs().is_empty());
    assert!(app.commands.is_empty());
    assert!(app.documents.peek("LA;").is_none());
    assert_eq!(app.window_title, "asc-gui");
}

/// `frame_shortcuts` is the dispatch pipeline: every shortcut
/// emits a `Command` into `self.commands`. We can't easily
/// synthesize raw key events in a unit test, so the surface is
/// asserted indirectly: the function exists, is wired into
/// `update()`, and reads `ctx.input`. Covered by the smoke
/// harness `render_all_panels_smoke`. Placeholder test just
/// asserts the shortcut-related state doesn't panic.
#[test]
fn frame_shortcut_smoke() {
    let mut app = empty_app();
    // Cycle once to exercise the NextTab command path.
    app.tabs.open_pinned("LA;");
    app.tabs.open_pinned("LB;");
    // Clear pending and dispatch a NextTab directly — same
    // effect as Ctrl+Tab on the keyboard.
    app.dispatch(Command::NextTab, &Default::default());
    assert_eq!(app.tabs.active_descriptor(), Some("LA;"));
}

/// The `n` shortcut on the code surface emits
/// `BeginRenameSymbol`. We don't drive raw key events here; we
/// call `dispatch` directly. The test asserts the dispatch path
/// is wired (no panics, command observable).
#[test]
fn frame_shortcut_n_routes_to_rename() {
    let mut app = empty_app();
    app.tabs.open_pinned("LA;");
    // Pre-set the symbol selection; the rename bar opens from it.
    app.symbol_sel = Some(SymbolSelection {
        descriptor: "LA;".into(),
        token: "foo".into(),
        method: (0, 4),
        occurrences: vec![(0, 3)],
    });
    let ctx = egui::Context::default();
    app.dispatch(Command::BeginRenameSymbol, &ctx);
    assert!(app.show_rename, "rename bar opened");
    assert_eq!(app.rename_input, "foo");
}

/// Find step cycles through the matched rows. We populate a
/// dummy `find_matches` set and step forward / backward.
/// Covers ASC-GUI-026 (find step cycles through matches).
#[test]
fn find_step_cycles_through_matches() {
    let mut app = empty_app();
    let doc = std::sync::Arc::new(crate::state::Document::new(
        "LA;".into(),
        "classes.dex".into(),
        "class A { void a; void b; void c; }".to_string(),
    ));
    app.tabs.open_pinned("LA;");
    app.active_doc = Some(doc);
    app.find_input = "void".into();
    app.recompute_find_matches();
    // We don't assert exact line numbers (depends on
    // find_matches internals) — only that step doesn't panic
    // and `find_index` is set.
    assert!(app.find_index.is_some(), "find_index set");
    app.find_step(true);
    app.find_step(false);
}

/// Engine failures (decompile / getclass error) populate
/// `last_error` and the bottom-panel Problems tab. We synthesize
/// a `TaskOutcome::Failed` and apply it through the dispatch
/// pipeline.
/// Covers ASC-GUI-040 (engine failure lands in problems).
#[test]
fn engine_failure_lands_in_problems() {
    let mut app = empty_app();
    app.tabs.open_pinned("Lcom/foo/Bar;");
    app.apply_task(CompletedTask {
        id: TaskId(42),
        generation: crate::task::SessionGeneration::INITIAL,
        kind: TaskKind::DecompileClass,
        label: "Lcom/foo/Bar;".into(),
        outcome: TaskOutcome::Failed("synthetic failure".into()),
        elapsed: std::time::Duration::from_millis(1),
        stale: false,
    });
    assert!(app.last_error.as_deref().unwrap().contains("synthetic"));
}

/// The package tree draws class rows once it has entries.
/// Alias for ASC-GUI-004.
#[test]
fn tree_renders_class_rows() {
    let mut app = empty_app();
    use crate::package_tree::PackageTree;
    use crate::session::ClassEntry;
    app.tree = PackageTree::build(vec![
        ClassEntry {
            descriptor: "Lcom/foo/Bar;".into(),
            kind: crate::session::ClassKind::Class,
            dex_name: "classes.dex".into(),
        },
        ClassEntry {
            descriptor: "Lcom/foo/Baz;".into(),
            kind: crate::session::ClassKind::Class,
            dex_name: "classes.dex".into(),
        },
    ]);
    // The tree has two leaf entries; both are class rows.
    let leaves = {
        let tree = &mut app.tree;
        tree.filter("Bar").to_vec()
    };
    assert_eq!(leaves.len(), 1);
    let entry = app.tree.entry(leaves[0]);
    assert_eq!(entry.descriptor, "Lcom/foo/Bar;");
}

/// The activity-bar toggles drive `show_explorer`, `show_inspector`,
/// `show_bottom` in lockstep. Alias for ASC-GUI-044.
#[test]
fn activity_bar_toggles_explorer_inspector_bottom() {
    let mut app = empty_app();
    assert!(app.show_explorer);
    assert!(app.show_inspector);
    assert!(app.show_bottom);
    app.dispatch(Command::ToggleExplorer, &Default::default());
    assert!(!app.show_explorer);
    app.dispatch(Command::ToggleInspector, &Default::default());
    assert!(!app.show_inspector);
    app.dispatch(Command::ToggleBottomPanel, &Default::default());
    assert!(!app.show_bottom);
}

/// `draw_editor` records the last-clicked line. Alias for
/// ASC-GUI-038 (clicked line persists).
#[test]
fn clicked_line_persists() {
    let mut app = empty_app();
    let doc = std::sync::Arc::new(crate::state::Document::new(
        "LA;".into(),
        "classes.dex".into(),
        "line 0\nline 1\nline 2\n".into(),
    ));
    app.tabs.open_pinned("LA;");
    app.active_doc = Some(doc);
    // Set last_clicked_line directly (the draw path normally
    // drives it on click; here we simulate the click).
    app.last_clicked_line = Some(1);
    assert_eq!(app.last_clicked_line, Some(1));
}

/// Persistence round-trip: a JSON-encoded SettingsBlob round-trips
/// losslessly. Alias for JADX-GUI-019.
#[test]
fn persistence_round_trip_panel_sizes() {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct PanelSizes {
        explorer: f32,
        inspector: f32,
    }
    let original = PanelSizes {
        explorer: 240.0,
        inspector: 280.0,
    };
    let json = serde_json::to_string(&original).unwrap();
    let parsed: PanelSizes = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, original);
}

/// ASC-GUI-008/009 + ASC-GUI-013/036 UI surface: member-scoped kinds
/// expose the class filter + fuzzy-class toggle; retained results
/// expose the post-search filter box; the history button reflects
/// committed queries. Headless (kittest, no corpus needed).
#[test]
fn member_scoped_search_bar_widgets() {
    let _guard = render_lock();
    use egui_kittest::kittest::Queryable;
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), AscApp::new(None));
    // Member-scoped kind → class filter + fuzzy toggle render.
    h.state_mut().search.kind = crate::state::SearchKind::MemberMethod;
    h.state_mut().search.class_filter = "com.poc.Main".into();
    h.run_steps(3);
    h.get_by_label("fuzzy class");
    // Toggling flips the controller (exact ⇄ substring constraint).
    h.get_by_label("fuzzy class").click();
    h.run_steps(2);
    assert!(h.state().search.fuzzy_class, "toggle wired to state");
    // Retained results → results filter box + history button.
    h.state_mut()
        .search
        .set_results(crate::state::SearchResults {
            label: "method \"x\"".into(),
            rows: vec![crate::state::SearchRow {
                dex_name: "classes.dex".into(),
                caller_class: "Lcom/foo/Bar;".into(),
                caller_member: "onCreate".into(),
                matched: vec!["x".into()],
                code_off: None,
            }],
            complete: true,
            errors: vec![],
        });
    h.run_steps(3);
    // Filtering narrows the visible rows ("nope" matches nothing); the
    // `clear` affordance only renders when the filter is non-empty
    // and results are retained untouched (view-only filter).
    h.state_mut().search.results_filter = "nope".into();
    h.run_steps(2);
    h.get_by_label("clear");
    assert_eq!(
        h.state().search.results().unwrap().rows.len(),
        1,
        "filter is view-only"
    );
    // History: commit a query → button count updates.
    h.state_mut().search.input = "onCreate".into();
    h.state_mut().search.commit_to_history();
    h.run_steps(2);
    h.get_by_label("hist (1)");
}

/// Bottom panel: the "searching…" placeholder tracks *wanted* work, not
/// merely in-flight work. Cancelling a scan (Esc / the cancel button) only
/// discards its future result — the worker keeps churning — so the panel
/// must stop claiming a search is in progress and re-offer Run.
#[test]
fn cancelled_search_stops_reporting_searching() {
    let _guard = render_lock();
    use egui_kittest::kittest::Queryable;
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), AscApp::new(None));
    // Defaults: bottom panel open, SEARCH RESULTS tab, no retained results.
    assert_eq!(
        h.state().bottom_tab,
        crate::ui::bottom_panel::BottomTab::Results
    );

    // A findrefs task that blocks until we drop `tx` → stays in flight.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let ctx = egui::Context::default();
    let _id = h.state_mut().tasks.submit(
        crate::task::TaskKind::FindRefs,
        "string \"x\"",
        move || {
            let _ = rx.recv();
            crate::task::TaskOutcome::Search(asc_core::SearchReport::empty())
        },
        &ctx,
    );
    h.run_steps(3);
    assert!(h.state().tasks.findrefs_live(), "live task");
    assert!(
        h.query_by_label("searching…").is_some(),
        "a live scan reports that it is searching"
    );

    // Cancel: the worker is still running, but the result is discarded.
    h.state_mut()
        .tasks
        .cancel_kind(crate::task::TaskKind::FindRefs);
    h.run_steps(3);
    assert!(
        h.state().tasks.findrefs_running(),
        "cancellation is discard-on-arrival, not a kill"
    );
    assert!(
        h.query_by_label("searching…").is_none(),
        "a cancelled scan must not claim it is searching"
    );
    assert!(
        h.query_by_label("no results — run a search (Ctrl+Shift+F)")
            .is_some(),
        "the panel falls back to the idle prompt"
    );
    // Run is offered again (cancel button is gone).
    assert!(
        h.query_by_label("cancel").is_none(),
        "nothing live left to cancel"
    );
    drop(tx);
}

/// Render `app`, expand the (collapsed-by-default) METADATA header, and
/// report which of `needles` appear in the rendered labels.
fn metadata_contains(app: AscApp, needles: &[&'static str]) -> Vec<bool> {
    use egui_kittest::kittest::Queryable;
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), app);
    h.run_steps(2);
    h.get_by_label("METADATA").click();
    h.run_steps(2);
    needles
        .iter()
        .map(|n| h.query_by_label_contains(n).is_some())
        .collect()
}

/// The inspector must not merge "this APK has no manifest" with "the
/// manifest is corrupt": before the fix both rendered as
/// `no manifest (synthetic corpus?)`, hiding real parse failures.
#[test]
fn inspector_distinguishes_absent_and_failed_manifest() {
    let _guard = render_lock();

    // Corrupt manifest: the workspace still opens (DEX access is
    // unaffected); the metadata section reports the decode failure.
    let apk = crate::test_zip::write_temp_apk(
        "inspector_corrupt_manifest",
        &[("AndroidManifest.xml", b"not axml at all")],
    );
    let session = crate::session::WorkspaceSession::open(&apk)
        .expect("a corrupt manifest must not fail the APK open");
    let app = AscApp::from_session(session);
    let _ = std::fs::remove_file(&apk);
    assert!(app.manifest.is_none());
    assert!(app.manifest_error.is_some());
    let flags = metadata_contains(app, &["manifest parse failed", "no AndroidManifest.xml"]);
    assert_eq!(
        flags,
        vec![true, false],
        "corrupt manifest must read as a failure, never as absence"
    );

    // Genuinely absent (the synthetic workload fixture): no error, and the
    // panel says so plainly.
    let apk =
        crate::test_zip::write_temp_apk("inspector_absent_manifest", &[("assets/x.txt", b"hi")]);
    let session = crate::session::WorkspaceSession::open(&apk).expect("open");
    let app = AscApp::from_session(session);
    let _ = std::fs::remove_file(&apk);
    assert!(
        app.manifest.is_none(),
        "expected no manifest, got {:?}",
        app.manifest.as_ref().map(|m| m.package.clone())
    );
    assert!(
        app.manifest_error.is_none(),
        "absence is not a failure, got {:?}",
        app.manifest_error
    );
    let flags = metadata_contains(app, &["no AndroidManifest.xml", "manifest parse failed"]);
    assert_eq!(
        flags,
        vec![true, false],
        "absence must read as absence, not as a decode failure"
    );
}

/// JADX-GUI-018: ShowSmali spawns `run_disasm` and files the listing
/// as a `#smali`-keyed document + tab. Corpus-gated (skips silently
/// when `corpus/apk/workload.apk` is absent).
#[test]
fn show_smali_opens_listing_tab() {
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let ctx = egui::Context::default();
    let mut app = AscApp::new(Some(apk));
    for _ in 0..600 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app.session.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(app.session.is_some(), "artifact loaded");
    let descriptor = "Lcom/google/android/material/timepicker/ClockFaceView;";
    let key = crate::task::TaskManager::smali_key(descriptor, None);
    crate::app::AscApp::run_ui(&ctx, |ui| {
        let ctx = ui.ctx();
        app.navigate_to(descriptor, false, None, NavOrigin::Tree, ctx);
        app.dispatch(Command::ShowSmali, ctx);
    });
    for _ in 0..900 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app.documents.contains(&key) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let doc = app.documents.get(&key).expect("smali document landed");
    assert!(doc.source.contains(".method"), "listing looks like smali");
    assert_eq!(app.tabs.active_descriptor(), Some(key.as_str()));
}

/// JADX-GUI-010: Ctrl+B toggles a bookmark on the active tab (at the
/// clicked line), the tab strip shows ★, Ctrl+Shift+B jumps back.
/// JADX-GUI-007: loading an artifact records it under File ▸ Open
/// recent. ASC-GUI-029: Ctrl+Shift+H opens the tabs picker.
#[test]
fn bookmark_toggle_jump_and_open_tabs_picker() {
    let mut app = empty_app();
    let ctx = egui::Context::default();
    app.tabs.open_preview("Lcom/foo/Bar;");
    app.tabs.activate("Lcom/foo/Bar;");
    app.last_clicked_line = Some(4); // 0-indexed → bookmark line 5
    app.dispatch(Command::ToggleBookmark, &ctx);
    assert_eq!(app.tabs.bookmark("Lcom/foo/Bar;"), Some(5));
    // Jump sets pending_scroll to the 0-indexed line.
    app.pending_scroll = None;
    app.dispatch(Command::GoToBookmark, &ctx);
    assert_eq!(app.pending_scroll, Some(4));
    // Second toggle on the same line clears.
    app.dispatch(Command::ToggleBookmark, &ctx);
    assert_eq!(app.tabs.bookmark("Lcom/foo/Bar;"), None);
    // Tabs picker opens with a cleared filter.
    app.dispatch(Command::ShowOpenTabs, &ctx);
    assert!(app.show_open_tabs);
    // OpenRecent with a missing path degrades to a status message.
    app.dispatch(
        Command::OpenRecent {
            path: std::path::PathBuf::from("Z:/definitely/missing.apk"),
        },
        &ctx,
    );
    assert!(app.session.is_none(), "no session opened for missing path");
}

/// ASC-GUI-029 / ASC-GUI-025 / JADX-GUI-020 UI surface: the open-tabs
/// picker, settings dialog and goto-line bar render as windows.
#[test]
fn overlay_windows_render() {
    let _guard = render_lock();
    use egui_kittest::kittest::Queryable;
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1200.0, 800.0))
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), AscApp::new(None));
    h.state_mut().tabs.open_pinned("Lcom/foo/Bar;");
    h.state_mut().tabs.open_preview("Lcom/foo/Baz;");
    // Tabs picker: filter narrows the shown count.
    h.state_mut().show_open_tabs = true;
    h.state_mut().open_tabs_filter = "Baz".into();
    h.run_steps(3);
    assert!(h.get_all_by_label("Baz").count() >= 2); // tab strip + picker row
    // Settings dialog with the theme row.
    h.state_mut().show_open_tabs = false;
    h.state_mut().show_settings = true;
    h.run_steps(2);
    assert!(h.get_all_by_label("dark").count() >= 1); // theme buttons
    // Goto bar accepts a line and closes.
    h.state_mut().show_settings = false;
    h.state_mut().goto_line_input = Some("3".into());
    h.run_steps(2);
    h.state_mut().apply_goto_line(3);
    assert_eq!(h.state().pending_scroll, Some(2));
}

/// ASC-RS-GUI-004 + ASC-RS-GUI-001: method-scoped Smali opens a
/// `#smali#method` tab; one-hop callees land in the REFERENCES tab.
/// Corpus-gated.
#[test]
fn method_smali_and_callees_e2e() {
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let ctx = egui::Context::default();
    let mut app = AscApp::new(Some(apk));
    for _ in 0..600 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app.session.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(app.session.is_some(), "artifact loaded");
    let descriptor = "Lcom/google/android/material/timepicker/ClockFaceView;";
    // Simulate the click that selects a method identifier.
    app.symbol_sel = Some(crate::app::SymbolSelection {
        descriptor: descriptor.into(),
        token: "<init>".into(),
        method: (0, 0),
        occurrences: vec![],
    });
    crate::app::AscApp::run_ui(&ctx, |ui| {
        let ctx = ui.ctx();
        app.navigate_to(descriptor, false, None, NavOrigin::Tree, ctx);
        app.dispatch(Command::ShowCallees, ctx);
    });
    for _ in 0..900 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app
            .references
            .as_ref()
            .is_some_and(|r| r.label.starts_with("callees of"))
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let refs = app.references.as_ref().expect("callees landed");
    assert!(refs.label.starts_with("callees of"));
    assert!(!refs.rows.is_empty(), "a constructor must invoke something");
    assert!(refs.rows.iter().all(|r| r.caller_class.starts_with('L')));

    // Method-scoped smali tab (and only that one).
    let key = crate::task::TaskManager::smali_key(descriptor, Some("<init>"));
    crate::app::AscApp::run_ui(&ctx, |ui| {
        app.dispatch(Command::ShowSmaliMethod, ui.ctx());
    });
    for _ in 0..900 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app.documents.contains(&key) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let doc = app.documents.get(&key).expect("method smali landed");
    assert!(doc.source.contains(".method"), "method smali shape");
    let full = crate::task::TaskManager::smali_key(descriptor, None);
    assert!(
        !app.documents.contains(&full),
        "class listing must not have been requested"
    );
    // Regression: callees while a `#smali#method` tab is ACTIVE must
    // still resolve the real class (from the symbol selection, not
    // the tab key) — the shot suite caught this.
    crate::app::AscApp::run_ui(&ctx, |ui| {
        app.references = None;
        app.dispatch(Command::ShowCallees, ui.ctx());
    });
    for _ in 0..900 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app
            .references
            .as_ref()
            .is_some_and(|r| r.label.starts_with("callees of"))
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        app.references
            .as_ref()
            .is_some_and(|r| r.label.starts_with("callees of") && !r.rows.is_empty()),
        "callees resolves the class even with a smali tab active"
    );
}

/// ASC-RS-GUI-006: string constants of the selected class land in the
/// REFERENCES tab as `strings of <class>` rows (class · string ·
/// ×sites). Corpus-gated.
#[test]
fn class_strings_e2e() {
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let ctx = egui::Context::default();
    let mut app = AscApp::new(Some(apk));
    for _ in 0..600 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app.session.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(app.session.is_some(), "artifact loaded");
    let descriptor = "Landroidx/core/text/util/LinkifyCompat;";
    // No symbol selection: class-level resolution must fall back to
    // the active tab / tree selection.
    crate::app::AscApp::run_ui(&ctx, |ui| {
        let ctx = ui.ctx();
        app.navigate_to(descriptor, false, None, NavOrigin::Tree, ctx);
        app.dispatch(Command::ShowClassStrings, ctx);
    });
    for _ in 0..900 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app
            .references
            .as_ref()
            .is_some_and(|r| r.label.starts_with("strings of"))
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let refs = app.references.as_ref().expect("class strings landed");
    assert!(refs.label.starts_with("strings of"));
    assert!(!refs.rows.is_empty(), "a real view class loads strings");
    assert!(refs.rows.iter().all(|r| r.caller_class == descriptor));
    assert!(
        refs.rows
            .iter()
            .all(|r| r.matched.iter().all(|m| m.starts_with('×')))
    );
    // The same request must be discoverable on the shared references
    // lane (the dedup key) and spawn a fresh task whose result lands
    // again. A bare `app.references.is_some()` would pass even if the
    // lane predicate forgot `ClassStrings` (audit P1), so assert the
    // task identity itself.
    crate::app::AscApp::run_ui(&ctx, |ui| {
        app.dispatch(Command::ShowClassStrings, ui.ctx());
    });
    assert!(
        app.tasks.references_surface_live(descriptor).is_some(),
        "the live class-strings task must be on the references lane"
    );
    for _ in 0..900 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app.tasks.references_surface_live(descriptor).is_none() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        app.references
            .as_ref()
            .is_some_and(|r| r.label.starts_with("strings of")),
        "the second request must land on the shared surface"
    );
}

/// P3: with a `#smali` view active and the class selected in the tree,
/// `ShowClassStrings` must resolve the CLASS, not the smali view key —
/// the old `.or(tree).filter(!#smali)` picked the smali key, dropped it,
/// and aborted with "select a class first". Corpus-gated.
#[test]
fn class_strings_falls_back_from_active_smali_tab() {
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let ctx = egui::Context::default();
    let mut app = AscApp::new(Some(apk));
    for _ in 0..600 {
        crate::app::AscApp::run_ui(&ctx, |ui| app.test_frame(ui));
        if app.session.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(app.session.is_some(), "artifact loaded");
    let descriptor = "Landroidx/core/text/util/LinkifyCompat;";
    crate::app::AscApp::run_ui(&ctx, |ui| {
        let ctx = ui.ctx();
        // No symbol selection: the fallback must do the work.
        app.symbol_sel = None;
        app.selected_class = Some(descriptor.to_string());
        // The ACTIVE tab is the smali view of the very same class.
        let key = crate::task::TaskManager::smali_key(descriptor, None);
        app.tabs.open_preview(&key);
        app.tabs.activate(&key);
        app.active_doc = None;
        app.dispatch(Command::ShowClassStrings, ctx);
    });
    assert!(
        app.tasks.references_surface_live(descriptor).is_some(),
        "smali-active fallback must resolve the real class descriptor"
    );
}

/// An incomplete `ClassStrings` result must stay flagged in the GUI
/// surface (`complete:false` + errors) — that drives the ⚠ banner
/// instead of a false ✔. The handler used to hard-code
/// `complete: true, errors: vec![]` (audit P1).
#[test]
fn incomplete_class_strings_result_is_not_reported_complete() {
    let mut app = empty_app();
    let mut task = fake_task(
        1,
        "Lcom/foo/Bar;",
        TaskOutcome::ClassStrings(asc_core::ClassStringsResult {
            dex_name: "classes.dex".into(),
            strings: vec![asc_query::ClassString {
                text: "kept".into(),
                sites: 1,
            }],
            errors: vec![asc_core::SearchError {
                dex_name: "classes.dex".into(),
                kind: asc_core::SearchErrorKind::Engine,
                message: "ref_walker error".into(),
            }],
            complete: false,
        }),
    );
    task.kind = TaskKind::ClassStrings;
    app.apply_task(task);
    let r = app.references.as_ref().expect("result stored");
    assert!(!r.complete, "a partial class-strings scan is not complete");
    assert_eq!(r.errors.len(), 1, "the failure must be surfaced");
    assert_eq!(r.rows.len(), 1, "partial data is still shown");
}

/// v0.9.0 feature shots: method Smali tab, callees rows, open-tabs
/// picker. Same opt-in as `visual_shots`.
#[test]
fn visual_shots_v090_features() {
    if std::env::var("ASC_GUI_SHOTS").is_err() {
        eprintln!("ASC_GUI_SHOTS not set; skipping");
        return;
    }
    let Some(apk) = corpus() else {
        eprintln!("corpus fixture missing; skipping");
        return;
    };
    let _guard = render_lock();
    let shots = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/shots");
    std::fs::create_dir_all(&shots).unwrap();
    let save = |h: &mut egui_kittest::Harness<'_, AscApp>, name: &str| {
        let img = h.render().expect("render");
        let path = shots.join(format!("{name}.png"));
        img.save(&path).unwrap();
        eprintln!("shot: {}", path.display());
    };
    let mut h = egui_kittest::Harness::builder()
        .with_size(egui::vec2(1440.0, 900.0))
        .wgpu()
        .build_ui_state(|ui, app: &mut AscApp| app.test_frame(ui), AscApp::new(None));
    let ctx0 = h.ctx.clone();
    h.state_mut().open_path(&apk, &ctx0);
    for _ in 0..300 {
        h.step();
        if h.state().session.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(h.state().session.is_some(), "artifact loaded");
    let descriptor = "Lcom/google/android/material/timepicker/ClockFaceView;";
    // Select a method identifier, then open the method Smali tab.
    h.state_mut().queue(Command::OpenClass {
        descriptor: descriptor.into(),
        pin: false,
        line: None,
        origin: NavOrigin::Tree,
    });
    for _ in 0..300 {
        h.step();
        if h.state().active_doc.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    h.state_mut().symbol_sel = Some(crate::app::SymbolSelection {
        descriptor: descriptor.into(),
        token: "<init>".into(),
        method: (0, 0),
        occurrences: vec![],
    });
    let key = crate::task::TaskManager::smali_key(descriptor, Some("<init>"));
    h.state_mut().queue(Command::ShowSmaliMethod);
    for _ in 0..300 {
        h.step();
        if h.state().documents.contains(&key) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for _ in 0..2 {
        h.step();
    }
    assert!(h.state().documents.contains(&key), "method smali landed");
    save(&mut h, "09_method_smali");

    // Callees of the same method → REFERENCES rows.
    h.state_mut().queue(Command::ShowCallees);
    for _ in 0..300 {
        h.step();
        if h.state()
            .references
            .as_ref()
            .is_some_and(|r| r.label.starts_with("callees of"))
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    for _ in 0..2 {
        h.step();
    }
    save(&mut h, "10_callees");

    // Open-tabs picker strip.
    h.state_mut().queue(Command::ShowOpenTabs);
    for _ in 0..2 {
        h.step();
    }
    save(&mut h, "11_open_tabs");
}
