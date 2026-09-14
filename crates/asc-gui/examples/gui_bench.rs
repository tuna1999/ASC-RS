//! GUI cost benchmark (Phase 0 baseline; see `docs/gui-audit.md`).
//!
//! Measures the costs the GUI imposes on top of the engine, on every
//! corpus APK:
//!
//! 1. `WorkspaceSession::open` (mmap + central-directory scan)
//! 2. `all_classes()` first call (per-DEX inflate + class enumeration)
//! 3. `PackageTree::build`
//! 4. `asc_manifest::parse_from_apk`
//! 5. `AscApp::new` equivalent (2 + 3 + 4) — synchronous work before
//!    the first frame can paint
//! 6. one `run_getclass` (class click → source)
//! 7. one `run_findrefs` (bottom-panel query)
//!
//! 8. `open_tabs()` snapshot cost with 8 tabs of real decompiled source
//!    (the per-frame clone the old render path paid)
//! 9. `PackageTree::filter` cost (per-frame while the filter box has
//!    text)
//!
//! Usage: `cargo run --release -p asc-gui --example gui_bench [apk …]`
//! Defaults to every corpus APK present.

use std::path::PathBuf;
use std::time::Instant;

use asc_core::{FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions};
use asc_gui::open_session;
use asc_gui::package_tree::PackageTree;
use asc_query::Query;

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn main() {
    let mut apks: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if apks.is_empty() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/apk");
        for name in [
            "workload.apk",
            "com.aurora.store_60.apk",
            "org.fdroid.fdroid_1016000.apk",
        ] {
            let p = root.join(name);
            if p.exists() {
                apks.push(p);
            }
        }
    }

    for apk in &apks {
        println!(
            "=== {} ===",
            apk.file_name().unwrap_or_default().to_string_lossy()
        );

        let t = Instant::now();
        let session = match open_session(apk) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("open failed: {e}");
                continue;
            }
        };
        println!("  session::open            {:8.1} ms", ms(t.elapsed()));

        let t = Instant::now();
        let classes = session.all_classes().expect("classes");
        println!(
            "  all_classes ({} cls)   {:8.1} ms",
            classes.len(),
            ms(t.elapsed())
        );

        let t = Instant::now();
        let mut tree = PackageTree::build(classes.clone());
        println!(
            "  PackageTree::build       {:8.1} ms  ({} nodes)",
            ms(t.elapsed()),
            tree.node_count()
        );

        let t = Instant::now();
        let _manifest = asc_manifest::parse_from_apk(session.path());
        println!("  manifest parse           {:8.1} ms", ms(t.elapsed()));

        // Per-frame filter cost (old draw path ran this every frame).
        let t = Instant::now();
        let hits = tree.filter("e").len();
        println!(
            "  tree::filter             {:8.1} ms  ({} hits)",
            ms(t.elapsed()),
            hits
        );

        // One class click: getclass (fresh APK open inside the pipeline).
        let target = session
            .all_classes()
            .expect("classes cached")
            .first()
            .map(|c| c.descriptor.clone())
            .expect("non-empty class list");
        let t = Instant::now();
        let res =
            asc_core::run_getclass(&GetClassJob::new(apk, &target), &GetClassOptions::default())
                .expect("getclass");
        println!(
            "  run_getclass             {:8.1} ms  ({} B source)",
            ms(t.elapsed()),
            res.source.len()
        );

        // One findrefs query.
        let t = Instant::now();
        let report = asc_core::run_findrefs(
            &FindRefsJob::new(apk, Query::string("e")),
            &FindRefsOptions::default(),
        )
        .expect("findrefs");
        println!(
            "  run_findrefs             {:8.1} ms  ({} caller lines)",
            ms(t.elapsed()),
            report.total_lines()
        );

        // Document path (replaces the old per-frame `open_tabs()`
        // clone): build ~512 KiB documents from the real decompiled
        // class — this is the worker-thread `Document::new` cost —
        // then measure what a frame pays (`cache.get` = one Arc
        // clone) and O(1) line slicing.
        let big_src = res
            .source
            .repeat((512 * 1024 / res.source.len().max(1)).max(1));
        let mut cache = asc_gui::state::DocumentCache::default();
        let t = Instant::now();
        for i in 0..8 {
            cache.put(std::sync::Arc::new(asc_gui::state::Document::new(
                format!("Lbench/Class{i};"),
                format!("classes{i}.dex"),
                big_src.clone(),
            )));
        }
        let build = ms(t.elapsed());
        let bytes = cache.bytes();
        let t = Instant::now();
        let mut lines_sliced = 0usize;
        for i in 0..8 {
            let doc = cache.get(&format!("Lbench/Class{i};")).expect("doc");
            for row in (0..doc.line_count()).step_by(64) {
                let _ = doc.line(row);
                lines_sliced += 1;
            }
        }
        let frame = ms(t.elapsed());
        println!(
            "  DocumentCache 8×512 KiB  build {:6.1} ms  ({:.1} MiB); frame-path get+slice {:.3} ms ({} slices)",
            build,
            bytes as f64 / (1024.0 * 1024.0),
            frame,
            lines_sliced,
        );

        // Reference: what the old `activate()` paid synchronously on
        // the UI thread per activation (now part of `Document::new`
        // on the worker).
        let t = Instant::now();
        let mut block = false;
        let span_rows: Vec<Vec<(usize, usize, asc_gui::highlight::Token)>> = big_src
            .lines()
            .map(|l| {
                let mut s = asc_gui::highlight::tokenize_line(l, &mut block);
                s.retain(|(a, b, _)| b > a);
                s
            })
            .collect();
        println!(
            "  tokenize 512 KiB doc     {:8.1} ms  ({} lines)",
            ms(t.elapsed()),
            span_rows.len()
        );
        let t = Instant::now();
        let _outline = asc_gui::highlight::outline(&big_src);
        println!("  outline 512 KiB doc      {:8.1} ms", ms(t.elapsed()));
        println!();
    }
}
