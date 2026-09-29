//! Multi-class getclass warm-cache benchmark for `DroidsawBackend`.
//!
//! Demonstrates that the `DroidsawBackend` parse cache hits when the
//! same rebuilt DEX bytes are decompiled repeatedly (warm path that the
//! GUI's "click around several classes in a session" workflow exercises).
//!
//! Run with:
//!   cargo run --release --example multi_getclass -- <apk>
//!
//! Defaults to `corpus/apk/MetaTrader-5-Forex-Stocks_500.6119_apkcube.apk`.

use std::env;
use std::path::PathBuf;
use std::time::Instant;

use asc_apk::Apk;
use asc_core::{GetClassJob, GetClassOptions, run_getclass};
use asc_decompile::droidsaw::DroidsawBackend;
use asc_dex::view::DexView;

fn main() {
    let apk = env::args()
        .nth(2)
        .unwrap_or_else(|| "corpus/apk/MetaTrader-5-Forex-Stocks_500.6119_apkcube.apk".to_string());
    let apk_path = PathBuf::from(&apk);
    println!("=== multi_getclass warm-cache demo on {apk} ===");

    // Step 1: list some classes starting with "Lnet/"
    let apk_obj = Apk::open(&apk_path).expect("open apk");
    let mut candidates: Vec<String> = Vec::new();
    for entry in apk_obj.dex_entries() {
        let bytes = apk_obj.read_entry(&entry).expect("read entry");
        if let Ok(view) = DexView::parse(bytes.as_slice()) {
            for ci in 0..view.class_def_count() {
                if let Ok(def) = view.class_def(ci)
                    && let Ok(t) = view.type_(def.class)
                    && let Ok(s) = view.string(t)
                {
                    let d = s.decode_lossy().into_owned();
                    if d.starts_with("Lnet/") && candidates.len() < 10 {
                        candidates.push(d);
                    }
                }
            }
        }
    }
    println!(
        "picked {} classes: {:?}",
        candidates.len(),
        &candidates[..3.min(candidates.len())]
    );

    // Step 2: decompile each class. First call pays the parse cost
    // (cold); subsequent calls on the same rebuild cache hit.
    let mut total_ms = 0.0;
    let mut cold_ms = 0.0;
    for (i, c) in candidates.iter().enumerate() {
        let started = Instant::now();
        let target = asc_core::normalize_class_name(c).expect("normalize");
        let job = GetClassJob::new(&apk_path, target);
        let opts = GetClassOptions::default();
        let _res = run_getclass(&job, &opts).expect("getclass");
        let ms = started.elapsed().as_secs_f64() * 1000.0;
        total_ms += ms;
        if i == 0 {
            cold_ms = ms;
        }
        println!("  [{}] class={} us={:.1}", i + 1, c, ms * 1000.0);
    }
    let warm_ms_avg = if candidates.len() > 1 {
        (total_ms - cold_ms) / ((candidates.len() - 1) as f64)
    } else {
        cold_ms
    };
    println!(
        "summary: cold_first_call_ms={:.1}  warm_subsequent_avg_ms={:.1}  total_ms={:.1}",
        cold_ms, warm_ms_avg, total_ms
    );
    // Touch the static so it's not optimised away.
    let _ = DroidsawBackend::new;
}
