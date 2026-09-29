//! In-process phase profiler for the `findrefs` and `getclass` pipelines.
//!
//! Replaces the `profile_findrefs` example referenced by
//! `benches/ASC-RS-BENCH.md` (which no longer exists in the tree).
//! Spawn cost (~15 ms, ~18% of cold CLI wall time) is deliberately
//! excluded: it is process startup, not engine work.
//!
//! Run: cargo run --release -p asc-core --example profile_pipeline

use std::time::Instant;

use asc_core::{FindRefsJob, GetClassJob, run_findrefs, run_getclass};

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

/// Total rendered matches across every DEX in the report.
fn total_matches(r: &asc_core::SearchReport) -> usize {
    r.results.iter().map(|d| d.matches.len()).sum()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let apk = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "../corpus/apk/workload.apk".to_string());
    let needle = args.get(2).cloned().unwrap_or_else(|| "Context".into());
    let target = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "Lcom/google/android/material/timepicker/ClockFaceView;".into());

    println!("apk={apk}\nneedle={needle}\ntarget={target}\n");

    // findrefs, 3 rounds (page cache warm after the first).
    for round in 0..3 {
        let t = Instant::now();
        let job = FindRefsJob {
            apk: apk.clone().into(),
            query: asc_query::Query::string(&needle),
        };
        let r = run_findrefs(&job, &Default::default());
        let hits = r.as_ref().map(total_matches).unwrap_or(usize::MAX);
        println!("findrefs round {round}: {:8.2} ms  (matches={hits})", ms(t));
    }

    // getclass, 3 rounds — dominated by the closure walk.
    for round in 0..3 {
        let t = Instant::now();
        let job = GetClassJob {
            apk: apk.clone().into(),
            target: target.clone(),
        };
        let r = run_getclass(&job, &Default::default());
        let len = r.map(|r| r.source.len()).unwrap_or(usize::MAX);
        println!("getclass round {round}: {:8.2} ms  (source={len}B)", ms(t));
    }
}
