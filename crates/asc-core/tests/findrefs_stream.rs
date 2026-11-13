//! `run_findrefs_stream` delivers every match incrementally and the final
//! report equals the non-streaming call.

use asc_core::{FindRefsJob, FindRefsOptions, run_findrefs, run_findrefs_stream};
use asc_query::Query;

fn apk() -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/apk/workload.apk");
    if !p.exists() {
        eprintln!("skipping: {} not present", p.display());
    }
    p.exists().then_some(p)
}

#[test]
fn sink_sees_every_match_and_the_report_matches() {
    let Some(p) = apk() else { return };
    let job = FindRefsJob::new(
        &p,
        Query::String {
            pattern: "Context".into(),
        },
    );
    let mut streamed = 0usize;
    let mut batches: Vec<String> = Vec::new();
    let report = run_findrefs_stream(&job, &FindRefsOptions::default(), &mut |dex| {
        assert!(!dex.dex_name.is_empty(), "batches carry their DEX name");
        batches.push(dex.dex_name.clone());
        streamed += dex.matches.len();
    })
    .expect("stream");
    let total: usize = report.results.iter().map(|d| d.matches.len()).sum();
    assert!(total > 0, "fixture must match");
    assert!(!batches.is_empty(), "at least one batch");
    assert_eq!(streamed, total, "the sink saw every match");

    let plain = run_findrefs(&job, &FindRefsOptions::default()).expect("plain");
    let plain_total: usize = plain.results.iter().map(|d| d.matches.len()).sum();
    assert_eq!(
        total, plain_total,
        "streaming changes nothing in the result"
    );
}
