//! Synthetic, corpus-free tests for how the pipeline aggregates engine
//! errors into the report (audit F04).
//!
//! A code item whose declared `insns_size` does not match the bytes the
//! DEX actually holds is rejected by `RefWalker::new`. That is a real
//! *engine* error: the per-DEX `complete` flips to `false`, and the CLI
//! prints its aggregated warning list, so the same error has to be in
//! both places.

mod common;

use asc_core::{FindRefsJob, FindRefsOptions, SearchErrorKind, run_findrefs};
use asc_query::Query;
use common::write_apk;
use common::{Dex, OBJECT, STRING, u};

const NEEDLE: &str = "needlehunter";
const MAIN: &str = "Lp/Main;";
const PADDING: &str = "Lpad/Filler;";

/// One method that really matches, one whose code item is damaged.
/// The 16-byte code_item header is the only thing that can tell them
/// apart, so the fixture is the minimum that separates "engine error"
/// from "nothing to report".
fn apk_with_damaged_code_item() -> (std::path::PathBuf, usize) {
    let method_ids: Vec<common::Member> = vec![
        (MAIN.to_string(), "good", (STRING, vec![])),
        (PADDING.to_string(), "bad", ("V", vec![])),
    ];
    let dex = Dex::new(&[OBJECT, MAIN, PADDING], vec![], method_ids, &[u(NEEDLE)]);
    let marker = dex.string(&u(NEEDLE)) as u16;
    // const-string v0, marker; return-void
    let good_insns = vec![0x001A, marker, 0x0011];
    // return-void only; damaged below.
    let bad_insns = vec![0x0011];
    let bytes = dex.finish(&[
        (MAIN, vec![], vec![("good", 0x0009, 1, 0, good_insns)]),
        (PADDING, vec![], vec![("bad", 0x0009, 0, 0, bad_insns)]),
    ]);

    // Locate the damage site: the damaged code item is the second one
    // emitted, immediately before the first class_def's class_data.
    // `Dex::finish` emits both code items back to back after the pools,
    // so scanning for the 16-byte header whose insns_size is 1 followed
    // by two zero bytes pins it exactly.
    let mut damaged = None;
    for i in (0x70..bytes.len() - 16).step_by(2) {
        let insns_size = u32::from_le_bytes(bytes[i + 12..i + 16].try_into().unwrap());
        let regs = u16::from_le_bytes(bytes[i..i + 2].try_into().unwrap());
        if insns_size == 1 && regs == 0 && bytes[i + 16] == 0x11 && bytes[i + 17] == 0x00 {
            damaged = Some(i);
            break;
        }
    }
    let damaged = damaged.expect("damaged code item not found in the built fixture");
    let mut bytes = bytes;
    // Claim 999 code units where only one is present.
    bytes[damaged + 12..damaged + 16].copy_from_slice(&999u32.to_le_bytes());

    let apk = common::write_apk("engine_err", &[("classes.dex", bytes)]);
    (apk, damaged)
}

#[test]
fn engine_errors_reach_both_the_dex_row_and_the_aggregate_list() {
    let (apk, _damaged_off) = apk_with_damaged_code_item();
    let job = FindRefsJob::new(
        apk.clone(),
        Query::String {
            pattern: NEEDLE.to_string(),
        },
    );
    let report = run_findrefs(&job, &FindRefsOptions::default()).unwrap();
    let _ = std::fs::remove_file(&apk);

    assert!(
        !report.complete,
        "a rejected code item must make the run incomplete"
    );
    let dex = report
        .results
        .iter()
        .find(|d| d.dex_name == "classes.dex")
        .expect("classes.dex must still appear in the report");
    assert!(!dex.complete, "the DEX row must not claim completeness");
    assert!(
        !dex.errors.is_empty(),
        "the DEX row must carry the engine error: {:?}",
        dex.errors
    );
    // The CLI's stderr warning list is SearchReport.errors, not
    // DexResults.errors — an engine error recorded in only one of the
    // two is invisible to the user.
    let aggregated: Vec<_> = report
        .errors
        .iter()
        .filter(|e| e.kind == SearchErrorKind::Engine)
        .collect();
    assert_eq!(
        aggregated.len(),
        dex.errors.len(),
        "every engine error must be aggregated: dex={:?} report={:?}",
        dex.errors,
        report.errors
    );
    assert!(
        aggregated.iter().all(|e| e.dex_name == "classes.dex"),
        "aggregated errors keep their owning DEX: {aggregated:?}"
    );
    // Hits from the intact method are still exported.
    assert_eq!(
        report
            .results
            .iter()
            .map(|d| d.matches.len())
            .sum::<usize>(),
        1,
        "results from the healthy code item must survive: {:?}",
        report.results
    );
}

/// A ZIP entry NAMED `classes.dex` whose bytes are not a DEX. Entry
/// discovery is by name, so this is a first-class entry: it must not
/// vanish without a word, and the entry that IS a DEX must still be
/// reported (audit F06).
///
/// The run stays `complete` on purpose — "we declined to decode this"
/// is not "the scan failed", and exit 2 must keep that meaning. The
/// skip has to be visible in the error list instead.
#[test]
fn non_dex_classes_entry_is_reported_but_does_not_fail_the_run() {
    let dex = {
        let d = Dex::new(
            &[OBJECT, MAIN],
            vec![],
            vec![(MAIN.to_string(), "good", (STRING, vec![]))],
            &[u(NEEDLE)],
        );
        let marker = d.string(&u(NEEDLE)) as u16;
        d.finish(&[(
            MAIN,
            vec![],
            vec![("good", 0x0009, 1, 0, vec![0x001A, marker, 0x0011])],
        )])
    };
    let apk = write_apk(
        "f06",
        &[
            ("classes.dex", b"not a dex at all, just padding".to_vec()),
            ("classes2.dex", dex),
        ],
    );
    let job = FindRefsJob::new(
        apk.clone(),
        Query::String {
            pattern: NEEDLE.to_string(),
        },
    );
    let report = run_findrefs(&job, &FindRefsOptions::default()).unwrap();
    let _ = std::fs::remove_file(&apk);

    assert!(
        report
            .errors
            .iter()
            .any(|e| e.dex_name == "classes.dex" && e.message.contains("not a DEX")),
        "the silently skipped entry must be reported: {:?}",
        report.errors
    );
    assert!(
        report.complete,
        "declining to decode an entry is not a failed scan: {:?}",
        report.errors
    );
    assert_eq!(
        report
            .results
            .iter()
            .map(|d| d.matches.len())
            .sum::<usize>(),
        1,
        "the real DEX next to it must still be scanned: {:?}",
        report.results
    );
}
