//! Synthetic (corpus-free) tests for the class-scoped scans'
//! completeness contract (audit P1).
//!
//! A class that loads a string / invokes a method and THEN hits an
//! unknown opcode must keep the partial data AND report
//! `complete == false` with the failure in `errors` — never present a
//! partial scan as complete. `0x73` is an unassigned opcode
//! (`asc-bytecode` treats it as `UnknownOpcode`), so it pins a walker
//! failure mid-body without needing a corpus fixture.

mod common;

use common::{Dex, OBJECT, u};

const MAIN: &str = "Lp/Main;";
const LITERAL: &str = "hello-const";

/// `const-string v0, "hello-const"` then unknown opcode `0x73`.
fn damaged_string_dex() -> Vec<u8> {
    let method_ids: Vec<common::Member> = vec![(MAIN.to_string(), "m", ("V", vec![]))];
    let dex = Dex::new(&[OBJECT, MAIN], vec![], method_ids, &[u(LITERAL)]);
    let marker = dex.string(&u(LITERAL)) as u16;
    let insns = vec![0x001A, marker, 0x0073];
    dex.finish(&[(MAIN, vec![], vec![("m", 0x0009, 1, 0, insns)])])
}

/// `invoke-static {}, Lp/Main;->t()V` then unknown opcode `0x73`.
fn damaged_invoke_dex() -> Vec<u8> {
    let method_ids: Vec<common::Member> = vec![
        (MAIN.to_string(), "m", ("V", vec![])),
        (MAIN.to_string(), "t", ("V", vec![])),
    ];
    let dex = Dex::new(&[OBJECT, MAIN], vec![], method_ids, &[]);
    let target = dex.method(MAIN, "t");
    let insns = vec![0x0071, target, 0x0000, 0x0073];
    dex.finish(&[(MAIN, vec![], vec![("m", 0x0009, 0, 0, insns)])])
}

#[test]
fn class_strings_keeps_partial_and_reports_incomplete() {
    let apk = common::write_apk("cs_partial", &[("classes.dex", damaged_string_dex())]);
    let r = asc_core::run_class_strings(&asc_core::ClassStringsJob::new(&apk, MAIN)).unwrap();
    let _ = std::fs::remove_file(&apk);
    assert!(
        !r.complete,
        "an unknown opcode must mark the scan incomplete"
    );
    assert!(!r.errors.is_empty(), "the walker failure must be surfaced");
    assert_eq!(
        r.strings.len(),
        1,
        "the string before the failure must be kept: {:?}",
        r.strings
    );
    assert_eq!(r.strings[0].text, LITERAL);
}

#[test]
fn callees_keeps_partial_and_reports_incomplete() {
    let apk = common::write_apk("callees_partial", &[("classes.dex", damaged_invoke_dex())]);
    let r = asc_core::run_callees(&asc_core::CalleesJob::new(&apk, MAIN, "m")).unwrap();
    let _ = std::fs::remove_file(&apk);
    assert!(
        !r.complete,
        "an unknown opcode must mark the scan incomplete"
    );
    assert!(!r.errors.is_empty(), "the walker failure must be surfaced");
    assert_eq!(
        r.callees.len(),
        1,
        "the invoke before the failure must be kept: {:?}",
        r.callees
    );
    assert_eq!(r.callees[0].target, "Lp/Main;->t");
}

#[test]
fn clean_body_scans_are_complete() {
    let method_ids: Vec<common::Member> = vec![(MAIN.to_string(), "m", ("V", vec![]))];
    let dex = Dex::new(&[OBJECT, MAIN], vec![], method_ids, &[u(LITERAL)]);
    let marker = dex.string(&u(LITERAL)) as u16;
    // const-string v0, LITERAL ; return-void
    let insns = vec![0x001A, marker, 0x0011];
    let bytes = dex.finish(&[(MAIN, vec![], vec![("m", 0x0009, 1, 0, insns)])]);
    let apk = common::write_apk("cs_clean", &[("classes.dex", bytes)]);
    let r = asc_core::run_class_strings(&asc_core::ClassStringsJob::new(&apk, MAIN)).unwrap();
    let _ = std::fs::remove_file(&apk);
    assert!(r.complete, "{:?}", r.errors);
    assert!(r.errors.is_empty());
    assert_eq!(r.strings.len(), 1);
}
