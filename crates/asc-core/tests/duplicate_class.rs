//! Regression tests for deterministic class lookup when the same class
//! is defined in more than one DEX (P2).
//!
//! Contract under test: `getclass` / `disasm` must pick the
//! class-defining DEX with the LOWEST entry index (`classes.dex` before
//! `classes2.dex`, like Android's multidex classloader), independent of
//! worker scheduling, thread count, and which worker finishes first.

mod common;

use asc_core::{DisasmJob, DisasmOptions, GetClassJob, GetClassOptions, run_disasm, run_getclass};
use common::{ACC_PUBLIC_STATIC, Dex, OBJECT, STRING, corrupt_dex, u, write_apk};

const TARGET: &str = "Ldup/Target;";
const OTHER: &str = "Ldup/Other;";

/// DEX defining `Ldup/Target;` with `tag()` returning `const-string <marker>`.
/// DEX defining `Ldup/Target;` (when `defines_target`, else `Ldup/Other;`)
/// with `tag()` returning `const-string <marker>`. `pad` prepends that
/// many one-method dummy classes so the target class-def sits at the
/// END of the class list — a big first DEX racing a small second one.
fn dex_with_class(defines_target: bool, marker: &str, pad: usize) -> Vec<u8> {
    let class = if defines_target { TARGET } else { OTHER };
    let mut method_ids: Vec<common::Member> = vec![(class.to_string(), "tag", (STRING, vec![]))];
    let mut dummy_descs: Vec<String> = Vec::with_capacity(pad);
    for i in 0..pad {
        let desc = format!("Lpad/P{i};");
        dummy_descs.push(desc.clone());
        method_ids.push((desc, "p", ("V", vec![])));
    }
    let dex = Dex::new(&[OBJECT, TARGET, OTHER], vec![], method_ids, &[u(marker)]);
    let idx = dex.string(&u(marker)) as u16;
    // const-string v0, marker ; return-object v0 (format 21c).
    let tag_insns = vec![0x001A, idx, 0x0011];
    // Dummies first, target last: class_defines has to walk them all.
    let mut classes: Vec<common::ClassSpec<'_>> = dummy_descs
        .iter()
        .map(|d| {
            (
                d.as_str(),
                vec![],
                vec![("p", ACC_PUBLIC_STATIC, 0, 0, vec![0x000E])],
            )
        })
        .collect();
    classes.push((
        class,
        vec![],
        vec![("tag", ACC_PUBLIC_STATIC, 1, 0, tag_insns)],
    ));
    dex.finish(&classes)
}

fn getclass(apk: &std::path::Path, threads: usize) -> asc_core::GetClassResult {
    let job = GetClassJob::new(apk.to_path_buf(), TARGET.to_string());
    let opts = GetClassOptions {
        threads,
        ..Default::default()
    };
    run_getclass(&job, &opts).expect("run_getclass")
}

fn disasm(apk: &std::path::Path, threads: usize) -> asc_core::DisasmResult {
    let job = DisasmJob {
        apk: apk.to_path_buf(),
        target: TARGET.to_string(),
        method: None,
    };
    let opts = DisasmOptions {
        threads,
        ..Default::default()
    };
    run_disasm(&job, &opts).expect("run_disasm")
}

#[test]
fn duplicate_class_prefers_lowest_dex_across_thread_counts() {
    let apk = write_apk(
        "dup",
        &[
            ("classes.dex", dex_with_class(true, "first_marker", 400)),
            ("classes2.dex", dex_with_class(true, "second_marker", 0)),
        ],
    );
    // Sweep thread counts and repeat each: the winner must never depend
    // on scheduling. Both the DEX name and the decompiled/disassembled
    // content (marker) come from `classes.dex`.
    for threads in 1..=8 {
        for _ in 0..4 {
            let result = getclass(&apk, threads);
            assert_eq!(
                result.dex_name, "classes.dex",
                "threads={threads}: wrong winner"
            );
            let listing = disasm(&apk, threads);
            assert_eq!(listing.dex_name, "classes.dex", "threads={threads}");
            assert!(
                listing.listing.contains("first_marker")
                    && !listing.listing.contains("second_marker"),
                "threads={threads}: disasm content must come from classes.dex"
            );
        }
    }
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn class_only_in_second_dex_is_found_there() {
    let apk = write_apk(
        "second",
        &[
            ("classes.dex", dex_with_class(false, "other_marker", 0)),
            ("classes2.dex", dex_with_class(true, "second_marker", 0)),
        ],
    );
    for threads in [1, 3, 8] {
        assert_eq!(getclass(&apk, threads).dex_name, "classes2.dex");
        assert_eq!(disasm(&apk, threads).dex_name, "classes2.dex");
    }
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn corrupt_first_dex_falls_through_to_valid_second() {
    let apk = write_apk(
        "corrupt_first",
        &[
            ("classes.dex", corrupt_dex()),
            ("classes2.dex", dex_with_class(true, "second_marker", 0)),
        ],
    );
    for threads in [1, 3, 8] {
        let result = getclass(&apk, threads);
        assert_eq!(result.dex_name, "classes2.dex");
    }
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn corrupt_middle_dex_does_not_hide_later_hit() {
    let apk = write_apk(
        "corrupt_mid",
        &[
            ("classes.dex", dex_with_class(false, "other_marker", 0)),
            ("classes2.dex", corrupt_dex()),
            ("classes3.dex", dex_with_class(true, "third_marker", 0)),
        ],
    );
    for threads in [1, 2, 8] {
        let result = getclass(&apk, threads);
        assert_eq!(result.dex_name, "classes3.dex");
        let listing = disasm(&apk, threads);
        assert_eq!(listing.dex_name, "classes3.dex");
        assert!(listing.listing.contains("third_marker"));
    }
    let _ = std::fs::remove_file(&apk);
}

#[test]
fn all_corrupt_reports_error_not_classnotfound_silently() {
    let apk = write_apk(
        "all_corrupt",
        &[
            ("classes.dex", corrupt_dex()),
            ("classes2.dex", corrupt_dex()),
        ],
    );
    let job = GetClassJob::new(apk.clone(), TARGET.to_string());
    let opts = GetClassOptions {
        threads: 4,
        ..Default::default()
    };
    // The recorded parse failure surfaces (Apk error), not a bare
    // ClassNotFound that would hide the corruption.
    match run_getclass(&job, &opts) {
        Err(asc_core::CoreError::Apk(_)) => {}
        other => panic!("expected CoreError::Apk, got {other:?}"),
    }
    let _ = std::fs::remove_file(&apk);
}
