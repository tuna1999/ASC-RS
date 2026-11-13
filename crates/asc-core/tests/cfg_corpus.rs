//! `run_cfg` block/edge output against a real corpus DEX.

use asc_core::{DisasmJob, DisasmOptions, run_cfg};

fn dex() -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apk/com.aurora.store_60.apk");
    if !p.exists() {
        eprintln!("skipping: {} not present", p.display());
    }
    p.exists().then_some(p)
}

#[test]
fn branchy_method_gets_blocks_and_edges() {
    let Some(p) = dex() else { return };
    let job = DisasmJob::new(&p, "Lcom/aurora/gplayapi/Address;", Some("dynamicMethod"));
    let out = run_cfg(&job, &DisasmOptions::default()).expect("cfg");
    assert!(out.listing.contains("# control flow of "), "header");
    assert!(out.listing.contains("B0:"), "block lines");
    assert!(out.listing.contains("-> B"), "at least one edge is printed");
    assert!(!out.listing.contains(".method"), "not a Smali listing");
}

#[test]
fn absent_method_is_reported() {
    let Some(p) = dex() else { return };
    let job = DisasmJob::new(&p, "Lcom/aurora/gplayapi/Address;", Some("nope_xyz"));
    let err = run_cfg(&job, &DisasmOptions::default()).expect_err("missing");
    assert!(format!("{err}").contains("nope_xyz"), "{err}");
}
