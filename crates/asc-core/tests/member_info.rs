//! `run_member_info` flags + signature against a real corpus DEX.

use asc_core::{MemberInfoJob, run_member_info};

fn dex() -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/dex/aurora_classes.dex");
    if !p.exists() {
        eprintln!("skipping: {} not present", p.display());
    }
    p.exists().then_some(p)
}

#[test]
fn public_method_reports_public_and_its_proto() {
    let Some(p) = dex() else { return };
    let job = MemberInfoJob::new(&p, "Landroidx/constraintlayout/widget/d;", "i");
    let info = run_member_info(&job).expect("info");
    assert!(info.flag_names.contains(&"public"), "{:?}", info.flag_names);
    assert!(info.proto.starts_with('('), "proto is descriptor form");
    assert!(
        info.proto.ends_with(")V"),
        "void renderer method returns V, got {}",
        info.proto
    );
}

#[test]
fn absent_method_is_reported_not_guessed() {
    let Some(p) = dex() else { return };
    let job = MemberInfoJob::new(&p, "Landroidx/constraintlayout/widget/d;", "nope_xyz");
    let err = run_member_info(&job).expect_err("missing method");
    assert!(format!("{err}").contains("nope_xyz"), "{err}");
}
