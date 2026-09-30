//! `run_resources` against real APKs (each test skips when its fixture is
//! absent). Golden numbers were cross-checked against a byte-level walk of
//! the arsc and androguard.

use asc_core::{ResourcesQuery, run_resources};

fn fixture(name: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/apk")
        .join(name);
    if !p.exists() {
        eprintln!("skipping: {name} not present");
    }
    p.exists().then_some(p)
}

fn query(id: Option<u32>, pattern: Option<&str>, limit: usize) -> ResourcesQuery {
    ResourcesQuery {
        id,
        pattern: pattern.map(str::to_owned),
        limit,
    }
}

#[test]
fn aurora_inventory_and_id_resolution() {
    let Some(p) = fixture("com.aurora.store_60.apk") else {
        return;
    };
    let r = run_resources(&p, &query(Some(0x7f0a_0001), None, 10)).unwrap();
    assert!(r.arsc_present && r.complete, "{:?}", r.diagnostics);
    assert_eq!(r.global_strings, 24_891);
    assert_eq!(r.packages.len(), 1);
    assert_eq!(r.packages[0].id, 0x7f);
    assert_eq!(r.packages[0].entries, 34_210);
    assert_eq!(r.packages[0].types.len(), 20);
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].key, "abc_config_activityShortDur");
    assert_eq!(r.hits[0].value, "150");

    // Entry 0 of type 2 is 0x7f020000; its key-string index (42) must not
    // leak into the ID.
    let r = run_resources(&p, &query(Some(0x7f02_0000), None, 10)).unwrap();
    assert_eq!(r.hits.len(), 1);
    let r = run_resources(&p, &query(Some(0x7f02_002a), None, 10)).unwrap();
    assert_ne!(
        r.hits.first().map(|h| h.key.as_str()),
        Some("design_appbar_state_list_animator")
    );
}

#[test]
fn every_res_path_in_the_table_exists_in_the_zip() {
    let Some(p) = fixture("org.fdroid.fdroid_1016000.apk") else {
        return;
    };
    let r = run_resources(&p, &query(None, Some("res/"), usize::MAX)).unwrap();
    assert!(r.complete);
    let names: std::collections::HashSet<String> = {
        let apk = asc_apk::Apk::open(&p).unwrap();
        apk.entries().map(|e| e.name).collect()
    };
    let mut checked = 0;
    for h in &r.hits {
        if let Some(path) = h
            .value
            .strip_prefix("\"res/")
            .and_then(|s| s.strip_suffix('"'))
        {
            assert!(names.contains(&format!("res/{path}")), "{}", h.value);
            checked += 1;
        }
    }
    assert!(checked > 500, "only {checked} simple res/ values checked");
}

#[test]
fn apk_without_arsc_is_reported_not_failed() {
    let Some(p) = fixture("workload.apk") else {
        return;
    };
    let r = run_resources(&p, &query(None, None, 10)).unwrap();
    assert!(!r.arsc_present && r.complete && r.packages.is_empty());
}
