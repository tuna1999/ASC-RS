//! API-35 URI-relative-filter-group oracle differential — asc-rs side.
//!
//! Reads `tests/fixtures/uri_match_cases.json` and, for every case, builds the
//! declared [`IntentFilter`] and prints the three-valued verdict of
//! [`evaluate_filter_uri`] plus its reason, as
//! `case_id<TAB>verdict<TAB>reason`. `tests/differential/run_uri_oracle.py`
//! diffs this against each case's `source_expected` and, when a real Android
//! oracle verdict file is supplied (`--oracle`), against the framework's.
//!
//! Run: `cargo run -p asc-manifest --example eval_uri -- tests/fixtures/uri_match_cases.json`
//!
//! This is a pure (bounded, deterministic) re-derivation of the evaluator for
//! the harness; it is NOT an Android oracle. The Android-API-35 reference must
//! come from `reference/oracle/uri_match/` (Gradle + Robolectric,
//! `src/test/java/us/ascrs/urioracle/UriOracle.java`).

use std::env;
use std::path::Path;

use asc_manifest::uri_match::UriMatchVerdict;
use asc_manifest::uri_match::Verdict;
use asc_manifest::uri_match::evaluate_filter_uri;
use asc_manifest::{
    DataSpec, IntentFilter, PathMatchKind, RelativeDataSpec, UriPart, UriPartMatcher,
    UriRelativeFilterGroup,
};

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: eval_uri <uri_match_cases.json>");
        std::process::exit(2);
    });
    let text = std::fs::read_to_string(Path::new(&path)).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        std::process::exit(2);
    });
    let root: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("bad JSON: {e}");
        std::process::exit(2);
    });
    for case in root["cases"].as_array().into_iter().flatten() {
        let id = case["case_id"].as_str().unwrap_or("?");
        let uri = case["uri"].as_str().unwrap_or("");
        let flag_on = case["flag_on"].as_bool().unwrap_or(true);
        let filter = build_filter(&case["filter"]);
        let v = evaluate_filter_uri(&filter, uri, flag_on);
        println!("{id}\t{}\t{}", verb(&v), v.reasons.join("; "));
    }
}

fn verb(v: &Verdict) -> &'static str {
    match v.outcome {
        UriMatchVerdict::Matches => "matches",
        UriMatchVerdict::CannotMatch => "cannot_match",
        UriMatchVerdict::Unknown => "unknown",
    }
}

fn kind(s: &str) -> PathMatchKind {
    match s {
        "prefix" => PathMatchKind::Prefix,
        "suffix" => PathMatchKind::Suffix,
        "pattern" => PathMatchKind::Pattern,
        "advanced" => PathMatchKind::AdvancedPattern,
        _ => PathMatchKind::Exact,
    }
}

fn part(s: &str) -> UriPart {
    match s {
        "query" => UriPart::Query,
        "fragment" => UriPart::Fragment,
        _ => UriPart::Path,
    }
}

fn s(v: Option<&serde_json::Value>) -> Option<String> {
    v.and_then(|x| x.as_str()).map(str::to_string)
}

fn build_filter(f: &serde_json::Value) -> IntentFilter {
    let mut data = Vec::new();
    if let Some(list) = f["data"].as_array() {
        for d in list {
            let port = match d.get("port") {
                Some(serde_json::Value::Number(n)) => Some(n.to_string()),
                v => s(v),
            };
            data.push(DataSpec {
                scheme: s(d.get("scheme")),
                host: s(d.get("host")),
                port,
                path: s(d.get("path")),
                path_prefix: s(d.get("path_prefix")),
                path_pattern: s(d.get("path_pattern")),
                path_advanced_pattern: s(d.get("path_advanced_pattern")),
                path_suffix: s(d.get("path_suffix")),
                mime_type: None,
            });
        }
    }
    let mut groups = Vec::new();
    if let Some(gl) = f["groups"].as_array() {
        for g in gl {
            let allow = g["allow"].as_bool().unwrap_or(true);
            let mut gdata = Vec::new();
            if let Some(dl) = g["data"].as_array() {
                for d in dl {
                    let mut parts = Vec::new();
                    if let Some(pl) = d["parts"].as_array() {
                        for p in pl {
                            parts.push(UriPartMatcher {
                                part: part(p["part"].as_str().unwrap_or("path")),
                                kind: kind(p["kind"].as_str().unwrap_or("exact")),
                                value: p["value"].as_str().unwrap_or("").to_string(),
                            });
                        }
                    }
                    gdata.push(RelativeDataSpec { parts });
                }
            }
            groups.push(UriRelativeFilterGroup { allow, data: gdata });
        }
    }
    IntentFilter {
        data,
        uri_relative_groups: groups,
        ..IntentFilter::default()
    }
}
