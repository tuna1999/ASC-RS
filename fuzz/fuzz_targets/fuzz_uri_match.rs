//! Contract: `asc_manifest::uri_match::evaluate_filter_uri` never panics on
//! arbitrary URI input — in particular `percent_decode` must not slice out of
//! bounds on a truncated/malformed escape (e.g. a `%A` at the very end of a
//! URI part). Arbitrary bytes are lossily UTF-8-rified into a URI and
//! evaluated against a fixed scheme+host+group filter in both flag states;
//! the target asserts only the absence of a panic, never semantics. Behind
//! the `manifest` feature.

use crate::FuzzOutcome;

#[cfg(feature = "manifest")]
pub fn run(input: &[u8]) -> FuzzOutcome {
    use asc_manifest::uri_match::evaluate_filter_uri;
    use asc_manifest::{DataSpec, IntentFilter, PathMatchKind, UriPart, UriPartMatcher};

    let f = IntentFilter {
        data: vec![DataSpec {
            scheme: Some("https".to_string()),
            host: Some("example.com".to_string()),
            path: Some("/public".to_string()),
            ..DataSpec::default()
        }],
        uri_relative_groups: vec![asc_manifest::UriRelativeFilterGroup {
            allow: true,
            data: vec![asc_manifest::RelativeDataSpec {
                parts: vec![UriPartMatcher {
                    part: UriPart::Path,
                    kind: PathMatchKind::Exact,
                    value: "/target".to_string(),
                }],
            }],
        }],
        ..IntentFilter::default()
    };
    let uri = String::from_utf8_lossy(input);
    for flag in [true, false] {
        let _ = evaluate_filter_uri(&f, &uri, flag);
    }
    FuzzOutcome::Ok
}

#[cfg(not(feature = "manifest"))]
pub fn run(_input: &[u8]) -> FuzzOutcome {
    FuzzOutcome::SkippedDisabled
}
