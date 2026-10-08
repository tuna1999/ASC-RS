//! API 35 `<uri-relative-filter-group>` evaluation — roadmap 5.2–5.4.
//!
//! Pure, bounded function: [`evaluate_filter_uri`] decides how a concrete
//! URI matches an [`IntentFilter`]'s **path layer**, i.e. the OR of the
//! filter's own `<data path*>` matchers and its ordered
//! `<uri-relative-filter-group>` allow/block groups.
//!
//! AOSP contract (docs/research/uri-relative-filter-groups.md §2):
//!
//! - **R1/R2** filter-level `<data>` stay pooled/ORed (`EffectiveData`);
//!   groups are consulted in declaration order and never pooled.
//! - **R3** a group's matchers are ANDed; a group with no `${data}` can
//!   never match.
//! - **R4** the group (and path) layer is consulted only after a scheme
//!   *and* host matched.
//! - **R5** the path layer matches if a sibling path matcher **or** the
//!   group layer matches.
//! - **R6** the first matching group decides by its `allow` flag; later
//!   groups are not consulted.
//! - **R7** PATH / FRAGMENT match the whole decoded part; an absent part
//!   never satisfies a fragment/path matcher.
//! - **R8** QUERY matches any single parameter, split on `&` then `;`.
//! - **R10** groups are ignored when the platform flag is off.
//!
//! Verdicts are **three-valued** (§4): `Matches` / `CannotMatch` /
//! `Unknown`. `Unknown` is returned for anything this module refuses to
//! claim — pattern (glob / advanced) matchers and decoding corner cases
//! that the AOSP API 35 oracle (§6.3 / §6.4) must decide before they can
//! be asserted. Nothing fabricates a match.
//!
//! Bounds (§4): a filter is capped at 64 groups, a group at 64 `<data>`
//! elements, a `<data>` at 256 matchers, and a URI at 1 MiB decoded;
//! exceeding a bound yields `Unknown`, never a silent truncation.

use crate::{IntentFilter, PathMatchKind, UriDependency, UriPart};

const MAX_GROUPS: usize = 64;
const MAX_DATA_PER_GROUP: usize = 64;
const MAX_PARTS_PER_DATA: usize = 256;
const MAX_URI_LEN: usize = 1 << 20;

/// Three-valued URI-match verdict (§4). `Unknown` must not be read as
/// "maybe"; it means the evaluator refuses to claim a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriMatchVerdict {
    Matches,
    CannotMatch,
    Unknown,
}

/// Verdict plus the reasons that justify it and the assumed platform flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub outcome: UriMatchVerdict,
    /// Human-readable reasons (non-empty whenever `outcome` is `Unknown`).
    pub reasons: Vec<String>,
    /// The assumed value of `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS`
    /// (whether groups were evaluated at all). Always reported; never a
    /// footnote (§6.2).
    pub assumed_flag_on: bool,
}

fn verdict(outcome: UriMatchVerdict, assumed_flag_on: bool, reasons: Vec<String>) -> Verdict {
    Verdict {
        outcome,
        reasons,
        assumed_flag_on,
    }
}

/// Decoded URI parts. Matching always happens on the decoded form (§2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
struct UriParts {
    scheme: Option<String>,
    host: Option<String>,
    port: Option<String>,
    path: Option<String>,
    query: Option<String>,
    fragment: Option<String>,
}

/// Percent-decode `s`; `None` when invalid (bad escape or not UTF-8). A
/// literal `+` in the query is **kept** as `+` (the `+`→space rule is an
/// oracle open question, §6.4).
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() + 1 && i + 2 <= bytes.len() {
            let hex = &bytes[i + 1..i + 3];
            let hi = hex_val(hex[0])?;
            let lo = hex_val(hex[1])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode an optional part; `None` (outer) when the part is present but
/// cannot be decoded (bad escape / non-UTF-8), which fails the parse.
fn dec(part: Option<&str>) -> Option<Option<String>> {
    match part {
        None => Some(None),
        Some(p) => percent_decode(p).map(Some),
    }
}

/// Split a URI into its decoded parts. Returns `None` for a malformed or
/// overflowing URI. Scheme/authority are not percent-decoded (hosts in
/// practice are ASCII; an internationalised host idna-encodes upstream).
fn parse_uri(uri: &str) -> Option<UriParts> {
    if uri.len() > MAX_URI_LEN {
        return None;
    }
    // fragment
    let (rest, fragment) = match uri.split_once('#') {
        Some((r, f)) => (r, Some(f)),
        None => (uri, None),
    };
    let fragment = dec(fragment)?;
    // query
    let (rest, query) = match rest.split_once('?') {
        Some((r, q)) => (r, Some(q)),
        None => (rest, None),
    };
    let query = dec(query)?;
    // scheme + authority + path
    let (scheme, rest2) = if let Some(colon) = rest.find("://") {
        (Some(&rest[..colon]), &rest[colon + 3..])
    } else {
        (None, rest)
    };
    // authority ends at the first '/' (or is the whole rest)
    let (authority, path) = match rest2.find('/') {
        Some(slash) => (&rest2[..slash], Some(&rest2[slash..])),
        None => (rest2, None),
    };
    let host;
    let port;
    if authority.is_empty() {
        host = None;
        port = None;
    } else {
        match authority.rsplit_once(':') {
            Some((h, pt)) if !pt.is_empty() => {
                host = Some(h.to_string());
                port = Some(pt.to_string());
            }
            _ => {
                host = Some(authority.to_string());
                port = None;
            }
        }
    }
    let path = dec(path)?;
    Some(UriParts {
        scheme: Some(scheme.map(str::to_string).unwrap_or_default()).filter(|s| !s.is_empty()),
        host,
        port,
        path,
        query,
        fragment,
    })
}

/// Match a single `(kind, value)` matcher against a whole part (`None` =
/// the part is absent, so it never matches — R7/R8).
///
/// Returns `Ok(true/false)` for deterministic kinds and `Err` when the kind
/// is not oracle-confirmed yet (`Pattern`, `AdvancedPattern`) or the query
/// contains a `+` (§6.4).
fn match_part(kind: PathMatchKind, value: &str, part: Option<&str>) -> Result<bool, String> {
    let Some(p) = part else {
        // An absent part never satisfies a matcher.
        return Ok(false);
    };
    match kind {
        PathMatchKind::Exact => Ok(p == value),
        PathMatchKind::Prefix => Ok(p.starts_with(value)),
        PathMatchKind::Suffix => Ok(p.ends_with(value)),
        PathMatchKind::Pattern | PathMatchKind::AdvancedPattern => {
            Err("pattern (glob/advanced) matcher not oracle-confirmed yet".to_string())
        }
    }
}

/// R8: a QUERY matcher matches any single parameter, split on `&` then `;`.
fn query_has_param(value: &str, query: Option<&str>) -> Result<bool, String> {
    let Some(q) = query else {
        return Ok(false);
    };
    if q.contains('+') {
        return Err("query contains '+' whose decoding is oracle-open".to_string());
    }
    let mut params: Vec<&str> = if q.contains('&') {
        q.split('&').collect()
    } else {
        q.split(';').collect()
    };
    if params.len() == 1 {
        // AOSP: when a single element, re-split on ';'.
        params = q.split(';').collect();
    }
    Ok(params.contains(&value))
}

/// Evaluate the path/group layer of `filter` against `uri`.
///
/// `assume_flag_on` is the assumed value of
/// `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS`; when `false`, groups are
/// ignored entirely (R10) and only the filter's own path matchers apply.
pub fn evaluate_filter_uri(f: &IntentFilter, uri: &str, assume_flag_on: bool) -> Verdict {
    let on = assume_flag_on;
    let Some(p) = parse_uri(uri) else {
        return verdict(
            UriMatchVerdict::Unknown,
            on,
            vec!["URI is malformed or exceeds the 1 MiB bound".to_string()],
        );
    };
    let eff = f.effective_data();

    // Scheme precondition: the data URI must carry a declared scheme.
    if !eff.schemes.is_empty() {
        let ok = p.scheme.as_ref().is_some_and(|s| eff.schemes.contains(s));
        if !ok {
            return verdict(
                UriMatchVerdict::CannotMatch,
                on,
                vec!["URI scheme not in the filter's pooled schemes".to_string()],
            );
        }
    }

    // R4: the authority branch must run for any path/group layer.
    let host_ok = match (eff.dependency, &p.host) {
        (UriDependency::NoScheme, _) | (UriDependency::NoHost, _) => false,
        (UriDependency::Complete, None) => false,
        (UriDependency::Complete, Some(h)) => eff.authorities.iter().any(|a| {
            a.host == *h
                && match &a.port {
                    Some(fp) => p.port.as_deref() == Some(fp.as_str()),
                    None => true,
                }
        }),
    };
    if !host_ok {
        return verdict(
            UriMatchVerdict::Unknown,
            on,
            vec!["no matching authority; host/path/group layer inert (R4)".to_string()],
        );
    }

    // R5: sibling path matcher (OR) — deterministic first.
    let mut sibling_uncertain = false;
    let mut sibling_matched = false;
    for pm in eff.paths.iter() {
        match match_part(pm.kind, &pm.value, p.path.as_deref()) {
            Ok(true) => {
                sibling_matched = true;
            }
            Ok(false) => {}
            Err(_) => {
                sibling_uncertain = true;
            }
        }
    }
    if sibling_matched {
        return verdict(
            UriMatchVerdict::Matches,
            on,
            vec!["a filter-level path matcher matched (R5)".to_string()],
        );
    }

    // R6: ordered groups (only when the flag is on).
    let mut group_uncertain = false;
    if on {
        for group in f.uri_relative_groups.iter().take(MAX_GROUPS) {
            if group.data.is_empty() {
                continue; // R3: an empty group never matches.
            }
            let mut group_matched = true;
            'group: for data in group.data.iter().take(MAX_DATA_PER_GROUP) {
                if data.parts.is_empty() {
                    group_matched = false;
                    break;
                }
                for part in data.parts.iter().take(MAX_PARTS_PER_DATA) {
                    let res = match part.part {
                        UriPart::Query => query_has_param(&part.value, p.query.as_deref()),
                        UriPart::Path => match_part(part.kind, &part.value, p.path.as_deref()),
                        UriPart::Fragment => {
                            match_part(part.kind, &part.value, p.fragment.as_deref())
                        }
                    };
                    match res {
                        Ok(true) => {}
                        Ok(false) => {
                            group_matched = false;
                            break 'group;
                        }
                        Err(_) => {
                            group_uncertain = true;
                            group_matched = false;
                            break 'group;
                        }
                    }
                }
            }
            if group_matched {
                // First matching group decides (R6).
                return if group.allow {
                    verdict(
                        UriMatchVerdict::Matches,
                        on,
                        vec!["first matching group has android:allow=true".to_string()],
                    )
                } else {
                    verdict(
                        UriMatchVerdict::CannotMatch,
                        on,
                        vec!["first matching group has android:allow=false (block)".to_string()],
                    )
                };
            }
        }
    }

    // No sibling path matched and no group decided.
    if sibling_uncertain || group_uncertain {
        verdict(
            UriMatchVerdict::Unknown,
            on,
            vec!["path/group match depends on an oracle-unevaluated pattern".to_string()],
        )
    } else {
        let reason = if !on {
            "no path layer match and groups are ignored (flag off)"
        } else {
            "no path matcher and no group matched"
        };
        verdict(UriMatchVerdict::CannotMatch, on, vec![reason.to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataSpec, IntentFilter, RelativeDataSpec, UriPartMatcher, UriRelativeFilterGroup};

    fn data(scheme: &str, host: &str) -> DataSpec {
        DataSpec {
            scheme: Some(scheme.to_string()),
            host: Some(host.to_string()),
            port: None,
            path: None,
            path_prefix: None,
            path_pattern: None,
            path_advanced_pattern: None,
            path_suffix: None,
            mime_type: None,
        }
    }

    fn path_data(p: &str) -> DataSpec {
        DataSpec {
            scheme: None,
            host: None,
            port: None,
            path: Some(p.to_string()),
            path_prefix: None,
            path_pattern: None,
            path_advanced_pattern: None,
            path_suffix: None,
            mime_type: None,
        }
    }

    fn group(allow: bool, parts: Vec<UriPartMatcher>) -> UriRelativeFilterGroup {
        UriRelativeFilterGroup {
            allow,
            data: vec![RelativeDataSpec { parts }],
        }
    }

    fn part(part_val: UriPart, kind: PathMatchKind, value: &str) -> UriPartMatcher {
        UriPartMatcher {
            part: part_val,
            kind,
            value: value.to_string(),
        }
    }

    const BASE: &str = "https://example.com/x";

    fn base_filter(groups: Vec<UriRelativeFilterGroup>, siblings: Vec<DataSpec>) -> IntentFilter {
        let mut data = vec![data("https", "example.com")];
        data.extend(siblings);
        IntentFilter {
            actions: vec![],
            categories: vec![],
            data,
            effective_data: Default::default(),
            uri_relative_groups: groups,
            auto_verify: None,
            priority: None,
        }
    }

    #[test]
    fn sibling_path_or_overrides_block_group() {
        // T9/T10: sibling <data path="/public"/> plus an allow=false group /private.
        let f = base_filter(
            vec![group(
                false,
                vec![part(UriPart::Path, PathMatchKind::Exact, "/private")],
            )],
            vec![path_data("/public")],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/public", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/private", true).outcome,
            UriMatchVerdict::CannotMatch
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/other", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn and_within_group_both_must_match() {
        // T3/T4: allow group path=/a/b AND query=token=1.
        let f = base_filter(
            vec![group(
                true,
                vec![
                    part(UriPart::Path, PathMatchKind::Exact, "/a/b"),
                    part(UriPart::Query, PathMatchKind::Exact, "token=1"),
                ],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a/b?token=1", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a/b?other=2", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn empty_group_never_matches() {
        // T5.
        let f = base_filter(
            vec![UriRelativeFilterGroup {
                allow: true,
                data: vec![],
            }],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, BASE, true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn first_matching_group_by_allow_and_order() {
        // T6: block-before-allow — exact /x block wins.
        let f = base_filter(
            vec![
                group(false, vec![part(UriPart::Path, PathMatchKind::Exact, "/x")]),
                group(true, vec![part(UriPart::Path, PathMatchKind::Prefix, "/x")]),
            ],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", true).outcome,
            UriMatchVerdict::CannotMatch
        );
        // T7: reversal — prefix allow first wins.
        let f2 = base_filter(
            vec![
                group(true, vec![part(UriPart::Path, PathMatchKind::Prefix, "/x")]),
                group(false, vec![part(UriPart::Path, PathMatchKind::Exact, "/x")]),
            ],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f2, "https://example.com/x", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn no_host_means_group_layer_inert_unknown() {
        // T8: scheme but no host → Unknown (not a fabricated cannot-match).
        let mut f = base_filter(vec![], vec![]);
        f.data = vec![DataSpec {
            scheme: Some("https".into()),
            host: None,
            port: None,
            path: None,
            path_prefix: None,
            path_pattern: None,
            path_advanced_pattern: None,
            path_suffix: None,
            mime_type: None,
        }];
        f.uri_relative_groups = vec![group(
            true,
            vec![part(UriPart::Path, PathMatchKind::Exact, "/a/b")],
        )];
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a/b", true).outcome,
            UriMatchVerdict::Unknown
        );
    }

    #[test]
    fn fragment_whole_part_requires_present_part() {
        // T12/T13.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Fragment, PathMatchKind::Exact, "sec")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a#sec", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn query_single_param_amp_and_semicolon() {
        // T14/T15/T15b.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Query, PathMatchKind::Exact, "token=1")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?token=1&x=2", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?x=2;token=1", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?token=0&x=2", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn pattern_kind_is_unknown_not_claim() {
        // T16/T17: simple-glob matchers are not oracle-confirmed → Unknown.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Path, PathMatchKind::Pattern, "/a/.*")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a/123", true).outcome,
            UriMatchVerdict::Unknown
        );
    }

    #[test]
    fn flag_off_ignores_groups() {
        // T19: flag off → group that would allow is ignored → CannotMatch.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Path, PathMatchKind::Exact, "/a/b")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a/b", false).outcome,
            UriMatchVerdict::CannotMatch
        );
        // T20: flag off, sibling path still matches.
        let f2 = base_filter(
            vec![group(
                false,
                vec![part(UriPart::Path, PathMatchKind::Exact, "/private")],
            )],
            vec![path_data("/public")],
        );
        assert_eq!(
            evaluate_filter_uri(&f2, "https://example.com/public", false).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn explicit_unknown_rows_always_carry_reasons() {
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Path, PathMatchKind::Pattern, "/x")],
            )],
            vec![],
        );
        let v = evaluate_filter_uri(&f, "https://example.com/x", true);
        assert_eq!(v.outcome, UriMatchVerdict::Unknown);
        assert!(!v.reasons.is_empty(), "unknown always explains itself");
    }
}
