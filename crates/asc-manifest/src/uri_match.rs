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

use crate::{IntentFilter, PathMatchKind, UriDependency, UriPart, UriRelativeFilterGroup};

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
    // A hierarchical URI with an authority must carry "://". A relative or
    // opaque URI (no "://") has no authority/path we can host-match against,
    // and this module refuses to guess → the parse fails (→ Unknown).
    let colon = rest.find("://")?;
    let (scheme, rest2) = (Some(&rest[..colon]), &rest[colon + 3..]);
    // authority ends at the first '/' (or is the whole rest)
    let (authority, path) = match rest2.find('/') {
        Some(slash) => (&rest2[..slash], Some(&rest2[slash..])),
        None => (rest2, None),
    };
    let path = dec(path)?;
    let (host, port) = split_authority(authority)?;
    Some(UriParts {
        scheme: scheme.map(str::to_string).filter(|s| !s.is_empty()),
        host,
        port,
        path,
        query,
        fragment,
    })
}

/// Split an authority into `(host, port)` the way `android.net.Uri` does
/// (`AbstractHierarchicalUri.parseHost` / `parsePort`): strip the userinfo at
/// the last `@`, then treat only a trailing `:digits` as the port (interior
/// colons — an IPv6 literal `[::1]` — are never a port separator). The host is
/// percent-decoded (`getHost()`); a non-numeric/empty port is absent
/// (`getPort()` would be `-1`). Returns `None` when the host cannot be decoded.
fn split_authority(authority: &str) -> Option<(Option<String>, Option<String>)> {
    if authority.is_empty() {
        return Some((None, None));
    }
    // AOSP uses `authority.lastIndexOf('@')` to strip userinfo.
    let auth = match authority.rsplit_once('@') {
        Some((_, rest)) => rest,
        None => authority,
    };
    // Find a trailing run of ASCII digits preceded by ':' (AOSP findPortSeparator).
    let bytes = auth.as_bytes();
    let mut j = auth.len();
    while j > 0 && bytes[j - 1].is_ascii_digit() {
        j -= 1;
    }
    let (host_raw, port) = if j > 0 && bytes[j - 1] == b':' {
        (&auth[..j - 1], Some(&auth[j..]))
    } else {
        (auth, None)
    };
    let host = percent_decode(host_raw)?;
    let port = port.and_then(|p| p.parse::<i32>().ok().map(|_| p.to_string()));
    Some((if host.is_empty() { None } else { Some(host) }, port))
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

/// R8: a QUERY matcher matches any single parameter, split on `&` (falling
/// back to `;` only when the query has no `&` — AOSP `matchQuery`), each
/// parameter tested with the matcher's *kind* (F4). A literal `+` is kept as
/// `+` (AOSP `Uri.getQuery()` decodes with convertPlus=false). Returns `Err`
/// for an unevaluable kind (Pattern / AdvancedPattern), never a guessed match.
fn query_has_param(kind: PathMatchKind, value: &str, query: Option<&str>) -> Result<bool, String> {
    let Some(q) = query else {
        return Ok(false);
    };
    // AOSP: split on '&'; when that yields one element (no '&'), split on ';'.
    let sep = if q.contains('&') { '&' } else { ';' };
    for param in q.split(sep) {
        match match_part(kind, value, Some(param)) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

/// Three-valued helper for a single decision (used inside the path/group
/// layer). `Unknown` = the module cannot determine the outcome from the
/// data it accepts to evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tri {
    Match,
    Cannot,
    Unknown,
}

/// AOSP `AuthorityEntry.match` (F5): a filter host with a leading `*` is a
/// wildcard — it matches any URI host that *ends with* the remainder,
/// case-insensitive, and never a shorter host. A non-wildcard host is
/// compared case-insensitively (`compareToIgnoreCase`, despite the stale
/// "case-sensitive" doc comment). Byte-safe: a decoded host may contain
/// multi-byte UTF-8, so the suffix compare slices bytes, never char cells.
fn host_matches(filter_host: &str, uri_host: &str) -> bool {
    let uri = uri_host.as_bytes();
    match filter_host.strip_prefix('*') {
        Some(base) => {
            let b = base.as_bytes();
            uri.len() >= b.len() && uri[uri.len() - b.len()..].eq_ignore_ascii_case(b)
        }
        None => uri.eq_ignore_ascii_case(filter_host.as_bytes()),
    }
}

/// AOSP `AuthorityEntry.match` port rule (F5): a filter declaring a port
/// requires the URI port to match *numerically* (`mPort == data.getPort()`,
/// where a missing URI port is `-1`); a filter without a port matches any /
/// absent port.
fn port_matches(filter_port: Option<&str>, uri_port: Option<&str>) -> bool {
    match filter_port {
        None => true,
        Some(fp) => match fp.parse::<i32>() {
            Ok(f) => uri_port.and_then(|up| up.parse::<i32>().ok()) == Some(f),
            Err(_) => false,
        },
    }
}

/// R3/R7/R8: match one `(kind, value)` matcher from a group against its URI
/// part, as `Tri`. An absent part never matches (R7/R8); a non-oracle-confirmed
/// kind (Pattern / AdvancedPattern) is `Unknown`.
fn match_tri(kind: PathMatchKind, value: &str, part: Option<&str>) -> Tri {
    match match_part(kind, value, part) {
        Ok(true) => Tri::Match,
        Ok(false) => Tri::Cannot,
        Err(_) => Tri::Unknown,
    }
}

/// Match every matcher of one group against `p`. A group's `<data>` children
/// (and each child's `parts`) are **ANDed** (R3): any deterministically-false
/// matcher makes the whole group `Cannot` regardless of any `Unknown` sibling
/// (a group that cannot match provably has no effect). A group with no
/// matchers at all never matches (an attribute-less `<data>` contributes none).
fn group_match(g: &UriRelativeFilterGroup, p: &UriParts) -> Tri {
    let mut saw_matcher = false;
    let mut any_unknown = false;
    for data in &g.data {
        for m in &data.parts {
            saw_matcher = true;
            let res = match m.part {
                // Query matches any single parameter with the matcher's kind (R8/F4).
                UriPart::Query => query_has_param(m.kind, &m.value, p.query.as_deref()),
                UriPart::Path => match_part(m.kind, &m.value, p.path.as_deref()),
                UriPart::Fragment => match_part(m.kind, &m.value, p.fragment.as_deref()),
            };
            match res {
                Ok(true) => {}
                Ok(false) => return Tri::Cannot,
                Err(_) => any_unknown = true,
            }
        }
    }
    if !saw_matcher {
        Tri::Cannot // R3: a group with zero filters can never match
    } else if any_unknown {
        Tri::Unknown
    } else {
        Tri::Match
    }
}

/// Evaluate the ordered group layer (R6, three-valued). AOSP
/// `matchGroupsToUri` returns on the *first* group that matches, by its `allow`
/// flag; later groups are never consulted. First-match-wins plus Unknown means:
/// the outcome is a definite `Match` iff every resolution of the unknown groups
/// allows, a definite `Cannot` iff every resolution blocks (`false`), and
/// `Unknown` when an earlier uncertain group could flip a later decision.
fn group_layer(groups: &[UriRelativeFilterGroup], p: &UriParts) -> (Tri, Vec<String>) {
    // First definitely-matching group (if any) + the uncertain groups before it
    // (only those can ever become the first matching group under some resolution).
    let mut first_def: Option<&UriRelativeFilterGroup> = None;
    let mut pre_unknown: Vec<&UriRelativeFilterGroup> = Vec::new();
    for g in groups {
        match group_match(g, p) {
            Tri::Match => {
                first_def = Some(g);
                break;
            }
            Tri::Unknown => pre_unknown.push(g),
            Tri::Cannot => {}
        }
    }
    // base = result when every pre-unknown group is resolved to "doesn't match".
    let base = first_def.is_some_and(|g| g.allow);
    // possible_true/false over all 2^n resolutions of the pre-unknown groups.
    let possible_true = base || pre_unknown.iter().any(|g| g.allow);
    let possible_false = !base || pre_unknown.iter().any(|g| !g.allow);
    match (possible_true, possible_false) {
        (true, true) => (
            Tri::Unknown,
            vec![
                "group-layer verdict depends on an earlier group whose matching is \
                 oracle-unevaluated (ordered first-match)"
                    .to_string(),
            ],
        ),
        (true, false) => (
            Tri::Match,
            vec!["first matching group has android:allow=true".to_string()],
        ),
        (false, true) => {
            // Some resolution blocks, none allows: either a matching block
            // group, or no group matches.
            let reason = if pre_unknown.is_empty() {
                match first_def {
                    Some(g) if !g.allow => "first matching group has android:allow=false (block)",
                    _ => "no group matched",
                }
            } else {
                "some group blocks and none can allow (no definite allow group)"
            };
            (Tri::Cannot, vec![reason.to_string()])
        }
        (false, false) => unreachable!("possible_true or possible_false is always true"),
    }
}

/// F2: before truncating a group layer we refuse to evaluate beyond a bound,
/// return `Some(reason)` → the caller returns `Unknown`. The bounds are only
/// relevant when the groups are actually consulted (flag on).
fn group_layer_overflow(groups: &[UriRelativeFilterGroup]) -> Option<String> {
    if groups.len() > MAX_GROUPS {
        return Some(format!(
            "uri-relative-filter-group count {0} exceeds the {1} limit",
            groups.len(),
            MAX_GROUPS
        ));
    }
    for g in groups {
        if g.data.len() > MAX_DATA_PER_GROUP {
            return Some(format!(
                "<data> count {0} in a group exceeds the {1} limit",
                g.data.len(),
                MAX_DATA_PER_GROUP
            ));
        }
        for d in &g.data {
            if d.parts.len() > MAX_PARTS_PER_DATA {
                return Some(format!(
                    "matcher count {0} in a <data> exceeds the {1} limit",
                    d.parts.len(),
                    MAX_PARTS_PER_DATA
                ));
            }
        }
    }
    None
}

/// Evaluate the path/group layer of `filter` against `uri`.
///
/// `assume_flag_on` is the assumed value of
/// `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS`; when `false`, groups are
/// ignored entirely (R10) and only the filter's own path matchers apply.
///
/// The verdict is three-valued and follows AOSP `IntentFilter.matchData`
/// (verified against the pinned API 35 source): when the authority matched and
/// the filter declares **no path matcher and no group** (flag on) — or no path
/// matcher at all with the flag off — the path layer is `authMatch` and the
/// URI *matches* (F1). Otherwise the path layer matches iff any sibling path
/// matcher matches (R5 OR) or the ordered group layer allows.
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

    // R4: the authority branch must run for any path/group layer. A
    // declared-but-unmatched host is a definite rejection; a filter with no
    // scheme/host leaves the layer inert (other URI dimensions are out of
    // scope → unknown).
    match eff.dependency {
        UriDependency::NoScheme | UriDependency::NoHost => {
            return verdict(
                UriMatchVerdict::Unknown,
                on,
                vec![
                    "scheme/host not fully declared; host/path/group layer inert (R4)".to_string(),
                ],
            );
        }
        UriDependency::Complete => {
            let host_ok = match &p.host {
                None => false,
                Some(h) => eff.authorities.iter().any(|a| {
                    host_matches(&a.host, h) && port_matches(a.port.as_deref(), p.port.as_deref())
                }),
            };
            if !host_ok {
                return verdict(
                    UriMatchVerdict::CannotMatch,
                    on,
                    vec!["declared host does not match the URI authority (R4)".to_string()],
                );
            }
        }
    }

    // F1: a filter with no sibling path matcher and (flag on) no group leaves
    // the path layer as `authMatch` → it matches (AOSP `paths == null [&&
    // groups == null] → match = authMatch`). With the flag off the same
    // applies whenever there is no sibling path at all (groups are ignored).
    if !on {
        if eff.paths.is_empty() {
            return verdict(
                UriMatchVerdict::Matches,
                on,
                vec![
                    "authMatch: no path matcher and the group layer is ignored (flag off)"
                        .to_string(),
                ],
            );
        }
    } else if eff.paths.is_empty() && f.uri_relative_groups.is_empty() {
        return verdict(
            UriMatchVerdict::Matches,
            on,
            vec![
                "authMatch: URI matches at the scheme/host level; no path matcher and no \
                 relative group narrow it"
                    .to_string(),
            ],
        );
    }

    // F2: refuse to give a definite verdict on a truncated group layer.
    if on && let Some(reason) = group_layer_overflow(&f.uri_relative_groups) {
        return verdict(UriMatchVerdict::Unknown, on, vec![reason]);
    }

    // R5: sibling path matchers are ORed with the group layer.
    let (sib, sib_reasons) = sibling_or(&eff.paths, p.path.as_deref());
    let (grp, grp_reasons) = if on {
        group_layer(&f.uri_relative_groups, &p)
    } else {
        (Tri::Cannot, Vec::new())
    };

    // OR over the three-valued layer results: a definite match wins; else any
    // uncertainty wins; else no-match.
    match (sib, grp) {
        (Tri::Match, _) => verdict(
            UriMatchVerdict::Matches,
            on,
            vec!["a filter-level path matcher matched (R5)".to_string()],
        ),
        (_, Tri::Match) => verdict(UriMatchVerdict::Matches, on, grp_reasons),
        (Tri::Unknown, _) | (_, Tri::Unknown) => {
            let mut reasons = sib_reasons;
            reasons.extend(grp_reasons);
            if reasons.is_empty() {
                reasons
                    .push("path/group match depends on an oracle-unevaluated pattern".to_string());
            }
            verdict(UriMatchVerdict::Unknown, on, reasons)
        }
        (Tri::Cannot, _) => {
            let mut reasons = grp_reasons;
            if reasons.is_empty() {
                reasons.push(if !on {
                    "no path layer match and groups are ignored (flag off)".to_string()
                } else {
                    "no path matcher and no group matched".to_string()
                });
            }
            verdict(UriMatchVerdict::CannotMatch, on, reasons)
        }
    }
}

/// R5: OR over the filter's own sibling path matchers, three-valued.
fn sibling_or(paths: &[crate::PathMatcher], path: Option<&str>) -> (Tri, Vec<String>) {
    let mut any_match = false;
    let mut any_unknown = false;
    for pm in paths {
        match match_tri(pm.kind, &pm.value, path) {
            Tri::Match => any_match = true,
            Tri::Cannot => {}
            Tri::Unknown => any_unknown = true,
        }
    }
    if any_match {
        (
            Tri::Match,
            vec!["a filter-level path matcher matched (R5)".to_string()],
        )
    } else if any_unknown {
        (
            Tri::Unknown,
            vec!["filter-level path match depends on an oracle-unevaluated pattern".to_string()],
        )
    } else {
        (Tri::Cannot, Vec::new())
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
        // T19: flag off → group (the only matcher) is ignored → the filter has
        // no sibling path, so AOSP `matchData` takes `paths == null` →
        // `match = authMatch` → it MATCHES (F1; source-confirmed).
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Path, PathMatchKind::Exact, "/a/b")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a/b", false).outcome,
            UriMatchVerdict::Matches
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

    // ---- F1: authMatch when there is no path matcher (and no group, flag on) ----

    #[test]
    fn no_path_no_group_authmatch_matches() {
        // scheme+host filter with neither a path nor a group: AOSP
        // `paths == null && groups == null → match = authMatch` → Matches.
        let f = base_filter(vec![], vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com", true).outcome,
            UriMatchVerdict::Matches
        );
        // Flag off, no path at all → the flag-off branch is `paths == null` → authMatch.
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", false).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn groups_present_but_none_match_is_cannot() {
        // paths==null but a group exists (and none match) → NOT the authMatch
        // short-circuit → CannotMatch.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Path, PathMatchKind::Exact, "/z")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    // ---- F2: bounds never silently truncate a decision ----

    fn groups_matching_last(how_many: usize, target_at: usize) -> Vec<UriRelativeFilterGroup> {
        (0..how_many)
            .map(|i| {
                let value = if i == target_at {
                    "/target".to_string()
                } else {
                    format!("/g{i}")
                };
                group(
                    true,
                    vec![part(UriPart::Path, PathMatchKind::Exact, &value)],
                )
            })
            .collect()
    }

    #[test]
    fn group_count_boundary_exact_cap_ok() {
        // Exactly MAX_GROUPS groups; the last one decides → deterministic.
        let f = base_filter(groups_matching_last(MAX_GROUPS, MAX_GROUPS - 1), vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/target", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn group_count_boundary_over_cap_unknown() {
        // MAX_GROUPS + 1 groups where the deciding matcher sits past the cap →
        // would be truncated → Must be Unknown, never a definite verdict.
        let f = base_filter(groups_matching_last(MAX_GROUPS + 1, MAX_GROUPS), vec![]);
        let v = evaluate_filter_uri(&f, "https://example.com/target", true);
        assert_eq!(v.outcome, UriMatchVerdict::Unknown);
        assert!(!v.reasons.is_empty(), "bounds-reason must explain itself");
        // …and the overflow does not fire when the groups are ignored (flag off).
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/target", false).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn data_and_parts_bounds_unknown() {
        // A group with > MAX_DATA_PER_GROUP <data> children. The in-cap 64 all
        // match "/same"; the 65th (overflow) would veto → Unknown, not a
        // truncated definite verdict.
        let mut datas: Vec<_> = (0..MAX_DATA_PER_GROUP)
            .map(|_| RelativeDataSpec {
                parts: vec![part(UriPart::Path, PathMatchKind::Exact, "/same")],
            })
            .collect();
        datas.push(RelativeDataSpec {
            parts: vec![part(UriPart::Path, PathMatchKind::Exact, "/different")],
        });
        let g = UriRelativeFilterGroup {
            allow: true,
            data: datas,
        };
        let f = base_filter(vec![g], vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/same", true).outcome,
            UriMatchVerdict::Unknown
        );

        // A group whose sole <data> has > MAX_PARTS_PER_DATA matchers, the
        // decision sitting past the limit.
        let mut parts: Vec<_> = (0..MAX_PARTS_PER_DATA)
            .map(|_| part(UriPart::Path, PathMatchKind::Exact, "/same"))
            .collect();
        // 257th matcher would veto the in-cap match → truncating it would flip
        // Matches→CannotMatch, so the verdict must be Unknown.
        parts.push(part(UriPart::Path, PathMatchKind::Exact, "/different"));
        let g = UriRelativeFilterGroup {
            allow: true,
            data: vec![RelativeDataSpec { parts }],
        };
        let f = base_filter(vec![g], vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/same", true).outcome,
            UriMatchVerdict::Unknown
        );
        // Boundary N is within the cap and stays deterministic: MAX_PARTS_PER_DATA
        // matchers that are all satisfiable together (all equal) → Matches.
        let parts: Vec<_> = (0..MAX_PARTS_PER_DATA)
            .map(|_| part(UriPart::Path, PathMatchKind::Exact, "/same"))
            .collect();
        let g = UriRelativeFilterGroup {
            allow: true,
            data: vec![RelativeDataSpec { parts }],
        };
        let f = base_filter(vec![g], vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/same", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    // ---- F3: three-valued logic & ordered groups ----

    #[test]
    fn unknown_block_then_definite_allow_is_unknown() {
        // Group1 matches ⇔ unknown, and is a BLOCK; Group2 definitively allows.
        // If group1 matches it blocks (later groups not consulted); if not,
        // group2 allows → verdict depends on the unknown → Unknown.
        let f = base_filter(
            vec![
                group(
                    false,
                    vec![part(UriPart::Path, PathMatchKind::Pattern, "/x")],
                ),
                group(true, vec![part(UriPart::Path, PathMatchKind::Exact, "/x")]),
            ],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", true).outcome,
            UriMatchVerdict::Unknown
        );
    }

    #[test]
    fn unknown_allow_then_definite_block_is_unknown() {
        let f = base_filter(
            vec![
                group(
                    true,
                    vec![part(UriPart::Path, PathMatchKind::Pattern, "/x")],
                ),
                group(false, vec![part(UriPart::Path, PathMatchKind::Exact, "/x")]),
            ],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", true).outcome,
            UriMatchVerdict::Unknown
        );
    }

    #[test]
    fn unknown_allow_group_alone_is_unknown() {
        // Only source of a possible match is unknown-allow → Unknown.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Path, PathMatchKind::Pattern, "/x")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", true).outcome,
            UriMatchVerdict::Unknown
        );
    }

    #[test]
    fn unknown_block_group_alone_is_certain_cannot() {
        // A lone unknown-BLOCK group: if it matched it blocks, if not nothing
        // else matches → either resolution gives CannotMatch.
        let f = base_filter(
            vec![group(
                false,
                vec![part(UriPart::Path, PathMatchKind::Pattern, "/x")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn sibling_unknown_plus_definite_block_group_is_unknown() {
        // An unevaluable sibling path is ORed with the group layer (R5): a
        // definitive block group cannot override it → Unknown, not CannotMatch.
        let mut f = base_filter(
            vec![group(
                false,
                vec![part(UriPart::Path, PathMatchKind::Exact, "/blocked")],
            )],
            vec![path_data("/public")],
        );
        f.data.push(DataSpec {
            path_pattern: Some("/a.*".into()),
            ..DataSpec::default()
        });
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/blocked", true).outcome,
            UriMatchVerdict::Unknown
        );
    }

    #[test]
    fn sibling_definite_match_plus_unknown_block_group_matches() {
        let f = base_filter(
            vec![group(
                false,
                vec![part(UriPart::Path, PathMatchKind::Pattern, "/x")],
            )],
            vec![path_data("/public")],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/public", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn group_with_definite_false_and_unknown_is_cannot() {
        // Group1 ANDs an unknown matcher with a provably-false one → it cannot
        // match, so it contributes no uncertainty; Group2's definite allow
        // decides → Matches.
        let f = base_filter(
            vec![
                group(
                    true,
                    vec![
                        part(UriPart::Path, PathMatchKind::Pattern, "/x"),
                        part(UriPart::Query, PathMatchKind::Exact, "token=NO"),
                    ],
                ),
                group(true, vec![part(UriPart::Path, PathMatchKind::Exact, "/ok")]),
            ],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/ok?token=1", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn provably_cannot_match_group_does_not_affect_result() {
        // Group1 is unknown but provably cannot match (definite-false AND);
        // Group2 definite allow → Matches (not Unknown).
        let f = base_filter(
            vec![
                group(
                    true,
                    vec![
                        part(UriPart::Path, PathMatchKind::Pattern, "/anything"),
                        part(UriPart::Path, PathMatchKind::Exact, "/not-here"),
                    ],
                ),
                group(true, vec![part(UriPart::Path, PathMatchKind::Exact, "/ok")]),
            ],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/ok", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    // ---- F4: QUERY matcher respects its kind ----

    #[test]
    fn query_prefix_matches_single_param() {
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Query, PathMatchKind::Prefix, "token=")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?token=123", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?x=1&token=456", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?tocado=1", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn query_suffix_matches() {
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Query, PathMatchKind::Suffix, "=done")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?state=done", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?state=do", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn query_pattern_and_advanced_pattern_are_unknown() {
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Query, PathMatchKind::Pattern, "token=.*")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?token=x", true).outcome,
            UriMatchVerdict::Unknown
        );
        let f2 = base_filter(
            vec![group(
                true,
                vec![part(
                    UriPart::Query,
                    PathMatchKind::AdvancedPattern,
                    "token=[0-9]+",
                )],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f2, "https://example.com/a?token=1", true).outcome,
            UriMatchVerdict::Unknown
        );
    }

    #[test]
    fn query_plus_is_literal() {
        // AOSP Uri.getQuery() decodes with convertPlus=false → '+' stays '+'.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Query, PathMatchKind::Exact, "token=a+b")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?token=a+b", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?token=a%20b", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn query_decoded_escapes_before_splitting() {
        // getQuery() percent-decodes first; %3D inside a param becomes '='.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Query, PathMatchKind::Exact, "token=a=b")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?token=a%3Db", true).outcome,
            UriMatchVerdict::Matches
        );
        // Empty parameter and duplicates don't change the semantics.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Query, PathMatchKind::Prefix, "token")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?token=1&token=2", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn query_mixed_separators_split_on_amp() {
        // With an '&' present AOSP splits only on '&'; the ';' stays inside a param.
        let f = base_filter(
            vec![group(
                true,
                vec![part(UriPart::Query, PathMatchKind::Prefix, "tok")],
            )],
            vec![],
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?a=1;tok=2&b=3", true).outcome,
            UriMatchVerdict::CannotMatch
        );
        // Without '&' it falls back to ';'.
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/a?a=1;tok=2;b=3", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    // ---- F5: authority matching & URI parsing ----

    fn authority_filter(
        host: &str,
        port: Option<&str>,
        groups: Vec<UriRelativeFilterGroup>,
    ) -> IntentFilter {
        let data = DataSpec {
            scheme: Some("https".into()),
            host: Some(host.into()),
            port: port.map(str::to_string),
            ..DataSpec::default()
        };
        IntentFilter {
            data: vec![data],
            uri_relative_groups: groups,
            ..IntentFilter::default()
        }
    }

    #[test]
    fn host_match_is_case_insensitive() {
        // AOSP AuthorityEntry uses compareToIgnoreCase despite the stale note.
        let f = authority_filter("example.com", None, vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://EXAMPLE.COM/x", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn wildcard_host_is_suffix_match() {
        let f = authority_filter("*.example.com", None, vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://sub.example.com/x", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://deep.sub.example.com/x", true).outcome,
            UriMatchVerdict::Matches
        );
        // AOSP: a wildcard host must be no longer than the data host.
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", true).outcome,
            UriMatchVerdict::CannotMatch
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://other.com/x", true).outcome,
            UriMatchVerdict::CannotMatch
        );
        // A decoded host with multi-byte UTF-8 must not panic the byte-based
        // suffix compare and must not match.
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com\u{00e9}/x", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn userinfo_is_stripped() {
        let f = authority_filter("example.com", None, vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://user:pass@example.com/x", true).outcome,
            UriMatchVerdict::Matches
        );
    }

    #[test]
    fn port_matches_numerically() {
        let f = authority_filter("example.com", Some("8080"), vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com:8080/x", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com:08080/x", true).outcome,
            UriMatchVerdict::Matches
        );
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com:8081/x", true).outcome,
            UriMatchVerdict::CannotMatch
        );
        // A filter-declared port never matches a URI without one (getPort()==-1).
        assert_eq!(
            evaluate_filter_uri(&f, "https://example.com/x", true).outcome,
            UriMatchVerdict::CannotMatch
        );
    }

    #[test]
    fn opaque_and_no_authority_uris_are_unknown() {
        let f = authority_filter("example.com", None, vec![]);
        // No "://": relative/opaque URI has no authority we can host-match.
        assert_eq!(
            evaluate_filter_uri(&f, "myapp:foo", true).outcome,
            UriMatchVerdict::Unknown
        );
    }

    #[test]
    fn ipv6_authority_parses_without_mangling() {
        let f = authority_filter("[::1]", Some("8080"), vec![]);
        assert_eq!(
            evaluate_filter_uri(&f, "https://[::1]:8080/x", true).outcome,
            UriMatchVerdict::Matches
        );
        let f2 = authority_filter("[::1]", None, vec![]);
        assert_eq!(
            evaluate_filter_uri(&f2, "https://[::1]/x", true).outcome,
            UriMatchVerdict::Matches
        );
    }
}
