# API 35 `<uri-relative-filter-group>` — AOSP semantics, evidence, roadmap

Date: 2026-10-08 · branch `master` @ `799f5b9` (v0.18.2) · status: **research
only, nothing implemented**.

ASC-RS today parses `<uri-relative-filter-group>` children of an
`<intent-filter>` and reports them verbatim (`asc-manifest`
`IntentFilter::uri_relative_groups`), and
`IntentFilter::has_uri_relative_groups()` marks `effective_data` as
incomplete whenever a filter declares one. That flag is honest, but it
means the URI surface ASC-RS reports for such a filter is *declared*, not
*effective*: the group layer (allow/block ordering, AND semantics,
sibling interaction) is not evaluated. This document records the
authoritative semantics (AOSP, API 35) and the roadmap for evaluating
them.

## 1. Why it matters for triage

An exported component whose `<intent-filter>` declares groups has a match
surface that depends on the group layer:

- A **block** group can forbid a URI that the scheme/host alone would
  appear to accept → reporting "reachable" from scheme+host is a
  **false positive**.
- An **allow** group can be the only path matcher a filter declares →
  reporting the scheme/host with no path is a **false negative**
  (`effective_data.effective_paths()` is empty, but the filter does match
  paths).
- With the platform flag off, groups are not evaluated at all
  (`IntentFilter.matchData` takes the `paths == null` branch), so the same
  manifest has a *different* surface depending on the device build.

None of the three may be presented as certainty. Detection must produce a
three-valued verdict (`matches` / `cannot match` / `unknown`) and name the
reason.

## 2. Primary evidence (read from source, not memory)

| Source | Establishes |
|---|---|
| developer.android.com → `<uri-relative-filter-group>` element page | syntax; `android:allow` default `true`; group `<data>` are **ANDed** while filter-level `<data>` are **ORed**; sibling `scheme`/`host` dependency; declaration-order rules; URI-encoded matching rules |
| developer.android.com → `<data>` element page | API 35 attributes `fragment*`, `query*` (each in `literal / Prefix / Suffix / Pattern / AdvancedPattern` form), legal **only** inside a group; the five `path*` kinds; pattern semantics (no backtracking, lazy `.*`, greedy `*`); `pathSuffix`/`pathAdvancedPattern` are API 31 |
| `frameworks/base/core/java/android/content/IntentFilter.java` (`matchData`) | where the group layer sits in the match |
| `frameworks/base/core/java/android/content/UriRelativeFilterGroup.java` | group match = AND over filters; ordered first-match-wins allow/block |
| `frameworks/base/core/java/android/content/UriRelativeFilter.java` | per-part matching: PATH → `Uri.getPath()`, FRAGMENT → whole `Uri.getFragment()`, QUERY → any single query parameter; `PatternMatcher` kinds |

### 2.1 `IntentFilter.matchData` — where groups attach

Inside the `schemes != null` → authority-matched branch:

```java
final ArrayList<PatternMatcher> paths = mDataPaths;
final ArrayList<UriRelativeFilterGroup> groups = mUriRelativeFilterGroups;
if (Flags.relativeReferenceIntentFilters()) {
    if (paths == null && groups == null) {
        match = authMatch;
    } else if (hasDataPath(data.getPath(), wildcardSupported)
            || matchRelRefGroups(data)) {
        match = MATCH_CATEGORY_PATH;
    } else {
        return NO_MATCH_DATA;
    }
} else {
    if (paths == null) {
        match = authMatch;
    } else if (hasDataPath(data.getPath(), wildcardSupported)) {
        match = MATCH_CATEGORY_PATH;
    } else {
        return NO_MATCH_DATA;
    }
}
```

Consequences:

1. **Groups are in the same OR-set as the filter's sibling path
   matchers**, not a separate veto layer: a sibling `<data
   android:path="/path" />` match makes the filter match even when a
   block group also matches. This is exactly the documented example
   ("The filter accepts `https://project.example.com/path?query` because
   it matches `<data android:path="/path" />`, which is outside the
   exclusion rule").
2. Groups are consulted **only** when the filter declares a host that
   matched (the authority branch). A filter with groups but no host has an
   *inert* group layer — the same dependency ASC-RS already models for
   paths (`UriDependency::{Complete, NoScheme, NoHost}`).
3. Groups are behind the aconfig flag `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS`
   (`@FlaggedApi`). Flag off → groups ignored entirely: a filter whose
   only matchers are groups behaves as if it had no path layer at all.

### 2.2 `UriRelativeFilterGroup` — ordered allow/block

```java
public static boolean matchGroupsToUri(List<UriRelativeFilterGroup> groups, Uri uri) {
    for (int i = 0; i < groups.size(); i++) {
        if (groups.get(i).matchData(uri)) {
            return groups.get(i).getAction() == UriRelativeFilterGroup.ACTION_ALLOW;
        }
    }
    return false;
}

public boolean matchData(@NonNull Uri data) {
    if (mUriRelativeFilters.size() == 0) return false;
    for (UriRelativeFilter filter : mUriRelativeFilters) {
        if (!filter.matchData(data)) return false;
    }
    return true;
}
```

- First group (declaration order) all of whose filters match decides:
  `allow=true` → the path layer matches, `allow=false` → it does not
  (the loop stops there; later groups are not consulted).
- No group matches → the group layer does not match.
- A group with zero filters can never match.
- Therefore **declaration order is semantic**: a block rule must be
  declared before the allow rule it narrows. Any data model that reorders
  or pools groups is wrong.

### 2.3 `UriRelativeFilter` — per-part matching

```java
case PATH:     return pe.match(data.getPath());
case QUERY:    return matchQuery(pe, data.getQuery());   // any single parameter
case FRAGMENT: return pe.match(data.getFragment());
```

```java
private boolean matchQuery(PatternMatcher pe, String query) {
    if (query != null) {
        String[] params = query.split("&");
        if (params.length == 1) params = query.split(";");
        for (String param : params) if (pe.match(param)) return true;
    }
    return false;
}
```

- PATH and FRAGMENT patterns must match the **entire** part;
  `PatternMatcher.match(null)` is `false`, so a URI without a fragment can
  never satisfy a group that declares a fragment filter.
- QUERY filters match **one parameter** (name, or `name=value`), not the
  whole query string; parameters split on `&`, falling back to `;` when
  the query has no `&`.
- Pattern kinds: `PATTERN_LITERAL` (exact), `PATTERN_PREFIX`,
  `PATTERN_SUFFIX`, `PATTERN_SIMPLE_GLOB` (`pathPattern`),
  `PATTERN_ADVANCED_GLOB` (`advancedPattern`).
- Matching is against the **decoded** URI parts: the docs' example
  (`android:query="param=value!"` matches both `?param=value!` and
  `?param=value%21`) follows from `Uri.getPath()/getQuery()/getFragment()`
  returning decoded components; writing the *encoded* form in the filter
  matches neither.
- `Uri.getFragment()` returns `null` for a URI without `#`.

## 3. Semantics to implement (rule list)

| # | Rule | Source |
|---|---|---|
| R1 | Parse order of `<data>` (filter level), then groups in declaration order | docs "Declaration order" + `matchData` |
| R2 | Filter-level `<data>` URI attributes are pooled (scheme/authority/path OR-sets) — already implemented | `EffectiveData` |
| R3 | Group `<data>` children are ANDed within their group; zero children → group never matches | `UriRelativeFilterGroup.matchData` |
| R4 | Groups only take effect after a host matched (scheme+host present and matching) | `matchData` nesting |
| R5 | Path layer = (any sibling path matcher matches) OR (group layer matches) | `matchData` |
| R6 | Group layer = first matching group decides by `allow`; none → false | `matchGroupsToUri` |
| R7 | PATH/FRAGMENT = whole-part match; absent part never matches | `UriRelativeFilter.matchData` |
| R8 | QUERY = any single parameter, split `&` then `;` | `matchQuery` |
| R9 | Five pattern kinds per attribute; `AdvancedPattern` = regex-like subset, `Pattern` = glob subset with documented non-backtracking behaviour | `<data>` docs |
| R10 | Flag off ⇒ groups ignored (filter behaves as if the group layer were absent) | `Flags.relativeReferenceIntentFilters()` |

## 4. Contract consequences for ASC-RS

- `data` (raw) and `effective_data` (pooled) keep their meaning; group
  evaluation is **additive** — a new evaluation result plus reasons, never
  a rewrite of the reported declarations.
- Text output keeps printing the group lines verbatim (the existing
  "declared, NOT evaluated" warning becomes a verdict line when a URI is
  supplied; without a URI the warning stays).
- JSON: additive fields only (`matches` / `cannot_match` / `unknown` with
  a reason list). Existing consumers must not have to change.
- The three-valued verdict is mandatory: an unevaluable construct
  (flag-off ambiguity, unsupported pattern, malformed group) yields
  `unknown`, never `matches`.
- Bounds: reuse the existing untrusted-input caps (MUTF-8 1 MiB, depth 64)
  and add explicit ones for groups per filter, `<data>` per group,
  matchers per element and pattern length; exceeding a cap yields
  `unknown` with a reason, not a silent truncation.

## 5. Roadmap

Ordered; each step's output is the next step's input. No step ships
without its gate.

**5.1 Evidence and acceptance criteria (this document).** Add a fixture
table: (manifest fragment, URI, expected verdict, reason) covering R1–R10,
including the three doc examples (AND vs OR, block-before-allow, sibling
path overriding a block group) and the flag-off variant.

**5.2 Data-model design.** Keep `UriRelativeFilterGroup { allow, data }`
as parsed. Add an evaluation view (no reordering): ordered groups →
ordered matchers with `(part, kind, pattern)`. Cache nothing derived at
parse time that a text/JSON consumer could misread as evaluated.

**5.3 Matcher / evaluator design.** New module in `asc-manifest`
(`match.rs`): pattern matchers (literal/prefix/suffix/simple glob/advanced
glob — no backtracking, single pass, bounded), decoded URI part
extraction, group evaluation per R3–R6, path-layer OR per R5, dependency
reuse per R4 (`UriDependency`), verdict + reasons per §4. Pure function:
`evaluate(filter, uri) -> Verdict`.

**5.4 Synthetic and differential testing.**
- Synthetic: `asc-manifest` already builds AXML blobs by hand
  (`src/tests.rs` helpers) — the fixture table from 5.1 becomes unit
  tests; no Android tooling needed.
- Oracle: run AOSP `IntentFilter.matchData` (`UriRelativeFilterGroup`) on
  a real Android API 35 build (device/emulator, or Robolectric on the
  framework jar) for each fixture URI; compare verdicts. Record the
  oracle recipe + version in the compatibility matrix.
- Real APKs: none of the five corpus APKs contains the element (byte
  search for `uri-relative-filter-group`, 2026-10-08), so coverage needs
  new fixtures: one aapt2-built APK per rule group (no Android SDK on
  this machine at research time — aapt2 is a prerequisite), plus any
  externally collected API-35 APK that uses the element (dev-only
  fixture, `docs/CORPUS.md` policy) — differential the ASC-RS verdict
  against the oracle's.

**5.5 Implementation.** Surface the verdict where deep links are consumed:
a CLI query (`manifest <apk> --match-uri <uri>`, text + JSON) and,
optionally, the GUI inspector. Update `skills/apk-analysis/SKILL.md`
(command list, output notes, pitfalls) in the same change; the
`uri-relative` warning text changes meaning and must be updated there.

**5.6 Full regression verification.** The standard gates (fmt, clippy
`-D warnings`, `cargo test --workspace`, release build, `--selfcheck`,
differential, perf selftest, fuzz smoke, MSRV) plus the new synthetic
suite and the oracle differential registered in
`tests/compatibility/parity_matrix.md`.

## 6. Open questions / unknowns (do not claim these before 5.4)

1. **AAPT2 output shape.** Do compiled manifests keep
   `<uri-relative-filter-group>` + `<data android:query=…>` as element and
   attribute names in the AXML string pool (ASC-RS maps attributes by
   local name, `URI_RELATIVE_ATTRS`), or does the build rewrite them?
   Runtime `writeToXml` writes an internal `uriRelativeFilter` form with
   integer `part`/`pattern` attributes — that is the *runtime* serializer,
   not necessarily what aapt2 emits. Needs one real APK to confirm.
2. **Flag coverage.** `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS` is an
   aconfig flag: verdicts must state the assumed flag state, and the
   "flag off" verdict is a separate row, not a footnote.
3. **`PatternMatcher` corner cases** (lazy `.*` stops at the first literal
   occurrence, greedy `*`, `[ ]` sets and `{ }` ranges in the advanced
   form, escaping `\\*`): the oracle decides, not prose.
4. **Decoding details** (percent-encoding, `+` in queries, `;` fallback
   when a query contains both separators) — oracle.
5. **Not in scope for the first cut:** intent *resolution* scoring
   (priority, categories, MIME types, `<queries>`), `android:autoVerify`
   App Links verification, `pathAdvancedPattern` performance parity.

## 7. Explicit non-claims

Nothing in this document asserts that any URI is reachable for any APK.
The current ASC-RS behaviour remains: groups are reported as declared and
the URI surface of a filter that declares them is **incomplete**.
