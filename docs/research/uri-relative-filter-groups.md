# API 35 `<uri-relative-filter-group>` — AOSP semantics, evidence, roadmap

Date: 2026-10-08 · branch `master` @ `9c6b90d` · status: **research +
5.1 acceptance criteria added (fixture table below); 5.2–5.6 not
implemented.**

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

#### 5.1.1 Acceptance fixture table (R1–R10)

Verdict is three-valued — `matches` / `cannot match` / `unknown` (§4). The
expected verdicts below are **derived from the AOSP source and platform
docs cited in §2**; they are acceptance criteria, *not* verified byte-for-byte
yet. They become the unit-test input in 5.4, after the AOSP (API 35) oracle
harness confirms each one. Wherever a case is flag-sensitive it is listed as
its own row and the assumed flag state is stated, never footnoted.

Unless a row says otherwise, every filter declares
`<data android:scheme="https" android:host="example.com" />` so the
authority branch runs (R4 `UriDependency::Complete`) and the group layer is
consulted.

| Row | Rule | Manifest fragment (scheme+host always present unless noted) | URI | Expected verdict | Reason |
|---|---|---|---|---|---|
| T1 | R1+R6 order | filter with `allow` group P (`path="/1"`) **then** group Q (`path="/2"`), both after the scheme/host `<data>` | `https://example.com/2` | matches | Parse/eval keeps declaration order: Q is consulted and, matching, is allowed. If order were pooled/reversed, P would be consulted first and not match, but the result is the same here; T6 exercises the order that actually flips the verdict. |
| T2 | R1 (sibling OR) | filter-level `<data path="/direct"/>` declared **before** a group; group G (`allow=false`, `path="/blocked"`) | `https://example.com/direct` | matches | Sibling path matcher is in the same OR-set as the group layer (R5): `/direct` matches the filter-level path regardless of the block group. |
| T3 | R3 (AND within group) | one `allow=true` group with two `<data>`: `path="/a/b"`, `query="token=1"` | `https://example.com/a/b?token=1` | matches | Every matcher in the group matches → the group matches → allow. |
| T4 | R3 (AND fails) | same manifest as T3 | `https://example.com/a/b?other=2` | cannot match | The group's `query="token=1"` matcher fails → the group (ANDed) fails; no sibling path → path layer empty. |
| T5 | R3 (empty group never matches) | one `allow=true` group with **no** `<data>` child | any | cannot match | `UriRelativeFilterGroup.matchData` returns false for zero filters; no other matcher → path layer empty. |
| T6 | R6 block-before-allow | group1 `allow=false path="/x"`, **then** group2 `allow=true pathPrefix="/x"` | `https://example.com/x` | cannot match | First matching group decides: group1's exact `/x` matches and is a block; group2 is never consulted. This is the doc's block-narrows-allow rule. |
| T7 | R6 order reversal | group1 `allow=true pathPrefix="/x"` **then** group2 `allow=false path="/x"` | `https://example.com/x` | matches | First matching group decides: group1 (prefix) matches and allows; group2 not consulted. Declaring order is semantic. |
| T8 | R4 host dependency | filter with scheme `https`, **no host**, and an `allow=true` group (`path="/a/b"`, `query="token=1"`) | `https://example.com/a/b?token=1` | unknown | The group layer is inert (R4: it sits inside the host-matched authority branch, and no host is declared → `UriDependency::NoHost`), so the group contributes nothing. Whether a scheme-only filter matches this URI is an intent-resolution question outside the path verdict (§6.5), so the evaluator reports `unknown`, never a fabricated `cannot match`; the oracle confirms in 5.4. |
| T9 | R5 sibling path overrides block | filter-level `<data path="/public"/>` **plus** group `allow=false path="/private"` | `https://example.com/public` | matches | `/public` matches the filter-level path, which is outside the block group (§2.1 documented example). |
| T10 | R5 block hits | same manifest as T9 | `https://example.com/private` | cannot match | Sibling `/public` doesn't match; the block group matches `/private` → path layer fails. |
| T11 | R7 (PATH whole-part) | one `allow=true` group `path="/a"` (Exact) | `https://example.com/a/` | cannot match | Whole-part match: `/a/` ≠ `/a`. |
| T12 | R7 (FRAGMENT whole-part + absent) | one `allow=true` group `fragment="sec"` | `https://example.com/a#sec` | matches | Whole fragment equals `sec`. |
| T13 | R7 (FRAGMENT absent) | same manifest as T12 | `https://example.com/a` | cannot match | `Uri.getFragment()` is null → `PatternMatcher.match(null)` is false. |
| T14 | R8 (QUERY single param, `&`) | one `allow=true` group `query="token=1"` | `https://example.com/a?token=1&x=2` | matches | QUERY splits on `&` and matches any single parameter: `token=1`. |
| T15 | R8 (QUERY single param, `;` fallback) | same manifest as T14 | `https://example.com/a?x=2;token=1` | matches | No `&` → split on `;` → `x=2`, `token=1`; the single parameter `token=1` matches. |
| T15b | R8 (no param matches) | same manifest as T14 | `https://example.com/a?token=0&x=2` | cannot match | No single parameter equals `token=1`. |
| T16 | R9 (simple glob) | one `allow=true` group `pathPattern="/a/.*"` | `https://example.com/a/123` | matches | `.*` greedy, single-pass: the literal `/a/` prefix with `.*` rest matches. |
| T17 | R9 (glob no match) | same manifest as T16 | `https://example.com/ab` | cannot match | Weak path does not start with literal `/a/`. |
| T18 | R9 (advanced glob) | one `allow=true` group `pathAdvancedPattern="/a/[0-9]+"` | `https://example.com/a/42` | matches | Regex-like char class + `+` on the advanced form. |
| T19 | R10 flag OFF (only source of match is a group) | `allow=true` group (`path="/a/b"`) **with flag off** | `https://example.com/a/b` | cannot match | `Flags.relativeReferenceIntentFilters()` false → groups ignored → behaves as if the path layer were absent (no sibling path). |
| T20 | R10 flag OFF (sibling still matches) | filter-level `<data path="/public"/>` + `allow=false` group, **flag off** | `https://example.com/public` | matches | Groups ignored, but the sibling path still matches (R5 unaffected by the flag). |
| T21 | R10 flag OFF (block inert) | filter-level `<data path="/public"/>` + `allow=false` group (`path="/private"`), **flag off** | `https://example.com/private` | cannot match | Block group ignored; `/private` is not a sibling path → no path match. |
| T22 | §4 unknown (unsupported/unevaluable) | a group whose `pathAdvancedPattern` uses a construct §5.4 marks unsupported (e.g. a lookahead) | `https://example.com/x` | unknown | Unevaluable construct → `unknown` with reason, never `matches` (§4). Final classification orbited by the 5.4 oracle. |
| T23 | R2 (pooled filter data) | two filter-level `<data scheme="https" host="example.com" path="/a"/>` and `<data scheme="https" host="example.com" path="/b"/>` | `https://example.com/b` | matches | Filter-level `<data>` are pooled/ORed (existing `EffectiveData`), a path matches. Group layer irrelevant here. |
| T24 | R3/§2.1 doc example (AND vs OR) | filter-level `<data path="/path"/>` + `allow=false` group whose **two** `<data>` (`path="/excluded"`, `query="token=secret"`) are ANDed; URI `?query` carries `token=secret` | `https://project.example.com/path?token=secret` | matches | The sibling `path="/path"` matches (OR), so the filter accepts even though the block group's ANDed matchers would also be satisfied — matches the documented example. |

**Accompanying invariants (asserted at 5.4, not per-row):**

- **R1** parse order is retained across `data` (`DataSpec`), group vector
  (`uri_relative_groups`) and each group's `data` / `parts` — no pooling or
  reordering anywhere that would change `matchGroupsToUri` first-match.
- **R2** filter-level `<data>` stay pooled/ORed (`EffectiveData`) exactly as
  today; group evaluation is additive and never rewrites them.
- **§4** every `unknown` row must come with a non-empty reason list, and no
  path may silently truncate a matcher/group that exceeds the §4 bounds.
- **Flag rows** (T19–T21) each state `assumed flag = off`; the verdict API
  must expose the flag state it assumed.

**Three doc examples mapped:** AND vs OR → T24 (+T3/T4); block-before-allow
→ T6/T7; sibling path overriding a block group → T9/T10. Flag-off variant →
T19–T21.


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
