# API-35 URI-relative-filter-group — Android oracle

This directory is the **Android API-35 oracle** for the `--match-uri`
evaluator — a reproducible Gradle + Robolectric test project. It is the
framework side of `tests/differential/run_uri_oracle.py`, which drives the
asc-rs side over `tests/fixtures/uri_match_cases.json`.

## Why this matters

ASC-RS derives its three-valued `matches` / `cannot_match` / `unknown` verdict
from the pinned AOSP `android-15.0.0_r1` source (see
`docs/research/uri-relative-filter-groups.md`). The deterministic rules are
verified against that source, but **source-verified ≠ framework-run**. Roadmap
5.4/5.6 require running the same fixtures against the real `IntentFilter.matchData`
/ `UriRelativeFilterGroup.matchGroupsToUri` before a verdict family can be
called `success` / closed.

## Status (2026-10-12, v0.19.2 review)

| | |
|---|---|
| Source revision | `android-15.0.0_r1` (Android 15 / API 35), flags-frozen |
| ASC-RS side | `tests/differential/run_uri_oracle.py` + `asc-manifest/examples/eval_uri.rs` — **runnable, green vs `source_expected`** |
| Oracle side | Gradle + Robolectric project below — **NOT RUN: no JDK / Android SDK / Gradle on this machine** (`java`/`gradle`/`ANDROID_SDK_ROOT` all absent) |
| Explicit gap | `oracle_verdicts.json` absent ⇒ every row is **`oracle=NOT_RUN` / `UNVERIFIED`**; `pattern`/`advanced` rows stay `unknown` in ASC-RS until oracle-confirmed |

No Android-equivalence claim is made from this repository state. The harness
reports `NOT_RUN` when there is no oracle file, `UNVERIFIED` where the asc-rs
verdict matches `source_expected` but has never been diffed against the
framework, `UNSUPPORTED` where asc-rs deliberately returns `unknown` (glob,
opaque URI, bound overflow), and a genuine `SOURCE-MISMATCH` / `ORACLE-MISMATCH`
only when a real divergence exists. Skipped oracle rows are never counted as
verified passes, and the runner **refuses any oracle file whose provenance
cannot prove its run and its flag state** (it exits 1 rather than confirming
from an unverified file).

## Layout

```
reference/oracle/uri_match/
  settings.gradle, build.gradle, gradle.properties   # Gradle + Robolectric
  src/test/java/us/ascrs/urioracle/UriOracle.java    # the Robolectric test
```

The fixture is read **straight from the repo** via `-Duri.fixtures` (set in
`build.gradle`) — there is no copy to drift. The output is written to
`build/oracle_verdicts.json` (`-Duri.oracle.out`).

## Prerequisites (to close the gap)

- JDK 17+
- Gradle 8.x (wrapper not committed; generate one locally with
  `gradle wrapper` if you want `./gradlew`)
- Robolectric `4.14+` resolving an **API-35 `android-all`** artifact for
  `@Config(sdk = 35)` (Robolectric resolves it from Maven Central at test
  time; offline maintainers must pre-populate their local `~/.m2`)
- A verified way to control `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS` (below)

**These were not installed/verified here.** The `build.gradle` versions are a
documented starting point, not a proven build.

## Reproducibility recipe

1. **asc-rs verdicts** (runs here, no Android needed):
   ```
   python tests/differential/run_uri_oracle.py          # regression vs source_expected
   ```
2. **Oracle verdicts** (needs the prerequisites — NOT run here):
   ```
   cd reference/oracle/uri_match
   gradle test --tests '*.UriOracle'                    # writes build/oracle_verdicts.json
   # or, if a wrapper was generated: ./gradlew test --tests '*.UriOracle'
   # To claim a flag mechanism, set URI_FLAG_MECHANISM (see "Flag handling");
   # without it the file is UNVERIFIED_SKIPPED and the runner rejects it.
   ```
3. **Diff** (ASC-RS vs source_expected AND vs the framework oracle):
   ```
   python tests/differential/run_uri_oracle.py --oracle reference/oracle/uri_match/build/oracle_verdicts.json
   ```
   Exit 0 only when every ASC-RS verdict equals `source_expected` and the
   oracle for every case the oracle actually exercised. Any divergence is a
   real finding to fix or re-classify.

## Flag handling

`IntentFilter.matchData` consults `android.content.pm.Flags.relativeReferenceIntentFilters()`;
in the framework build that frozen aconfig flag gates the group branch of
`matchData`. The two states must each be exercised:

- **flag on**: the group-aware branch (`paths==null && groups==null → authMatch`,
  else `hasDataPath || matchRelRefGroups`). Default assumption for fixtures
  with `flag_on: true`.
- **flag off**: `paths == null → authMatch` (groups ignored). Fixtures with
  `flag_on: false` (T19–T21).

**The flag is NOT runtime-toggleable from Robolectric.** It is frozen at
framework build time. `UriOracle` therefore does **not** assume which state it
is in — it **reads the actual state** via `android.content.pm.Flags.relativeReferenceIntentFilters()`
and records it as `provenance.flag_state_actual`:

- A case whose required `flag_on` equals `flag_state_actual` is exercised and
  a verdict is emitted.
- Every other case (required state ≠ this build's state) is added to
  `provenance.flag_skipped` and **no verdict is emitted** — the runner reports
  it `UNVERIFIED(FLAG|SKIP)`, never confirmed, and a verdict that is neither
  present nor in `flag_skipped` is a hard-runner error (missing oracle result).
- If the flag state cannot be read at all, `UriOracle` **fails closed**: the
  JUnit test throws, no verdicts are written, and `status` is
  `UNVERIFIED_SKIPPED`.

`provenance.flag_mechanism` (from `-Duri.flag.mechanism`, env
`URI_FLAG_MECHANISM`) records *how* that build's flag state was established.
A file whose `flag_mechanism` is `UNKNOWN`, whose `status` is
`UNVERIFIED_SKIPPED`, or which omits `flag_state_actual` is **rejected by the
runner** — it can never produce `ORACLE-CONFIRMED`.

**Exercising both states requires two builds** (the flag is frozen per build):
run the same physical fixtures against two android-all artifacts with the flag
in opposite states, producing two `oracle_verdicts.json` files. Each diff
confirms only the cases its build exercised; the union of the two runs covers
both flag states. A single run confirming only one flag state leaves the other
state's rows `UNVERIFIED(FLAG)`, which is the honest, intended outcome.

## Verdict mapping

`matchData` returns `>= 0` matching categories (`MATCH_CATEGORY_HOST/PORT/PATH/…`)
for a match and negative `NO_MATCH_*` for a rejection. The framework is
**deterministic** — it has no `unknown`. Map `>= 0 → matches`, `< 0 →
cannot_match`. A row ASC-RS cannot decide (pattern/advanced glob, opaque URI,
bound overflow) has **no direct** matchData answer; the harness surfaces that
as `ORACLE-OPEN` (a real finding under the framework's deterministic answer) —
never as "the oracle also says unknown" and never as a passing confirmation.

`UriOracle` implements this mapping and, when run, embeds provenance
(framework revision, API level, **actual** flag state, skipped flag-mismatched
cases, flag mechanism, Robolectric version, input/output paths). Review it
against the pinned source before trusting it.
