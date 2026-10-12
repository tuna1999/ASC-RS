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
verified passes.

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
- Gradle (wrapper not committed) that can run the `org.robolectric` plugin
- Robolectric `4.14+` resolving an **API-35 `android-all`** artifact for
  `@Config(sdk = 35)`
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
   ./gradlew test --tests '*.UriOracle'                 # writes build/oracle_verdicts.json
   ```
3. **Diff** (ASC-RS vs source_expected AND vs the framework oracle):
   ```
   python tests/differential/run_uri_oracle.py --oracle reference/oracle/uri_match/build/oracle_verdicts.json
   ```
   Exit 0 only when every ASC-RS verdict equals `source_expected` and the
   oracle. Any divergence is a real finding to fix or re-classify.

## Flag handling

`IntentFilter.matchData` consults `Flags.relativeReferenceIntentFilters()`; in
the framework build that flag gates the group branch of `matchData`. The two
states must each be exercised:

- **flag on**: the group-aware branch (`paths==null && groups==null → authMatch`,
  else `hasDataPath || matchRelRefGroups`). Default assumption for fixtures with
  `flag_on: true`.
- **flag off**: `paths == null → authMatch` (groups ignored). Fixtures with
  `flag_on: false` (T19–T21).

**Control mechanism.** The aconfig flag is frozen at framework build time; it
is **not runtime-toggleable** from a Robolectric test. To test both states you
must run the same physical manifest against two framework builds whose flag
toggled, or against an API-35 device/emulator where the flag can be switched
and rebooted. `UriOracle` does **not** toggle the flag — it selects the
scenario by `flag_on`, asserts it against the build's actual flag state, and
records `provenance.flag_mechanism` (set via `-Duri.flag.mechanism`, env
`URI_FLAG_MECHANISM`, default `UNKNOWN`). A file whose mechanism is `UNKNOWN`
is reported `UNVERIFIED_SKIPPED`, never a pass. A maintainer must record the
exact mechanism next to the oracle file before it is trusted.

## Verdict mapping

`matchData` returns `>= 0` matching categories (`MATCH_CATEGORY_HOST/PORT/PATH/…`)
for a match and negative `NO_MATCH_*` for a rejection. The framework is
**deterministic** — it has no `unknown`. Map `>= 0 → matches`, `< 0 →
cannot_match`. A row ASC-RS cannot decide (pattern/advanced glob, opaque URI,
bound overflow) has **no direct** `matchData` answer; the harness compares
ASC-RS `unknown` to the oracle's deterministic answer and records the
divergence as a real finding, never as "the oracle also says unknown".

`UriOracle` implements this mapping and, when run, embeds provenance
(framework revision, API level, assumed flag states, flag mechanism,
Robolectric version, input/output paths). Review it against the pinned source
before trusting it.
