# API-35 URI-relative-filter-group — Android oracle

This directory holds the **Android API-35 oracle** for the `--match-uri`
evaluator. It is the framework side of
`tests/differential/run_uri_oracle.py`, which drives the asc-rs side over
`tests/fixtures/uri_match_cases.json`.

## Why this matters

ASC-RS derives its three-valued `matches` / `cannot_match` / `unknown` verdict
from the pinned AOSP `android-15.0.0_r1` source (see
`docs/research/uri-relative-filter-groups.md`). The deterministic rules are
verified against that source, but **source-verified ≠ framework-run**. Roadmap
5.4/5.6 require running the same fixtures against the real `IntentFilter.matchData`
/ `UriRelativeFilterGroup.matchGroupsToUri` before a verdict family can be
called `success` / closed. Until an oracle verdict file is produced and diffed,
`run_uri_oracle.py` reports every oracle row as `PENDING` and ASC-RS makes no
Android-equivalence claim.

## Status

| | |
|---|---|
| Source revision | `android-15.0.0_r1` (Android 15 / API 35), flags-frozen |
| ASC-RS side | `tests/differential/run_uri_oracle.py` + `asc-manifest/examples/eval_uri.rs` — **runnable, green (36/36 vs source_expected)** |
| Oracle side | `UriOracle.java` (Robolectric, below) — **NOT RUN: no Android SDK / JVM / emulator on this machine** |
| Explicit gap | Oracle verdict file absent ⇒ `oracle=PENDING` on every row; `pattern`/`advanced` rows stay `unknown` in ASC-RS until oracle-confirmed |

## Prerequisites (to close the gap)

- JDK 17+
- Android SDK with `platforms;android-35` (`android-15` / API 35) and `aapt2`
- A way to enable the aconfig flag `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS`
  (see below), or run against a device/emulator where it is on
- Gradle + Robolectric (4.14+) resolving `android-all` for API 35

## Reproducibility recipe

1. **asc-rs verdicts** (already runnable here):
   ```
   python tests/differential/run_uri_oracle.py          # regression vs source_expected
   ```
2. **Oracle verdicts** (needs the prerequisites — NOT run here):
   ```
   cd reference/oracle/uri_match
   ./gradlew test --tests '*.UriOracle'                 # writes oracle_verdicts.json
   ```
   `UriOracle` emits `oracle_verdicts.json` `{case_id: matches|cannot_match|unknown}`
   for every fixture in `tests/fixtures/uri_match_cases.json`.
3. **Diff**:
   ```
   python tests/differential/run_uri_oracle.py --oracle reference/oracle/uri_match/oracle_verdicts.json
   ```
   Exit 0 only when every ASC-RS verdict equals both `source_expected` and the
   oracle. Any divergence is a real finding to fix or re-classify.

### Flag handling

`IntentFilter.matchData` consults `Flags.relativeReferenceIntentFilters()`. In
the framework build the flag gates the group branch of `matchData`. The oracle
test must exercise both states:

- **flag on**: the group-aware branch (`paths==null && groups==null → authMatch`,
  else `hasDataPath || matchRelRefGroups`). Default assumption for fixtures with
  `flag_on: true`.
- **flag off**: `paths == null → authMatch` (groups ignored). Fixtures with
  `flag_on: false` (T19–T21).

Where the aconfig API is not directly callable, run the same physical manifest
against two builds (flag enabled/disabled) or drive `matchData` through the
flagged path with the flag toggled by the test harness. Record which method was
used next to the oracle file.

## Verdict mapping

`matchData` returns `>= 0` matching categories (`MATCH_CATEGORY_HOST/PORT/PATH/…`)
for a match and negative `NO_MATCH_*` for a rejection. Map:

- `>= 0` → `matches`
- `< 0` → `cannot_match`
- a row ASC-RS cannot decide (pattern/advanced glob, opaque URI, bound
  overflow) has no direct `matchData` answer — compare ASC-RS `unknown` to the
  oracle's deterministic answer and record the divergence as a real finding, not
  as "the oracle also says unknown".

`UriOracle` implements this mapping for the fixtures; review it against the
pinned source before trusting it.
