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

## Status (2026-10-12, v0.19.2 follow-up — EXECUTION VERIFIED)

| | |
|---|---|
| Source revision | `android-15.0.0_r1` (Android 15 / API 35), flags-frozen |
| ASC-RS side | `tests/differential/run_uri_oracle.py` + `asc-manifest/examples/eval_uri.rs` — **runnable, green vs `source_expected`** |
| Oracle side | Gradle + Robolectric project below — **COMPILES and RUNS** against the real framework on this machine (JDK 17.0.20.1 + Gradle 8.10.2, both portable/local; the build classpath was corrected, see build.gradle) |
| Framework artifact | `org.robolectric:android-all-instrumented:15-robolectric-12650502-i7` (verified present in the jar; records in `provenance.framework_artifact`) |
| Observed flag state | `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS` = **ON** (read at runtime from the relocated `android.content.pm.Flags`, recorded in `provenance.flag_state_actual`) |
| Result | 51 cases: **36 ORACLE-CONFIRMED, 12 ORACLE-OPEN, 3 UNVERIFIED(FLAG)**, 0 mismatches. Exit 0. |

Run (real, this machine):
```
python tests/differential/run_uri_oracle.py --oracle reference/oracle/uri_match/build/oracle_verdicts.json
```
```
51 cases; 0 source-mismatches; 0 oracle-mismatches.
36 ORACLE-CONFIRMED; 12 ORACLE-OPEN (asc-rs `unknown` surfaced); 3 UNVERIFIED (flag-state not exercisable in this build).
```

The **flag-OFF** state (fixtures `T19`–`T21`) is NOT reproducible with any
published Robolectric android-all: the android-all build freezes the aconfig
flag at the AOSP default (`ON`), and Robolectric publishes exactly one
android-all per SDK. Exercising OFF would require a maintainer-built android-all
with the flag disabled. Those 3 rows are therefore reported `UNVERIFIED(FLAG)`,
never confirmed. This is the honest, intended outcome (README "Flag handling").

No Android-equivalence claim is made for the 12 ORACLE-OPEN rows (asc-rs
deliberately returns `unknown` for glob/advanced-pattern/opaque/bound-overflow
inputs whose AOSP branch asc-rs does not model). The harness reports them as
open findings — a possible future engine improvement — never as oracle
agreement. A genuine `SOURCE-MISMATCH` / `ORACLE-MISMATCH` only appears when a
real divergence exists.

## Layout

```
reference/oracle/uri_match/
  settings.gradle, build.gradle, gradle.properties   # Gradle + Robolectric
  src/test/java/us/ascrs/urioracle/UriOracle.java    # the Robolectric test
```

The fixture is read **straight from the repo** via `-Duri.fixtures` (set in
`build.gradle`) — there is no copy to drift. The output is written to
`build/oracle_verdicts.json` (`-Duri.oracle.out`).

## Prerequisites (verified on this machine, 2026-10-12)

- JDK 17+ (Temurin 17.0.20.1, installed portable and local — not a global install)
- Gradle 8.x (Gradle 8.10.2, local)
- Network to Maven Central / Google Maven (Robolectric resolves
  `android-all-instrumented` and the androidx.test AAR at build/test time;
  ~200 MB first download, cached in the Gradle user home)
- A verified way to control `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS` (below)

These were installed and the full pipeline run for real on 2026-10-12: see
"Status". The `build.gradle` was corrected from the earlier un-proven draft —
it now compiles and runs (plain-`java` AAR handling, android-all compile
classpath, relocated hidden `Flags` API — see the header comment in
`build.gradle`).

## Reproducibility recipe

1. **asc-rs verdicts** (runs here, no Android needed):
   ```
   python tests/differential/run_uri_oracle.py          # regression vs source_expected
   ```
2. **Oracle verdicts** (run here; JDK + Gradle installed locally):
   ```
   cd reference/oracle/uri_match
   URI_FLAG_MECHANISM="android-all:15-robolectric-12650502 frozen aconfig default" \
     gradle test --tests '*.UriOracle'         # writes build/oracle_verdicts.json
   # or, if a wrapper was generated: ./gradlew test --tests '*.UriOracle'
   # Without URI_FLAG_MECHANISM the file is marked UNVERIFIED_SKIPPED and the
   # runner rejects it (a real flag mechanism must be asserted).
   ```
3. **Diff** (ASC-RS vs source_expected AND vs the framework oracle):
   ```
   python tests/differential/run_uri_oracle.py --oracle reference/oracle/uri_match/build/oracle_verdicts.json
   ```
   Exit 0 only when every ASC-RS verdict equals `source_expected` and the
   oracle for every case the oracle actually exercised. Any divergence is a
   real finding to fix or re-classify.

## Flag handling

`IntentFilter.matchData` consults
`Flags.relativeReferenceIntentFilters()` (a `android.content.pm.Flags`
aconfig-generated method; in the Robolectric android-all build the class is a
hidden API relocated to
`com.android.internal.hidden_from_bootclasspath.android.content.pm.Flags`, and
`UriOracle` imports it from there). In the framework build that frozen aconfig
flag gates the group branch of `matchData`. The two states must each be
exercised:

- **flag on**: the group-aware branch (`paths==null && groups==null → authMatch`,
  else `hasDataPath || matchRelRefGroups`). Default assumption for fixtures
  with `flag_on: true`.
- **flag off**: `paths == null → authMatch` (groups ignored). Fixtures with
  `flag_on: false` (T19–T21).

**The flag is NOT runtime-toggleable from Robolectric.** It is frozen at
framework build time. `UriOracle` therefore does **not** assume which state it
is in — it **reads the actual state** via
`Flags.relativeReferenceIntentFilters()` and records it as
`provenance.flag_state_actual`:

- A case whose required `flag_on` equals `flag_state_actual` is exercised and
  a verdict is emitted.
- Every other case (required state ≠ this build's state) is added to
  `provenance.flag_skipped` and **no verdict is emitted** — the runner reports
  it `UNVERIFIED(FLAG)`, never confirmed.
- If the flag state cannot be read at all, `UriOracle` **fails closed**: the
  JUnit test throws, no verdicts are written, and `status` is
  `UNVERIFIED_SKIPPED`.

The runner (`validate_oracle_coverage`) enforces an exact bijection and exits 1
on any violation — it never silently ignores a malformed report:

- every EXERCISABLE case (required flag == actual) must have a valid verdict and
  must NOT be in `flag_skipped` (an exercisable case in `flag_skipped` is a
  dropped result);
- every flag-MISMATCHED case must be in `flag_skipped` and must NOT have a
  verdict (a verdict on such a case is a wrong-flag result);
- every `flag_skipped` id must be a real fixture case and must be
  flag-mismatched;
- every verdict id must be a fixture case and must not also be in
  `flag_skipped`; an id in `oracle` that is not a fixture case is rejected.

`provenance.flag_mechanism` (from `-Duri.flag.mechanism`, env
`URI_FLAG_MECHANISM`) records *how* that build's flag state was established
(here: the frozen aconfig default of the pinned android-all artifact, with the
observed state read at runtime). A file whose `flag_mechanism` is `UNKNOWN`,
whose `status` is `UNVERIFIED_SKIPPED`, which omits `flag_state_actual`, or
which lacks a real `framework_artifact` / `api_level_observed` is **rejected by
the runner** — it can never produce `ORACLE-CONFIRMED`.

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

## Next roadmap phase — aapt2-compiled manifest fixtures (BEGINNED 2026-10-12)

The framework side is now reproducible, so the parity work moves to real
binary manifests. The pipeline was PROVEN end-to-end this session:

1. **Compile a real API-35 binary manifest with aapt2** (aapt2 2.20 (9.4.1),
   `-I android-35/android.jar` from Google's `platform-35_r02`):
   ```
   aapt2 link -I <platform-35>/android.jar \
     --manifest AndroidManifest.xml --min-sdk-version 35 --target-sdk-version 35 \
     -o out.apk
   ```
   `<uri-relative-filter-group android:allow="true">` with
   `pathPrefix`/`queryPrefix` (etc.) `<data>` children compiles into the binary
   AXML verbatim (verified with `aapt2 dump xmltree`).

2. **ASC-RS parses and evaluates it**: `asc-rs manifest out.apk --match-uri <uri>`
   decodes the group to `(path,prefix,/a) (query,prefix,token=)` `allow=true`
   and produces a three-valued verdict. A smoke check on a scheme/host +
   `uri-relative-filter-group` filter agreed with the framework oracle
   semantics: `https://example.com/a/b?token=1` → `matches`,
   `…/x?token=1` → `cannot match` (path prefix missed), `https://other.com/…` →
   `cannot match` (R4 host).

**Remaining phase work (a proper harness, needs its own task/spec):**

- a fixture generator that maps `tests/fixtures/uri_match_cases.json` →
  `<uri-relative-filter-group>` manifest XML → aapt2 link → a minimal APK per
  case (only the binary `AndroidManifest.xml` and a stub `classes.dex` are
  needed for `manifest`).
- a comparison driver: `asc-rs manifest <apk> --match-uri <uri>` vs the
  framework oracle verdict for the SAME filter (the oracle currently consumes
  the fixture JSON; it needs an APK-derived-filter entry point or a parallel
  JSON producer).
- honour the flag-state caveat: this aapt2/android.jar path does not change
  the aconfig flag (frozen ON here); flag-off parity stays `UNVERIFIED(FLAG)`
  exactly as the framework oracle.
- the external tools are NOT vendored: aapt2 + `platform-35`/`android.jar`
  (and JDK/Gradle) are local prerequisites. Do not pin them into the repo.
