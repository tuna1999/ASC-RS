# Corpus fixtures

The `corpus/` tree is gitignored. CI recreates the **public** fixtures below
on every run; the dev-only fixtures exist only on machines that downloaded
them manually. A test whose fixture is missing skips silently — set
`ASC_REQUIRE_CORPUS=<names>` (comma-separated basenames, prefix match) to
make a listed-but-missing fixture **fail** instead. CI sets
`ASC_REQUIRE_CORPUS=aurora,fdroid,workload` for `cargo test`, so a broken
download or extraction step turns into test failures, not green skips.

## Public fixtures (CI recreates these — never edit by hand)

| Fixture | Source |
|---|---|
| `corpus/apk/com.aurora.store_60.apk` | F-Droid repo (`https://f-droid.org/repo/com.aurora.store_60.apk`) |
| `corpus/apk/org.fdroid.fdroid_1016000.apk` | F-Droid repo (`https://f-droid.org/repo/org.fdroid.fdroid_1016000.apk`) |
| `corpus/apk/workload.apk` | Deterministic STORED ZIP wrapping the `classes.dex` from `MG1937/asc @ ccc6bae` `tests/fixtures/reference-workload.zip` (see `reference/FREEZE.md`, `.github/workflows/ci.yml`) |
| `corpus/dex/workload_classes.dex` | Same `classes.dex` as above |
| `corpus/dex/aurora_classes*.dex`, `corpus/dex/fdroid_classes*.dex` | Extracted from the two APKs above |

Recreate locally with the exact steps in `.github/workflows/ci.yml`
(steps "Download corpus APKs", "Build workload.apk from frozen oracle",
"Extract DEX fixtures").

## Dev-only fixtures (never in CI — do not distribute)

| Fixture | Purpose of the tests that need it |
|---|---|
| `corpus/apk/com.locket.Locket.apk` | Split-APK markers (`base__abi,base__density`), Hermes bundle v96, exact native-method counts (447/174), P3 structurer diagnostics (BACKENDS.md §11), v2/v3-only signing shape |
| `corpus/apk/Locket Widget_1.216.0_APKPure.xapk` | Nested-ZIP (XAPK) split path: inner `config.arm64_v8a.apk`, split manifest markers |

These skip silently everywhere; a green CI proves nothing about them.
When a test here regresses, it regresses only on dev machines — run
`cargo test --workspace` locally with the fixtures present before shipping.

## Policy

1. **Synthetic tests are mandatory** — they build their inputs from bytes
   and must never skip.
2. **Public-corpus tests fail in CI when their fixture is missing**
   (`ASC_REQUIRE_CORPUS`).
3. **Dev-only tests skip by design.** Prefer promoting a dev-only shape to
   a synthetic fixture (builders exist for DEX, AXML, ZIP, signing blocks)
   before adding new dev-only coverage.
