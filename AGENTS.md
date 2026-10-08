# Repository Guidelines

## Project Overview

**ASC-RS** is a pure-Rust port of [MG1937/ASC](https://github.com/MG1937/ASC) (oracle frozen at commit `ccc6bae`). On-demand APK/DEX analysis via CLI commands (inputs: APK or bare `.dex`):

- `findrefs string|type|method|field` — locate references in DEX bytecode.
- `getclass <descriptor>` — locate a class, rebuild a minimal standalone DEX, decompile to Java.
- `disasm <descriptor> [--method NAME]` — Smali-syntax listing of one class from the WHOLE DEX (no rebuild/closure, no Java structurer). Renderer: `asc-decompile/src/disasm.rs` (droidsaw `fmt_instruction` + 9 audited overrides, refuses malformed code); gate: `asc-decompile/tests/disasm_synthetic.rs`, differential: `tests/differential/run_disasm_diff.py` (androguard, `reference/venv`).
- `listclass`, `manifest`, `inspect`, `native`, `cert`, `resources`, `strings`, `extract`, `axml` — class list, manifest dump, inventory/packer signals, ELF/JNI inventory, signing-cert display, resources.arsc view, full DEX string-pool dump, single-entry extraction, and decoding of any compiled binary-XML entry (`--format json` on all).
- `hermes <apk>` — Hermes bytecode bundle string-table extraction (v96 only; `crates/asc-core/src/hermes.rs`; UTF-16 lengths are code units per upstream). `xapk <file>` — ZIP-of-APKs member inventory with per-member completeness (`crates/asc-core/src/xapk.rs`).

Pillars: **lazy** DEX access, **zero-copy** pools, **bounded memory**. No whole-APK preprocessing, no global xref graphs, no Python/JVM/Node at runtime. Outputs: `target/release/asc-rs.exe` (CLI) and `asc-gui.exe` (egui workbench). Oracle + spec live (read-only) under `reference/` (`BEHAVIOR.md`, `FREEZE.md`; `reference/asc/` is gitignored, never write to it).

## Architecture & Data Flow

Strict layered DAG; `asc-core` is the only fan-in node. CLI and GUI depend on `asc-core`, never on each other.

```
L0 asc-dex        zero-copy DEX 035..041 reader (only dep: thiserror)
L1 asc-apk        mmap ZIP + bounded inflate      asc-bytecode  opcode table + RefWalker
L2 asc-manifest   binary AXML                     asc-query     locators, find_refs, CodeOwners
   asc-resources  resources.arsc reader (shares asc-apk `string_pool` with asc-manifest)
   asc-rebuild    closure + remap + rewrite + layout (minimal DEX) + StringPatch
   asc-paranoid   Paranoid/LSParanoid detect + decode (opt-in `--paranoid`)
L3 asc-decompile  ClassDecompiler trait + DroidsawBackend (no internal deps: the firewall)
L4 asc-core       run_findrefs / run_getclass / WorkerPool / text+json emitters
L5 asc-cli (bin asc-rs, single main.rs)   asc-gui (bin asc-gui)
```

**findrefs:** `Apk::open` (mmap) → `dex_entries()` (numeric sort of `classes(\d*).dex`) → per DEX `DexView::parse[_at]` → `asc_query::find_refs` → `resolve_target_ids` → `CodeOwners::build` → per-`code_off` `RefWalker` → match `TargetSets` → `RefHit` → `render_hits` → `format_search_report_*`.

**getclass:** `WorkerPool` fans over `classes*.dex` (`AtomicUsize` cursor, `AtomicBool` found, `OnceLock<(String, Vec<u8>)>` winner cell) → `asc_rebuild::rebuild` → `DroidsawBackend::decompile` inside `catch_unwind`.

**GUI ingestion boundary:** the GUI never imports `asc-rebuild` or `asc-decompile` (verified by grep); engine access is only `asc_core::{run_findrefs, run_getclass, run_callees, run_class_strings}` (plus artifact loading) on `std::thread` workers.

**GUI flow:** draw fns / `frame_shortcuts` never touch the engine; they `queue(Command)`. `render.rs` drains the queue at end of frame → `AscApp::dispatch` (only mutator) → `TaskManager::spawn_*` (one thread per task, `catch_unwind`, mpsc) → next frame `poll_workers` → `apply_task`. Staleness gates: `SessionGeneration` (bumped in `apply_artifact`), `pending_open` id check for artifact loads, and activation intent held in `TabController` (a late decompile cannot steal focus). `FindRefsClass`, `Callees` and `ClassStrings` (`Command::ShowClassStrings`, ASC-RS-GUI-006) share **one references lane** (all publish into `AscApp::references` and the REFERENCES tab), so each supersedes the other and an identical live request is reused rather than queued twice; a result never moves the bottom panel while `bottom_focus_pinned` is set (the user picked a tab or toggled the panel themselves). Supersede = discard-on-arrival, not cancellation (no cancel hook in the engine). Tab keys are **view** identities (`L…;#smali`, `L…;#smali#<method>`), not class identities: every class-scoped action (references, copy descriptor/FQN, Smali, strings, re-decompile) resolves through `AscApp::active_class_descriptor` (built on `state::tabs::class_of_tab_key`), and `spawn_decompile` / `navigate_to` reject non-class keys — never hand `tabs.active_descriptor()` to the engine raw. Reloading a view whose document was evicted goes through `AscApp::reload_document` (called by `draw_code_area`), which decodes the key once via `state::tabs::smali_view_of`: a Smali view re-issues `spawn_disasm` for its owning class + method scope, a class tab a getclass job, and anything else nothing — a reload must never drop a Smali tab on the empty state (audit F2), and the per-view dedup in `TaskManager` makes the re-issue idempotent. Click selection is split into an anti-stale **document identity** (`SymbolSelection`) and a **resolved symbol** (`semantic::ResolvedSymbol`): the document key is never used as a declaration owner. `resolved_method()` yields `(declaring_class, name)` only for an actual method with a proven owner, and `ShowSmaliMethod`/`ShowCallees`/`GoToDeclaration`/`FindUsagesOfClicked` act on that owner — a `#smali` click resolves through the semantic parser (`.method`/`invoke-*`/`.field`/`L…;` targets), a local/register identifier is never dispatched as a member, and an unresolvable owner is refused rather than guessed (audit F2).

## Key Directories

| Path | Purpose |
|---|---|
| `crates/asc-{dex,bytecode,apk,manifest,query,rebuild,paranoid,decompile,core}/` | Engine layers (see DAG) |
| `crates/asc-cli/` | `asc-rs` clap binary |
| `crates/asc-gui/src/` | `app.rs` (shell + dispatch), `app/render.rs` (`eframe::App` impl), `app/tests.rs`, `command.rs`, `task.rs`, `session.rs`, `selfcheck.rs`, `state/` (documents, tabs, navigation, search), `ui/` |
| `tests/` | `differential/` runner, `fixtures/golden/` + `capture_golden.py`, `compatibility/parity_matrix.md`, `gui_features/` manifest |
| `corpus/` | **Gitignored** APK/DEX fixtures; policy + recipe in `docs/CORPUS.md`, CI recreates the public fixtures and sets `ASC_REQUIRE_CORPUS` so a missing one fails |
| `benches/` | `perf_compare.py` (perf gate), `benchmark.py`, `bench_ascrs.py` |
| `fuzz/` | **Detached workspace** (own `Cargo.lock`), 18 contract targets (+1 self-test dummy), in-tree deterministic runner (no cargo-fuzz/nightly) |
| `reference/` | Frozen oracle pin + behavior spec + `requirements-freeze.txt` |
| `scripts/build_release.py` | Byte-reproducible source ZIP + `SHA256SUMS` |
| `docs/` | GUI audit/architecture/design docs |
| `skills/` | Agent skills shipped with the tool; `skills/apk-analysis/SKILL.md` documents the `asc-rs` CLI for end users/agents |

## Development Commands

Run from the repo root.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace [--release]
cargo build --release                       # asc-rs.exe + asc-gui.exe

cargo run --release -p asc-cli -- getclass <apk> <descriptor> [-o OUT] [--threads N] [--debug]
cargo run --release -p asc-cli -- disasm <apk> <descriptor> [--method NAME] [-o OUT]
cargo run --release -p asc-cli -- findrefs <apk> string|type <substr> [--format text|json]
cargo run --release -p asc-cli -- findrefs <apk> method|field [name] [--class X [--fuzzy-class]]

cargo run --release -p asc-gui -- <apk>               # open artifact
cargo run --release -p asc-gui -- --selfcheck <apk>   # headless smoke
ASC_GUI_SHOTS=1 cargo test -p asc-gui --lib visual_shots

python tests/differential/run_differential.py target/release/asc-rs.exe [--strict]
python benches/perf_compare.py --selftest | --samples 31
cargo run --release -p asc-core --example profile_findrefs
cargo bench -p asc-decompile --bench decompile_bench
python scripts/build_release.py v0.2.0 --output dist
```

CLI flags are `#[arg(global = true)]` (`SharedFlags`), valid before or after the APK. Exit codes: `0` ok, `1` not-found / invalid input, `2` engine error; `findrefs` with any per-DEX scan failure prints all found hits + stderr warnings and exits `2` (`crates/asc-cli/src/main.rs`).

Fuzz (from `fuzz/`): `cargo run --release --bin fuzz-runner -- --list`; `./run.sh <target> [sec] [features]` (or `.\run.ps1 -Target <t> [-Features all]`); `--regress regress` replays committed fixtures (per-target `<target>-<fnv1a>.bin` filtering; SKIP+0 when a target has none). Features `dex|bytecode|apk|rebuild|resources|core|decompile|manifest|all` are OFF by default → targets report `SkippedDisabled`; CI's `fuzz` job runs `cargo test --features all` (registry tests prove parsers engaged) plus a 10 s-per-target smoke loop and crash-regression replay.

## Code Conventions & Common Patterns

- **Rust 2024, MSRV 1.95, resolver 3.** 1.95 (not lower) is forced by the egui 0.36 stack, which declares `rust-version = 1.95` in its manifests — check with `cargo metadata --format-version 1` before claiming an older floor, and confirm a floor change with a real toolchain (verified 2026-10-07: this workspace checks clean on 1.95.0). No `rust-toolchain.toml`/`rustfmt.toml`/`clippy.toml`: cargo defaults. CI runs the `lint-build-test` lane on the latest `stable` (so a new compiler/clippy lint surfaces there), a separate `msrv` lane pinned to `1.95.0` (`cargo check --workspace --all-targets --all-features`), and `release.yml` pins `1.97.1` for reproducible release binaries; local rustc may therefore drift from all of them. Deps inherit via `.workspace = true`; `droidsaw-dex`, `eframe`/`egui_kittest` 0.36, `parking_lot`, `rfd` are intentionally crate-local (do not hoist into `[workspace.dependencies]`). `asc-manifest` uses a literal path to `asc-apk` (only exception). All GitHub Actions are pinned to full commit SHAs with a version comment (`.github/workflows/*.yml`); `dtolnay/rust-toolchain` is pinned at the SHA of its `stable` branch and therefore always sets `with: toolchain:` explicitly (the ref is a SHA, so the action cannot read a version from it).
- **Errors:** one `thiserror` enum per crate (`DexError`, `ApkError`, `BytecodeError`, `RebuildError`, …); `CoreError` (`asc-core/src/pipeline.rs`) is hand-rolled composition. `DexError` derives `Eq`, handy in tests.
- **Untrusted-input discipline:** all fixed-width reads go through `asc-dex/src/read.rs` → `DexError::Truncated`; pool extents validated once (`pools::check_pool`); hard caps: MUTF-8 1 MiB scan, encoded-value depth 64, LEB 5/10 bytes, inflate 1 GiB. Inflation itself is capped by the *declared* size: `inflate_into_vec` is never asked to produce more than `declared + 1` bytes, so a lying central-directory size cannot buy uncharged work from any caller that reserves the declared size (`asc_core::budget`, `asc_core::xapk`). New parsing code must use these helpers and keep such bounds.
- **Pool indexes** are `#[repr(transparent)]` newtypes (`StringIdx`, `TypeIdx`, …), `NO_INDEX = 0xFFFF_FFFF` (`asc-dex/src/ids.rs`). `asc-bytecode` holds a *verbatim copy* (`dex_ids`) rather than a re-export — do not "fix" casually.
- **`unsafe`:** only in `asc-apk` (`Mmap::map`, `Send/Sync` impls). `#![deny(unsafe_op_in_unsafe_fn)]` in dex/bytecode/core; `#![forbid(unsafe_code)]` in `asc-decompile`. `RefWalker` indexing relies on an opcode-table invariant (`opcode.rs read_index`).
- **Panic safety:** `panic = "unwind"` in the release profile on purpose — `droidsaw-dex` calls (`asc-decompile/src/droidsaw.rs`) and GUI worker threads (`task.rs`) run under `catch_unwind`. Never switch to `abort`.
- **No async, no builders, no DI framework.** Threads: hand-rolled pool (`asc-core/src/worker.rs`, deliberately not rayon; `rayon` is in the workspace only for criterion). One public trait: `ClassDecompiler: Send + Sync`.
- **State:** `AscApp` owns plain UI-thread data; only `WorkspaceSession` holds `parking_lot::Mutex` (class cache, findrefs history). Documents are `Arc<Document>` in a byte-budgeted LRU (`state/documents.rs`). Theme is a global `AtomicU8`. Rename (`n`) / comment (`;`) are per-tab scratchpads, intentionally not persisted.
- **Memoization:** `WorkspaceSession::classes_for_dex` lazy; `DroidsawBackend` 16-entry FIFO parse cache keyed by `crc32fast::hash(dex_bytes)`; `static OPCODE_TABLE` from `const fn build_table()`.
- **Naming:** `PascalCase` types, `snake_case` fns, `SCREAMING_SNAKE` consts. Block GUI features that lack engine data (Smali, CFG, call graphs); never approximate them.
- **Intent-filter URI semantics (`asc-manifest`):** keep the raw `<data>` list and the pooled `EffectiveData` apart, and model the cross-dimension **dependency** rather than a plain cross product: Android ignores hosts/ports/paths when the filter declares no `scheme` anywhere, and ports/paths when it declares no `host` (`UriDependency::{Complete,NoScheme,NoHost}`, `EffectiveData::effective_authorities` / `effective_paths`; AOSP `IntentFilter.matchData` nests the authority loop inside `schemes != null` and the path loop inside the authority branch). A `mimeType`-only filter implicitly matches `content:`/`file:` (`EffectiveData::implicit_schemes`). Declared-but-inert attributes stay in the output and are labelled `ignored` — never dropped, never presented as reachable. API 35 `<uri-relative-filter-group>` is parsed verbatim into `IntentFilter::uri_relative_groups` and **not** evaluated (ANDed children, allow/deny order, sibling-`<data>` precedence): every renderer that prints a filter must say so when `has_uri_relative_groups()` is true.
- **Files:** working copies are CRLF on Windows (autocrlf); LF/CRLF warnings are harmless. New files should match.

## Important Files

- Workspace: `Cargo.toml` (release: `lto="thin"`, `codegen-units=1`, `strip="debuginfo"`), `Cargo.lock` (only pin of `droidsaw-dex 2.0.0`), `.gitignore`, `.github/workflows/{ci,release}.yml`.
- Engine entry points: `asc-core/src/pipeline.rs` (`run_findrefs` ~199, `run_getclass` ~535, winner cell ~563), `asc-core/src/worker.rs`, `asc-core/src/format.rs`, `asc-query/src/scan.rs` (`TargetSets` ~34, `find_refs` ~160), `asc-dex/src/view.rs` (`DexView`, DEX-041 logical offsets), `asc-apk/src/apk.rs` (`Apk::open`, `dex_entries`), `asc-rebuild/src/lib.rs` (`rebuild`), `asc-decompile/BACKENDS.md` (backend verdicts).
- Frontends: `asc-cli/src/main.rs`, `asc-gui/src/{main,lib,app,task,session,selfcheck}.rs`, `asc-gui/build.rs` (Windows icon).
- Contracts: `reference/BEHAVIOR.md`, `reference/FREEZE.md`, `tests/compatibility/parity_matrix.md`, `crates/asc-query/GOLDEN_DIVERGENCES.md`, `docs/CORPUS.md`.
- Line numbers drift; grep the symbol before relying on them.

## Runtime/Tooling Preferences

- **Cargo only** (no Makefile/just/nix). Python is used solely for the oracle, differential, perf, golden capture and release packaging; use `reference/venv/Scripts/python.exe` for oracle-touching scripts. No global installs.
- **CI** (`ci.yml`): push/PR on `master` + manual; matrix `ubuntu-22.04` and `windows-2022`, each running the whole gate. It rebuilds `corpus/` first, then gates in order: fmt → clippy → `cargo test --workspace` (debug, with `ASC_REQUIRE_CORPUS=aurora,fdroid,workload` and `ASC_GUI_SHOTS=1`) → `build --release` → `asc-gui --selfcheck corpus/apk/workload.apk` → differential parity → `perf_compare --selftest` → upload binaries. Two more jobs: `fuzz` (registry tests + 10 s smoke + crash-regression replay) and `msrv` (pinned 1.95.0, `cargo check --workspace --all-targets --all-features` — the declared floor, no corpus/GPU needed). `release.yml` (tags `v*`) reruns the same gates minus perf with the same two test env vars, on a **pinned** toolchain (1.97.1) so release binaries are reproducible; workflow permissions are `contents: read` with `contents: write` granted only to the `publish` job. `deny.yml` is a separate, read-only workflow: `cargo-deny check` against `deny.toml` (advisories/licenses/bans/sources) on push/PR plus a weekly schedule, deliberately not part of `ci.yml` because it needs the network (RustSec DB) and an upstream outage must not block the build gates.
- **Release ZIP** packs only git-tracked `Cargo.toml, Cargo.lock, README.md, .gitignore, LICENSE, NOTICE, crates, tests, benches, fuzz, docs, seeds, skills`; not `reference/`, `scripts/`, `.github/`, `deny.toml`, `AGENTS.md`. Deterministic (fixed 1980 timestamp, DEFLATED, mode 0o100644).
- GUI is eframe/egui (glow). The agent is headless: GUI changes end with a hand-visual repro handed to the user.
- **Skills stay in sync with features.** Any change that adds or alters user-visible behavior (new CLI subcommand/flag, output format, exit code, new tolerance/limitation, GUI capability) MUST update the matching skill in the same change — `skills/apk-analysis/SKILL.md` for `asc-rs` CLI behavior. Update the command list, "Choosing the command" table, Output notes, and Pitfalls as applicable; document only verified behavior. A feature is not done until its skill reflects it.
- **Versioning:** the agent decides version bumps autonomously when a change adds meaningful user-visible value (new subcommand/flag, GUI capability, notable perf/robustness gain). Bump the `version` in the root `Cargo.toml` (workspace `[workspace.package]`) in the same change: patch for fixes/refactors, minor for new features, major for breaking CLI/output changes. Pure internal refactors and docs do not bump. No release tag is created unless the user asks.
- **No library API is published or supported.** The workspace ships two binaries (`asc-rs`, `asc-gui`) plus a source ZIP; the `crates/*` are internal layers of those binaries, not a library anyone consumes. `[workspace.package] publish = false` (inherited by every crate via `publish.workspace = true`) encodes that, and `cargo publish` refuses. Consequences: adding a variant to a public enum, adding a field to a public struct, or changing a public signature is **not** a SemVer event and needs no minor/major bump — version the *user-visible* behavior (CLI/GUI/output), which is what the rule above means. If the crates ever become a supported dependency, that decision must land with real SemVer bookkeeping (versioned path deps, `#[non_exhaustive]` on new public enums), not by quietly re-reading this rule.

## Testing & QA

Standard `#[test]` + criterion (one `[[bench]]`: `asc-decompile`). No proptest/quickcheck. Baseline as of this commit: **682 passed** workspace-wide under the CI configuration (`ASC_REQUIRE_CORPUS=aurora,fdroid,workload ASC_GUI_SHOTS=1`; 679 tests + 3 doctests); asc-gui 188 unit + 4 integration. Must not regress. Without those two variables the corpus/render-dependent tests self-skip, so a locally green run proves less and the count is lower.

- **Corpus-free suites (trust these):** `asc-dex/tests/{tiny_dex,container_041}.rs` (byte-level builder in `tests/common/mod.rs`), `asc-bytecode/tests`, `asc-apk/tests/integration.rs` (`ZipBuilder`: STORED/DEFLATE/ZIP64/CRC/zip-bomb), `asc-query/tests/synthetic.rs` (programmable DEX `Builder`), asc-manifest synthetic blobs. Test builders are duplicated per crate (`tests/common/mod.rs`); no shared test-utils crate.
- **Corpus-dependent tests skip silently by default; with `ASC_REQUIRE_CORPUS=<names>` set (CI sets `aurora,fdroid,workload`), a listed fixture that is missing FAILS instead of skipping.** The fail-loud guard is implemented in the golden-parity suite (`asc-query/tests/golden.rs`) and 6 others (`asc-cli/tests/new_commands.rs`, `asc-core/tests/{cert_inventory,integration_gate,resources_corpus}.rs`, `asc-gui/src/app/tests.rs`, `asc-manifest/src/tests.rs`); the remaining corpus suites (`asc-query/tests/common`, `asc-dex/tests/corpus_smoke.rs`, `asc-decompile/tests/integration.rs`, `asc-core/tests/{disasm_corpus,p3_diagnostics,inspect_synthetic}.rs`) still skip unconditionally, so a green `cargo test` without `corpus/{apk,dex}` proves little there; check test output for "skipping" lines. Always resolve fixtures via `env!("CARGO_MANIFEST_DIR")/../../corpus/...`: cargo runs tests with cwd = the crate dir, so a bare `"corpus/..."` path can never resolve.
- **Golden parity:** `asc-query/tests/golden.rs` vs `tests/fixtures/golden/*.counts.json` (generated by `capture_golden.py`; never hand-edit `cases.json`). Divergence allowlist = `GOLDEN_DIVERGENCES.md` + `divergence_verification.rs` (2 accepted cases; the test panics if a divergence disappears — update the allowlist then). Engine may be a strict *superset* of the oracle (oracle ⊆ engine), never miss its hits.
- **Differential:** `run_differential.py` compares findrefs as output-line *sets* and getclass structurally (`--strict` = byte-exact); expected 12/12 PASS; `--selftest` for the harness itself. Adding a case: follow the recipe in `tests/compatibility/parity_matrix.md`.
- **End-to-end gate:** `asc-core/tests/integration_gate.rs` (≥500 code items, ≥1000 hits on `workload.apk`; aurora multidex).
- **GUI:** headless via `egui::Context` + `eframe::Frame::_new_kittest()` (`AscApp::test_frame`, `run_ui`, `from_session`, `last_clipboard`); controllers under `state/` are unit-tested without a window. `tests/gui_features/feature_manifest.json` maps features to acceptance test paths; `score.py` counts a feature only if its test passed. `visual_shots`, `glyph_pixel_audit`, etc. need `ASC_GUI_SHOTS=1` (CI sets it for `cargo test --workspace`; unset, they print "skipping" and pass vacuously).
- **Perf gate:** `benches/perf_compare.py` — paired one-sided sign test, Bonferroni, ≥3% median floor, `MIN_SAMPLES=15`.
- **Fuzz:** `fuzz/tests/registry.rs` pins contract targets to `SkippedDisabled` with default features; enabling a feature requires updating it. Green = runner exit 0; crashes land in `crashes/<target>-<fnv1a>.bin`, replay with `--regress`.

**Required gates:** fmt → clippy `-D warnings` → `cargo test --workspace` → `cargo build --release` → `asc-gui --selfcheck corpus/apk/workload.apk` → `perf_compare --selftest` → (GUI changes) hand-visual repro → (user-visible changes) matching `skills/` update.
