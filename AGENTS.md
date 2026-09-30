# Repository Guidelines

## Project Overview

**ASC-RS** is a pure-Rust port of [MG1937/ASC](https://github.com/MG1937/ASC) (oracle frozen at commit `ccc6bae`). On-demand APK/DEX analysis via CLI commands (inputs: APK or bare `.dex`):

- `findrefs string|type|method|field` — locate references in DEX bytecode.
- `getclass <descriptor>` — locate a class, rebuild a minimal standalone DEX, decompile to Java.
- `listclass`, `manifest`, `inspect`, `native`, `cert` — class list, manifest dump, inventory/packer signals, ELF/JNI inventory, signing-cert display (`--format json` on all).

Pillars: **lazy** DEX access, **zero-copy** pools, **bounded memory**. No whole-APK preprocessing, no global xref graphs, no Python/JVM/Node at runtime. Outputs: `target/release/asc-rs.exe` (CLI) and `asc-gui.exe` (egui workbench). Oracle + spec live (read-only) under `reference/` (`BEHAVIOR.md`, `FREEZE.md`; `reference/asc/` is gitignored, never write to it).

## Architecture & Data Flow

Strict layered DAG; `asc-core` is the only fan-in node. CLI and GUI depend on `asc-core`, never on each other.

```
L0 asc-dex        zero-copy DEX 035..041 reader (only dep: thiserror)
L1 asc-apk        mmap ZIP + bounded inflate      asc-bytecode  opcode table + RefWalker
L2 asc-manifest   binary AXML                     asc-query     locators, find_refs, CodeOwners
   asc-rebuild    closure + remap + rewrite + layout (minimal DEX) + StringPatch
   asc-paranoid   Paranoid/LSParanoid detect + decode (opt-in `--paranoid`)
L3 asc-decompile  ClassDecompiler trait + DroidsawBackend (no internal deps: the firewall)
L4 asc-core       run_findrefs / run_getclass / WorkerPool / text+json emitters
L5 asc-cli (bin asc-rs, single main.rs)   asc-gui (bin asc-gui)
```

**findrefs:** `Apk::open` (mmap) → `dex_entries()` (numeric sort of `classes(\d*).dex`) → per DEX `DexView::parse[_at]` → `asc_query::find_refs` → `resolve_target_ids` → `CodeOwners::build` → per-`code_off` `RefWalker` → match `TargetSets` → `RefHit` → `render_hits` → `format_search_report_*`.

**getclass:** `WorkerPool` fans over `classes*.dex` (`AtomicUsize` cursor, `AtomicBool` found, `OnceLock<(String, Vec<u8>)>` winner cell) → `asc_rebuild::rebuild` → `DroidsawBackend::decompile` inside `catch_unwind`.

**GUI ingestion boundary:** the GUI never imports `asc-rebuild` or `asc-decompile` (verified by grep); engine access is only `asc_core::{run_findrefs, run_getclass}` on `std::thread` workers.

**GUI flow:** draw fns / `frame_shortcuts` never touch the engine; they `queue(Command)`. `render.rs` drains the queue at end of frame → `AscApp::dispatch` (only mutator) → `TaskManager::spawn_*` (one thread per task, `catch_unwind`, mpsc) → next frame `poll_workers` → `apply_task`. Staleness gates: `SessionGeneration` (bumped in `apply_artifact`), `pending_open` id check for artifact loads, and activation intent held in `TabController` (a late decompile cannot steal focus). Supersede = discard-on-arrival, not cancellation (no cancel hook in the engine).

## Key Directories

| Path | Purpose |
|---|---|
| `crates/asc-{dex,bytecode,apk,manifest,query,rebuild,paranoid,decompile,core}/` | Engine layers (see DAG) |
| `crates/asc-cli/` | `asc-rs` clap binary |
| `crates/asc-gui/src/` | `app.rs` (shell + dispatch), `app/render.rs` (`eframe::App` impl), `app/tests.rs`, `command.rs`, `task.rs`, `session.rs`, `selfcheck.rs`, `state/` (documents, tabs, navigation, search), `ui/` |
| `tests/` | `differential/` runner, `fixtures/golden/` + `capture_golden.py`, `compatibility/parity_matrix.md`, `gui_features/` manifest |
| `corpus/` | **Gitignored** APK/DEX fixtures; recipe in `corpus/MANIFEST.md`, CI recreates them |
| `benches/` | `perf_compare.py` (perf gate), `benchmark.py`, `bench_ascrs.py` |
| `fuzz/` | **Detached workspace** (own `Cargo.lock`), 12 targets, in-tree deterministic runner (no cargo-fuzz/nightly) |
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

CLI flags are `#[arg(global = true)]` (`SharedFlags`), valid before or after the APK. Exit codes: `0` ok, `1` not-found, `2` engine error (`crates/asc-cli/src/main.rs:32-55`).

Fuzz (from `fuzz/`): `cargo run --release --bin fuzz-runner -- --list`; `./run.sh <target> [sec]` (or `.\run.ps1 -Target <t>`). Features `dex|bytecode|apk|rebuild|all` are OFF by default → targets report `SkippedDisabled`; `run.sh` does not pass `--features`.

## Code Conventions & Common Patterns

- **Rust 2024, MSRV 1.93, resolver 3.** No `rust-toolchain.toml`/`rustfmt.toml`/`clippy.toml`: cargo defaults; CI uses `stable`, so local rustc may drift. Deps inherit via `.workspace = true`; `droidsaw-dex`, `eframe`/`egui_kittest` 0.36, `parking_lot`, `rfd` are intentionally crate-local (do not hoist into `[workspace.dependencies]`). `asc-manifest` uses a literal path to `asc-apk` (only exception).
- **Errors:** one `thiserror` enum per crate (`DexError`, `ApkError`, `BytecodeError`, `RebuildError`, …); `CoreError` (`asc-core/src/pipeline.rs`) is hand-rolled composition. `DexError` derives `Eq`, handy in tests.
- **Untrusted-input discipline:** all fixed-width reads go through `asc-dex/src/read.rs` → `DexError::Truncated`; pool extents validated once (`pools::check_pool`); hard caps: MUTF-8 1 MiB scan, encoded-value depth 64, LEB 5/10 bytes, inflate 1 GiB. New parsing code must use these helpers and keep such bounds.
- **Pool indexes** are `#[repr(transparent)]` newtypes (`StringIdx`, `TypeIdx`, …), `NO_INDEX = 0xFFFF_FFFF` (`asc-dex/src/ids.rs`). `asc-bytecode` holds a *verbatim copy* (`dex_ids`) rather than a re-export — do not "fix" casually.
- **`unsafe`:** only in `asc-apk` (`Mmap::map`, `Send/Sync` impls). `#![deny(unsafe_op_in_unsafe_fn)]` in dex/bytecode/core; `#![forbid(unsafe_code)]` in `asc-decompile`. `RefWalker` indexing relies on an opcode-table invariant (`opcode.rs read_index`).
- **Panic safety:** `panic = "unwind"` in the release profile on purpose — `droidsaw-dex` calls (`asc-decompile/src/droidsaw.rs`) and GUI worker threads (`task.rs`) run under `catch_unwind`. Never switch to `abort`.
- **No async, no builders, no DI framework.** Threads: hand-rolled pool (`asc-core/src/worker.rs`, deliberately not rayon; `rayon` is in the workspace only for criterion). One public trait: `ClassDecompiler: Send + Sync`.
- **State:** `AscApp` owns plain UI-thread data; only `WorkspaceSession` holds `parking_lot::Mutex` (class cache, findrefs history). Documents are `Arc<Document>` in a byte-budgeted LRU (`state/documents.rs`). Theme is a global `AtomicU8`. Rename (`n`) / comment (`;`) are per-tab scratchpads, intentionally not persisted.
- **Memoization:** `WorkspaceSession::classes_for_dex` lazy; `DroidsawBackend` 16-entry FIFO parse cache keyed by `crc32fast::hash(dex_bytes)`; `static OPCODE_TABLE` from `const fn build_table()`.
- **Naming:** `PascalCase` types, `snake_case` fns, `SCREAMING_SNAKE` consts. Block GUI features that lack engine data (Smali, CFG, call graphs); never approximate them.
- **Files:** working copies are CRLF on Windows (autocrlf); LF/CRLF warnings are harmless. New files should match.

## Important Files

- Workspace: `Cargo.toml` (release: `lto="thin"`, `codegen-units=1`, `strip="debuginfo"`), `Cargo.lock` (only pin of `droidsaw-dex 2.0.0`), `.gitignore`, `.github/workflows/{ci,release}.yml`.
- Engine entry points: `asc-core/src/pipeline.rs` (`run_findrefs` ~199, `run_getclass` ~535, winner cell ~563), `asc-core/src/worker.rs`, `asc-core/src/format.rs`, `asc-query/src/scan.rs` (`TargetSets` ~34, `find_refs` ~160), `asc-dex/src/view.rs` (`DexView`, DEX-041 logical offsets), `asc-apk/src/apk.rs` (`Apk::open`, `dex_entries`), `asc-rebuild/src/lib.rs` (`rebuild`), `asc-decompile/BACKENDS.md` (backend verdicts).
- Frontends: `asc-cli/src/main.rs`, `asc-gui/src/{main,lib,app,task,session,selfcheck}.rs`, `asc-gui/build.rs` (Windows icon).
- Contracts: `reference/BEHAVIOR.md`, `reference/FREEZE.md`, `tests/compatibility/parity_matrix.md`, `crates/asc-query/GOLDEN_DIVERGENCES.md`, `corpus/MANIFEST.md`.
- Line numbers drift; grep the symbol before relying on them.

## Runtime/Tooling Preferences

- **Cargo only** (no Makefile/just/nix). Python is used solely for the oracle, differential, perf, golden capture and release packaging; use `reference/venv/Scripts/python.exe` for oracle-touching scripts. No global installs.
- **CI** (`ci.yml`): push/PR on `master` + manual; matrix `ubuntu-22.04` and `windows-2022`. It rebuilds `corpus/` first, then gates in order: fmt → clippy → `cargo test --workspace` (debug) → `build --release` → `asc-gui --selfcheck corpus/apk/workload.apk` → differential parity → `perf_compare --selftest` → upload binaries. `release.yml` (tags `v*`) reruns gates minus perf, then packages binaries + source ZIP + `SHA256SUMS`. Known stale comments in `ci.yml` (~L41-43 mention rust 1.85 / droidsaw 1.0.0) and `fuzz/Cargo.toml` MSRV 1.85.
- **Release ZIP** packs only git-tracked `Cargo.toml, Cargo.lock, README.md, .gitignore, crates, tests, benches, fuzz, docs, seeds`; not `reference/`, `scripts/`, `AGENTS.md`. Deterministic (fixed 1980 timestamp, DEFLATED, mode 0o100644).
- GUI is eframe/egui (glow). The agent is headless: GUI changes end with a hand-visual repro handed to the user.
- **Skills stay in sync with features.** Any change that adds or alters user-visible behavior (new CLI subcommand/flag, output format, exit code, new tolerance/limitation, GUI capability) MUST update the matching skill in the same change — `skills/apk-analysis/SKILL.md` for `asc-rs` CLI behavior. Update the command list, "Choosing the command" table, Output notes, and Pitfalls as applicable; document only verified behavior. A feature is not done until its skill reflects it.
- **Versioning:** the agent decides version bumps autonomously when a change adds meaningful user-visible value (new subcommand/flag, GUI capability, notable perf/robustness gain). Bump the `version` in the root `Cargo.toml` (workspace `[workspace.package]`) in the same change: patch for fixes/refactors, minor for new features, major for breaking CLI/output changes. Pure internal refactors and docs do not bump. No release tag is created unless the user asks.

## Testing & QA

Standard `#[test]` + criterion (one `[[bench]]`: `asc-decompile`). No proptest/quickcheck. Baseline as of this commit: **358 passed** workspace-wide (355 tests + 3 doctests); asc-gui 133 unit + 3 integration. Must not regress.

- **Corpus-free suites (trust these):** `asc-dex/tests/{tiny_dex,container_041}.rs` (byte-level builder in `tests/common/mod.rs`), `asc-bytecode/tests`, `asc-apk/tests/integration.rs` (`ZipBuilder`: STORED/DEFLATE/ZIP64/CRC/zip-bomb), `asc-query/tests/synthetic.rs` (programmable DEX `Builder`), asc-manifest synthetic blobs. Test builders are duplicated per crate (`tests/common/mod.rs`); no shared test-utils crate.
- **Corpus-dependent tests skip silently, they do not fail or `#[ignore]`.** A green `cargo test` without `corpus/{apk,dex}` fixtures proves little (~55 tests affected); check test output for "skipping" lines. Always resolve fixtures via `env!("CARGO_MANIFEST_DIR")/../../corpus/...`: cargo runs tests with cwd = the crate dir, so a bare `"corpus/..."` path can never resolve (these were fixed in `asc-core/src/pipeline.rs`, `asc-manifest/src/tests.rs`, `asc-gui/tests/integration.rs`; the fixed paths have not yet been exercised against real fixtures).
- **Golden parity:** `asc-query/tests/golden.rs` vs `tests/fixtures/golden/*.counts.json` (generated by `capture_golden.py`; never hand-edit `cases.json`). Divergence allowlist = `GOLDEN_DIVERGENCES.md` + `divergence_verification.rs` (2 accepted cases; the test panics if a divergence disappears — update the allowlist then). Engine may be a strict *superset* of the oracle (oracle ⊆ engine), never miss its hits.
- **Differential:** `run_differential.py` compares findrefs as output-line *sets* and getclass structurally (`--strict` = byte-exact); expected 12/12 PASS; `--selftest` for the harness itself. Adding a case: follow the recipe in `tests/compatibility/parity_matrix.md`.
- **End-to-end gate:** `asc-core/tests/integration_gate.rs` (≥500 code items, ≥1000 hits on `workload.apk`; aurora multidex).
- **GUI:** headless via `egui::Context` + `eframe::Frame::_new_kittest()` (`AscApp::test_frame`, `run_ui`, `from_session`, `last_clipboard`); controllers under `state/` are unit-tested without a window. `tests/gui_features/feature_manifest.json` maps features to acceptance test paths; `score.py` counts a feature only if its test passed. `visual_shots`, `glyph_pixel_audit`, etc. need `ASC_GUI_SHOTS=1`.
- **Perf gate:** `benches/perf_compare.py` — paired one-sided sign test, Bonferroni, ≥3% median floor, `MIN_SAMPLES=15`.
- **Fuzz:** `fuzz/tests/registry.rs` pins contract targets to `SkippedDisabled` with default features; enabling a feature requires updating it. Green = runner exit 0; crashes land in `crashes/<target>-<fnv1a>.bin`, replay with `--regress`.

**Required gates:** fmt → clippy `-D warnings` → `cargo test --workspace` → `cargo build --release` → `asc-gui --selfcheck corpus/apk/workload.apk` → `perf_compare --selftest` → (GUI changes) hand-visual repro → (user-visible changes) matching `skills/` update.
