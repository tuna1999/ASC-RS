# Repository Guidelines

## Project Overview

**ASC-RS** is a pure-Rust port of [MG1937/ASC](https://github.com/MG1937/ASC) (frozen at commit `ccc6bae`). It performs on-demand APK analysis with two CLI commands:

- `findrefs string|type|method|field` — locate references in DEX bytecode.
- `getclass <descriptor>` — locate a class, extract a minimal standalone DEX, decompile to Java source.

Design pillars: **lazy** DEX access, **zero-copy** pools, **bounded memory**. No whole-APK preprocessing, no global xref graphs, no Python/JVM/Node runtime. Target outputs:

- `target/release/asc-rs.exe` (~2.7 MB) — CLI.
- `target/release/asc-gui.exe` (~8.6 MB) — jadx-style workbench (egui/eframe).

Oracles frozen for parity testing live under `reference/asc/` (read-only). Bench scripts and golden fixtures under `tests/fixtures/golden/` and `tests/differential/`.

## Architecture & Data Flow

Strict layered DAG. `asc-core` is the only fan-in node; CLI and GUI both depend on `asc-core` and never on each other.

```
Layer 0 leaf : asc-dex        (DEX 035..041 zero-copy reader, only thiserror dep)
Layer 1      : asc-apk        (mmap ZIP/APK, DEFLATE, CRC32)
                asc-bytecode   (256-opcode table + RefWalker)
Layer 2      : asc-manifest   (binary AXML)
                asc-query      (locators + find_refs + CodeOwners)
                asc-rebuild    (minimal DEX reconstruction, closure+remap+rewrite+layout)
Layer 3      : asc-decompile  (ClassDecompiler trait + DroidsawBackend, droidsaw-dex =1.0.0 pinned)
Layer 4 fan-in: asc-core      (orchestration, pipeline, WorkerPool, format emitters)
Layer 5      : asc-cli        (clap binary asc-rs)
                asc-gui        (eframe/egui binary asc-gui)
```

**Data flow — findrefs:**
`Apk::open` (mmap) → `dex_entries()` (numeric sort `^classes(\d*)\.dex$`) → per-DEX `read_entry` → magic check → `DexView::parse` or `DexView::parse_at` (DEX-041) → `asc_query::find_refs` → `resolve_target_ids` → `CodeOwners::build` → per-`code_off` `RefWalker` → match `TargetSets` → `RefHit` → `render_hits` → `format_search_report_text/json`.

**Data flow — getclass:**
WorkerPool fans over `classes*.dex` (AtomicUsize cursor + AtomicBool found + `OnceLock<(String,Vec<u8>)>` winner cell); winner → `DexView::parse` → `asc_rebuild::rebuild` (closure → remap → rewrite → layout + SHA-1 + Adler32) → `DroidsawBackend::decompile` (wrapped in `catch_unwind`).

**Ingestion boundary:** the GUI **never** imports `asc-rebuild` or `asc-decompile`. All engine access goes through `asc_core::{run_findrefs, run_getclass}` on `std::thread` workers; results merge via `TaskManager` (TaskId + SessionGeneration staleness gate) and `WorkspaceSession` caches (`parking_lot::Mutex`).

## Key Directories

| Path | Purpose |
|---|---|
| `crates/asc-dex/` | DEX 035..041 zero-copy parser. Hand-rolled bounds-checked reads, MUTF-8/ULEB128. |
| `crates/asc-bytecode/` | Opcode metadata + `RefWalker` streaming iterator over `insns`. |
| `crates/asc-apk/` | mmap ZIP engine + bounded DEFLATE inflate (1 GiB cap). |
| `crates/asc-query/` | `Query`, `ClassConstraint`, `find_refs`, `class_defines`, `CodeOwners`. |
| `crates/asc-rebuild/` | Closure + pool remap + in-place rewrite + canonical section emit. |
| `crates/asc-decompile/` | `ClassDecompiler` trait + `DroidsawBackend`. |
| `crates/asc-manifest/` | Binary AXML decoder for AndroidManifest.xml. |
| `crates/asc-core/` | `run_findrefs`, `run_getclass`, `WorkerPool`, text/json formatters. |
| `crates/asc-cli/` | `asc-rs` binary (`getclass`, `findrefs` subcommands). |
| `crates/asc-gui/` | `asc-gui` binary: app, command, design, highlight, icons, package_tree, selfcheck, session, source_edit, state/, task, ui/. |
| `tests/` | Differential parity harness + parity matrix + fixtures/golden. |
| `corpus/` | 3 real APKs + 5 extracted DEX bytes. Spec: `corpus/MANIFEST.md`. |
| `benches/` | Python oracle baseline (`benchmark.py`) + ASC-RS cold-run (`bench_ascrs.py`) + paired sign-test gate (`perf_compare.py`). |
| `fuzz/` | **Detached workspace** (excluded from root `Cargo.toml`). 12 contract targets, custom deterministic mutator. |
| `reference/` | Frozen Python oracle at `asc/ @ ccc6bae` + `BEHAVIOR.md` + `FREEZE.md` + `requirements-freeze.txt`. |
| `docs/` | `gui-audit.md`, `gui-architecture.md`, `gui-redesign-plan.md`, `design-language.md`. |
| `scripts/` | `build_release.py` — byte-reproducible source ZIP + SHA256SUMS. |
| `seeds/` | Top-level mirror of `fuzz/seeds` (committed). |

## Development Commands

All commands run from `E:/Dev/ASC-RS/`.

### Format / lint / build / test
```bash
cargo fmt --all -- --check
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build                                       # debug
cargo build --release
cargo test --workspace
cargo test --workspace --release
```

### CLI (`asc-rs`)
```bash
cargo build --release -p asc-cli                 # → target/release/asc-rs.exe
cargo run --release -p asc-cli -- getclass <apk> <descriptor> [-o OUT] [--threads N] [--debug]
cargo run --release -p asc-cli -- findrefs <apk> string <substring> [-o OUT] [--threads N] [--debug] [--format text|json]
cargo run --release -p asc-cli -- findrefs <apk> type   <substring> ...
cargo run --release -p asc-cli -- findrefs <apk> method [name] [--class X [--fuzzy-class]] ...
cargo run --release -p asc-cli -- findrefs <apk> field  [name] [--class X [--fuzzy-class]] ...
```

Exit codes: `0` success, `1` not-found, `2` engine error (`crates/asc-cli/src/main.rs:29-50`).

### GUI (`asc-gui`)
```bash
cargo run --release -p asc-gui                    # empty state
cargo run --release -p asc-gui -- <path.apk>      # open artifact
cargo run --release -p asc-gui -- --selfcheck <apk>     # headless smoke; prints SelfcheckReport
cargo run --release -p asc-gui -- --help
cargo run --release -p asc-gui --example gui_bench [apk …]   # GUI cost baseline
ASC_GUI_SHOTS=1 cargo test -p asc-gui --lib visual_shots    # screenshot harness
```

GUI verify ends with hand-visual repro to the user (agent is headless and cannot render egui).

### Differential parity
```bash
python tests/differential/run_differential.py target/release/asc-rs.exe [--strict] [--loose-whitespace]
python tests/differential/run_differential.py --selftest
```

### Bench / perf
```bash
reference/venv/Scripts/python.exe benches/benchmark.py --count 5
python benches/bench_ascrs.py
python benches/perf_compare.py --selftest
python benches/perf_compare.py --samples 31 [--metric cli_findrefs --metric cli_getclass]
cargo run --release -p asc-core --example profile_findrefs
cargo bench -p asc-decompile
```

### Release packaging
```bash
python scripts/build_release.py v0.1.1 --output dist
# writes dist/ASC-RS-v0.1.1-source.zip + dist/SHA256SUMS (byte-reproducible).
```

### Fuzz (separate workspace under `fuzz/`)
```bash
cargo run --release --bin gen-seeds                                            # regenerate seeds/<default_seed>/
cargo run --release --bin fuzz-runner -- --list                                 # list 12 targets
./run.sh <target> [budget_sec]                                                  # bash restart loop (default 30s)
.\run.ps1 -Target <target> [-BudgetSec N]                                       # PowerShell restart loop
cargo run --release --bin fuzz-runner -- --target <name> --seconds N \
    --seeds seeds/<name> --corpus-out corpus-out/<name> --crash-dir crashes --verbose 1
cargo run --release --bin fuzz-runner -- --target <name> --regress crashes      # replay saved crashes
```

### All-gates sequence
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release
target/release/asc-gui.exe --selfcheck corpus/apk/workload.apk
python benches/perf_compare.py --selftest
```

## Code Conventions & Common Patterns

**Language & toolchain:** Rust 2024, MSRV `1.85`, resolver `3`. Per-crate Cargo.toml inherits via `.workspace = true`. No `rust-toolchain.toml`, no `rustfmt.toml`, no `clippy.toml`, no `.cargo/config.toml` — rely on cargo defaults.

**Errors:** every crate uses `thiserror` for its `*Error` enum (`DexError`, `ApkError`, `BytecodeError`, `ManifestError`, `RebuildError`, `SearchError`, `SessionError`, `SelfcheckError`, `DecompileError`). `CoreError` (`crates/asc-core/src/pipeline.rs:65`) is hand-rolled to compose variants from sibling crates.

**No async.** Verified absence of `tokio`, `async-std`, `smol`. GUI uses `std::thread::spawn` + `std::sync::mpsc::channel`. `crates/asc-gui/src/task.rs:35/224`.

**No builder pattern.** No `impl Builder` anywhere in production code.

**One public trait:** `ClassDecompiler: Send + Sync` in `crates/asc-decompile/src/lib.rs:114`. Single impl (`DroidsawBackend`); third-party `droidsaw-dex` wrapped in `catch_unwind`.

**State management:**
- `WorkspaceSession` uses `parking_lot::Mutex` (preferred over `std::sync::Mutex` per `Cargo.toml:18-19`).
- GUI controllers are headless-testable under `crates/asc-gui/src/state/` (`documents`, `tabs`, `navigation`, `search`).
- `DocumentCache` is LRU + byte-budgeted (`state/documents.rs:215`).
- No `Arc<RwLock>`; `Arc<Document>` clone-out + `parking_lot::Mutex` for shared state.

**Parallelism:** hand-rolled `std::thread` pool in `crates/asc-core/src/worker.rs` with `AtomicUsize` cursor + `AtomicBool` found flag + `Arc<[T]>` items. Deliberately **not** rayon (see comment `worker.rs:17-25`). `rayon` is in `[workspace.dependencies]` only because criterion's bench harness needs it; no `use rayon` in ASC-RS source.

**Bounds-checking discipline:** all fixed-width reads through `crates/asc-dex/src/read.rs::{read_u16, read_u32, slice}` returning `Err(DexError::Truncated)`. Pool extents validated once at parse via `pools::check_pool` (`pools.rs:172`).

**Lazy / memoization:**
- `WorkspaceSession::classes_for_dex` lazy-fills per-dex class cache (`session.rs:182-198`).
- `PackageTree::filter_cache` holds `(needle, hits)`.
- `OnceLock<(String, Vec<u8>)>` winner cell in `run_getclass` (`pipeline.rs:452`).
- `static OPCODE_TABLE: [OpcodeInfo; 256]` built via `const fn build_table()` (`crates/asc-bytecode/src/opcode.rs:171/173`).

**Panic safety:** `droidsaw-dex` calls wrapped in `catch_unwind(AssertUnwindSafe(...))` (`crates/asc-decompile/src/droidsaw.rs:18/82/113`). GUI workers run inside `catch_unwind` (`crates/asc-gui/src/task.rs:225`).

**Pinned deps:** `droidsaw-dex = "=1.0.0"` exact pin (`crates/asc-decompile/Cargo.toml:10`). `eframe = "0.33"` with features `["default_fonts","glow","persistence"]` pinned locally per Lead (NOT in `[workspace.dependencies]`). `parking_lot 0.12`, `rfd 0.15`.

**`unsafe` policy:** `#![deny(unsafe_op_in_unsafe_fn)]` in `crates/asc-dex/src/lib.rs:72`, `crates/asc-bytecode/src/lib.rs:80`, `crates/asc-core/src/lib.rs:34`. `#![forbid(unsafe_code)]` boundary in `asc-decompile/src/lib.rs:36`. The only `unsafe` blocks live in `asc-apk` for `Mmap::map` and `unsafe impl Send/Sync` (`apk.rs:56/129-130/198-199`).

**Naming:** `PascalCase` types, `snake_case` fns/fields, `SCREAMING_SNAKE` constants. Pool indexes are `#[repr(transparent)]` typed wrappers (`StringIdx`, `TypeIdx`, `ProtoIdx`, `FieldIdx`, `MethodIdx`, `CallSiteIdx`, `MethodHandleIdx`) with `NO_INDEX = 0xFFFF_FFFF`. `crates/asc-dex/src/ids.rs:14-46`.

**Source-edit semantics (GUI only):** rename `n` (F25) and comment `;` (F26) are method/line scratchpads — intentionally lost on tab reload; don't try to persist them.

## Important Files

**Workspace / config:**
- `Cargo.toml` — workspace manifest, shared deps.
- `.gitignore` — `/target`, `fuzz/target`, `**/*.rs.bk`, `/reference/asc/`, `/reference/venv/`, generated bench outputs (`benches/ascrs_results.json`, `benches/raw_runs.json`, `benches/raw_runs.txt`, `bench-out.txt`), debug scratch (`gui-check*.png`, `rebuilt-*.dex`, `*.heap`, `probe*.rs`).
- `README.md` — philosophy + crate layout table + dev commands.
- `crates/asc-gui/build.rs` — Windows `winresource` icon embed (no-op on non-Windows).

**Engine entry points:**
- `crates/asc-core/src/lib.rs` — facade; re-exports `run_findrefs`, `run_getclass`, `format_*`, `normalize_class_name`, `WorkerPool`, `WorkerOutcome`.
- `crates/asc-core/src/pipeline.rs` — pipelines (findrefs @ line 199, getclass @ line 424), `render_hits`, `OnceLock` winner cell.
- `crates/asc-core/src/worker.rs` — `WorkerPool` (line 17-25 "Why not rayon?" comment).
- `crates/asc-core/src/format.rs` — text/JSON emitters.
- `crates/asc-dex/src/view.rs` — `DexView` zero-copy reader + DEX-041 logical offsets.
- `crates/asc-dex/src/header.rs` — `DexHeader`, `DexVersion`.
- `crates/asc-apk/src/apk.rs` — `Apk::open` (line 42), `dex_entries` (numeric sort, line 72).
- `crates/asc-query/src/scan.rs` — `find_refs` (line 160), `TargetSets` (line 48).
- `crates/asc-rebuild/src/lib.rs` — `rebuild` (line 98), `RebuiltDex`, `PoolCounts`.

**Frontend entry points:**
- `crates/asc-cli/src/main.rs` — clap dispatch (exit codes 0/1/2 at lines 29-50).
- `crates/asc-gui/src/main.rs` — `--selfcheck`, `--help`, else `eframe::run_native`.
- `crates/asc-gui/src/lib.rs` — re-exports `AscApp`, `run_selfcheck`, `SelfcheckReport`, `WorkspaceSession`, `open_session`.
- `crates/asc-gui/src/app.rs` — `AscApp` eframe shell, `poll_workers`, `apply_task`.
- `crates/asc-gui/src/task.rs` — `TaskManager`, `TaskId`, `SessionGeneration`, supersede/cancel.
- `crates/asc-gui/src/session.rs` — `WorkspaceSession` (class cache + findrefs history).
- `crates/asc-gui/src/selfcheck.rs` — `run_selfcheck`.

**Contracts / oracles:**
- `reference/BEHAVIOR.md` — oracle CLI/format contract (frozen pointers).
- `reference/FREEZE.md` — oracle freeze: `MG1937/asc @ ccc6bae7704f5c5ef1a7271e27314837079621fb`, Python 3.14.6, androguard 4.1.3.
- `reference/requirements-freeze.txt` — pip freeze lock.
- `tests/compatibility/parity_matrix.md` — Python oracle ↔ asc-rs invocation table.
- `tests/differential/report.md` — latest frozen parity report (12/12 PASS expected).
- `corpus/MANIFEST.md` — APK/DEX fixture inventory with SHA-256.

## Runtime/Tooling Preferences

- **Cargo only.** No Makefile, no justfile, no Taskfile, no nix.
- **No CI configured** (no `.github/workflows/`). All gates are manual.
- **No IDE configs** at root (no `.vscode/`, `.idea/`, `.editorconfig`, `CLAUDE.md`).
- **Python oracle:** activate via `reference/venv/Scripts/python.exe` (Windows). Frozen venv, no global pip install.
- **GUI** is eframe/egui. Default backend `glow`; `egui_kittest` wgpu backend available in dev-deps for headless test rendering.
- **Fuzz workspace is detached** (`fuzz/Cargo.toml` not in root members). Default features OFF → contract targets return `SkippedDisabled`; enable per-crate features (`dex`, `bytecode`, `apk`, `rebuild`) or `--features all`.
- **Seed:** fuzz runner uses splitmix64 with default seed `0xA5A5_C0DE_BEEF` (incremented per restart). Crash dumps land in `crashes/<target>-<fnv1a_hex16>.bin`.
- **Determinism:** source ZIP release is byte-reproducible (fixed `ZipInfo` timestamp `1980-01-01`, `create_system=3`, `external_attr=0o100644<<16`, DEFLATED).
- **LF/CRLF warnings on Windows are harmless** (memory note).

## Testing & QA

**Frameworks:** standard `#[test]` + criterion benches. No `proptest`, no `quickcheck`. GUI tests use `egui::Context::run` (headless); `egui_kittest::Harness` only in test helpers.

**Run all tests:**
```bash
cargo test --workspace            # ~244+ tests across 10 crates; asc-gui currently 72/72
cargo test --workspace --release
```

**Per-crate integration suites:**
- `crates/asc-dex/tests/` — `tiny_dex.rs`, `container_041.rs`, `corpus_smoke.rs`; builder in `common/mod.rs`.
- `crates/asc-bytecode/tests/` — `walker.rs`, `opcode_table.rs` (256-opcode exhaustiveness).
- `crates/asc-apk/tests/integration.rs` — STORED/DEFLATE, ZIP64, CRC, multidex, zip-bomb bound; builder in `common/mod.rs`.
- `crates/asc-query/tests/` — `golden.rs` (parity vs `tests/fixtures/golden/*.counts.json`), `synthetic.rs`, `divergence_verification.rs`.
- `crates/asc-core/tests/integration_gate.rs` — end-to-end gate: ≥500 code items, ≥1_000 ref hits, zero boundary errors on `corpus/apk/workload.apk`.
- `crates/asc-rebuild/tests/roundtrip.rs` — ClockFaceView round-trip + droidsaw decompile cross-check.
- `crates/asc-decompile/tests/integration.rs` — droidsaw backend integration + malformed-input panic guard.
- `crates/asc-gui/tests/integration.rs` — `--selfcheck`, `open_session`, history cap.

**Unit tests (`#[cfg(test)] mod tests`):** every engine crate carries focused unit tests — `header.rs` (magic recognition), `leb.rs` (uleb/sleb), `mutf8.rs` (MUTF-8), `query::locator.rs` (descriptor normalization), `query::scan.rs` (TargetSets), `query::owner.rs`, `core::worker.rs` (winner stops pool), `core::pipeline.rs`. GUI unit tests: `task.rs` (TaskId/Generation/dupe-decompile), `state/documents.rs` (F28 \uXXXX decode), `state/navigation.rs`, `state/search.rs`, `state/tabs.rs`, `highlight.rs`, `package_tree.rs`, `source_edit.rs`, `ui/inspector.rs`, `design.rs` (theme toggle), `app.rs` (largest in repo).

**Corpus fixtures:**
- `corpus/apk/workload.apk` (single-dex), `corpus/apk/com.aurora.store_60.apk`, `corpus/apk/org.fdroid.fdroid_1016000.apk` (multidex).
- `corpus/dex/` — 5 extracted DEX bytes.
- `corpus/MANIFEST.md` — SHA-256 + reproduction curl.

**Golden outputs:** `tests/fixtures/golden/<case_id>.{txt,counts.json}` + `cases.json` regenerated via `tests/fixtures/capture_golden.py`.

**Differential parity:** `python tests/differential/run_differential.py target/release/asc-rs.exe` must pass 12/12. `--selftest` for synthetic gate. Divergences are allowlisted in `crates/asc-query/tests/divergence_verification.rs`; if a divergence vanishes, the test panics to force an allowlist update.

**Benchmarks:**
- `cargo bench -p asc-decompile --bench decompile_bench` — criterion cold + warm path on `corpus/dex/workload_classes.dex` `ClockFaceView`.
- `cargo run --release -p asc-gui --example gui_bench [apk …]` — phase-0 GUI cost baseline (NOT a `[[bench]]`).
- `cargo run --release -p asc-core --example profile_findrefs` — per-phase findrefs profile.

**Perf gate:** `python benches/perf_compare.py --samples 31` runs paired one-sided sign test + Bonferroni + 3% median floor against the Python oracle. `--selftest` synthetic check. `MIN_SAMPLES = 15`.

**Fuzz gates:** `./run.sh <target>` for 30s, must exit 0 (GREEN). Crashes auto-dumped via panic hook + FNV-1a filename. Pre-saved crashes replayable via `--regress fuzz/regress`.

**Required gates (all must pass):**
1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo test --workspace` (asc-gui must remain 72/72)
4. `cargo build --release` (`asc-gui.exe` ~8.6 MB, `asc-rs.exe` ~2.7 MB)
5. `target/release/asc-gui.exe --selfcheck corpus/apk/workload.apk`
6. `python benches/perf_compare.py --selftest`
7. (GUI changes only) hand-visual repro to user — agent is headless and cannot render egui.
