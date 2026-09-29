# ASC-RS

Pure Rust rewrite of [MG1937/ASC](https://github.com/MG1937/ASC) — on-demand
Android APK analysis: `findrefs` (string/type/method/field cross-reference
search across all DEX entries), `getclass` (locate a class, extract a
minimal standalone DEX, decompile), and `listclass` (enumerate every class
descriptor across all DEX entries, with optional ASCII prefix filter).
No Python, no JVM, no Node at runtime.

## Philosophy

Read only what is necessary to answer the query. Lazy DEX views, zero-copy
pools, bounded memory, safe on malformed/adversarial input. No whole-APK
preprocessing, no global xref graphs, no fully-materialized object graphs.

## Layout

| Path | Responsibility |
|---|---|
| `crates/asc-dex` | Zero-copy DEX 035–041 reader (typed indexes, lazy class_data/code/annotations) |
| `crates/asc-bytecode` | Dalvik opcode metadata, instruction widths, `RefWalker` reference extraction |
| `crates/asc-apk` | Read-only mmap APK/ZIP engine: EOCD, central directory, `classes*.dex`, bounded inflate |
| `crates/asc-query` | Locators + code-owner discovery + reference scanning (findrefs) |
| `crates/asc-rebuild` | Minimal standalone DEX reconstruction (closure, remap, rewrite, valid emit) |
| `crates/asc-decompile` | Backend-neutral class decompiler abstraction |
| `crates/asc-manifest` | Binary AXML (AndroidManifest) parsing |
| `crates/asc-core` | Orchestration: getclass/findrefs/listclass pipelines, bounded parallelism, cancellation |
| `crates/asc-cli` | CLI parity frontend |
| `crates/asc-gui` | eframe/egui desktop UI (behind feature, ships later) |
| `reference/asc` | Frozen Python oracle (commit `ccc6bae`) — read-only, not a runtime dep |
| `tests/fixtures` | Golden outputs captured from the oracle |
| `corpus/` | Test APK/DEX corpus |
| `benches/` | Benchmark methodology + baselines |
| `fuzz/` | Fuzzing (separate workspace) |

## Quick start

```bash
cargo build --release
# build artifact: target/release/asc-rs (or asc-rs.exe on Windows)
asc-rs findrefs <apk> string https://              # all callers of any string containing "https://"
asc-rs findrefs <apk> type   Fragment              # all callers whose code references type descriptors containing "Fragment"
asc-rs findrefs <apk> method onClick              # callers of method name "onClick"
asc-rs findrefs <apk> method onLayout --class Lcom/foo/Bar;   # precise class
asc-rs findrefs <apk> field  textColor --fuzzy-class --class Foo
asc-rs getclass   <apk> Lcom/foo/Bar;              # decompiled Java source on stdout
asc-rs getclass   <apk> com.foo.Bar                 # dotted form also accepted
asc-rs listclass  <apk> --prefix Lcom/foo          # every descriptor in the APK
```

Class names accept Dalvik descriptor (`Lcom/foo/Bar;`) **or** dotted Java form (`com.foo.Bar`).
Shared flags (`-o/--output`, `--threads N`, `--debug`, `--format text|json`) can appear before or after the APK positional. Exit codes: `0` success, `1` not-found / invalid input, `2` engine error. Each command also accepts `--help`.

## Development

Minimum supported Rust version: **1.93** (set by `droidsaw-dex 2.0.0`).

```bash
cargo build --release
cargo test --workspace --release
```

Correctness gates: `cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets --all-features -- -D warnings`, differential fixtures vs the
frozen Python oracle.

Release / perf dev tooling:

```bash
python scripts/build_release.py v0.2.0 --output dist   # byte-reproducible source ZIP + SHA256SUMS
python benches/perf_compare.py --selftest              # paired sign-test + Bonferroni + 3% floor gate (synthetic)
python benches/perf_compare.py --samples 31            # real binary comparison against target/release/asc-rs.exe
```

## AI skill: `apk-analysis`

`skills/apk-analysis/SKILL.md` teaches an AI agent how to drive `asc-rs` (command choice, output formats, exit codes, pitfalls).

Install by copying (or symlinking) the folder into your agent's skills directory:

```bash
# Claude Code (global)         cp -r skills/apk-analysis ~/.claude/skills/
# Claude Code (this project)   cp -r skills/apk-analysis .claude/skills/
# omp                          cp -r skills/apk-analysis ~/.omp/agent/skills/
```

Build the CLI first (`cargo build --release -p asc-cli`). Then ask the agent e.g. *"use apk-analysis: who calls `getSystemService` in `app.apk`?"*. The agent runs `asc-rs` itself; the skill is picked up by its `description` trigger.
