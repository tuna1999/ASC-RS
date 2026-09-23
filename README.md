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

## Development

```bash
cargo build --release
cargo test --workspace --release
```

Correctness gates: `cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets --all-features -- -D warnings`, differential fixtures vs the
frozen Python oracle.

Release / perf dev tooling:

```bash
python scripts/build_release.py v0.1.1 --output dist   # byte-reproducible source ZIP + SHA256SUMS
python benches/perf_compare.py --selftest              # paired sign-test + Bonferroni + 3% floor gate (synthetic)
python benches/perf_compare.py --samples 31            # real binary comparison against target/release/asc-rs.exe
```
