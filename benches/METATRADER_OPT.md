# Perf optimization report — 2026-09-28

Supersedes the 2026-09-26 pass, which measured `MetaTrader-5-Forex-Stocks_500.6119_apkcube.apk`.
That APK is no longer in `corpus/`; every number below was re-measured on the
current corpus with `target/release/asc-rs.exe` rebuilt from HEAD.

## Environment

| Item | Value |
|------|-------|
| OS | Windows 11 Enterprise 10.0.26200 |
| CPU | i7-12700T, 20 logical cores |
| rustc | 1.97.1 (8bab26f4f 2026-07-14), LLVM 22.1.6 |
| Binary | `target/release/asc-rs.exe`, 2,674,688 B |

## Corpus (current)

| APK | DEXes | Raw DEX | Compression |
|-----|------:|--------:|-------------|
| `workload.apk` | 1 | 9.1 MB | STORED |
| `com.aurora.store_60.apk` | 2 | 6.7 MB | DEFLATED |
| `org.fdroid.fdroid_1016000.apk` | 2 | 14.0 MB | DEFLATED |
| `com.locket.Locket.apk` | 8 | 53.3 MB | STORED |

`workload.apk` and `com.locket.Locket.apk` are **STORED**, so `read_entry`
returns a borrowed mmap slice and the DEFLATE path never runs for them.

## Method

Speedups below are **head-to-head on one machine**: two binaries built from
`ff52317` (PRE, before this work) and from the final tree (POST), measured
back to back in an interleaved loop (N=15, page cache warm, median). Both
were `--release` builds of the same source except for the three changes
described here. Wall time is `time.perf_counter()` around `subprocess.run`,
so it includes ~9 ms of process spawn on both sides.

## P0 — findrefs: index caller `code_off` once

`crates/asc-core/src/pipeline.rs` — `resolve_first_line` scanned **every**
`class_def` to find a caller's `code_off`, once **per caller**. That is
O(callers × class_defs). Replaced with `source_code_off_index`, a single
pass building `method_idx → code_off`.

The old code carried the comment *"if it ever becomes hot we'll cache it on
the worker"* — it had become hot.

## P1 — getclass: index the closure's source `code_off` once

`crates/asc-rebuild/src/closure.rs` — `find_source_code_off` had the same
O(methods × class_defs) shape, called once per method in `augment_pass`.
Replaced with `source_code_off_index`. `to_walk` is snapshotted before the
loop, so the index stays valid while `walk_code_item` mutates `self.methods`.

Instrumented measurement of the old code:

| case | to_walk | class_defs | class_data reads | lookup |
|------|--------:|-----------:|-----------------:|-------:|
| ClockFaceView | 74 | 6220 | 59,792 | 143,211 µs |
| Locket Analytics | 38 | 6181 | 27,901 | 82,437 µs |

`class_data reads ≈ to_walk × class_defs`. After the change `closure_us`
went 165,403 µs → 5,093 µs on ClockFaceView (**~32×**), from 95–96% of
`rebuild` down to a minor share.

## P2 — release profile

```toml
[profile.release]
lto = "thin"
codegen-units = 1
strip = "debuginfo"
```

`panic` is left at `unwind` **on purpose**: `asc-decompile` wraps the
third-party droidsaw-dex parser in `catch_unwind` and `asc-gui` worker
threads do the same. `panic = "abort"` would delete those guards. The
`asc-decompile` panic-guard test (6 tests) passes under this profile.

Build 46 s → 118 s. `asc-rs.exe` 2,786,816 B → 2,674,688 B.

## Results

| case | PRE | POST | speedup |
|------|----:|-----:|--------:|
| `findrefs string Context` workload (28) | 68.0 ms | 46.9 ms | 1.45× |
| `findrefs string get` workload (219) | 259.1 ms | 53.7 ms | **4.82×** |
| `findrefs string https://` aurora (57) | 123.6 ms | 90.6 ms | 1.37× |
| `findrefs string https://` fdroid | 154.6 ms | 144.7 ms | 1.07× |
| `findrefs string Context` locket, 8 dex (725) | 1169.1 ms | 221.2 ms | **5.28×** |
| `getclass ClockFaceView` workload | 147.2 ms | 37.3 ms | **3.95×** |
| `getclass Locket Analytics` (8 dex) | 128.3 ms | 60.6 ms | 2.12× |

Narrow queries (few callers) are unchanged, by design — see below:

| case | PRE | POST | speedup |
|------|----:|-----:|--------:|
| `findrefs string compare` workload (1 caller) | 42.5 ms | 42.8 ms | 0.99× |
| `findrefs string hashCode` workload (2) | 45.3 ms | 45.2 ms | 1.00× |
| `findrefs method onClick` aurora (10) | 89.4 ms | 90.3 ms | 0.99× |

## Index vs linear scan threshold

Building the index costs one full class-def walk (~24 ms on a 6,220-class
DEX). The old per-caller scan stops at the first match, so it averages half
that. An index-only version therefore **regressed** narrow queries — a
1-caller findrefs went 43.6 ms → 46.4 ms (0.94×, reproduced across runs).

`render_hits` now picks per query: `LINEAR_SCAN_CALLER_LIMIT = 2`. At or
below that caller count it uses the original early-exit scan; above it, it
builds the index. Break-even was measured, not guessed.

`findrefs method onClick` aurora at 0.99× is inside measurement noise
(N=41: median 0.991×, min 0.988×, stdev ≈13% CV) — not a real regression.
Its engine-only cost is ~78 ms of the ~90 ms wall.

## Rejected after measurement

| Idea | Why not |
|------|---------|
| Index unconditionally | Regressed 1-caller queries to 0.94×. Fixed with the threshold above. |
| Drop `.to_vec()` on `read_entry` | Measured 1.35 ms for 9.1 MB = **1.7%** of findrefs. Not worth the signature churn. |
| `zlib-rs` instead of `miniz_oxide` | Irrelevant — the large corpus APKs are STORED, so inflate does not run. |
| Reuse the 64 KiB inflate scratch buffer | Only affects DEFLATED entries; ≤1 ms there. |
| `madvise` / `PrefetchVirtualMemory` on the mmap | Needs a new `unsafe` block in `asc-apk`; cold page-fault cost did not measure as significant. |
| `parking_lot::RwLock` for the droidsaw parse cache | Cache is read-mostly and tiny (16 entries); not contended in practice. |

## Gates

| Gate | Result |
|------|--------|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | clean |
| `cargo test --workspace --release` | 358 passed, 0 failed |
| `cargo test --release -p asc-decompile` (panic guard) | 6 passed — `catch_unwind` intact under LTO |
| `python tests/differential/run_differential.py target/release/asc-rs.exe` | 12 PASS / 0 FAIL |
| `python benches/perf_compare.py --selftest` | selftest OK |
| `asc-gui --selfcheck corpus/apk/workload.apk` | exit 0, 6220 classes |
| stdout byte-identical to pre-change baseline | verified (3520 / 9036 / 4184 / 1218 B) |

## Note on prior numbers

`benches/ASC-RS-BENCH.md` (2026-09-14) reports `findrefs string Context
workload` at 27.2 ms. The PRE binary built from `ff52317` measures 68.0 ms
on this machine. The 2.5× gap is unexplained; the ASC-RS-BENCH machine or a
regression between 2026-09-14 and 2026-09-26 are the candidates. The oracle
column (`benches/BASELINE.md`) is unchanged and still valid.

## Next candidates

1. **Process spawn (~9 ms fixed).** Largest remaining fixed cost; ~20% of
   post-change `getclass` wall time.
2. **`getclass layout` phase** — 3.5 ms, now comparable to the closure walk.
3. **`run_findrefs` is still serial across DEX entries.** `getclass` already
   fans out over `WorkerPool`; findrefs does not. On the 8-dex Locket APK
   that is 8 sequential index builds (~131 ms of a 221 ms run). Not yet
   measured for a real win — parallelising changes hit ordering, which the
   differential runner compares.
