# ASC-RS vs Python ASC — Release Benchmark

Date: 2026-09-14 · Machine: i7-12700T (20 threads), Windows 11, rustc 1.97.1 release
Methodology: identical to `BASELINE.md` (cold process per run, 7 runs, median; wall
time via `time.perf_counter` around `subprocess.run`). Reproduce with
`python benches/bench_ascrs.py` (writes `ascrs_results.json`).

## Results (median wall time, cold)

| Case | Python ASC | asc-rs | Speedup |
|---|---:|---:|---:|
| findrefs string `https://` workload.apk (1×9.5MB dex) | 326 ms | **27.2 ms** | **12.0×** |
| findrefs string `https://` aurora (multidex) | 342 ms | **55.4 ms** | **6.2×** |
| findrefs string `https://` fdroid (multidex, larger) | 429 ms | **86.2 ms** | **5.0×** |
| findrefs method `onCreate` aurora | 436 ms | **64.7 ms** | **6.7×** |
| getclass ClockFaceView workload.apk (locate→rebuild→decompile) | 183 ms | **110.2 ms** | **1.7×** |

## Notes

- Phase profile (`cargo run --release -p asc-core --example profile_findrefs`):
  APK open 0.18ms · inflate 5.4ms · `DexView::parse` 12.7µs (O(1) as designed) ·
  code-owner build 4.9ms · find_refs scan 14.2ms.
- getclass is bounded by the droidsaw-dex cold parse of the minimal DEX plus
  process startup (~15ms of the 110ms is process spawn).
- A first pass measured findrefs at 364–719 ms — an O(n²) code_off dedup
  (linear `Vec::find` per method) inside `CodeOwners::build`; replaced with a
  per-call `HashMap<u32, usize>` index (NOT a persistent global xref; §13
  preserved). 70× on the build phase, 28× on the scan.
- Startup (`asc-rs --help`) is ~5 ms vs Python's 84 ms (`main.py --help`) +
  36 ms interpreter spawn.
- Differential parity after the optimization: 12/12 cases
  (`python tests/differential/run_differential.py target/release/asc-rs.exe`).

## Caveats

- Peak RSS not yet instrumented for asc-rs (Python baseline ~4 MB working set
  reported by psutil; asc-rs mmap + one inflated dex is expected comparable or
  lower; measure before release).
- Corpus APKs are small-to-medium (≤10 MB). The original ASC demo target was a
  352 MB commercial APK; no such fixture is in the corpus yet.
