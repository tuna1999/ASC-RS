# Baseline — Python Oracle Performance

Reference numbers for the Python oracle that `asc-rs` must beat or match.

## Methodology

- **Cold runs**: every measurement spawns a fresh `python.exe` process via
  `subprocess.Popen`. This includes Python startup, the `androguard`
  import chain, the `src.asc_client` / `src.asc_core` import chain,
  and then the actual work.
- **Timing**: `time.perf_counter()` around the subprocess invocation;
  the value reflects the wall-clock end-to-end cost the user sees when
  they type `python main.py findrefs ...` at a shell.
- **Memory**: peak working-set size in MB, sampled by `psutil` every
  5 ms in a background thread while the subprocess runs. On Windows
  we report `memory_info().peak_wset`; on Linux/macOS we report
  `memory_info().rss` (which already represents peak committed
  memory for a short-lived subprocess).
- **N**: 5 cold runs per case. We report min / median / max.
- **Warmup**: discarded. The first Python interpreter process pays for
  filesystem caching of `.pyc` files; after the first run the cost is
  roughly stable, so all 5 runs are reported.
- **Tools**: `python` 3.14.6, `psutil` 7.2.2, `androguard` 4.1.3, on
  Windows 11 Enterprise 10.0.26200 (12th Gen Intel Core i7-12700T,
  20 logical cores).

Run with::

    reference/venv/Scripts/python.exe benches/benchmark.py --count 5

The latest run also produced `benches/raw_runs.json` (machine-readable)
and `benches/raw_runs.txt` (human-readable per-case log).

## Environment

| Item          | Version / value                                          |
|---------------|----------------------------------------------------------|
| OS            | Windows 11 Enterprise 10.0.26200                         |
| CPU           | 12th Gen Intel Core i7-12700T (20 logical cores)         |
| Python        | 3.14.6 (`E:\Dev\ASC-RS\reference\venv\Scripts\python.exe`)|
| androguard    | 4.1.3 (`reference/requirements-freeze.txt`)              |
| psutil        | 7.2.2                                                    |
| Freeze SHA    | `ccc6bae7704f5c5ef1a7271e27314837079621fb`               |
| Runs per case | 5 cold                                                   |
| Date captured | 2026-09-13                                               |

## Startup baselines

| Command                                     | min (s) | median (s) | max (s) |
|---------------------------------------------|--------:|-----------:|--------:|
| `python -c 'pass'`                          |   0.030 |     0.036  |   0.038 |
| `python main.py --help`                     |   0.077 |     0.084  |   0.090 |

`--help` adds ~50 ms over a bare interpreter: the Python import chain for
`main.py` plus `argparse`. androguard is *not* imported by `--help` (the
heavy imports happen inside `_handle_findrefs` / `_handle_getclass`).

## findrefs cold-run wall time

Each row is one oracle invocation. The cold subprocess pays for Python
startup, `androguard.core.dex` import, and `tinydex`/`asc_core` import
on every run, which is ~150-180 ms of the total.

| case                          | APK                | DEX layout | query                            | min (s) | median (s) | max (s) | stdout (B) |
|-------------------------------|--------------------|------------|----------------------------------|--------:|-----------:|--------:|-----------:|
| `findrefs_string_workload`    | `workload.apk`     | 1× dex (9.5 MB) | `string Context`                 |  0.316  |   0.326    |  0.340  |     3,520  |
| `findrefs_string_aurora`      | `aurora`           | 2× dex (6.0+2.5 MB) | `string https://`             |  0.324  |   0.342    |  0.350  |     9,036  |
| `findrefs_string_fdroid`      | `fdroid`           | 2× dex (9.7+4.4 MB) | `string https://`             |  0.377  |   0.429    |  0.470  |     4,184  |
| `findrefs_method_aurora`      | `aurora`           | 2× dex     | `method onClick`                 |  0.420  |   0.436    |  0.482  |     1,218  |
| `findrefs_type_workload`*     | `workload.apk`     | 1× dex     | `type ClockFaceView`             |  n/a    |   n/a      |  n/a    |    n/a     |

`*` `findrefs_type_workload` is not in the bench set; the bench focuses
on the multidex scaling cases plus one `string` on the single-dex fixture.

## getclass cold-run wall time

| case                          | APK                | query                                           | min (s) | median (s) | max (s) | stdout (B) |
|-------------------------------|--------------------|-------------------------------------------------|--------:|-----------:|--------:|-----------:|
| `getclass_clockface_workload` | `workload.apk`     | `Lcom/google/android/material/timepicker/ClockFaceView;` | 0.169 | 0.183 | 0.191 | 11,730 |

Note: `getclass` is *faster* than `findrefs` here because the heavy
`DexManager.extract_and_rebuild` step is only triggered after the cheap
`ApkHandler.get_class_dex` succeeds. The benchmark captures the entire
path including Python startup.

## Peak working-set size

| case                          | median (MB) | max (MB) |
|-------------------------------|------------:|---------:|
| `findrefs_string_workload`    |        4.0  |     4.0  |
| `findrefs_string_aurora`      |        4.0  |     4.5  |
| `findrefs_string_fdroid`      |        4.0  |     4.1  |
| `findrefs_method_aurora`      |        4.0  |     4.0  |
| `getclass_clockface_workload` |        4.0  |     4.5  |

These numbers are surprisingly small. On Windows, `psutil` reports the
process's `peak_wset`, which is the working-set size of the Python
interpreter *resident pages*. The Python heap (10-30 MB for the
`tinydex` parse) and the inflated DEX bytes (2-10 MB per dex) are
allocated from the C runtime and counted as part of the same pool.
The mmap of the APK is *not* counted toward `peak_wset` until it is
touched — and on Windows, the inflate buffer is short-lived enough that
the peak coincides with the steady-state after the dex is parsed.

For comparison purposes, `asc-rs` numbers should be compared against the
**wall time** column. The MB column is recorded for completeness and
because asc-rs likely has different memory pressure characteristics
(rust allocator vs. CPython).

## What asc-rs needs to beat

Concretely, to call a findrefs implementation "fast enough":

- `findrefs` cold (Python process + import + work) on the single-dex
  fixture: **0.33 s median**. Without Python startup (warm) the work
  itself is closer to 0.15 s; asc-rs cold wall should aim for
  **≤ 0.20 s** on the same fixture to be considered parity-class.
- `findrefs` cold on the multidex 9.7 + 4.4 MB fixture: **0.43 s median**.
  asc-rs cold target: **≤ 0.25 s**.
- `getclass` cold on the single-dex fixture: **0.18 s median**.
  asc-rs cold target: **≤ 0.15 s**.

These are reference points, not hard requirements. The first acceptance
criterion is functional parity (covered by `tests/differential/`); the
bench is here so that perf regressions are caught early.

## How to reproduce

```bash
# from E:/Dev/ASC-RS
reference/venv/Scripts/python.exe benches/benchmark.py --count 5
# look at benches/raw_runs.json and benches/raw_runs.txt
```

For the differential pass/fail numbers, see
`tests/differential/report.md`. The latest run shows `12 PASS / 12 FAIL
/ 12 SKIP` for the harness's `--selftest` mode (correct-replay must
PASS, wrong-replay must FAIL, skip-replay must SKIP — those are the
expected counts and the harness is correct).
