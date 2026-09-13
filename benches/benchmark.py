#!/usr/bin/env python3
"""Measure baseline performance of the Python oracle.

For each case we run the oracle N times (default 5; ``--count N`` to
override) and record:

- wall-clock time (seconds)
- peak working-set size (MB) via psutil
- exit code, line count

Output: ``benches/raw_runs.json`` plus a human-readable
``benches/raw_runs.txt`` summary. ``benches/BASELINE.md`` is generated
from these by the manual step (or rerun this script to refresh the
data).
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover -- psutil is in requirements-freeze.txt
    psutil = None

REPO_ROOT = Path(__file__).resolve().parents[1]
ASC_ROOT = REPO_ROOT / "reference" / "asc"
ASC_MAIN = ASC_ROOT / "main.py"
VENV_PY = REPO_ROOT / "reference" / "venv" / "Scripts" / "python.exe"
CORPUS_APK = REPO_ROOT / "corpus" / "apk"
GOLDEN = REPO_ROOT / "tests" / "fixtures" / "golden"
OUT_DIR = Path(__file__).resolve().parent

# Cases measured by the benchmark. Mirrors the differential harness's
# case list (cases.json) but is decoupled so the bench can be re-run
# without affecting golden capture. Each entry is one bench target.
BENCH_CASES = [
    {
        "id": "findrefs_string_workload",
        "label": "findrefs string Context (workload, single dex)",
        "argv": ["findrefs", str(CORPUS_APK / "workload.apk"), "string", "Context"],
    },
    {
        "id": "findrefs_string_aurora",
        "label": "findrefs string https:// (Aurora, multidex)",
        "argv": ["findrefs", str(CORPUS_APK / "com.aurora.store_60.apk"),
                 "string", "https://"],
    },
    {
        "id": "findrefs_string_fdroid",
        "label": "findrefs string https:// (F-Droid, multidex, larger)",
        "argv": ["findrefs", str(CORPUS_APK / "org.fdroid.fdroid_1016000.apk"),
                 "string", "https://"],
    },
    {
        "id": "findrefs_method_aurora",
        "label": "findrefs method onClick (Aurora)",
        "argv": ["findrefs", str(CORPUS_APK / "com.aurora.store_60.apk"),
                 "method", "onClick"],
    },
    {
        "id": "getclass_clockface_workload",
        "label": "getclass ClockFaceView (workload)",
        "argv": ["getclass", str(CORPUS_APK / "workload.apk"),
                 "Lcom/google/android/material/timepicker/ClockFaceView;"],
    },
]

def _subprocess_peak_rss_mb(argv: list[str]) -> tuple[int, int, float | None, float | None]:
    """Run ``argv`` and return (exit_code, stdout_bytes, peak_rss_mb, peak_wset_mb).

    ``peak_wset_mb`` is only populated on Windows; on Linux/macOS it's
    ``None`` (where the raw ``rss`` field already gives the equivalent
    measurement).
    Uses ``psutil`` to track peak working set of the child; falls back
    to ``None`` if psutil is unavailable.
    """
    if psutil is None:
        proc = subprocess.run(
            argv,
            cwd=str(ASC_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
        return proc.returncode, len(proc.stdout.encode("utf-8")), None, None

    proc = psutil.Popen(
        argv,
        cwd=str(ASC_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    peak_bytes = proc.memory_info().rss  # initial
    peak_wset_bytes = 0
    stop = False

    def _poll() -> None:
        nonlocal peak_bytes, peak_wset_bytes, stop
        while not stop:
            try:
                mi = proc.memory_info()
                if mi.rss > peak_bytes:
                    peak_bytes = mi.rss
                if hasattr(mi, "peak_wset") and mi.peak_wset:
                    if mi.peak_wset > peak_wset_bytes:
                        peak_wset_bytes = mi.peak_wset
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return
            time.sleep(0.005)

    import threading
    t = threading.Thread(target=_poll, daemon=True)
    t.start()
    try:
        stdout, _stderr = proc.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        stop = True
        raise
    finally:
        stop = True
        t.join(timeout=2.0)
    peak_wset_mb = peak_wset_bytes / (1024 * 1024.0) if peak_wset_bytes else None
    return proc.returncode, len(stdout.encode("utf-8")), peak_bytes / (1024 * 1024.0), peak_wset_mb


def _cold_run(argv: list[str]) -> tuple[float, int, int, float | None, float | None]:
    cmd = [str(VENV_PY), str(ASC_MAIN), *argv]
    t0 = time.perf_counter()
    exit_code, stdout_b, peak_mb, peak_wset_mb = _subprocess_peak_rss_mb(cmd)
    elapsed = time.perf_counter() - t0
    return elapsed, exit_code, stdout_b, peak_mb, peak_wset_mb

def _stats(xs: list[float]) -> dict:
    if not xs:
        return {}
    xs_sorted = sorted(xs)
    p10 = xs_sorted[max(0, (len(xs_sorted) - 1) // 10)]
    p90 = xs_sorted[min(len(xs_sorted) - 1, (len(xs_sorted) - 1) * 9 // 10)]
    return {
        "count": len(xs),
        "min": min(xs),
        "max": max(xs),
        "mean": statistics.fmean(xs),
        "median": statistics.median(xs),
        "stdev": statistics.stdev(xs) if len(xs) > 1 else 0.0,
        "p10": p10,
        "p90": p90,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--count", type=int, default=5,
        help="Number of cold runs per case. Default 5.",
    )
    parser.add_argument(
        "--skip-startup", action="store_true",
        help="Skip the startup baseline measurements.",
    )
    args = parser.parse_args()

    if not VENV_PY.exists():
        print(f"ERROR: oracle python not found at {VENV_PY}", file=sys.stderr)
        return 2

    results: dict = {
        "oracle_python": str(VENV_PY),
        "oracle_commit": "ccc6bae7704f5c5ef1a7271e27314837079621fb",
        "n_per_case": args.count,
        "startup": {},
        "cases": [],
    }

    summary_lines: list[str] = []
    summary_lines.append("# Raw oracle benchmark runs")
    summary_lines.append("")
    summary_lines.append(f"- runs per case: {args.count}")
    summary_lines.append(f"- python: `{VENV_PY}`")
    summary_lines.append("")
    summary_lines.append("## Startup")
    summary_lines.append("")

    if not args.skip_startup:
        # Python interpreter startup
        cmd = [str(VENV_PY), "-c", "pass"]
        cmd2 = [str(VENV_PY), str(ASC_MAIN), "--help"]
        start_times: list[float] = []
        start_help_times: list[float] = []
        for i in range(args.count):
            t0 = time.perf_counter()
            subprocess.run(cmd, cwd=str(ASC_ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            start_times.append(time.perf_counter() - t0)

            t0 = time.perf_counter()
            subprocess.run(cmd2, cwd=str(ASC_ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            start_help_times.append(time.perf_counter() - t0)
        results["startup"] = {
            "python_pass": _stats(start_times),
            "python_main_help": _stats(start_help_times),
        }
        summary_lines.append(
            f"python -c 'pass' median: {statistics.median(start_times):.3f}s, "
            f"min: {min(start_times):.3f}s, max: {max(start_times):.3f}s"
        )
        summary_lines.append(
            f"python main.py --help median: {statistics.median(start_help_times):.3f}s, "
            f"min: {min(start_help_times):.3f}s, max: {max(start_help_times):.3f}s"
        )

    summary_lines.append("")

    for case in BENCH_CASES:
        cid = case["id"]
        argv = case["argv"]
        label = case["label"]
        cold_times: list[float] = []
        cold_stdout_b = 0
        cold_exit = -1
        cold_rss: list[float] = []
        cold_wset: list[float] = []
        for i in range(args.count):
            t, exit_code, sb, rss, wset = _cold_run(argv)
            cold_times.append(t)
            cold_exit = exit_code
            cold_stdout_b = sb
            if rss is not None:
                cold_rss.append(rss)
            if wset is not None:
                cold_wset.append(wset)
            print(f"  cold {cid} #{i+1}: {t:.3f}s exit={exit_code} rss={rss} wset={wset}",
                  file=sys.stderr)

        case_result = {
            "id": cid,
            "label": label,
            "argv": argv,
            "cold": _stats(cold_times),
            "cold_exit": cold_exit,
            "cold_stdout_bytes": cold_stdout_b,
            "peak_rss_mb": _stats(cold_rss),
            "peak_wset_mb": _stats(cold_wset),
        }
        results["cases"].append(case_result)

        summary_lines.append(f"## `{cid}`")
        summary_lines.append("")
        summary_lines.append(f"label: {label}")
        summary_lines.append(f"argv: `{' '.join(argv)}`")
        summary_lines.append(
            f"cold: n={len(cold_times)} min={min(cold_times):.3f}s "
            f"median={statistics.median(cold_times):.3f}s "
            f"max={max(cold_times):.3f}s"
        )
        if cold_rss:
            summary_lines.append(
                f"peak_rss_mb: n={len(cold_rss)} "
                f"min={min(cold_rss):.1f} "
                f"median={statistics.median(cold_rss):.1f} "
                f"max={max(cold_rss):.1f}"
            )
        summary_lines.append(f"cold stdout bytes: {cold_stdout_b}")
        summary_lines.append(f"cold exit: {cold_exit}")
        summary_lines.append("")

    (OUT_DIR / "raw_runs.json").write_text(
        json.dumps(results, indent=2, sort_keys=True), encoding="utf-8"
    )
    (OUT_DIR / "raw_runs.txt").write_text(
        "\n".join(summary_lines) + "\n", encoding="utf-8"
    )
    print(f"# wrote {OUT_DIR / 'raw_runs.json'}", file=sys.stderr)
    print(f"# wrote {OUT_DIR / 'raw_runs.txt'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
