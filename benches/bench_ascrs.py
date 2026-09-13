"""Release-gate benchmark: asc-rs vs the Python baseline cases.

Times cold runs (new process each) of the same queries used in
benches/BASELINE.md, reports medians. Dev tooling only — not part of
the runtime.
"""
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

BIN = "target/release/asc-rs.exe"
GOLDEN = Path("tests/fixtures/golden/cases.json")

# (label, argv-suffix)
CASES = [
    ("findrefs_string_workload", ["findrefs", "corpus/apk/workload.apk", "string", "https://"]),
    ("findrefs_string_aurora", ["findrefs", "corpus/apk/com.aurora.store_60.apk", "string", "https://"]),
    ("findrefs_string_fdroid", ["findrefs", "corpus/apk/org.fdroid.fdroid_1016000.apk", "string", "https://"]),
    ("findrefs_method_aurora", ["findrefs", "corpus/apk/com.aurora.store_60.apk", "method", "onCreate"]),
    ("getclass_clockface_workload", ["getclass", "corpus/apk/workload.apk",
     "Lcom/google/android/material/timepicker/ClockFaceView;"]),
]

RUNS = 7


def run_once(argv):
    t0 = time.perf_counter()
    p = subprocess.run([BIN, *argv], capture_output=True, cwd=".")
    dt = (time.perf_counter() - t0) * 1000.0
    if p.returncode != 0:
        print(f"  !! exit {p.returncode}: {p.stderr[:200]!r}")
    return dt


def main():
    rows = []
    for label, argv in CASES:
        times = [run_once(argv) for _ in range(RUNS)]
        med = statistics.median(times)
        rows.append((label, med, min(times), max(times)))
        print(f"{label}: median {med:.1f} ms (min {min(times):.1f}, max {max(times):.1f})")
    out = [{"case": r[0], "median_ms": round(r[1], 1), "min_ms": round(r[2], 1),
            "max_ms": round(r[3], 1)} for r in rows]
    Path("benches/ascrs_results.json").write_text(json.dumps(out, indent=2))
    print("wrote benches/ascrs_results.json")


if __name__ == "__main__":
    sys.exit(main())
