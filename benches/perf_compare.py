"""Paired perf-regression gate for ASC-RS CLI timings.

Ports the protocol in reference/asc/tests/test_performance_compare.py +
.github/workflows/tests.yml (paired one-sided sign test, Bonferroni over
gated metrics, 3% median-ratio floor) and runs it as a standalone script.

Usage:
    # Real measurement (must come after `cargo build --release`):
    python benches/perf_compare.py --samples 31 \
        --metric cli_findrefs --metric cli_getclass

    # Self-check without timing real binaries:
    python benches/perf_compare.py --selftest
"""
from __future__ import annotations

import argparse
import math
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BIN = REPO_ROOT / "target" / "release" / "asc-rs.exe"

# Minimum samples — oracle requires >=15 paired samples.
MIN_SAMPLES = 15
DEFAULT_SAMPLES = 31
DEFAULT_FLOOR = 3.0  # median slowdown percent that counts as material
DEFAULT_ALPHA = 0.05


# ---- statistical core -----------------------------------------------------


def compare_pairs(
    base: list[float],
    candidate: list[float],
    metric_count: int,
    *,
    alpha: float = DEFAULT_ALPHA,
    effect_floor_percent: float = DEFAULT_FLOOR,
) -> dict:
    """Paired one-sided sign test + Bonferroni + 3% median floor.

    Mirrors reference/asc/tests/performance_compare.py:compare_pairs. Returns
    a dict with all fields the report needs.
    """
    if len(base) != len(candidate) or len(base) < MIN_SAMPLES:
        raise ValueError(
            f"at least {MIN_SAMPLES} complete paired samples are required"
        )
    if metric_count < 1 or not 0 < alpha < 1 or effect_floor_percent < 0:
        raise ValueError("invalid comparison parameters")
    if any(not math.isfinite(v) or v <= 0 for v in (*base, *candidate)):
        raise ValueError("timings must be finite and positive")

    ratios = [c / b for b, c in zip(base, candidate)]
    slower = sum(r > 1 for r in ratios)
    faster = sum(r < 1 for r in ratios)
    n = slower + faster
    # P(>=slower | H0: median ratio = 1) under exact binomial(n, 0.5).
    p_value = sum(math.comb(n, k) for k in range(slower, n + 1)) / 2 ** n
    threshold = alpha / metric_count
    paired_median_change_percent = (statistics.median(ratios) - 1) * 100
    significant = p_value < threshold
    material = paired_median_change_percent >= effect_floor_percent
    return {
        "n": len(base),
        "base_median": statistics.median(base),
        "candidate_median": statistics.median(candidate),
        "paired_median_change_percent": paired_median_change_percent,
        "slower_pairs": slower,
        "faster_pairs": faster,
        "p_value": p_value,
        "threshold": threshold,
        "effect_floor_percent": effect_floor_percent,
        "statistically_significant": significant,
        "material_slowdown": material,
        "regression": significant and material,
    }


# ---- measurement ---------------------------------------------------------


def _run_once(bin_path: str, argv: list[str]) -> float:
    """Return wall-clock seconds for one CLI invocation."""
    t0 = time.perf_counter()
    proc = subprocess.run(
        [bin_path, *argv],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    dt = time.perf_counter() - t0
    if proc.returncode != 0:
        raise RuntimeError(
            f"{bin_path} {' '.join(argv)} exited {proc.returncode}: "
            f"{proc.stderr[:200]!r}"
        )
    return dt


def measure_metric(
    base_bin: str,
    candidate_bin: str,
    base_argv: list[str],
    candidate_argv: list[str],
    samples: int,
) -> tuple[list[float], list[float]]:
    """Interleave paired samples (warm-then-cold alternation, oracle-style)."""
    base: list[float] = []
    candidate: list[float] = []
    for i in range(samples):
        # index -1 is a warm-up discarded by the oracle; we just don't append.
        if i % 2 == 0:
            order = [("base", base_bin, base_argv), ("candidate", candidate_bin, candidate_argv)]
        else:
            order = [("candidate", candidate_bin, candidate_argv), ("base", base_bin, base_argv)]
        times = {}
        for side, bin_path, argv in order:
            if i == 0:
                # warm-up run, not recorded
                _run_once(bin_path, argv)
                continue
            times[side] = _run_once(bin_path, argv)
        if times:
            base.append(times["base"])
            candidate.append(times["candidate"])
    return base, candidate


# ---- selftest -------------------------------------------------------------


def _selftest_cases() -> list[tuple[str, list[float], list[float], bool]]:
    """Synthetic data covering the three known verdicts.

    (label, base, candidate, expect_regression)
    """
    n = 31
    # Clear regression: candidate ~2x base, all 31 pairs slower → regression.
    big_slow = [100.0] * n
    big_slow_cand = [200.0] * n

    # No regression: equal timings → not a regression.
    equal = [100.0] * n
    equal_cand = [100.0] * n

    # Sub-floor slowdown: candidate 1.001x base → 31/0 split, statistically
    # significant, but median < 3% → not material → not a regression.
    subfloor = [100.0] * n
    subfloor_cand = [100.1] * n

    # Improvement: candidate is faster → never a regression.
    faster = [100.0] * n
    faster_cand = [50.0] * n

    # Balanced noise: half slower, half faster → not significant.
    noise = [100.0] * n
    noise_cand = [90.0, 110.0] * 15 + [100.0]

    return [
        ("clear_regression_2x", big_slow, big_slow_cand, True),
        ("equal_timings", equal, equal_cand, False),
        ("subfloor_slowdown_0.1pct", subfloor, subfloor_cand, False),
        ("candidate_faster_2x", faster, faster_cand, False),
        ("balanced_noise", noise, noise_cand, False),
    ]


def run_selftest() -> int:
    cases = _selftest_cases()
    rc = 0
    print("# perf_compare selftest")
    # Bonferroni over the case count is what gates sign-test significance here.
    metric_count = len(cases)
    for label, base, cand, expect in cases:
        result = compare_pairs(base, cand, metric_count)
        verdict = "REGRESSION" if result["regression"] else "PASS"
        expected = "REGRESSION" if expect else "PASS"
        ok = verdict == expected
        marker = "PASS" if ok else "FAIL"
        print(
            f"  [{marker}] {label}: "
            f"med={result['paired_median_change_percent']:+.3f}%  "
            f"p={result['p_value']:.2e}  "
            f"slower/faster={result['slower_pairs']}/{result['faster_pairs']}  "
            f"verdict={verdict} (expected {expected})"
        )
        if not ok:
            rc = 1
    if rc == 0:
        print("selftest OK: clear_regression detected, others PASS")
    return rc


# ---- main -----------------------------------------------------------------


# Built-in metric recipes. Each is (label, base_argv, candidate_argv).
DEFAULT_METRICS: dict[str, tuple[list[str], list[str]]] = {
    "cli_findrefs": (
        ["findrefs", "corpus/apk/workload.apk", "string", "https://"],
        ["findrefs", "corpus/apk/workload.apk", "string", "https://"],
    ),
    "cli_getclass": (
        ["getclass", "corpus/apk/workload.apk",
         "Lcom/google/android/material/timepicker/ClockFaceView;"],
        ["getclass", "corpus/apk/workload.apk",
         "Lcom/google/android/material/timepicker/ClockFaceView;"],
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base", default=str(DEFAULT_BIN),
        help="Baseline asc-rs binary (default: target/release/asc-rs.exe).",
    )
    parser.add_argument(
        "--candidate", default=str(DEFAULT_BIN),
        help="Candidate asc-rs binary (default: same as --base).",
    )
    parser.add_argument(
        "--samples", type=int, default=DEFAULT_SAMPLES,
        help=f"Paired samples per metric (default {DEFAULT_SAMPLES}, min {MIN_SAMPLES}).",
    )
    parser.add_argument(
        "--metric", action="append", default=None,
        choices=sorted(DEFAULT_METRICS),
        help="Metric to test (may repeat). Default: all built-in metrics.",
    )
    parser.add_argument(
        "--alpha", type=float, default=DEFAULT_ALPHA,
        help=f"Family-wise alpha before Bonferroni (default {DEFAULT_ALPHA}).",
    )
    parser.add_argument(
        "--effect-floor", type=float, default=DEFAULT_FLOOR,
        help=f"Median-slowdown floor in percent (default {DEFAULT_FLOOR}).",
    )
    parser.add_argument(
        "--selftest", action="store_true",
        help="Run synthetic self-check and exit.",
    )
    args = parser.parse_args()

    if args.selftest:
        return run_selftest()

    if args.samples < MIN_SAMPLES:
        parser.error(f"at least {MIN_SAMPLES} paired samples are required")

    metrics = args.metric or sorted(DEFAULT_METRICS)
    if not Path(args.base).exists():
        print(f"ERROR: --base binary not found: {args.base}", file=sys.stderr)
        return 2
    if not Path(args.candidate).exists():
        print(f"ERROR: --candidate binary not found: {args.candidate}", file=sys.stderr)
        return 2

    failures: list[str] = []
    print(f"# perf_compare: base={args.base} candidate={args.candidate} "
          f"samples={args.samples} floor={args.effect}% alpha={args.alpha}")
    for name in metrics:
        base_argv, cand_argv = DEFAULT_METRICS[name]
        try:
            base_times, cand_times = measure_metric(
                args.base, args.candidate, base_argv, cand_argv, args.samples,
            )
        except (RuntimeError, OSError) as exc:
            failures.append(f"{name}: measurement failed: {exc}")
            continue
        result = compare_pairs(
            base_times, cand_times, len(metrics),
            alpha=args.alpha, effect_floor_percent=args.effect_floor,
        )
        verdict = "REGRESSION" if result["regression"] else "ok"
        print(
            f"  {name}: med {result['paired_median_change_percent']:+.2f}%  "
            f"p={result['p_value']:.2e}  "
            f"base_med={result['base_median']*1000:.1f}ms  "
            f"cand_med={result['candidate_median']*1000:.1f}ms  "
            f"slower/faster={result['slower_pairs']}/{result['faster_pairs']}  "
            f"verdict={verdict}"
        )
        if result["regression"]:
            failures.append(
                f"{name}: significant material slowdown "
                f"({result['paired_median_change_percent']:+.2f}%)"
            )
    if failures:
        print("FAIL:", *failures, sep="\n  ", file=sys.stderr)
        return 1
    print("perf_compare OK: no material regressions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
