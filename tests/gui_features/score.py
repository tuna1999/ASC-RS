#!/usr/bin/env python3
"""Deterministic ASC-RS GUI completion scoring.

Inputs:
  --manifest tests/gui_features/feature_manifest.json
  --results  results.json    # map {acceptance_id: bool} — gate author outputs

Output (stdout, machine-readable):
  METRIC gui_completion_score=<number>
  METRIC p0_parity_score=<number>
  METRIC p1_workbench_score=<number>
  METRIC p2_extension_score=<number>
  METRIC gui_acceptance_passed=<number>
  METRIC gui_acceptance_failed=<number>
  METRIC gui_acceptance_total=<number>
  METRIC gui_completion_weight_passed=<number>
  METRIC gui_completion_weight_total=<number>
  METRIC blocked_count=<number>
  METRIC missing_count=<number>
  METRIC partial_count=<number>
  METRIC complete_count=<number>
  METRIC not_applicable_count=<number>

A feature counts as PASS only when its `acceptance` identifier maps to
`true` in `--results`. Code presence alone does not count.

Exit code is 0 unless the inputs are malformed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict


# ----- helpers --------------------------------------------------------

def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        print(f"score: missing input: {exc.filename}", file=sys.stderr)
        raise SystemExit(2)
    except json.JSONDecodeError as exc:
        print(f"score: invalid JSON in {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)


def _status_counts(features: list[dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {
        "COMPLETE": 0,
        "PARTIAL": 0,
        "MISSING": 0,
        "BLOCKED": 0,
        "NOT_APPLICABLE": 0,
    }
    for f in features:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    return counts


# ----- core ------------------------------------------------------------


def score(manifest: dict, results: Dict[str, bool]) -> Dict[str, int | float]:
    features = manifest["features"]
    weights = manifest["weights"]

    # Bucket sums (only `applicable: true` features count toward completion).
    passed_weight_by_prio: Dict[str, int] = {"P0": 0, "P1": 0, "P2": 0, "polish": 0}
    total_weight_by_prio: Dict[str, int] = {"P0": 0, "P1": 0, "P2": 0, "polish": 0}
    passed_total_weight = 0
    total_weight = 0
    acceptance_passed = 0
    acceptance_failed = 0
    acceptance_total = 0

    for f in features:
        prio = f["priority"]
        w = int(f["weight"])
        applicable = bool(f.get("applicable", True))
        acceptance = f.get("acceptance") or "n/a"

        if applicable:
            total_weight_by_prio[prio] = total_weight_by_prio.get(prio, 0) + w
            total_weight += w
            # Count every acceptance-id probe against the gate totals.
            acceptance_total += 1
            passed = bool(results.get(acceptance, False))
            if passed:
                passed_weight_by_prio[prio] = passed_weight_by_prio.get(prio, 0) + w
                passed_total_weight += w
                acceptance_passed += 1
            else:
                acceptance_failed += 1

    def _pct(num: int, den: int) -> float:
        if den == 0:
            return 0.0
        return round((num / den) * 100, 2)

    return {
        "gui_completion_score": _pct(passed_total_weight, total_weight),
        "p0_parity_score": _pct(passed_weight_by_prio.get("P0", 0), total_weight_by_prio.get("P0", 0)),
        "p1_workbench_score": _pct(passed_weight_by_prio.get("P1", 0), total_weight_by_prio.get("P1", 0)),
        "p2_extension_score": _pct(passed_weight_by_prio.get("P2", 0), total_weight_by_prio.get("P2", 0)),
        "polish_score": _pct(passed_weight_by_prio.get("polish", 0), total_weight_by_prio.get("polish", 0)),
        "gui_completion_weight_passed": passed_total_weight,
        "gui_completion_weight_total": total_weight,
        "gui_acceptance_passed": acceptance_passed,
        "gui_acceptance_failed": acceptance_failed,
        "gui_acceptance_total": acceptance_total,
        **_status_counts(features),
    }


# ----- CLI -------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--manifest",
        default="tests/gui_features/feature_manifest.json",
        type=Path,
        help="Path to feature_manifest.json",
    )
    parser.add_argument(
        "--results",
        type=Path,
        required=True,
        help="Path to results.json (map {acceptance_id: bool})",
    )
    args = parser.parse_args()

    manifest = _load_json(args.manifest)
    results_doc = _load_json(args.results)
    results_map: Dict[str, bool] = {k: bool(v) for k, v in results_doc.items()}

    s = score(manifest, results_map)
    for key, value in s.items():
        # All metrics emitted on stdout; harness greps METRIC lines.
        print(f"METRIC {key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
