#!/usr/bin/env python3
"""Capture golden outputs from the Python oracle.

This script is the *single source* for everything in
`tests/fixtures/golden/`. Re-running it with the same corpus should produce
byte-identical output (Python oracle is deterministic given the pinned
commit). It is also responsible for the `cases.json` index that the
differential harness consumes.

Usage::

    reference/venv/Scripts/python.exe tests/fixtures/capture_golden.py
    reference/venv/Scripts/python.exe tests/fixtures/capture_golden.py --filter findrefs_string_workload

Running this script writes:

- ``golden/<case_id>.txt``         raw stdout (+ stderr) for that case
- ``golden/<case_id>.counts.json`` machine-readable per-DEX hit counts and
                                   the set of matched caller method ids
- ``golden/cases.json``            index of every captured case

The oracle is invoked from ``reference/asc/`` because ``main.py`` does its
imports via the implicit ``src.`` package root and the venv's
``site-packages`` for ``androguard``.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VENV_PY = REPO_ROOT / "reference" / "venv" / "Scripts" / "python.exe"
ASC_ROOT = REPO_ROOT / "reference" / "asc"
ASC_MAIN = ASC_ROOT / "main.py"
CORPUS_APK = REPO_ROOT / "corpus" / "apk"
GOLDEN = Path(__file__).resolve().parent / "golden"

# Per-class output line: "<dex> | <caller_cls;>-><caller_name> | matched=(... )"
_LINE_RE = re.compile(
    r"^(?P<dex>[^|]+) \| "
    r"(?P<cls>L[^;]+;)->(?P<caller>[A-Za-z0-9_$<>]+) \| "
    r"matched=\((?P<matched>.*)\)$"
)


@dataclasses.dataclass(frozen=True)
class Case:
    """One oracle invocation."""

    case_id: str
    apk: str                # path relative to corpus/apk/
    subcommand: str         # "findrefs" or "getclass"
    query: tuple[str, ...]  # argv after the apk (or after apk + class for getclass)
    description: str
    expect_error: bool = False

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "apk": self.apk,
            "subcommand": self.subcommand,
            "query": list(self.query),
            "description": self.description,
            "expect_error": self.expect_error,
        }


# The matrix below is the *contractual* list. Adding cases requires
# re-running this script and updating the parity matrix in
# tests/compatibility/parity_matrix.md. The case_id is the file basename.
CASES: list[Case] = [
    # ---- single-dex fixture (workload.apk) ----
    Case(
        case_id="findrefs_string_workload",
        apk="workload.apk",
        subcommand="findrefs",
        query=("string", "Context"),
        description="Find every caller of a const-string opcode whose payload contains 'Context' (substring).",
    ),
    Case(
        case_id="findrefs_type_workload",
        apk="workload.apk",
        subcommand="findrefs",
        query=("type", "ClockFaceView"),
        description="Find every caller that uses a type whose descriptor contains 'ClockFaceView' (substring, fuzzy type).",
    ),
    Case(
        case_id="findrefs_method_workload",
        apk="workload.apk",
        subcommand="findrefs",
        query=("method", "onClick"),
        description="Find every caller of a method named '*onClick*' across all classes.",
    ),
    Case(
        case_id="findrefs_method_precise_workload",
        apk="workload.apk",
        subcommand="findrefs",
        query=("method", "onLayout",
               "--class", "Lcom/google/android/material/timepicker/ClockFaceView;"),
        description="Find every caller of method 'onLayout' only on ClockFaceView (precise class).",
    ),
    Case(
        case_id="findrefs_field_workload",
        apk="workload.apk",
        subcommand="findrefs",
        query=("field", "textColor"),
        description="Find every caller of a field whose name contains 'textColor' across all classes.",
    ),
    Case(
        case_id="findrefs_field_fuzzy_class_workload",
        apk="workload.apk",
        subcommand="findrefs",
        query=("field", "gradientColors",
               "--class", "ClockFaceView", "--fuzzy-class"),
        description="Find every caller of field 'gradientColors' on classes whose descriptor contains 'ClockFaceView'.",
    ),
    Case(
        case_id="getclass_clockface_workload",
        apk="workload.apk",
        subcommand="getclass",
        query=("Lcom/google/android/material/timepicker/ClockFaceView;",),
        description="Decompile ClockFaceView and emit the Java-like source the oracle produces.",
    ),
    # ---- multidex fixture (Aurora Store) ----
    Case(
        case_id="findrefs_string_aurora",
        apk="com.aurora.store_60.apk",
        subcommand="findrefs",
        query=("string", "https://"),
        description="Find every URL-bearing string constant. Exercises central-directory scan + per-DEX iteration.",
    ),
    Case(
        case_id="findrefs_type_aurora",
        apk="com.aurora.store_60.apk",
        subcommand="findrefs",
        query=("type", "Fragment"),
        description="Find every caller referencing a type whose descriptor contains 'Fragment' (substring).",
    ),
    Case(
        case_id="findrefs_method_aurora",
        apk="com.aurora.store_60.apk",
        subcommand="findrefs",
        query=("method", "onClick"),
        description="Find every caller of a method named '*onClick*' across both DEX entries.",
    ),
    # ---- multidex fixture (F-Droid), larger ----
    Case(
        case_id="findrefs_string_fdroid",
        apk="org.fdroid.fdroid_1016000.apk",
        subcommand="findrefs",
        query=("string", "https://"),
        description="Same query on the larger F-Droid APK; checks scaling of per-DEX iteration.",
    ),
    # ---- edge case: nonexistent class for getclass ----
    Case(
        case_id="getclass_notfound",
        apk="workload.apk",
        subcommand="getclass",
        query=("Lno/such/Class;",),
        description=("Oracle should print 'Error: Class ... not found in APK.' "
                     "to stderr, exit 1, and emit no source."),
        expect_error=True,
    ),
]


def _argv_for(case: Case, apk_abs: Path) -> list[str]:
    return [str(VENV_PY), str(ASC_MAIN), case.subcommand, str(apk_abs), *case.query]


def run_case(case: Case) -> tuple[int, str, str]:
    """Run one oracle case. Returns (exit_code, stdout, stderr)."""
    apk_abs = CORPUS_APK / case.apk
    if not apk_abs.exists():
        raise FileNotFoundError(f"APK missing: {apk_abs}")

    argv = _argv_for(case, apk_abs)
    proc = subprocess.run(
        argv,
        cwd=str(ASC_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    return proc.returncode, proc.stdout, proc.stderr


def parse_findrefs(stdout: str) -> dict:
    """Walk the oracle stdout and produce a counts index."""
    per_dex: dict[str, list[dict]] = {}
    matched_methods: set[str] = set()
    for line in stdout.splitlines():
        line = line.rstrip("\n")
        if not line:
            continue
        m = _LINE_RE.match(line)
        if m is None:
            # Anything that does not match the expected line shape is
            # treated as a debug overlay (--debug) and skipped.
            continue
        dex = m["dex"].strip()
        caller = f"{m['cls']}->{m['caller']}"
        matched = m["matched"]
        per_dex.setdefault(dex, []).append({
            "caller": caller,
            "matched": matched,
        })
        matched_methods.add(caller)
    return {
        "line_count": sum(len(v) for v in per_dex.values()),
        "dex_count": len(per_dex),
        "matched_method_count": len(matched_methods),
        "matched_methods_sorted": sorted(matched_methods),
        "per_dex_count": {k: len(v) for k, v in sorted(per_dex.items())},
    }


def write_case(case: Case, exit_code: int, stdout: str, stderr: str) -> dict:
    """Persist the case artifacts and return the counts index."""
    GOLDEN.mkdir(parents=True, exist_ok=True)
    txt_path = GOLDEN / f"{case.case_id}.txt"
    cnt_path = GOLDEN / f"{case.case_id}.counts.json"

    # .txt contains the literal observation: stdout then stderr (separated
    # by a recognisable delimiter so consumers can split them back out).
    body_parts = [
        f"# oracle exit_code: {exit_code}",
        f"# case_id: {case.case_id}",
        "----- stdout -----",
        stdout,
    ]
    if stdout and not stdout.endswith("\n"):
        body_parts.append("")
    body_parts.append("----- stderr -----")
    body_parts.append(stderr)
    body = "\n".join(body_parts) + "\n"
    txt_path.write_text(body, encoding="utf-8")

    if case.subcommand == "findrefs":
        counts = parse_findrefs(stdout)
    elif case.subcommand == "getclass":
        body_lines = [ln for ln in stdout.splitlines() if ln.strip()]
        counts = {
            "stdout_line_count": len(body_lines),
            "stdout_byte_count": len(stdout.encode("utf-8")),
            "stderr_byte_count": len(stderr.encode("utf-8")),
            "exit_code": exit_code,
        }
    else:
        counts = {"exit_code": exit_code}

    counts["case_id"] = case.case_id
    counts["apk"] = case.apk
    counts["subcommand"] = case.subcommand
    counts["query"] = list(case.query)
    counts["expect_error"] = case.expect_error
    cnt_path.write_text(json.dumps(counts, indent=2, sort_keys=True), encoding="utf-8")
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--filter", default=None,
        help="Only capture cases whose case_id matches this regex.",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List case ids and exit.",
    )
    args = parser.parse_args()

    selected = CASES
    if args.filter:
        sel = re.compile(args.filter)
        selected = [c for c in CASES if sel.search(c.case_id)]
    if args.list:
        for c in selected:
            print(c.case_id, "-", c.description)
        return 0

    if not VENV_PY.exists():
        print(f"ERROR: oracle python not found at {VENV_PY}", file=sys.stderr)
        return 2

    print(f"# capturing {len(selected)} case(s); venv={VENV_PY}", file=sys.stderr)
    summary = []
    for case in selected:
        try:
            exit_code, stdout, stderr = run_case(case)
        except subprocess.TimeoutExpired:
            print(f"  timeout: {case.case_id}", file=sys.stderr)
            return 3
        except Exception as exc:
            print(f"  failed: {case.case_id} -> {exc}", file=sys.stderr)
            return 4
        counts = write_case(case, exit_code, stdout, stderr)
        ok = (exit_code != 0) if case.expect_error else (exit_code == 0)
        line_field = "line_count" if case.subcommand == "findrefs" else "stdout_line_count"
        print(
            f"  {case.case_id}: exit={exit_code} "
            f"lines={counts.get(line_field, '?')} "
            f"matched_methods={counts.get('matched_method_count','-')} "
            f"({'ok' if ok else 'MISMATCH'})",
            file=sys.stderr,
        )
        summary.append({
            "case_id": case.case_id,
            "exit_code": exit_code,
            "expected_error": case.expect_error,
            "line_count": counts.get(line_field, 0),
            "matched_method_count": counts.get("matched_method_count", 0),
            "ok": ok,
        })

    index = {
        "oracle_commit": "ccc6bae7704f5c5ef1a7271e27314837079621fb",
        "capture_python": sys.executable,
        "case_count": len(selected),
        "cases": [c.to_dict() for c in selected],
        "summary": summary,
    }
    (GOLDEN / "cases.json").write_text(
        json.dumps(index, indent=2, sort_keys=True), encoding="utf-8"
    )
    bad = [s for s in summary if not s["ok"]]
    if bad:
        print(f"ERROR: {len(bad)} case(s) did not match expected exit code", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    sys.exit(main())
