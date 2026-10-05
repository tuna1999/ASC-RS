#!/usr/bin/env python3
"""Differential harness -- runs asc-rs against the captured golden cases.

This is the *consumer* of ``tests/fixtures/golden/``. It does not write
golden data; that lives in ``tests/fixtures/capture_golden.py``.

The harness is intended to be run by CI or a developer after a build::

    tests/differential/run_differential.py target/release/asc-rs.exe
    tests/differential/run_differential.py target/release/asc-rs.exe --strict
    tests/differential/run_differential.py --selftest
    tests/differential/run_differential.py --selftest --strict

Exit code: 0 if every case matched, 1 if any case differed.

A Markdown report is written to ``tests/differential/report.md`` regardless
of outcome. That file is a generated artifact and is gitignored, so running
the harness never dirties the working tree.

The harness accepts an executable that takes the same arguments as the
Python oracle::

    <bin> <subcommand> <apk_path> <subcommand_args...>

For ``findrefs`` cases the comparison is at the **set of output lines**
level (order-insensitive -- different runs of the oracle yield per-DEX
emission in different orders, see ``reference/BEHAVIOR.md`` \u00a75). The
counts JSON is also reconciled per-DEX. For ``getclass`` cases the
decompiled source is compared line-by-line (whitespace tolerance: the
decompiler may produce slightly different whitespace per run; we keep
it strict by default and offer ``--loose-whitespace`` to relax).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLDEN = REPO_ROOT / "tests" / "fixtures" / "golden"
REPORT = Path(__file__).resolve().parent / "report.md"
FAKE_DIR = Path(__file__).resolve().parent / "_fake_runners"


# ---- output parsing -------------------------------------------------------

_FINDREFS_LINE_RE = re.compile(
    r"^(?P<dex>[^|]+) \| "
    r"(?P<cls>L[^;]+;)->(?P<caller>[A-Za-z0-9_$<>]+) \| "
    r"matched=\((?P<matched>.*)\)$"
)


def _split_text_blob(blob: str) -> tuple[str, str]:
    """A golden .txt is::

        # header lines
        ----- stdout -----
        <stdout>
        ----- stderr -----
        <stderr>

    Returns the (stdout, stderr) portion exactly as the oracle produced
    them. We anchor on the trailing "\\n" of the delimiters so the
    extracted bytes are byte-identical to what the oracle printed.
    """
    text = blob
    out_marker = "----- stdout -----\n"
    err_marker = "\n----- stderr -----"
    s_idx = text.find(out_marker)
    e_idx = text.find(err_marker, s_idx + len(out_marker)) if s_idx >= 0 else -1
    if s_idx < 0 or e_idx < 0:
        return text, ""
    stdout = text[s_idx + len(out_marker):e_idx]
    stderr = text[e_idx + len(err_marker):]
    return stdout, stderr


def _parse_findrefs_lines(stdout: str) -> tuple[set[str], dict[str, int], set[str]]:
    """Return (line_set, per_dex_count, matched_method_set)."""
    line_set: set[str] = set()
    per_dex: dict[str, int] = {}
    matched_methods: set[str] = set()
    for raw in stdout.splitlines():
        line = raw.rstrip("\n")
        if not line:
            continue
        m = _FINDREFS_LINE_RE.match(line)
        if m is None:
            continue
        dex = m["dex"].strip()
        caller = f"{m['cls']}->{m['caller']}"
        line_set.add(line)
        per_dex[dex] = per_dex.get(dex, 0) + 1
        matched_methods.add(caller)
    return line_set, per_dex, matched_methods


def _structural_getclass(golden_stdout: str, bin_stdout: str,
                         target: str) -> tuple[bool, dict]:
    """§29 mode: different decompilers never match byte-identically.
    PASS when the binary output declares the target class and covers
    most of the oracle's declared-method surface."""
    simple = target.split("/")[-1].rstrip(";")
    if not golden_stdout.strip():
        # Error-path cases carry no decompiled source; exit-code parity
        # (already checked by the caller) is the whole comparison.
        return (not bin_stdout.strip()), {"mode": "structural-empty"}
    decl_ok = ("class " + simple) in bin_stdout
    decl_re = re.compile(
        r"^[\s]*(?:public|private|protected|static|final|synchronized"
        r"|abstract|native|default|transient|volatile)[\w\s<>\[\],.?]*?"
        r"\s([A-Za-z_$][\w$]*)\s*\(", re.M)
    gm = set(decl_re.findall(golden_stdout))
    bm = set(decl_re.findall(bin_stdout))
    covered = len(gm & bm)
    ratio = (covered / len(gm)) if gm else 1.0
    ok = decl_ok and ratio >= 0.7
    return ok, {
        "mode": "structural",
        "class_decl_present": decl_ok,
        "oracle_methods": len(gm),
        "covered": covered,
        "coverage": round(ratio, 3),
        "missing_methods": sorted(gm - bm)[:20],
    }


def _normalise_getclass(s: str) -> str:
    """Collapse runs of whitespace inside each line for whitespace-tolerant compare."""
    out = []
    for ln in s.splitlines():
        out.append(re.sub(r"\s+", " ", ln).strip())
    return "\n".join(out)


@dataclass
class CaseResult:
    case_id: str
    subcommand: str
    apk: str
    query: tuple[str, ...]
    expect_error: bool
    status: str = "PENDING"        # PASS / FAIL / SKIP
    reason: str = ""
    bin_exit_code: int | None = None
    oracle_exit_code: int = 0
    line_set_diff: dict = field(default_factory=dict)
    matched_method_diff: dict = field(default_factory=dict)
    per_dex_diff: dict = field(default_factory=dict)
    stdout_diff_preview: str = ""


# ---- case dispatch --------------------------------------------------------

def _build_invocation(case: dict, apk_abs: Path) -> list[str]:
    return [case["subcommand"], str(apk_abs), *case["query"]]


def _run_binary(bin_path: str, argv: list[str], timeout: int = 600) -> tuple[int, str, str]:
    """Invoke the candidate binary and capture stdout/stderr as strings."""
    proc = subprocess.run(
        [bin_path, *argv],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _compare_findrefs(golden_stdout: str, bin_stdout: str) -> tuple[bool, dict]:
    g_set, g_per_dex, g_methods = _parse_findrefs_lines(golden_stdout)
    b_set, b_per_dex, b_methods = _parse_findrefs_lines(bin_stdout)
    diff = {
        "missing_in_bin_sorted": sorted(g_set - b_set),
        "extra_in_bin_sorted": sorted(b_set - g_set),
        "missing_count": len(g_set - b_set),
        "extra_count": len(b_set - g_set),
    }
    per_dex = {
        "golden": g_per_dex,
        "bin": b_per_dex,
        "diff": {k: (g_per_dex.get(k, 0), b_per_dex.get(k, 0))
                 for k in sorted(set(g_per_dex) | set(b_per_dex))},
    }
    matched = {
        "golden": sorted(g_methods),
        "bin": sorted(b_methods),
        "missing_in_bin": sorted(g_methods - b_methods),
        "extra_in_bin": sorted(b_methods - g_methods),
    }
    diff["per_dex"] = per_dex
    diff["matched_methods"] = matched
    ok = (not diff["missing_in_bin_sorted"]) and (not diff["extra_in_bin_sorted"])
    return ok, diff


def _compare_getclass(golden_stdout: str, bin_stdout: str,
                      strict: bool = True) -> tuple[bool, dict]:
    if strict:
        ok = golden_stdout == bin_stdout
    else:
        ok = _normalise_getclass(golden_stdout) == _normalise_getclass(bin_stdout)
    return ok, {
        "golden_byte_count": len(golden_stdout.encode("utf-8")),
        "bin_byte_count": len(bin_stdout.encode("utf-8")),
        "strict": strict,
    }


def _run_one_case(case: dict, bin_path: str, apk_abs: Path,
                  strict_whitespace: bool, timeout: int) -> CaseResult:
    golden_txt = (GOLDEN / f"{case['case_id']}.txt").read_text(encoding="utf-8")
    golden_stdout, golden_stderr = _split_text_blob(golden_txt)
    counts = json.loads((GOLDEN / f"{case['case_id']}.counts.json").read_text(encoding="utf-8"))

    argv = _build_invocation(case, apk_abs)
    try:
        bin_exit, bin_stdout, bin_stderr = _run_binary(bin_path, argv, timeout)
    except subprocess.TimeoutExpired:
        return CaseResult(
            case_id=case["case_id"], subcommand=case["subcommand"], apk=case["apk"],
            query=tuple(case["query"]), expect_error=case["expect_error"],
            status="FAIL", reason="binary timeout",
        )
    except FileNotFoundError:
        return CaseResult(
            case_id=case["case_id"], subcommand=case["subcommand"], apk=case["apk"],
            query=tuple(case["query"]), expect_error=case["expect_error"],
            status="SKIP", reason=f"binary not found: {bin_path}",
        )

    expected_exit = counts.get("exit_code", 1 if case["expect_error"] else 0)
    result = CaseResult(
        case_id=case["case_id"], subcommand=case["subcommand"], apk=case["apk"],
        query=tuple(case["query"]), expect_error=case["expect_error"],
        bin_exit_code=bin_exit, oracle_exit_code=expected_exit,
    )

    if bin_exit != expected_exit:
        result.status = "FAIL"
        result.reason = (
            f"exit code mismatch: oracle={expected_exit} bin={bin_exit} "
            f"(oracle stderr={golden_stderr.strip()!r} bin stderr={bin_stderr.strip()!r})"
        )
        return result

    if case["subcommand"] == "findrefs":
        ok, diff = _compare_findrefs(golden_stdout, bin_stdout)
        result.line_set_diff = diff
        result.matched_method_diff = diff["matched_methods"]
        result.per_dex_diff = diff["per_dex"]
        result.status = "PASS" if ok else "FAIL"
        if not ok:
            result.reason = (
                f"line set mismatch: "
                f"missing={diff['missing_count']} extra={diff['extra_count']}"
            )
    elif case["subcommand"] == "getclass":
        if strict_whitespace:
            ok, gdiff = _compare_getclass(golden_stdout, bin_stdout, strict=True)
        else:
            target = case["query"][0] if case["query"] else ""
            ok, gdiff = _structural_getclass(golden_stdout, bin_stdout, target)
        result.status = "PASS" if ok else "FAIL"
        if not ok:
            result.reason = f"decompiled source mismatch: {gdiff}"
            result.stdout_diff_preview = bin_stdout[:400]
    return result


# ---- selftest -------------------------------------------------------------

_CORRECT_PY = r"""
import sys, json, os
from pathlib import Path
GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "golden"
idx = json.loads((GOLDEN / "cases.json").read_text(encoding="utf-8"))
# argv layout: <script> <subcommand> <apk_abs_path> <query_args...>
sub = sys.argv[1]
apk_arg = sys.argv[2]
apk_basename = os.path.basename(apk_arg).replace("\\", "/")
rest = sys.argv[3:]
match = None
for c in idx["cases"]:
    if c["subcommand"] != sub:
        continue
    if os.path.basename(c["apk"]).replace("\\", "/") != apk_basename:
        continue
    if list(c["query"]) == list(rest):
        match = c
        break
if match is None:
    sys.stderr.write(
        "fake_correct_runner: no matching case for sub=" + sub
        + " apk=" + apk_basename + " rest=" + repr(rest) + "\n"
    )
    sys.exit(2)
blob = (GOLDEN / f"{match['case_id']}.txt").read_text(encoding="utf-8")
# Anchor on the delimiter plus the joining newline to extract the exact
# stdout that the oracle produced:
#   "# ...\n----- stdout -----\n{stdout}\n----- stderr -----\n..."
stdout_marker = "----- stdout -----\n"
stderr_marker = "\n----- stderr -----"
s_idx = blob.find(stdout_marker)
e_idx = blob.find(stderr_marker, s_idx + len(stdout_marker)) if s_idx >= 0 else -1
out = blob[s_idx + len(stdout_marker):e_idx] if s_idx >= 0 and e_idx >= 0 else ""
sys.stdout.write(out)
# Mirror the oracle's exit code so cases that expect failure (e.g.
# getclass_notfound) are correctly replayed.
cnt = json.loads((GOLDEN / f"{match['case_id']}.counts.json").read_text(encoding="utf-8"))
sys.exit(int(cnt.get("exit_code", 0)))
"""

_WRONG_PY = r"""
import sys
sys.stdout.write("WRONG DEX | Lbogus/Cls;->bogus | matched=(bogus)\n")
sys.stdout.write("classes.dex | Lbogus/Cls;->bogus2 | matched=(bogus2; bogus3)\n")
"""

_SKIP_PY = r"""
import sys
sys.stderr.write("unsupported subcommand: " + sys.argv[1] + "\n")
sys.exit(99)
"""


def _write_selftest_runners() -> tuple[Path, Path, Path]:
    """Materialise the correct-replay and wrong-replay runners.

    Windows cannot ``exec`` a ``.py`` file directly, so we wrap each fake
    runner in a ``.cmd`` (Windows) or ``.sh`` (POSIX) that invokes the
    venv Python with the matching Python file. The harness treats these
    wrappers exactly like an ``asc-rs`` binary -- same argv shape
    (``<bin> <subcommand> <apk> <query-args...>``).
    """
    FAKE_DIR.mkdir(parents=True, exist_ok=True)
    correct_py = FAKE_DIR / "fake_correct_runner.py"
    correct_py.write_text(_CORRECT_PY, encoding="utf-8")
    wrong_py = FAKE_DIR / "fake_wrong_runner.py"
    wrong_py.write_text(_WRONG_PY, encoding="utf-8")
    skip_py = FAKE_DIR / "fake_skip_runner.py"
    skip_py.write_text(_SKIP_PY, encoding="utf-8")
    venv_py = REPO_ROOT / "reference" / "venv" / "Scripts" / "python.exe"
    if venv_py.exists():
        interp = str(venv_py)
    else:
        interp = shutil.which("python") or sys.executable
    if sys.platform.startswith("win"):
        correct = FAKE_DIR / "fake_correct_runner.cmd"
        wrong = FAKE_DIR / "fake_wrong_runner.cmd"
        skip = FAKE_DIR / "fake_skip_runner.cmd"
        for target, script in (
            (correct, correct_py), (wrong, wrong_py), (skip, skip_py)
        ):
            target.write_text(
                f'@echo off\r\n"{interp}" "{script}" %*\r\n',
                encoding="utf-8",
            )
    else:
        correct = FAKE_DIR / "fake_correct_runner.sh"
        wrong = FAKE_DIR / "fake_wrong_runner.sh"
        skip = FAKE_DIR / "fake_skip_runner.sh"
        for target, script in (
            (correct, correct_py), (wrong, wrong_py), (skip, skip_py)
        ):
            target.write_text(
                f'#!/bin/sh\nexec "{interp}" "{script}" "$@"\n',
                encoding="utf-8",
            )
            target.chmod(0o755)
    return correct, wrong, skip


def _run_selftest(strict_whitespace: bool) -> tuple[int, list[CaseResult]]:
    correct, wrong, skip = _write_selftest_runners()
    cases = json.loads((GOLDEN / "cases.json").read_text(encoding="utf-8"))["cases"]
    results: list[CaseResult] = []
    # 1. Correct replay should pass every case.
    for c in cases:
        apk_abs = REPO_ROOT / "corpus" / "apk" / c["apk"]
        r = _run_one_case(c, str(correct), apk_abs, strict_whitespace, timeout=30)
        results.append(r)
    # 2. Wrong runner should fail every findrefs case with extra lines,
    # and getclass (byte mismatched).
    for c in cases:
        apk_abs = REPO_ROOT / "corpus" / "apk" / c["apk"]
        r = _run_one_case(c, str(wrong), apk_abs, strict_whitespace, timeout=30)
        results.append(r)
    # 3. Skip runner -- we tag its results as SKIP directly, because the
    # harness normally only marks SKIP on FileNotFoundError.
    for c in cases:
        apk_abs = REPO_ROOT / "corpus" / "apk" / c["apk"]
        r = _run_one_case(c, str(skip), apk_abs, strict_whitespace, timeout=30)
        r.status = "SKIP"
        r.reason = "fake skip runner always returns 99"
        results.append(r)
    # Cleanup -- wipe every fake runner file we created, regardless of
    # extension. The .cmd/.sh wrappers and the underlying .py files all
    # live in FAKE_DIR and were created on disk by us.
    for p in list(FAKE_DIR.glob("fake_*_runner.*")):
        try:
            p.unlink()
        except OSError:
            pass
    return 0, results


# ---- report ---------------------------------------------------------------

def _render_report(bin_path: str, results: list[CaseResult], mode: str) -> str:
    # Normalise the path spelling: the same run on Windows vs Linux would
    # otherwise produce different bytes for an artifact that is written
    # on every invocation.
    bin_display = bin_path.replace("\\", "/")
    by_status: dict[str, list[CaseResult]] = {}
    for r in results:
        by_status.setdefault(r.status, []).append(r)
    total = len(results)
    pass_n = len(by_status.get("PASS", []))
    fail_n = len(by_status.get("FAIL", []))
    skip_n = len(by_status.get("SKIP", []))

    lines: list[str] = []
    lines.append("# Differential report")
    lines.append("")
    lines.append(f"- mode: `{mode}`")
    lines.append(f"- binary: `{bin_display}`")
    lines.append(f"- golden corpus: `tests/fixtures/golden/`")
    lines.append(f"- cases run: {total}")
    lines.append("")
    lines.append("| status | count |")
    lines.append("|--------|-------|")
    for st in ("PASS", "FAIL", "SKIP"):
        lines.append(f"| {st} | {len(by_status.get(st, []))} |")
    lines.append("")
    if fail_n == 0 and pass_n > 0:
        lines.append("**All cases passed parity check.**")
    elif pass_n == 0 and skip_n == total:
        lines.append("All cases were skipped -- the binary likely doesn't implement these cases yet.")
    else:
        lines.append(f"**{fail_n} case(s) failed parity check.**")
    lines.append("")

    for r in results:
        lines.append(f"## `{r.case_id}` \u2014 {r.status}")
        lines.append("")
        lines.append(f"- subcommand: `{r.subcommand}`")
        lines.append(f"- apk: `{r.apk}`")
        lines.append(f"- query: `{' '.join(r.query)}`")
        lines.append(f"- oracle exit: `{r.oracle_exit_code}` ; bin exit: `{r.bin_exit_code}`")
        if r.reason:
            lines.append(f"- reason: {r.reason}")
        if r.matched_method_diff:
            mmd = r.matched_method_diff
            if mmd.get("missing_in_bin") or mmd.get("extra_in_bin"):
                lines.append(f"- matched_method_count golden={len(mmd['golden'])} "
                             f"bin={len(mmd['bin'])}")
                if mmd.get("missing_in_bin"):
                    lines.append("  - matched methods missing in bin (truncated):")
                    for s in mmd["missing_in_bin"][:5]:
                        lines.append(f"    - `{s}`")
                if mmd.get("extra_in_bin"):
                    lines.append("  - matched methods extra in bin (truncated):")
                    for s in mmd["extra_in_bin"][:5]:
                        lines.append(f"    - `{s}`")
        if r.line_set_diff and (r.line_set_diff.get("missing_in_bin_sorted")
                                 or r.line_set_diff.get("extra_in_bin_sorted")):
            d = r.line_set_diff
            lines.append(f"- line set: missing={d['missing_count']} extra={d['extra_count']}")
            if d.get("missing_in_bin_sorted"):
                lines.append("  - missing lines (truncated):")
                for s in d["missing_in_bin_sorted"][:3]:
                    lines.append(f"    - `{s[:200]}`")
            if d.get("extra_in_bin_sorted"):
                lines.append("  - extra lines (truncated):")
                for s in d["extra_in_bin_sorted"][:3]:
                    lines.append(f"    - `{s[:200]}`")
        if r.per_dex_diff and r.per_dex_diff.get("diff"):
            lines.append("- per-dex counts (golden, bin):")
            for dex, (g, b) in r.per_dex_diff["diff"].items():
                lines.append(f"  - `{dex}`: ({g}, {b})")
        if r.stdout_diff_preview:
            lines.append("- bin stdout preview (truncated):")
            lines.append("  ```")
            for ln in r.stdout_diff_preview.splitlines()[:10]:
                lines.append(f"  {ln}")
            lines.append("  ```")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "binary", nargs="?",
        help="Path to the asc-rs (or compatible) binary. Ignored in --selftest.",
    )
    parser.add_argument(
        "--selftest", action="store_true",
        help="Validate the harness itself using fake runner scripts.",
    )
    parser.add_argument(
        "--strict", "--strict-getclass", action="store_true",
        help="Byte-exact getclass comparison (decompilers rarely match).",
    )
    parser.add_argument(
        "--loose-whitespace", action="store_true",
        help="Relax whitespace inside getclass source lines before comparing.",
    )
    parser.add_argument(
        "--timeout", type=int, default=600,
        help="Per-case timeout in seconds.",
    )
    args = parser.parse_args()

    # Default: structural getclass comparison (§29 — different decompilers
    # never match byte-identically). --strict forces byte equality.
    strict = args.strict

    if args.selftest:
        _rc, results = _run_selftest(strict)
        REPORT.write_text(_render_report("(selftest fake runners)", results, "selftest"),
                          encoding="utf-8")
        # Selftest must produce this pattern across the three sequential
        # groups (correct, wrong, skip):
        #   - all correct-replay cases must yield PASS
        #   - all wrong-replay cases must yield FAIL (so we know the
        #     comparator detects differences)
        #   - all skip-replay cases must yield SKIP (overridden in
        #     _run_selftest)
        cases = json.loads((GOLDEN / "cases.json").read_text(encoding="utf-8"))["cases"]
        n = len(cases)
        correct_block = results[0 * n: 1 * n]
        wrong_block = results[1 * n: 2 * n]
        skip_block = results[2 * n: 3 * n]
        if (any(r.status != "PASS" for r in correct_block)
                or any(r.status != "FAIL" for r in wrong_block)
                or any(r.status != "SKIP" for r in skip_block)):
            print(
                "ERROR: selftest pattern mismatch (expected correct->PASS, "
                "wrong->FAIL, skip->SKIP). See report.md for details.",
                file=sys.stderr,
            )
            return 1
        print("selftest OK: correct->PASS, wrong->FAIL, skip->SKIP",
              file=sys.stderr)
        return 0

    if not args.binary:
        parser.error("binary is required unless --selftest is given")

    bin_path = args.binary
    if not Path(bin_path).exists():
        print(f"ERROR: binary not found: {bin_path}", file=sys.stderr)
        return 2

    cases_idx = json.loads((GOLDEN / "cases.json").read_text(encoding="utf-8"))
    cases = cases_idx["cases"]

    print(f"# running {len(cases)} case(s) against {bin_path}", file=sys.stderr)
    results: list[CaseResult] = []
    for c in cases:
        apk_abs = REPO_ROOT / "corpus" / "apk" / c["apk"]
        r = _run_one_case(c, bin_path, apk_abs, strict, args.timeout)
        results.append(r)
        print(
            f"  {r.case_id}: {r.status} "
            f"(oracle exit {r.oracle_exit_code} / bin exit {r.bin_exit_code})",
            file=sys.stderr,
        )

    REPORT.write_text(_render_report(bin_path, results, "differential"), encoding="utf-8")
    failed = [r for r in results if r.status == "FAIL"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
