#!/usr/bin/env python3
"""API-35 URI-relative-filter-group oracle differential (roadmap 5.4 / 5.6).

Drives the asc-rs evaluator over `tests/fixtures/uri_match_cases.json` and
compares the three-valued verdict with each case's `source_expected` (derived
from the pinned AOSP android-15.0.0_r1 source). When `--oracle <file>` is
given, it also diffs against a real Android API-35 oracle verdict file
(produced by `reference/oracle/uri_match/UriOracle.java` under Robolectric),
format `{ "case_id": "matches|cannot_match|unknown", ... }`.

No Android SDK is required to run this script in regression mode; the oracle
column stays PENDING until a framework oracle file is supplied. Without an
oracle file the script never claims Android equivalence — those rows are
reported as `oracle=PENDING`.

Usage (from repo root, with asc-rs workspace buildable):
  python tests/differential/run_uri_oracle.py
  python tests/differential/run_uri_oracle.py --oracle query/oracle_verdicts.json
  python tests/differential/run_uri_oracle.py --binary target/release/asc-rs.exe
Exit codes: 0 = asc-rs matches source_expected (and oracle if given); 1 = any mismatch.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "uri_match_cases.json"


def run_eval_uri(fixtures: Path) -> dict[str, str]:
    """Run the asc-manifest eval_uri example, return {case_id: verdict}."""
    res = subprocess.run(
        ["cargo", "run", "-q", "--manifest-path", str(REPO_ROOT / "Cargo.toml"),
         "-p", "asc-manifest", "--example", "eval_uri", "--", str(fixtures)],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=600,
    )
    if res.returncode != 0:
        print(res.stderr, file=sys.stderr)
        raise SystemExit(f"eval_uri failed (rc={res.returncode})")
    out: dict[str, str] = {}
    for line in res.stdout.splitlines():
        if "\t" in line:
            cid, verdict, *_ = line.split("\t")
            out[cid] = verdict
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixtures", default=str(FIXTURES))
    ap.add_argument("--oracle", default=None, help="JSON file {case_id: verdict}")
    args = ap.parse_args()

    cases = json.loads(Path(args.fixtures).read_text(encoding="utf-8"))["cases"]
    asc = run_eval_uri(Path(args.fixtures))
    oracle = None
    if args.oracle:
        oracle = json.loads(Path(args.oracle).read_text(encoding="utf-8"))

    fails, pending = 0, 0
    print(f"{'case':<34}{'uri':<40}{'asc-rs':<13}{'expected':<12}{'oracle':<12}status")
    for c in cases:
        cid, uri, exp = c["case_id"], c["uri"], c["source_expected"]
        got = asc.get(cid, "?")
        exp_ok = got == exp
        orc = "PENDING" if oracle is None else oracle.get(cid, "?")
        orc_ok = (oracle is None) or (orc == got and orc != "?")
        status = "OK"
        if not exp_ok:
            status = "SOURCE-MISMATCH"
        elif not orc_ok:
            status = "ORACLE-MISMATCH"
        elif orc == "PENDING":
            status = "ORACLE-PENDING" if exp == "unknown" else "OK(regression)"
            pending += 1 if orc == "PENDING" else 0
        if not exp_ok or not orc_ok:
            fails += 1
        print(f"{cid:<34}{uri[:38]:<40}{got:<13}{exp:<12}{orc:<12}{status}")

    print(f"\n{len(cases)} cases; {fails} failed; {pending} oracle rows still PENDING.")
    if fails:
        print("ERROR: asc-rs (or the oracle where supplied) diverges — see above.",
              file=sys.stderr)
        return 1
    if oracle is None:
        print("NOTE: no --oracle file supplied; Android-equivalence rows remain UNVERIFIED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
