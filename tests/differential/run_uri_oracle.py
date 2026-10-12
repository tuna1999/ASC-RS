#!/usr/bin/env python3
"""API-35 URI-relative-filter-group oracle differential (roadmap 5.4 / 5.6).

Drives the asc-rs evaluator over `tests/fixtures/uri_match_cases.json` and
compares the three-valued verdict with each case's `source_expected` (derived
from the pinned AOSP android-15.0.0_r1 source). When `--oracle <file>` is
given, it also diffs against a real Android API-35 oracle verdict file
(produced by `reference/oracle/uri_match` under Gradle + Robolectric),
format `{ "verdicts": { case_id: "matches|cannot_match" }, "provenance": {...} }`
(a bare `{ case_id: verdict }` map is also accepted).

No Android SDK is required in regression (no-oracle) mode. The report is
explicit about what was and was not verified:

  REGRESSION-OK  verdict equals source_expected (engine self-consistent)
  UNVERIFIED     regression-ok but never diffed against a framework oracle
  UNSUPPORTED    asc-rs deliberately returns `unknown` (glob / opaque /
                 bound overflow); its real Android answer is oracle-pending
  NOT_RUN        no --oracle file supplied
  SOURCE-MISMATCH / ORACLE-MISMATCH   genuine divergence

Skipped oracle rows are NEVER counted as verified passes.

Usage (from repo root, with asc-rs workspace buildable):
  python tests/differential/run_uri_oracle.py
  python tests/differential/run_uri_oracle.py --oracle reference/oracle/uri_match/build/oracle_verdicts.json
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


def load_oracle(path: str):
    """Return (verdicts: dict, provenance: dict) for an oracle report file."""
    j = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(j, dict) and "verdicts" in j:
        return j["verdicts"], j.get("provenance", {})
    # Backwards-compatible bare { case_id: verdict } map.
    return j, {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixtures", default=str(FIXTURES))
    ap.add_argument("--oracle", default=None, help="JSON report {verdicts, provenance}")
    args = ap.parse_args()

    cases = json.loads(Path(args.fixtures).read_text(encoding="utf-8"))["cases"]
    asc = run_eval_uri(Path(args.fixtures))

    # Fail on structural errors in the fixture/harness contract before any
    # verdict is judged (Phase 5): duplicate required IDs, a fixture ID the
    # evaluator did not produce (missing result row), or stray output rows.
    ids = [c["case_id"] for c in cases]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    missing = [i for i in ids if i not in asc]
    extra = sorted(set(asc) - set(ids))
    if dupes or missing or extra:
        if dupes:
            print(f"ERROR: duplicate case_id(s) in fixture: {dupes}", file=sys.stderr)
        if missing:
            print(f"ERROR: eval_uri produced no row for fixture case_id(s): {missing}",
                  file=sys.stderr)
        if extra:
            print(f"ERROR: eval_uri emitted unexpected case_id(s): {extra}",
                  file=sys.stderr)
        return 1

    oracle = None
    provenance = {}
    if args.oracle:
        oracle, provenance = load_oracle(args.oracle)

    n_source_fail = n_oracle_fail = 0
    n_not_run = n_unsupported = n_verified_unknown = 0
    print(f"{'case':<34}{'uri':<40}{'asc-rs':<13}{'expected':<12}{'oracle':<12}status")
    for c in cases:
        cid, uri, exp = c["case_id"], c["uri"], c["source_expected"]
        got = asc.get(cid, "?")
        exp_ok = got == exp
        orc = "NOT_RUN" if oracle is None else oracle.get(cid, "?")
        if oracle is None:
            # No framework evidence: never a verified pass.
            if not exp_ok:
                status = "SOURCE-MISMATCH"
            elif exp == "unknown":
                status = "REGRESSION-OK(UNSUPPORTED)"
                n_unsupported += 1
            else:
                status = "REGRESSION-OK(UNVERIFIED)"
                n_not_run += 1
            if not exp_ok:
                n_source_fail += 1
        else:
            src_ok = exp_ok
            orc_ok = (orc == got and orc != "?")
            if not src_ok:
                status = "SOURCE-MISMATCH"
                n_source_fail += 1
            elif orc_ok:
                status = "ORACLE-CONFIRMED"
                if exp == "unknown":
                    n_verified_unknown += 1
            else:
                # asc-rs `unknown` vs a deterministic framework answer is a
                # REAL finding (glob/oracle-open), never "the oracle also says
                # unknown".
                status = "ORACLE-MISMATCH"
                n_oracle_fail += 1
        print(f"{cid:<34}{uri[:38]:<40}{got:<13}{exp:<12}{orc:<12}{status}")

    print(f"\n{len(cases)} cases; {n_source_fail} source-mismatches; "
          f"{n_oracle_fail} oracle-mismatches.")
    if oracle is not None:
        print(f"  oracle file: {args.oracle}")
        if provenance:
            p = provenance
            print(f"  provenance: framework={p.get('framework')} api_level={p.get('api_level')} "
                  f"flag_mechanism={p.get('flag_mechanism')} "
                  f"flag_assumed_on={p.get('flag_assumed_on')} "
                  f"status={p.get('status')}")
        print(f"  {n_verified_unknown} oracle-confirmed rows; "
              f"{n_unsupported} asc-rs `unknown` rows surfaced against the oracle.")
    else:
        print(f"  oracle NOT_RUN ({n_not_run} rows UNVERIFIED, "
              f"{n_unsupported} rows UNSUPPORTED).")
        print("  NOTE: no --oracle file supplied; Android-equivalence rows "
              "remain UNVERIFIED. Skipped oracle rows are NOT verified passes.")

    if n_source_fail or n_oracle_fail:
        print("ERROR: asc-rs (or the oracle where supplied) diverges — see above.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
