#!/usr/bin/env python3
"""API-35 URI-relative-filter-group oracle differential (roadmap 5.4 / 5.6).

Drives the asc-rs evaluator over `tests/fixtures/uri_match_cases.json` and
compares the three-valued verdict with each case's `source_expected` (derived
from the pinned AOSP android-15.0.0_r1 source). When `--oracle <file>` is
given, it also diffs against a real Android API-35 framework-backed oracle
(produced by `reference/oracle/uri_match` under Gradle + Robolectric), whose
format is:

    { "verdicts": { case_id: "matches"|"cannot_match", ... },
      "provenance": { "framework", "api_level", "status",
                      "flag_state_actual", "flag_skipped",
                      "flag_mechanism", ... } }

A bare `{ case_id: verdict }` map is parsed only to be rejected: it carries no
provenance, so it can never confirm anything.

No Android SDK is required in regression (no-oracle) mode. The report is
explicit about what was and was not verified:

  REGRESSION-OK(UNVERIFIED)  verdict equals source_expected, never framework-run
  REGRESSION-OK(UNSUPPORTED) verdict equals source_expected == unknown (glob /
                             opaque / bound-overflow; oracle-pending)
  SOURCE-MISMATCH            asc-rs contradicts source_expected (real bug)
  ORACLE-CONFIRMED           asc-rs equals a PROVEN oracle run, on a case the
                             oracle actually exercised in its required flag state
  ORACLE-OPEN                asc-rs conservatively `unknown`; the framework
                             resolved it deterministically -- surfaced, never
                             counted as confirmed, not a passing claim
  ORACLE-MISMATCH            asc-rs deterministic verdict contradicts the oracle
  UNVERIFIED(FLAG|SKIP)      case not exercisable in the oracle build's flag
                             state; never confirmed, not a failure

Hard errors (exit 1) are raised for: missing/duplicate/unexpected oracle
verdict ids, invalid verdict values, and provenance that is missing, invalid,
or reports UNVERIFIED_SKIPPED. Skipped oracle rows are NEVER counted as
verified passes, and ORACLE-CONFIRMED is never emitted without a proven run.

Flag handling / why this is strict: the group-aware branch of AOSP
`IntentFilter.matchData` is gated by the frozen build-time aconfig flag
`Flags.relativeReferenceIntentFilters()`, which Robolectric cannot toggle at
runtime. `UriOracle` therefore reads the build's ACTUAL flag state and only
emits a verdict for a case whose required `flag_on` equals that state; every
other case lands in `provenance.flag_skipped`. Verdicts for the wrong flag
state are impossible (they are not produced), and the runner refuses to confirm
any case the oracle file does not prove it exercised in the right state.

Usage (from repo root, with asc-rs workspace buildable):
  python tests/differential/run_uri_oracle.py
  python tests/differential/run_uri_oracle.py --oracle reference/oracle/uri_match/build/oracle_verdicts.json
Exit codes: 0 = asc-rs matches source_expected (and the oracle for every case
the oracle actually exercised); 1 = any hard error or genuine mismatch.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "uri_match_cases.json"

# A verdict value outside this set means the oracle produced something
# malformed; treat as a hard error, never as an answer.
VALID_VERDICTS = {"matches", "cannot_match"}


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


def strict_json_loads(text: str):
    """json.loads that rejects duplicate keys instead of silently keeping the last."""
    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError(f"duplicate JSON key in oracle report: {k!r}")
            d[k] = v
        return d
    return json.loads(text, object_pairs_hook=no_dupes)


def load_oracle(path: str):
    """Return (verdicts: dict, provenance: dict) for an oracle report file."""
    text = Path(path).read_text(encoding="utf-8")
    j = strict_json_loads(text)
    if not isinstance(j, dict):
        raise ValueError("oracle report must be a JSON object")
    if isinstance(j.get("verdicts"), dict):
        return j["verdicts"], j.get("provenance", {})
    # Backwards-compatible bare { case_id: verdict } map (empty provenance).
    return j, {}


def validate_oracle_provenance(provenance) -> str | None:
    """Return an error message if the oracle cannot be treated as authoritative,
    else None. A file whose provenance is missing, invalid, or reports
    UNVERIFIED_SKIPPED must never produce ORACLE-CONFIRMED."""
    if not isinstance(provenance, dict) or not provenance:
        return "provenance missing/empty (bare {case:verdict} map can never confirm)"
    if provenance.get("status") != "RUN":
        return (f"provenance.status={provenance.get('status')!r} != 'RUN' "
                "(missing / UNVERIFIED_SKIPPED → not authoritative)")
    if provenance.get("framework") != "android-15.0.0_r1":
        return f"provenance.framework={provenance.get('framework')!r} != android-15.0.0_r1"
    if provenance.get("api_level") != 35:
        return f"provenance.api_level={provenance.get('api_level')!r} != 35"
    mechanism = provenance.get("flag_mechanism")
    if not mechanism or mechanism == "UNKNOWN":
        return "provenance.flag_mechanism missing or UNKNOWN (flag state not verified)"
    if not isinstance(provenance.get("flag_state_actual"), bool):
        return (f"provenance.flag_state_actual={provenance.get('flag_state_actual')!r} "
                "is not a bool (flag state not verified)")
    if not isinstance(provenance.get("flag_skipped"), list):
        return "provenance.flag_skipped missing (must be a list of skipped case ids)"
    return None


def validate_oracle_coverage(cases, oracle, provenance) -> list[str]:
    """Return hard structural errors about the oracle verdict set: a fixture
    case with no verdict that the oracle did NOT skip, an invalid verdict
    value, or an unexpected oracle id. Duplicate keys are already rejected by
    strict_json_loads."""
    ids = [c["case_id"] for c in cases]
    id_set = set(ids)
    actual = provenance["flag_state_actual"]
    skipped = set(provenance.get("flag_skipped", []))
    errors: list[str] = []
    for c in cases:
        cid = c["case_id"]
        req_flag = c.get("flag_on", True)
        if req_flag != actual or cid in skipped:
            # Not exercisable / not exercised: no verdict expected.
            continue
        if cid not in oracle:
            errors.append(f"missing oracle verdict for case {cid!r} (not skipped)")
        elif oracle[cid] not in VALID_VERDICTS:
            errors.append(f"invalid oracle verdict for case {cid!r}: {oracle[cid]!r}")
    for oid in oracle:
        if oid not in id_set:
            errors.append(f"unexpected oracle verdict id: {oid!r}")
    return errors


def classify_row(cid: str, case: dict, asc: dict, oracle, provenance):
    """Return (status, is_failure) for one case.

    Caller guarantees: when `oracle` is not None, provenance is valid and
    `validate_oracle_coverage` has passed, so every cursed case is either
    skipped (→ UNVERIFIED) or present in `oracle` with a valid value."""
    exp = case["source_expected"]
    got = asc.get(cid, "?")
    if oracle is None:
        if got != exp:
            return "SOURCE-MISMATCH", True
        if exp == "unknown":
            return "REGRESSION-OK(UNSUPPORTED)", False
        return "REGRESSION-OK(UNVERIFIED)", False

    if got != exp:
        return "SOURCE-MISMATCH", True

    req_flag = case.get("flag_on", True)
    actual = provenance["flag_state_actual"]
    if req_flag != actual or cid in provenance.get("flag_skipped", []):
        how = "FLAG" if req_flag != actual else "SKIP"
        return f"UNVERIFIED({how})", False

    orc = oracle[cid]
    if got == "unknown":
        # asc-rs conservatively declined; the framework is deterministic and
        # resolved it. Surface it, never confirm, never treat as a contradiction.
        return "ORACLE-OPEN", False
    if got == orc:
        return "ORACLE-CONFIRMED", False
    return "ORACLE-MISMATCH", True


def classify_cases(cases, asc, oracle, provenance):
    """Return (rows, summary). Rows: list of (cid, uri, got, exp, orc, status).
    summary: dict of counters. `oracle` may be None (regression mode)."""
    rows = []
    summary = dict(source_fail=0, oracle_fail=0, not_run=0, unsupported=0,
                   oracle_open=0, confirmed=0, flag_skipped=0)
    for c in cases:
        cid, uri, exp = c["case_id"], c["uri"], c["source_expected"]
        got = asc.get(cid, "?")
        orc = "NOT_RUN" if oracle is None else oracle.get(cid, "-")
        status, fail = classify_row(cid, c, asc, oracle, provenance)
        if status == "SOURCE-MISMATCH":
            summary["source_fail"] += 1
        elif status == "ORACLE-MISMATCH":
            summary["oracle_fail"] += 1
        elif status == "ORACLE-CONFIRMED":
            summary["confirmed"] += 1
        elif status == "ORACLE-OPEN":
            summary["oracle_open"] += 1
        elif status == "REGRESSION-OK(UNSUPPORTED)":
            summary["unsupported"] += 1
        elif status == "REGRESSION-OK(UNVERIFIED)":
            summary["not_run"] += 1
        elif status.startswith("UNVERIFIED("):
            summary["flag_skipped"] += 1
        rows.append((cid, uri, got, exp, orc, status))
    return rows, summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixtures", default=str(FIXTURES))
    ap.add_argument("--oracle", default=None, help="JSON report {verdicts, provenance}")
    args = ap.parse_args()

    cases = json.loads(Path(args.fixtures).read_text(encoding="utf-8"))["cases"]
    asc = run_eval_uri(Path(args.fixtures))

    # Hard structural check on the fixture/harness contract before any verdict
    # is judged: duplicate required IDs, a fixture ID the evaluator did not
    # produce (missing result row), or stray output rows.
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
        try:
            oracle, provenance = load_oracle(args.oracle)
        except ValueError as e:
            print(f"ERROR: cannot parse oracle file {args.oracle}: {e}", file=sys.stderr)
            return 1
        # Fail closed: an oracle without proven provenance can confirm nothing.
        prov_err = validate_oracle_provenance(provenance)
        if prov_err:
            print(f"ERROR: oracle {args.oracle} is not authoritative: {prov_err}",
                  file=sys.stderr)
            print("  No ORACLE-CONFIRMED row is possible from this file. "
                  "Re-run reference/oracle/uri_match with a verified flag "
                  "mechanism (see README 'Flag handling').", file=sys.stderr)
            return 1
        coverage_errors = validate_oracle_coverage(cases, oracle, provenance)
        if coverage_errors:
            for e in coverage_errors:
                print(f"ERROR: {e}", file=sys.stderr)
            return 1

    rows, summary = classify_cases(cases, asc, oracle, provenance)

    print(f"{'case':<34}{'uri':<40}{'asc-rs':<13}{'expected':<12}{'oracle':<12}status")
    for cid, uri, got, exp, orc, status in rows:
        print(f"{cid:<34}{uri[:38]:<40}{got:<13}{exp:<12}{orc:<12}{status}")

    print(f"\n{len(cases)} cases; "
          f"{summary['source_fail']} source-mismatches; "
          f"{summary['oracle_fail']} oracle-mismatches.")
    if oracle is not None:
        p = provenance
        print(f"  oracle file: {args.oracle}")
        print(f"  provenance: framework={p.get('framework')} api_level={p.get('api_level')} "
              f"status={p.get('status')} flag_state_actual={p.get('flag_state_actual')} "
              f"flag_mechanism={p.get('flag_mechanism')}")
        print(f"  {summary['confirmed']} ORACLE-CONFIRMED; "
              f"{summary['oracle_open']} ORACLE-OPEN (asc-rs `unknown` surfaced); "
              f"{summary['flag_skipped']} UNVERIFIED (flag-state not exercisable in this build).")
        if summary["confirmed"] == 0:
            print("  NOTE: 0 ORACLE-CONFIRMED — this oracle file proved no case "
                  "in its exercised flag state; do not treat any row as "
                  "Android-parity confirmed.")
    else:
        print(f"  oracle NOT_RUN ({summary['not_run']} rows UNVERIFIED, "
              f"{summary['unsupported']} rows UNSUPPORTED).")
        print("  NOTE: no --oracle file supplied; Android-equivalence rows "
              "remain UNVERIFIED. Skipped oracle rows are NOT verified passes.")

    if summary["source_fail"] or summary["oracle_fail"]:
        print("ERROR: asc-rs (or the oracle where supplied) diverges — see above.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
