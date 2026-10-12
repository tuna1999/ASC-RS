"""Regression tests for the API-35 URI oracle differential harness.

These exercise the pure judging logic in `run_uri_oracle.py` (provenance
gating, oracle-coverage validation, three-way classification) without running
cargo or requiring a framework-backed oracle. They lock in the contract:

  - invalid / missing / UNVERIFIED_SKIPPED provenance can never confirm a row;
  - a hard validation error (invalid provenance, missing/dup/unexpected oracle
    verdict, invalid verdict value) must be raised, not silently downgraded;
  - asc-rs `unknown` vs a deterministic oracle answer is ORACLE-OPEN (surfaced,
    never confirmed, not a contradiction);
  - a flag-mismatched / skipped case is UNVERIFIED, never confirmed.

Run:  python -m pytest tests/differential/test_run_uri_oracle.py
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import run_uri_oracle as uro


def case(cid, flag_on=True, exp="matches"):
    return {"case_id": cid, "uri": "https://example.com/a", "flag_on": flag_on,
            "source_expected": exp}


def prov(flag_on_state=True, skipped=(), mechanism="two-build-android-all",
         status="RUN", framework="android-15.0.0_r1", api=35,
         flag_state=None):
    if flag_state is None:
        flag_state = flag_on_state
    return {"framework": framework, "api_level": api, "status": status,
            "flag_state_actual": flag_state, "flag_skipped": list(skipped),
            "flag_mechanism": mechanism}


# --------------------------------------------------------------------------
# Provenance gating (Task 1 / Task 4): ORACLE-CONFIRMED requires proof.
# --------------------------------------------------------------------------

def test_valid_provenance_passes():
    assert uro.validate_oracle_provenance(prov()) is None


@pytest.mark.parametrize("mutate", [
    lambda p: p.clear(),                       # empty provenance
    lambda p: p.update(status="UNVERIFIED_SKIPPED"),
    lambda p: p.pop("status", None),           # missing status
    lambda p: p.update(flag_mechanism="UNKNOWN"),
    lambda p: p.pop("flag_mechanism", None),   # missing mechanism
    lambda p: p.update(framework="android-14.0.0_r1"),
    lambda p: p.update(api_level=34),
    lambda p: p.update(flag_state_actual="yes"),  # not a bool → unverified
    lambda p: p.update(flag_state_actual=None),
    lambda p: p.pop("flag_state_actual", None),
    lambda p: p.pop("flag_skipped", None),     # missing skip list
])
def test_invalid_provenance_rejected(mutate):
    p = prov()
    mutate(p)
    assert uro.validate_oracle_provenance(p) is not None


def test_bare_map_has_no_provenance_and_never_confirms(tmp_path):
    # A bare {case:verdict} map is parsed but carries no provenance.
    f = tmp_path / "oracle.json"
    f.write_text('{"T1_order": "matches"}', encoding="utf-8")
    oracle, provd = uro.load_oracle(str(f))
    assert oracle == {"T1_order": "matches"}
    assert provd == {}
    assert uro.validate_oracle_provenance(provd) is not None  # never compatible


def test_duplicate_json_key_rejected():
    with pytest.raises(ValueError):
        uro.strict_json_loads('{"verdicts": {"a": "matches"}, '
                              '"verdicts": {"b": "cannot_match"}}')


# --------------------------------------------------------------------------
# Oracle-coverage validation (Task 1): missing/dup/unexpected/invalid results.
# --------------------------------------------------------------------------

def test_missing_verdict_not_skipped_is_error():
    cases = [case("T1"), case("T2")]
    # provenance from a flag-ON build; both cases require flag ON and neither
    # is skipped, but the oracle only produced T1.
    p = prov(flag_on_state=True, skipped=[])
    oracle = {"T1": "matches"}
    errs = uro.validate_oracle_coverage(cases, oracle, p)
    assert any("missing oracle verdict" in e and "T2" in e for e in errs)


def test_skipped_case_without_verdict_is_ok():
    cases = [case("T1"), case("T19", flag_on=False)]
    p = prov(flag_on_state=True, skipped=["T19"])
    oracle = {"T1": "matches"}
    assert uro.validate_oracle_coverage(cases, oracle, p) == []


def test_flag_mismatch_without_verdict_is_ok():
    # T19 needs flag OFF but this build is flag ON → no verdict expected.
    cases = [case("T19", flag_on=False)]
    p = prov(flag_on_state=True, skipped=[])
    oracle = {}
    assert uro.validate_oracle_coverage(cases, oracle, p) == []


def test_unexpected_oracle_id_is_error():
    cases = [case("T1")]
    oracle = {"T1": "matches", "NOPE": "matches"}
    assert any("unexpected oracle verdict id" in e for e in
               uro.validate_oracle_coverage(cases, oracle, prov()))


def test_invalid_oracle_verdict_value_is_error():
    cases = [case("T1")]
    oracle = {"T1": "maybe"}
    assert any("invalid oracle verdict" in e for e in
               uro.validate_oracle_coverage(cases, oracle, prov()))


# --------------------------------------------------------------------------
# Three-way classification (Task 4).
# --------------------------------------------------------------------------

def test_oracle_confirmed():
    status, fail = uro.classify_row("T1", case("T1"), {"T1": "matches"},
                                    {"T1": "matches"}, prov(flag_on_state=True))
    assert status == "ORACLE-CONFIRMED" and fail is False


def test_unsupported_matcher_is_oracle_open_not_mismatch():
    # asc-rs conservatively `unknown`; framework deterministic. Surfaced, not
    # a failure, never confirmed.
    status, fail = uro.classify_row("T16", case("T16", exp="unknown"),
                                    {"T16": "unknown"}, {"T16": "matches"},
                                    prov())
    assert status == "ORACLE-OPEN" and fail is False


def test_oracle_mismatch_is_a_contradiction():
    # asc-rs agrees with source_expected but the framework oracle disagrees.
    status, fail = uro.classify_row("T1", case("T1"),
                                    {"T1": "matches"}, {"T1": "cannot_match"},
                                    prov())
    assert status == "ORACLE-MISMATCH" and fail is True


def test_source_mismatch_dominates():
    status, fail = uro.classify_row("T1", case("T1"), {"T1": "cannot_match"},
                                    {"T1": "cannot_match"}, prov())
    assert status == "SOURCE-MISMATCH" and fail is True


def test_flag_mismatch_never_confirmed():
    # Required flag ON, build is flag OFF → verdict (if any) is in the wrong
    # configuration and must never be ORACLE-CONFIRMED.
    status, fail = uro.classify_row("T1", case("T1"), {"T1": "matches"},
                                    {"T1": "matches"},
                                    prov(flag_on_state=False))
    assert status == "UNVERIFIED(FLAG)" and fail is False


def test_skipped_case_never_confirmed():
    # In the skip list AND its required flag state matches the build, so the
    # reason is SKIP (not FLAG); still must never be confirmed.
    status, fail = uro.classify_row("T19", case("T19", flag_on=True),
                                    {"T19": "matches"}, {},
                                    prov(flag_on_state=True, skipped=["T19"]))
    assert status == "UNVERIFIED(SKIP)" and fail is False


def test_no_oracle_never_confirmed():
    status, fail = uro.classify_row("T1", case("T1"), {"T1": "matches"},
                                    None, {})
    assert status == "REGRESSION-OK(UNVERIFIED)" and fail is False


def test_no_oracle_unsupported():
    status, fail = uro.classify_row("T16", case("T16", exp="unknown"),
                                    {"T16": "unknown"}, None, {})
    assert status == "REGRESSION-OK(UNSUPPORTED)" and fail is False


def test_no_oracle_source_mismatch():
    status, fail = uro.classify_row("T1", case("T1"), {"T1": "cannot_match"},
                                    None, {})
    assert status == "SOURCE-MISMATCH" and fail is True


def test_classify_cases_summary_mixed():
    cases = [case("T1"),                                # confirmed
             case("T16", exp="unknown"),                # oracle-open
             case("T19", flag_on=False),                # flag-mismatch → unverified
             case("Tbad", exp="matches")]               # source-mismatch
    asc = {"T1": "matches", "T16": "unknown",
           "T19": "matches", "Tbad": "cannot_match"}
    oracle = {"T1": "matches", "T16": "matches",
              "T19": "matches"}  # T19 verdict present but wrong-flag
    rows, summary = uro.classify_cases(cases, asc, oracle, prov(flag_on_state=True))
    by = {cid: status for cid, *_rest, status in rows}
    assert by["T1"] == "ORACLE-CONFIRMED"
    assert by["T16"] == "ORACLE-OPEN"
    assert by["T19"] == "UNVERIFIED(FLAG)"
    assert by["Tbad"] == "SOURCE-MISMATCH"
    assert summary["confirmed"] == 1
    assert summary["oracle_open"] == 1
    assert summary["flag_skipped"] == 1
    assert summary["source_fail"] == 1
    assert summary["oracle_fail"] == 0
