#!/usr/bin/env bash
# ASC-RS GUI autoresearch harness.
#
# Runs every required gate, parses cargo test output into a results
# JSON keyed by the manifest's `acceptance` identifiers, and emits the
# scoring METRIC lines defined in `docs/gui-feature-matrix.md` §7.
#
# Output is stable and machine-readable; downstream tooling can grep
# `^METRIC ` lines.
#
# Usage:
#   bash autoresearch.sh                  # full run (uses existing build)
#   ASC_RS_FAST=1 bash autoresearch.sh    # skip selfcheck + perf selftest
#                                       # (intended for CI without corpus)
#
# Exit code: number of failed gates (0 = all green).

set -uo pipefail

# Resolve repo root (script's directory).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --------------------------------------------------------------------------
# Output artefacts (kept under target/ for gitignore cleanliness).
# --------------------------------------------------------------------------
ART_DIR="target/autoresearch"
mkdir -p "$ART_DIR"
RESULTS_JSON="$ART_DIR/results.json"
SCORE_LOG="$ART_DIR/score.txt"
GATE_LOG="$ART_DIR/gate.log"
LOG="$ART_DIR/run.log"

exec 3>"$GATE_LOG"
exec 4>"$LOG"

log() { printf '%s\n' "$*" >&4; }
gate() { printf '%s\n' "$*" >&3; }

# Track gate outcomes.
declare -A GATE_STATUS=(
    [fmt]=PENDING
    [clippy]=PENDING
    [tests]=PENDING
    [visual_shots]=PENDING
    [build]=PENDING
    [selfcheck]=PENDING
)

declare -A GATE_FAIL=(
    [fmt]=0
    [clippy]=0
    [tests]=0
    [visual_shots]=0
    [build]=0
    [selfcheck]=0
)

# Aggregate counters.
WORKSPACE_TESTS_FAILED=0
WORKSPACE_TESTS_PASSED=0
CLIPPY_WARNINGS=0
SELFCHECK_FAILURES=0
VISUAL_REGRESSIONS=0

# --------------------------------------------------------------------------
# 1. cargo fmt --all -- --check
# --------------------------------------------------------------------------
gate "### cargo fmt --all -- --check"
log "### cargo fmt"
if cargo fmt --all -- --check >>"$LOG" 2>&1; then
    GATE_STATUS[fmt]=PASS
    gate "  ok"
else
    GATE_STATUS[fmt]=FAIL
    GATE_FAIL[fmt]=1
    gate "  FAILED — see $LOG"
fi

# --------------------------------------------------------------------------
# 2. cargo clippy --workspace --all-targets --all-features -- -D warnings
# --------------------------------------------------------------------------
gate "### cargo clippy --workspace --all-targets --all-features"
CLIPPY_LOG="$ART_DIR/clippy.log"
log "### cargo clippy"
if cargo clippy --workspace --all-targets --all-features -- -D warnings >"$CLIPPY_LOG" 2>&1; then
    GATE_STATUS[clippy]=PASS
    CLIPPY_WARNINGS=0
    gate "  ok"
else
    GATE_STATUS[clippy]=FAIL
    GATE_FAIL[clippy]=1
    # Count warnings/errors. Clippy prints one line per warning.
    CLIPPY_WARNINGS=$(grep -c "^warning:" "$CLIPPY_LOG" || true)
    CLIPPY_ERRORS=$(grep -c "^error:" "$CLIPPY_LOG" || true)
    gate "  FAILED — $CLIPPY_ERRORS errors, $CLIPPY_WARNINGS warnings (see $CLIPPY_LOG)"
fi

# --------------------------------------------------------------------------
# 3. cargo test --workspace
# --------------------------------------------------------------------------
gate "### cargo test --workspace"
TEST_LOG="$ART_DIR/cargo-test.log"
log "### cargo test"
# --no-fail-fast so we still see all outcomes even on first failure.
set +e
cargo test --workspace --no-fail-fast >"$TEST_LOG" 2>&1
TEST_RC=$?
set -e

# Parse `cargo test` output. The lines we care about look like:
#   test state::documents::tests::line_indexing_is_o1_and_exact ... ok
#   test state::documents::tests::some_test ... FAILED
#   test result: ok. 244 passed; 0 failed; ...
# Cargo emits one "test result:" line per binary test group; sum them.
WORKSPACE_TESTS_PASSED=$(grep -E '^test result: ok\.' "$TEST_LOG" \
    | sed -E 's/.*ok\. ([0-9]+) passed.*/\1/' \
    | awk 'BEGIN{s=0} {s+=$1} END{print s}' || echo 0)
WORKSPACE_TESTS_PASSED=${WORKSPACE_TESTS_PASSED:-0}
WORKSPACE_TESTS_FAILED=$(grep -E '^test result:' "$TEST_LOG" \
    | sed -E 's/.* ([0-9]+) failed.*/\1/' \
    | awk 'BEGIN{s=0} {s+=$1} END{print s}' || echo 0)
WORKSPACE_TESTS_FAILED=${WORKSPACE_TESTS_FAILED:-0}

if [[ "$TEST_RC" -eq 0 ]]; then
    GATE_STATUS[tests]=PASS
    gate "  ok ($WORKSPACE_TESTS_PASSED passed)"
else
    GATE_STATUS[tests]=FAIL
    GATE_FAIL[tests]=1
    gate "  FAILED — $WORKSPACE_TESTS_FAILED failed, $WORKSPACE_TESTS_PASSED passed"
fi

# --------------------------------------------------------------------------
# 4. ASC_GUI_SHOTS=1 cargo test -p asc-gui --lib visual_shots
# --------------------------------------------------------------------------
gate "### ASC_GUI_SHOTS=1 cargo test -p asc-gui --lib visual_shots"
SHOTS_LOG="$ART_DIR/visual_shots.log"
log "### visual_shots"
set +e
ASC_GUI_SHOTS=1 cargo test -p asc-gui --lib visual_shots >"$SHOTS_LOG" 2>&1
SHOTS_RC=$?
set -e

# The visual_shots test fails only when an image diff exceeds tolerance.
if [[ "$SHOTS_RC" -eq 0 ]]; then
    GATE_STATUS[visual_shots]=PASS
    gate "  ok"
else
    GATE_STATUS[visual_shots]=FAIL
    GATE_FAIL[visual_shots]=1
    VISUAL_REGRESSIONS=$(grep -cE "diff|FAIL|mismatch" "$SHOTS_LOG" || true)
    gate "  FAILED — see $SHOTS_LOG"
fi

# --------------------------------------------------------------------------
# 5. cargo build --release -p asc-gui (skip when FAST)
# --------------------------------------------------------------------------
gate "### cargo build --release -p asc-gui"
BUILD_LOG="$ART_DIR/build.log"
log "### cargo build --release"
if [[ "${ASC_RS_FAST:-0}" == "1" ]]; then
    GATE_STATUS[build]=SKIP
    gate "  SKIPPED (ASC_RS_FAST=1)"
else
    if cargo build --release -p asc-gui >"$BUILD_LOG" 2>&1; then
        GATE_STATUS[build]=PASS
        gate "  ok"
    else
        GATE_STATUS[build]=FAIL
        GATE_FAIL[build]=1
        gate "  FAILED — see $BUILD_LOG"
    fi
fi

# --------------------------------------------------------------------------
# 6. asc-gui --selfcheck corpus/apk/workload.apk (skip when FAST)
# --------------------------------------------------------------------------
SELFCHECK_LOG="$ART_DIR/selfcheck.log"
gate "### target/release/asc-gui --selfcheck corpus/apk/workload.apk"
log "### selfcheck"
if [[ "${ASC_RS_FAST:-0}" == "1" ]]; then
    GATE_STATUS[selfcheck]=SKIP
    SELFCHECK_FAILURES=0
    gate "  SKIPPED (ASC_RS_FAST=1)"
else
    if [[ ! -f "corpus/apk/workload.apk" ]]; then
        GATE_STATUS[selfcheck]=SKIP
        gate "  SKIPPED (corpus/apk/workload.apk missing)"
    else
        set +e
        target/release/asc-gui --selfcheck corpus/apk/workload.apk >"$SELFCHECK_LOG" 2>&1
        SELFCHECK_RC=$?
        set -e
        if [[ "$SELFCHECK_RC" -eq 0 ]]; then
            GATE_STATUS[selfcheck]=PASS
            SELFCHECK_FAILURES=0
            gate "  ok"
        else
            GATE_STATUS[selfcheck]=FAIL
            GATE_FAIL[selfcheck]=1
            SELFCHECK_FAILURES=1
            gate "  FAILED — see $SELFCHECK_LOG"
        fi
    fi
fi

# --------------------------------------------------------------------------
# 7. Build results.json from cargo test output
# --------------------------------------------------------------------------
gate "### building acceptance results from cargo test output"

# The Python script reads the cargo test log directly and writes
# results.json keyed by each manifest feature's `acceptance` ID.
# (score.py expects the acceptance key, not the feature id.)
python3 - "$RESULTS_JSON" <<PY
import json, re, sys, pathlib

test_log = pathlib.Path("$TEST_LOG")
manifest = json.loads(
    pathlib.Path("tests/gui_features/feature_manifest.json")
    .read_text(encoding="utf-8")
)

# Parse cargo test output for individual test lines.
raw_map = {}
pat = re.compile(r"^test ([a-zA-Z0-9_:]+) \.\.\. (ok|FAILED|ignored)$")
for line in test_log.read_text(encoding="utf-8", errors="replace").splitlines():
    mm = pat.match(line)
    if not mm:
        continue
    raw_map[mm.group(1)] = (mm.group(2) == "ok")

# Resolve each manifest feature's acceptance against the test map.
results = {}
for f in manifest["features"]:
    acc = f.get("acceptance") or ""
    if not acc:
        results[f["id"]] = False
        continue
    bare = acc.split("::")[-1]
    found = False
    if "*" in bare:
        prefix = bare.split("*", 1)[0]
        for path, ok in raw_map.items():
            if path.split("::")[-1].startswith(prefix) and ok:
                found = True
                break
    else:
        for path, ok in raw_map.items():
            if path.split("::")[-1] == bare and ok:
                found = True
                break
    # Key results.json by acceptance ID so score.py can resolve it.
    results[acc] = found

pathlib.Path(sys.argv[1]).write_text(
    json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

gate "  acceptance results -> $RESULTS_JSON"

# --------------------------------------------------------------------------
# 8. Run the scoring script.
# --------------------------------------------------------------------------
gate "### python tests/gui_features/score.py"
SCORE_OUT=$(python3 tests/gui_features/score.py --manifest tests/gui_features/feature_manifest.json --results "$RESULTS_JSON" 2>&1)
SCORE_RC=$?
printf '%s\n' "$SCORE_OUT" | tee "$SCORE_LOG"
if [[ "$SCORE_RC" -ne 0 ]]; then
    gate "  scoring script failed (exit $SCORE_RC)"
fi

# --------------------------------------------------------------------------
# 9. Aggregate required METRIC lines.
# --------------------------------------------------------------------------
gate ""
gate "=== autoresearch summary ==="
for key in fmt clippy tests visual_shots build selfcheck; do
    st="${GATE_STATUS[$key]}"
    case "$st" in
        PASS) mark="OK" ;;
        FAIL) mark="FAIL" ;;
        SKIP) mark="SKIP" ;;
        *)    mark="?" ;;
    esac
    gate "  gate $key: $mark"
done

# Required METRIC lines (always emitted):
printf 'METRIC workspace_tests_failed=%d\n'  "$WORKSPACE_TESTS_FAILED"
printf 'METRIC workspace_tests_passed=%d\n'  "$WORKSPACE_TESTS_PASSED"
printf 'METRIC clippy_warnings=%d\n'         "$CLIPPY_WARNINGS"
printf 'METRIC selfcheck_failures=%d\n'      "$SELFCHECK_FAILURES"
printf 'METRIC visual_regressions=%d\n'      "$VISUAL_REGRESSIONS"
printf 'METRIC gate_failures=%d\n'           "$((GATE_FAIL[fmt] + GATE_FAIL[clippy] + GATE_FAIL[tests] + GATE_FAIL[visual_shots] + GATE_FAIL[build] + GATE_FAIL[selfcheck]))"

# Final exit code.
TOTAL_FAIL=$((GATE_FAIL[fmt] + GATE_FAIL[clippy] + GATE_FAIL[tests] + GATE_FAIL[visual_shots] + GATE_FAIL[build] + GATE_FAIL[selfcheck]))
exit "$TOTAL_FAIL"