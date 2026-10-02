#!/usr/bin/env bash
# Restart loop for fuzz-runner. Builds, then runs the runner until
# the wall-time budget elapses without a panic (= GREEN) or the user
# stops it.
#
# Usage:  ./run.sh <target> [budget_seconds] [features]
#         FEATURES=dex,apk ./run.sh <target>     (env form)
#
# `features` (or $FEATURES) is a comma list of fuzz-workspace cargo
# features (dex|bytecode|apk|rebuild|resources|core|decompile|all).
# Without it the runner builds with default features and every
# contract target reports SkippedDisabled.
#
# Exit codes:
#   0  = green (no panics within budget)
#   1  = red   (one or more panics; see crashes/)
#   2  = usage / setup error
# Regression replay is separate: committed fixtures live in regress/
# and are replayed directly (`fuzz-runner --target T --regress regress`);
# this script only runs the mutation loop and writes NEW crashes to
# crashes/.

set -u

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <target> [budget_seconds] [features]" >&2
    exit 2
fi

TARGET="$1"
BUDGET_SEC="${2:-30}"
FEATURES="${3:-${FEATURES:-}}"
SEEDS_DIR="seeds/${TARGET}"
LOGDIR="crashes"

mkdir -p "$LOGDIR" "corpus-out/${TARGET}"

# Build first so a panic doesn't waste time compiling during the
# mutation loop.
if [ -n "$FEATURES" ]; then
    cargo build --release --bin fuzz-runner --features "$FEATURES" >/dev/null
else
    cargo build --release --bin fuzz-runner >/dev/null
fi
BUILD_EXIT=$?
if [ "$BUILD_EXIT" -ne 0 ]; then
    echo "build failed (features=${FEATURES:-none})" >&2
    exit 2
fi
BIN="./target/release/fuzz-runner.exe"
[ -x "$BIN" ] || BIN="./target/release/fuzz-runner"

START=$(date +%s)
END=$((START + BUDGET_SEC))
PANICS=0
# Decimal: clap parses --seed as a plain u64 (no 0x/underscores), and
# bash arithmetic accepts the 0x form here exactly once.
LAST_SEED=$((0xA5A5C0DEBEEF))

echo "=== fuzz-runner restart loop ==="
echo "target=$TARGET budget=${BUDGET_SEC}s features=${FEATURES:-none} seeds=$SEEDS_DIR crash_dir=$LOGDIR"

while [ "$(date +%s)" -lt "$END" ]; do
    REMAINING=$((END - $(date +%s)))
    [ "$REMAINING" -le 0 ] && break

    # Re-run with the remaining budget. Use a different seed on each
    # restart so we don't deterministically re-crash on the same
    # input after the panic hook saved it.
    SEED=$LAST_SEED
    "$BIN" \
        --target "$TARGET" \
        --seconds "$REMAINING" \
        --seeds "$SEEDS_DIR" \
        --corpus-out "corpus-out/${TARGET}" \
        --crash-dir "$LOGDIR" \
        --seed "$SEED" \
        2>&1
    EXIT=$?

    if [ "$EXIT" -eq 0 ]; then
        echo "fuzz-runner exited cleanly with remaining budget; stopping"
        break
    fi

    PANICS=$((PANICS + 1))
    LAST_SEED=$((LAST_SEED + 1))
    echo "[$(date '+%H:%M:%S')] fuzz-runner exited with code $EXIT (panic #$PANICS); restarting"
done

echo "=== summary ==="
echo "target=$TARGET panics=$PANICS budget=${BUDGET_SEC}s"
if [ "$PANICS" -eq 0 ]; then
    echo "GREEN: no crashes within budget"
    exit 0
else
    echo "RED: panics observed; see $LOGDIR/"
    exit 1
fi
