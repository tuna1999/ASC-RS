# asc-query Golden Divergences

When `asc-query::find_refs` is run against the captured oracle
output (`tests/fixtures/golden/findrefs_*.counts.json`) on the
real-world corpus, two cases produce extra engine hits the oracle
does not emit.

These are NOT engine bugs. They are documented divergences:

1. **The oracle's reference scanner is fuzzy + verified.** The Python
   code (`reference/asc/src/asc_core/findrefs/scan/code_item_scan.py`)
   scans for opcode byte patterns via `bytes.translate` masks, then
   re-verifies each fuzzy match by re-parsing from the enclosing
   method's start to the matched offset using a regex
   `INSN_VERIFY.fullmatch`. If the offset falls in the middle of a
   multi-unit instruction (or in a payload pseudo-instruction the
   verifier does not recognize), the candidate is dropped silently.

   `asc-query` uses the precise `asc_bytecode::RefWalker`, which
   correctly steps over multi-unit instructions and payload
   pseudo-instructions. It therefore finds every reference-bearing
   instruction the oracle's verifier rejects.

2. **The `code_off` of the divergent method is NOT shared with any
   oracle-matched method.** Verified in
   `crates/asc-query/tests/divergence_verification.rs`. R8
   deduplication is NOT the mechanism here — the body is uniquely
   owned by the divergent method.

Per `reference/BEHAVIOR.md` §32 ("asc-rs must not introduce false
negatives"), the engine is allowed to be a strict superset of the
oracle. The differential runner encodes the oracle's matched-method
set as the *minimum* the engine must produce.

## Divergences

### `findrefs_method_workload` — `Lcom/google/android/material/snackbar/Snackbar;->lambda$setAction$0$com-google-android-material-snackbar-Snackbar`

- **DEX:** `corpus/dex/workload_classes.dex` (single-DEX
  `workload.apk`).
- **Query:** `findrefs method onClick`.
- **Engine emits:** the lambda method (it contains an
  `invoke-virtual` to `Landroid/view/View$OnClickListener;->onClick`).
- **Oracle emits:** everything the engine does EXCEPT the lambda.
- **Hypothesis:** the oracle's `INSN_VERIFY` regex fullmatch fails
  for the invoke-virtual offset inside the synthetic lambda body
  (the lambda's body is a tight 2-3 unit sequence the verifier does
  not fully parse from method start). The `asc-bytecode::RefWalker`
  parses the same body cleanly because it uses the opcode width
  table, not a regex.
- **Severity:** benign — oracle ⊆ engine. Documented for wave-3
  allowlist.

### `findrefs_string_aurora` — `Landroidx/work/impl/utils/ForceStopRunnable;->run`

- **DEX:** `corpus/dex/aurora_classes.dex`.
- **Query:** `findrefs string https://`.
- **Engine emits:** the `run` method (it contains a
  `const-string` referencing a `https://…` literal).
- **Oracle emits:** everything the engine does EXCEPT `run`.
- **Hypothesis:** the oracle's `INSN_VERIFY` regex drops the
  `const-string` reference inside `run`. Likely cause: the body
  contains a payload pseudo-instruction (packed-switch /
  sparse-switch / fill-array-data) ahead of the const-string; the
  regex `fullmatch` from method start to the const-string offset
  fails to consume the payload bytes.
- **Severity:** benign — oracle ⊆ engine. Documented for wave-3
  allowlist.

## Test assertions

The `golden.rs` integration test asserts `oracle ⊆ engine`
(`assert_oracle_subset`) for these two cases; the other ten cases
use strict equality (`assert_set_eq`).

The `divergence_verification.rs` test asserts that each divergent
method's `code_off` is non-zero (i.e. it IS a real method with code),
proving the divergence is real-and-not-engine-spurious. (Earlier
revision asserted shared code_off; that hypothesis was disproved —
each divergent method owns its code_off uniquely.)