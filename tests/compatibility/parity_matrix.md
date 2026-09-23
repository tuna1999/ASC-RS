# Python Oracle ↔ asc-rs Parity Matrix

This document maps every Python oracle invocation captured under
`tests/fixtures/golden/cases.json` to the planned `asc-rs` invocation that
must reproduce it. The harness (`tests/differential/run_differential.py`)
applies the same argv shape to the binary it is given, so any asc-rs that
follows this table will produce a directly-comparable transcript.

## Python CLI invocation

For reference, the oracle is invoked as:

```bash
reference/venv/Scripts/python.exe reference/asc/main.py <subcommand> <args...>
```

`main.py` parses argv as:

```
main.py getclass <apk> <class> [-o out] [--threads N] [--debug]
main.py findrefs <apk> string <value> [-o out] [--threads N] [--debug]
main.py findrefs <apk> type   <value> [-o out] [--threads N] [--debug]
main.py findrefs <apk> method [name] [--class X [--fuzzy-class]] [-o out] [--threads N] [--debug]
main.py findrefs <apk> field  [name] [--class X [--fuzzy-class]] [-o out] [--threads N] [--debug]
```

(See `reference/BEHAVIOR.md` §1 for the exact argparse definition.)

## Planned asc-rs CLI

The parity target is:

```
asc-rs getclass   <apk> <class>                                    [-o out] [--threads N] [--debug]
asc-rs findrefs   <apk> string <value>                              [-o out] [--threads N] [--debug] [--format text|json]
asc-rs findrefs   <apk> type   <value>                              [-o out] [--threads N] [--debug] [--format text|json]
asc-rs findrefs   <apk> method [name] [--class X [--fuzzy-class]]   [-o out] [--threads N] [--debug] [--format text|json]
asc-rs findrefs   <apk> field  [name] [--class X [--fuzzy-class]]   [-o out] [--threads N] [--debug] [--format text|json]
asc-rs listclass  <apk> [--prefix P]                               [-o out] [--threads N] [--debug]
```

Key constraints:

- `--debug`, `-o/--output`, `--threads` are accepted in either position
  (before or after the subcommand-specific args). asc-rs may adopt either
  convention as long as it matches.
- The harness invokes the binary as
  `<bin> <subcommand> <apk_abs> <subcommand_args...>` so the order shown
  in the table below is what the differential runner uses.

## Per-case parity

The "case_id" column is the file basename under
`tests/fixtures/golden/`. Each row also shows the exact harness invocation
that the differential runner will use (binary path is supplied at
runtime; the harness substitutes it for `<asc-rs>` in this table).

### findrefs cases

| case_id                              | oracle invocation                                                              | asc-rs invocation (planned)                                                                  | fixture APK                  | expects |
|--------------------------------------|--------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|------------------------------|---------|
| findrefs_string_workload             | `python main.py findrefs corpus/apk/workload.apk string Context`               | `asc-rs findrefs corpus/apk/workload.apk string Context`                                     | `workload.apk`               | exit 0  |
| findrefs_type_workload               | `python main.py findrefs corpus/apk/workload.apk type ClockFaceView`           | `asc-rs findrefs corpus/apk/workload.apk type ClockFaceView`                                 | `workload.apk`               | exit 0  |
| findrefs_method_workload             | `python main.py findrefs corpus/apk/workload.apk method onClick`               | `asc-rs findrefs corpus/apk/workload.apk method onClick`                                     | `workload.apk`               | exit 0  |
| findrefs_method_precise_workload     | `python main.py findrefs corpus/apk/workload.apk method onLayout --class Lcom/google/android/material/timepicker/ClockFaceView;` | `asc-rs findrefs corpus/apk/workload.apk method onLayout --class Lcom/google/android/material/timepicker/ClockFaceView;` | `workload.apk` | exit 0 |
| findrefs_field_workload              | `python main.py findrefs corpus/apk/workload.apk field textColor`              | `asc-rs findrefs corpus/apk/workload.apk field textColor`                                    | `workload.apk`               | exit 0  |
| findrefs_field_fuzzy_class_workload  | `python main.py findrefs corpus/apk/workload.apk field gradientColors --class ClockFaceView --fuzzy-class` | `asc-rs findrefs corpus/apk/workload.apk field gradientColors --class ClockFaceView --fuzzy-class` | `workload.apk` | exit 0 |
| findrefs_string_aurora               | `python main.py findrefs corpus/apk/com.aurora.store_60.apk string "https://"` | `asc-rs findrefs corpus/apk/com.aurora.store_60.apk string "https://"`                       | `com.aurora.store_60.apk`    | exit 0  |
| findrefs_type_aurora                 | `python main.py findrefs corpus/apk/com.aurora.store_60.apk type Fragment`     | `asc-rs findrefs corpus/apk/com.aurora.store_60.apk type Fragment`                           | `com.aurora.store_60.apk`    | exit 0  |
| findrefs_method_aurora               | `python main.py findrefs corpus/apk/com.aurora.store_60.apk method onClick`     | `asc-rs findrefs corpus/apk/com.aurora.store_60.apk method onClick`                           | `com.aurora.store_60.apk`    | exit 0  |
| findrefs_string_fdroid               | `python main.py findrefs corpus/apk/org.fdroid.fdroid_1016000.apk string "https://"` | `asc-rs findrefs corpus/apk/org.fdroid.fdroid_1016000.apk string "https://"`              | `org.fdroid.fdroid_1016000.apk` | exit 0 |

### getclass cases

| case_id                       | oracle invocation                                                            | asc-rs invocation (planned)                                                  | fixture APK    | expects                                                |
|-------------------------------|------------------------------------------------------------------------------|------------------------------------------------------------------------------|----------------|--------------------------------------------------------|
| getclass_clockface_workload   | `python main.py getclass corpus/apk/workload.apk Lcom/google/android/material/timepicker/ClockFaceView;` | `asc-rs getclass corpus/apk/workload.apk Lcom/google/android/material/timepicker/ClockFaceView;` | `workload.apk` | exit 0; decompiled Java source on stdout |
| getclass_notfound             | `python main.py getclass corpus/apk/workload.apk Lno/such/Class;`             | `asc-rs getclass corpus/apk/workload.apk Lno/such/Class;`                   | `workload.apk` | exit 1; stderr `Error: Class Lno/such/Class; not found in APK.`; no stdout source |

### listclass cases

The frozen Python oracle at `reference/asc @ ccc6bae` does **not**
include the `listclass` subcommand (it was added in MG1937/ASC commit
`752477e`, which sits ahead of the freeze). The two golden fixtures
below were hand-captured from `target/release/asc-rs.exe` itself and
are reproducible byte-for-byte. They are NOT in `cases.json` (the
differential harness ignores them) and the differential runner will
continue to PASS even when these outputs drift.

To promote them to full oracle-driven parity, bump
`reference/asc` past `5395f17`, add matching `Case(...)` entries to
`tests/fixtures/capture_golden.py`, re-run the capture, and remove the
hand-captured `.txt`/`.counts.json` in favor of the regenerated ones.

| case_id                          | asc-rs invocation (planned)                                                | fixture APK    | expects                                                                                       |
|----------------------------------|----------------------------------------------------------------------------|----------------|-----------------------------------------------------------------------------------------------|
| listclass_workload               | `asc-rs listclass corpus/apk/workload.apk`                                  | `workload.apk` | exit 0; 6,220 descriptors in DEX-definition order, one per line                              |
| listclass_with_prefix_workload   | `asc-rs listclass corpus/apk/workload.apk --prefix com.google`              | `workload.apk` | exit 0; 1,297 descriptors matching `Lcom/google*`, dotted and `L…` prefixes normalized identically |


## Edge cases the parity check expects to surface

These are not separate cases; they are properties of the cases above and
will be exercised automatically by the differential runner:

- **Multidex per-DEX iteration**: `findrefs_string_aurora` and
  `findrefs_string_fdroid` emit lines for *both* `classes.dex` and
  `classes2.dex`. The line-set comparator treats per-DEX emission
  order as unstable, so the harness only checks that the *set* of
  per-DEX lines equals the golden set.
- **Method/field `--class` precise vs fuzzy**:
  - `findrefs_method_precise_workload` uses `--class` *without*
    `--fuzzy-class`. asc-rs must binary-search the type_ids table
    for an exact descriptor match (`Lcom/.../ClockFaceView;`).
  - `findrefs_field_fuzzy_class_workload` uses `--class X --fuzzy-class`,
    so asc-rs must substring-match the class descriptor via the type
    locator and then intersect with the field matches.
- **`getclass` minimal DEX**: the oracle builds a minimal DEX in memory
  (`DexManager.extract_and_rebuild`) and only exposes the decompiled
  source to stdout / `-o`. asc-rs may implement getclass however it
  likes as long as the decompiled source is byte-identical (or
  whitespace-identical under `--loose-whitespace`).
- **Not-found error path**: `getclass_notfound` exercises the error
  branch. asc-rs must exit 1, print `Error: Class ... not found in APK.`
  to stderr, and emit no source on stdout. The harness checks exit code
  first; if that matches, it skips the source comparison for this case.
- **DEX 035 + DEX 039 in the corpus**: `aurora_*` and `fdroid_*` are
  `dex\n035\x00`; `workload_classes.dex` is `dex\n039\x00`. Both are
  covered.

## How to add a new case

1. Add a `Case(...)` entry to the `CASES` list in
   `tests/fixtures/capture_golden.py`.
2. Add a matching row to the table above (both findrefs and getclass
   sections).
3. Re-run capture:
   `reference/venv/Scripts/python.exe tests/fixtures/capture_golden.py`
4. Commit the new `golden/<case_id>.{txt,counts.json}` files together
   with the case-list change. **Do not** manually edit `cases.json` --
   it is generated.
5. Run `tests/differential/run_differential.py --selftest` to confirm
   the harness still produces the expected PASS/FAIL/SKIP pattern, then
   run it against your asc-rs build to confirm parity.