# Differential report

- mode: `differential`
- binary: `target/release/asc-rs.exe`
- golden corpus: `tests/fixtures/golden/`
- cases run: 12

| status | count |
|--------|-------|
| PASS | 12 |
| FAIL | 0 |
| SKIP | 0 |

**All cases passed parity check.**

## `findrefs_string_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `string Context`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (28, 28)

## `findrefs_type_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `type ClockFaceView`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (2, 2)

## `findrefs_method_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `method onClick`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (17, 17)

## `findrefs_method_precise_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `method onLayout --class Lcom/google/android/material/timepicker/ClockFaceView;`
- oracle exit: `0` ; bin exit: `0`

## `findrefs_field_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `field textColor`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (16, 16)

## `findrefs_field_fuzzy_class_workload` — PASS

- subcommand: `findrefs`
- apk: `workload.apk`
- query: `field gradientColors --class ClockFaceView --fuzzy-class`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (2, 2)

## `getclass_clockface_workload` — PASS

- subcommand: `getclass`
- apk: `workload.apk`
- query: `Lcom/google/android/material/timepicker/ClockFaceView;`
- oracle exit: `0` ; bin exit: `0`

## `findrefs_string_aurora` — PASS

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `string https://`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (41, 41)
  - `classes2.dex`: (15, 15)

## `findrefs_type_aurora` — PASS

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `type Fragment`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (8, 8)
  - `classes2.dex`: (176, 176)

## `findrefs_method_aurora` — PASS

- subcommand: `findrefs`
- apk: `com.aurora.store_60.apk`
- query: `method onClick`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (6, 6)
  - `classes2.dex`: (4, 4)

## `findrefs_string_fdroid` — PASS

- subcommand: `findrefs`
- apk: `org.fdroid.fdroid_1016000.apk`
- query: `string https://`
- oracle exit: `0` ; bin exit: `0`
- per-dex counts (golden, bin):
  - `classes.dex`: (10, 10)
  - `classes2.dex`: (14, 14)

## `getclass_notfound` — PASS

- subcommand: `getclass`
- apk: `workload.apk`
- query: `Lno/such/Class;`
- oracle exit: `1` ; bin exit: `1`

