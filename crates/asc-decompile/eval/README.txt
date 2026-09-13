asc-decompile eval/ directory
============================

Contains structural-evaluation outputs and benchmark numbers for the
DroidsawBackend adapter against the Python oracle. The decompiled Java
source itself is NOT stored here — only structural statistics
(counts, method-signature prefixes, identifier set sizes) and timing
numbers. The full decompiled source for the golden target is produced
on demand by running the integration test
`roundtrip_workload_clockface_decompiles_to_java_containing_class_name`
or the criterion bench.

Files
-----

workload_dex_metadata.txt
  SHA256 / size / magic version / class-def count of the input fixture
  (corpus/dex/workload_classes.dex).

structural_comparison.txt
  Side-by-side structural stats between the Python oracle output
  (tests/fixtures/golden/getclass_clockface_workload.txt) and the
  droidsaw-dex live output for the same target class:
  - byte/line counts
  - method-signature intersection (14/18 identical, 4 are synthetic
    access$XXX trampolines in both)
  - class-declaration shape (byte-identical structure)
  - parameter-naming comparison

smoke_test.txt
  Per-class decompile timing for 5 representative classes in
  workload_classes.dex (warm-path, after parse+census prebuilt).
  All 5 decompile in 1-4 ms.

criterion_bench.txt
  Criterion output for the two bench functions:
  - decompile_clockface_workload_cold
  - decompile_clockface_workload_warm_emit_only
  plus comparison vs the Python oracle's reported ~183 ms median.

Reproducing
-----------

  cargo test  -p asc-decompile --tests -- --nocapture
  cargo bench -p asc-decompile --bench decompile_bench
