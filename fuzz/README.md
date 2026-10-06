# asc-fuzz

Deterministic mutation fuzzer for the ASC-RS read-only stack
(`asc-dex`, `asc-bytecode`, `asc-apk`, `asc-rebuild`).

## Toolchain decision

Environment: Windows 11, rustc 1.97.1 stable, **no** rustup, **no**
nightly, **no** cargo-fuzz. cargo-fuzz normally needs nightly +
sanitizers, both unavailable here. The decision: build a custom
deterministic mutation runner in-tree (this crate) and write the
fuzz targets so they ALSO run under `cargo-fuzz` on machines that
have it installed. Switching from the in-tree runner to cargo-fuzz
means changing the binary invocation only; the target functions
themselves are portable.

Targets are written against the **contract APIs** of sibling crates
(`asc_dex::DexView`, `asc_bytecode::RefWalker`, `asc_apk::ZipView`,
`asc_rebuild::rebuild`). Every target is registered unconditionally
but its crate-coupling body is gated behind a per-crate Cargo
feature — `dex`, `bytecode`, `apk`, `rebuild`, `resources`, `core`,
`decompile`, `manifest` — so
`cargo build` in `fuzz/` stays green while sibling agents finish
landing the real APIs. With features OFF, each contract target
reports `FuzzOutcome::SkippedDisabled` and the registry remains
fully populated (18 entries). At integration, flip the matching
feature on:

```bash
cargo build --release --features dex        # turn on DEX targets
cargo build --release --features all        # everything
```

When a sibling crate lands, change its feature gate from off to on
in `fuzz/Cargo.toml`. The target source already references the
contract API.

## Layout

```
fuzz/
  Cargo.toml          # detached workspace
  .gitignore
  README.md
  run.sh              # bash restart loop
  run.ps1             # PowerShell restart loop
  src/
    lib.rs            # registry, FuzzOutcome, panic hook, helpers
    seeds.rs          # seed-corpus emitter
    dex_builder.rs    # byte-level DEX assembler for the seed corpus
    bin/
      fuzz-runner.rs  # the mutation driver
      gen-seeds.rs    # seeded-corpus emitter
  fuzz_targets/
    mod.rs            # one module per target
    dummy.rs          # deliberately buggy (self-test)
    fuzz_dex_header.rs
    fuzz_uleb128.rs
    fuzz_mutf8.rs
    fuzz_class_data.rs
    fuzz_code_item.rs
    fuzz_ref_walker.rs
    fuzz_encoded_value.rs
    fuzz_annotations.rs
    fuzz_dex041.rs
    fuzz_zip_directory.rs
    fuzz_elf.rs
    fuzz_signing.rs
    fuzz_arsc.rs
    fuzz_apk_open.rs
    fuzz_inspect.rs
    fuzz_rebuild.rs
    fuzz_disasm.rs
    fuzz_hermes.rs
    fuzz_xapk.rs
  seeds/              # committed seed corpus (one subdir per target)
```

## Running

### Generate the corpus (idempotent)

```bash
cargo run --release --bin gen-seeds
```

Writes 1–5 small files (< 1 KiB each) per target under
`fuzz/seeds/<default_seed>/`. Re-running overwrites.

### List targets

```bash
cargo run --release --bin fuzz-runner -- --list
```

### Run a target for a wall-time budget

```bash
# Inside the outer restart loop (recommended):
./run.sh dummy 5                          # bash, default features
./run.sh fuzz_dex_header 30 all           # bash, engines enabled
.\run.ps1 -Target dummy -BudgetSec 5      # PowerShell, default features
.\run.ps1 -Target fuzz_dex_header -Features all   # engines enabled

Feature-less runs build fast but every contract target reports
`SkippedDisabled`; pass a feature list (or `all`) to actually exercise
the parsers — this is what CI does.

# Directly, with the panic hook + abort behaviour:
cargo run --release --bin fuzz-runner -- \
    --target dummy \
    --seconds 2 \
    --seeds seeds/dummy \
    --corpus-out corpus-out/dummy \
    --crash-dir crashes \
    --verbose 1
```

A panic during execution causes the panic hook to dump the
failing input to `crashes/<target>-<fnv1a_hex>.bin` and abort
the process. The outer restart loop notices the nonzero exit,
increments the panic counter, and starts another invocation
with a fresh `--seed`.

### Replay regression fixtures

```bash
cargo run --release --bin fuzz-runner --features apk -- \
    --target fuzz_zip_directory --regress regress
```

Two directories with different jobs:

- `regress/` — **committed** regression fixtures, replayed by CI.
  Named `<target>-<fnv1a_hex16>.bin`, the same convention the
  panic hook uses. Only files whose prefix matches `--target`
  are replayed, so one target never ingests another target's
  crash.
- `crashes/` — where the panic hook writes **new** crashes while
  fuzzing. Promote a crash to a regression by `git mv` into
  `regress/` (the name already matches).

Exit codes: `0` every fixture replayed clean, or the target has no
committed fixture (a transparent `SKIP` line is printed); `2` the
fixture directory or a fixture file cannot be read; `3` a fixture
replayed as `SkippedDisabled` — the feature gate is off, so the
replay exercised no parser and proves nothing. A panic aborts the
process (nonzero exit), which is the regression actually firing.

## Mutation strategies

The runner applies one of six mutations per iteration, picked
uniformly by `splitmix64` seeded from `--seed` (default
`0xA5A5_C0DE_BEEF`):

1. **bit flip** (40%) — 1–4 random bits flipped in random
   positions. Cheap, exposes alignment / endian bugs.
2. **byte substitute** (20%) — 1–4 random positions
   replaced with random bytes. Reaches new code paths.
3. **truncate** (10%) — keep a random prefix.
4. **extend** (10%) — append a magic token from the
   dictionary plus 0–7 random bytes.
5. **splice** (10%) — replace a chunk of the base input with
   a random chunk of another seed in the corpus.
6. **chunk overwrite** (10%) — overwrite a 1–8 byte run
   with random bytes.

The magic dictionary contains the bytes the parsers actually
care about:

- `dex\n035\x00` … `dex\n041\x00` — DEX magic + version
- `PK\x03\x04`, `PK\x01\x02`, `PK\x05\x06` — ZIP local / central / EOCD signatures
- well-formed ULEB128s (1, 5-byte max, 9-byte corrupt)
- boundary uleb edge cases (0x7F, 0x80)

Output is capped at 256 KiB per iteration to bound peak memory.

## Determinism

Same `--seed` always yields the same mutation sequence. The seed
is logged at startup so any captured crash can be reproduced:

```
$ ./fuzz-runner --target dummy --seed 0xA5A5_C0DE_BEEF --seconds 2
fuzz-runner: target='dummy' seed=0xa5a5_c0de_beef seconds=2 ...
PANIC caught by asc-fuzz hook: index out of bounds ...
Saved crashing input to crashes/dummy-37d0e842e64dcd1c.bin
```

Re-run with the same seed + saved input to reproduce.

## Self-test (`dummy` target)

`fuzz_targets/dummy.rs` is a deliberately-buggy toy parser
written to (a) exercise the runner and (b) prove the panic
hook actually fires:

- It naively shifts 7 bits/byte for up to 10 bytes into a u64
  accumulator (spec max is 5; panics on overflow in debug
  builds).
- It then performs an unchecked slice read where the index
  is derived from the accumulator modulo `len + 64`. The 64
  window past the end guarantees an OOB panic in BOTH debug
  and release builds, so the runner reliably catches it.

`cargo run --release --bin fuzz-runner -- --target dummy
--seconds 2` finds a crashing input within a few hundred
iterations. The runner dumps it to `crashes/dummy-*.bin`.
Re-running with `--target dummy --regress crashes` aborts on the first
replayed crash (panic hook → process abort → nonzero exit).

## Switching to cargo-fuzz later

The target functions are pure `fn(&[u8]) -> FuzzOutcome` and
do not depend on the in-tree runner. To run under cargo-fuzz
when nightly + sanitizers are available:

```toml
# Add a [[bin]] entry per target with harness = false,
# or use the standard cargo-fuzz project layout.
```

The target files in `fuzz_targets/*.rs` only depend on the
sibling crates and on `crate::FuzzOutcome` — both are
straightforward to adapt to the `libfuzzer-sys` harness.

## Contract APIs awaited

The targets below call into the listed crate APIs. Each is
gated by a Cargo feature; flip the feature on at integration
when the matching crate lands.

| Target                | Crate         | API                                                                 |
|-----------------------|---------------|---------------------------------------------------------------------|
| `fuzz_dex_header`     | `asc-dex`     | `DexView::parse`, `DexView::parse_at`, `DexView::logical_header_offsets`, plus accessors `magic` / `version` / `*_count` |
| `fuzz_uleb128`        | `asc-dex`     | `asc_dex::uleb128(&[u8]) -> Result<(u64, usize), Error>`            |
| `fuzz_mutf8`          | `asc-dex`     | `asc_dex::decode_mutf8_lossy(&[u8]) -> String`                      |
| `fuzz_class_data`     | `asc-dex`     | `DexView::class_data(off: u32) -> Result<ClassData, Error>`         |
| `fuzz_code_item`      | `asc-dex`     | `DexView::code_item(off: u32) -> Result<CodeItem, Error>`           |
| `fuzz_ref_walker`     | `asc-bytecode`| `RefWalker::new(input, units)`, `walker.next() -> Option<Result<Ref, Error>>` |
| `fuzz_encoded_value`  | `asc-dex`     | `asc_dex::encoded_value(&[u8]) -> Result<(Value, usize), Error>`    |
| `fuzz_annotations`    | `asc-dex`     | `asc_dex::annotations(&[u8])`, `DexView::annotations(off)`          |
| `fuzz_dex041`         | `asc-dex`     | `DexView::parse_at`, `DexView::logical_header_offsets` (DEX-041 paths) |
| `fuzz_zip_directory`  | `asc-apk`     | `ZipView::parse`, `entry.name()`, `ZipView::classes_dex_offsets()`  |
| `fuzz_elf`            | `asc-apk`     | `elf::parse_elf(&[u8]) -> Result<ElfInfo, &str>`                    |
| `fuzz_signing`        | `asc-apk`     | `signing::scan`, `der::parse_cert`, `der::parse_pkcs7`              |
| `fuzz_arsc`           | `asc-resources` | `asc_resources::parse`, `Table::render`, `describe_config`        |
| `fuzz_axml`          | `asc-manifest` | `axml::parse_axml(&[u8])`, `axml::format_axml_text(&doc)`           |
| `fuzz_apk_open`      | `asc-apk`     | `Apk::open(path)`, `entries()`, `read_entry_prefix`, `dex_entries()`, `signing_scan()` |
| `fuzz_inspect`       | `asc-core`    | `run_inspect`, `run_native`, `run_cert`, `run_resources(path, query)` |
| `fuzz_rebuild`        | `asc-rebuild` | `rebuild(view, type_idx) -> Result<Vec<u8>, Error>`                 |
| `fuzz_disasm`         | `asc-decompile` | `DroidsawBackend::disassemble(bytes, descriptor, method) -> Result<String, DecompileError>` |
| `fuzz_hermes`        | `asc-core`    | `hermes::extract_strings(bytes, opts)` (bytes-level, no ZIP)          |
| `fuzz_xapk`          | `asc-core`    | `xapk::analyze_member(name, c, u, bytes)` (member APK bytes, no outer ZIP) |

`dummy` is always compiled and never touches a sibling crate —
it exists for self-test only.

## Status

- `cargo build --release` in `fuzz/` is GREEN (features OFF).
- `cargo test` is GREEN: registry-len assertion + seed-output
  assertion.
- `cargo run --release --bin fuzz-runner -- --target dummy
  --seconds 2` finds a crash and writes
  `crashes/dummy-<hash>.bin`.
- `cargo run --release --bin fuzz-runner -- --target dummy
  --regress crashes` exits nonzero when replaying the saved
  crash.
- All 18 seed subdirectories are populated by `gen-seeds`.
- `fuzz_disasm` ran 20 s (`--features decompile`, seed
  0xA5A5C0DEBEEF, 6 seeds) with no panic: 4243 executions,
  ok=67 / boundary=4176. `ok` counts inputs that got past the DEX
  gate into the smali renderer. The target re-seals the header
  (SHA-1 + adler32, and `file_size` / `header_size` / `endian_tag`)
  for 7 of every 8 inputs so mutations reach the renderer instead of
  the checksum, and fails the run when `disassemble` returns a
  `BackendError` carrying the backend's caught-panic marker. The
  1-in-8 un-sealed case and the 5 cheap `dex_minimal` seeds keep the
  gate path fuzzed. `--regress` over
  `corpus/dex/aurora_classes2.dex` reports `ok`.
- `fuzz_apk_open` and `fuzz_inspect` each ran 20 s
  (`--seeds seeds/apk_file --verbose 1`) with no panic; both stage
  every input into `%TEMP%` as a uniquely named file that is deleted
  when the target returns.
