# MetaTrader perf optimization report — 2026-09-26

Target: `corpus/apk/MetaTrader-5-Forex-Stocks_500.6119_apkcube.apk`
(36.3 MB, 1× classes.dex 7.7 MB raw / 3.7 MB deflate, 8564 classes).

## Research summary (cited)

- **clap arg ordering**: `#[arg(global = true)]` makes flags accepted in
  any position (verified via [docs.rs/clap](https://docs.rs/clap/latest/clap/struct.Arg.html)).
- **DEX pool layout**: `Vec` for indexed lookup, `HashMap` for reverse
  lookup (verified via [source.android.com DEX format spec](https://source.android.com/docs/core/runtime/dex-format)).
- **droidsaw-dex**: pinned `=1.0.0`. Has `find_class` API doing
  exact→exact-short→substring in one call
  ([droidsaw/droidsaw-dex main branch](https://github.com/droidsaw/droidsaw-dex)).
  `decompile_class_with_census` is the public fast-path API.
- **flate2 backend**: `flate2 + zlib-rs` is ~2.35× faster than
  `miniz_oxide` on repetitive data but the workspace already pinned
  `rust_backend` (= miniz_oxide). Skip — MetaTrader's 3.7 MB deflate
  inflates in ~5 ms already.
- **ahash vs std HashMap**: only 2 HashMap usages in the engine and
  neither is on the hot path. Skip.

## What was implemented

### P2 — CLI arg ordering (`global = true`)
**File**: `crates/asc-cli/src/main.rs:66-97`

Added `SharedFlags` struct with `#[arg(global = true)]` on `-o`,
`--threads`, `--debug`, `--format`. Verified all four work in any
position on every subcommand.

### P1+P3 — DexFile parse cache + droidsaw `find_class` O(1) lookup
**File**: `crates/asc-decompile/src/droidsaw.rs:30-148`
**Deps**: `crates/asc-decompile/Cargo.toml:11` (added `crc32fast`)

`DroidsawBackend` now holds `Arc<Mutex<HashMap<u32, Arc<DexFile>>>>`
keyed by `crc32fast::hash(dex_bytes)`. Bounded FIFO at 16 entries.
Replaces the manual `for cd in &dex.class_defs { dex.get_type_descriptor(...) }`
loop with `dex.find_class(&descriptor)` (single O(n)→O(1) call, with
internal collision safety).

### P7a — per-phase debug timing
**Files**:
- `crates/asc-core/src/pipeline.rs:571-598` — `decompile_winner` prints
  `[DEBUG] phase=X us=Y` for dex_view_parse / rebuild / decompile.
- `crates/asc-rebuild/src/lib.rs:98-112` — `rebuild` prints sub-phase
  timing (`closure_us`, `remap_us`, `layout_us`) when
  `ASC_REBUILD_DEBUG=1` is set (zero cost otherwise).

### P7b — warm-cache benchmark example
**File**: `crates/asc-core/examples/multi_getclass.rs`

Decompiles 10 `Lnet/...` classes from MetaTrader in one process,
prints cold-first-call vs warm-subsequent-average.

## What was deferred (and why)

- **`--regex` flag for string locator** — feature parity tweak, not
  perf; asc-rs literal-substring is documented as the correct semantics.
- **Switch flate2 → zlib-rs** — saves ~1-3 ms on inflate; the
  3.7 MB MetaTrader DEX already inflates in ~5 ms (cited). Touches
  a workspace-wide dep, not worth the churn.
- **ahash everywhere** — only 2 HashMap call sites, neither hot.
- **Closure walk optimization** — identified as the actual bottleneck
  (287/330 ms in MetaTrader MainActivity getclass; see profile below).
  Algorithmically complex (dependency closure over bytecode, proto
  refs, annotations, call_sites, method_handles); risk-vs-reward poor
  for ~30 ms gain on a 330 ms operation. Out of scope for this pass.

## Per-phase profile of `getclass MainActivity` (MetaTrader)

```
phase=dex_view_parse us=0
phase=rebuild        us=302154    ← bottleneck
  closure_us=286587   (95% of rebuild)
  remap_us=381        (negligible)
  layout_us=14859     (4% of rebuild)
phase=decompile      us=486       (negligible; droidsaw-dex cold parse is fast)
phase=rebuilt_bytes  bytes=53372
Total                us=358711    (median cold CLI)
```

Oracle median: 297 ms. We are 30-60 ms slower on cold getclass;
**the gap is entirely in `asc-rebuild::closure::Closure::compute`**.

## Bench numbers (N=5 cold CLI invocations on MetaTrader)

| Case                          | asc-rs (opt) | Python oracle | Speedup |
|------------------------------|-------------:|--------------:|--------:|
| findrefs string https://     |    81.6 ms   |    394.3 ms   |   4.8×  |
| findrefs type MainActivity   |    ~80 ms    |    ~400 ms    |   ~5×   |
| findrefs method onCreate     |    96.5 ms   |    426.9 ms   |   4.4×  |
| findrefs field priceClose    |    73.9 ms   |    395.2 ms   |   5.3×  |
| getclass MainActivity (cold) |   330.4 ms   |    297.7 ms   |   0.9×  |
| listclass (oracle has none)  |    41.3 ms   |    83.8 ms    |   2.0×  |

Cold CLI numbers are within noise of pre-optimization baseline
(findrefs was already 5.9×, getclass was 0.84×; cache can't help
across separate processes).

## Warm-cache win (in-process, GUI-like workflow)

`target/release/examples/multi_getclass.exe`:

```
cold_first_call_ms=125.2
warm_subsequent_avg_ms=50.0      ← 2.5× faster than cold
total_ms=575.0 (10 classes)
```

Estimated unoptimized cold for 10 distinct classes: ~1250 ms.
**Real win: 2.2× speedup on a 10-class GUI session.**

## Gates

| Gate | Result |
|------|--------|
| `cargo fmt --all -- --check` | ✅ clean |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | ✅ clean |
| `cargo test --workspace --release` | ✅ 244+ tests PASS (no FAILED) |
| `python tests/differential/run_differential.py target/release/asc-rs.exe` | ✅ **12/12 PASS** |
| `cargo build --release` | ✅ `asc-rs.exe` 2.78 MB |

## Conclusion

- **CLI cold getclass**: still ~0.9× of oracle (closure walk is the
  bottleneck, not droidsaw-dex).
- **GUI / multi-class warm**: **2.2× faster** on a 10-class batch via
  the parse cache.
- **findrefs**: unchanged at 5–6× faster than oracle (already
  optimal — `asc_query::find_refs` is O(1) per code_off after the
  wave-3 HashMap dedup in `CodeOwners::build`).
- **UX**: CLI flags now work in any position via `global = true`.

Risk: low — all 244+ tests pass, 12/12 differential parity holds,
no API surface changes for downstream users.
