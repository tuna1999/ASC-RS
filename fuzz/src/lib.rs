//! # asc-fuzz
//!
//! Deterministic mutation fuzzer for the ASC-RS read-only stack
//! (`asc-dex`, `asc-bytecode`, `asc-apk`, `asc-rebuild`).
//!
//! Designed to run on stable Rust WITHOUT cargo-fuzz / sanitizers:
//! the runner drives mutations from a corpus using `splitmix64`,
//! per-input panics are caught by a process-wide panic hook that dumps
//! the failing input to `crashes/`, and an outer shell loop
//! (`run.sh` / `run.ps1`) restarts the runner until the time budget
//! elapses without a panic (= "green").
//!
//! Targets are written against the **contract APIs** of sibling crates;
//! every target is registered unconditionally but compiles its
//! integration body behind a per-crate Cargo feature (`dex`,
//! `bytecode`, `apk`, `rebuild` — all OFF by default). With features
//! off, each target reports `FuzzOutcome::SkippedDisabled` so the
//! registry remains populated and `cargo build` stays green while
//! sibling agents finish landing the real APIs.

#[path = "../fuzz_targets/mod.rs"]
pub mod fuzz_targets;

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// What a single target invocation reported.
///
/// Targets must NEVER assert on the semantic correctness of the input
/// — only on the absence of panics / OOM / hang. Targets that hit a
/// notable **boundary** error class (truncated stream, invalid magic,
/// out-of-range offset) report `BoundaryHit` so the runner can retain
/// the input for regression testing without confusing panics with
/// ordinary parse failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzOutcome {
    /// No notable signal — drop the input.
    Ok,
    /// Reached a parse/format boundary that we want to keep as a
    /// regression seed.
    BoundaryHit(&'static str),
    /// Target was disabled by feature flag — runner logs once and
    /// moves on.
    SkippedDisabled,
}

impl FuzzOutcome {
    pub fn is_ok(&self) -> bool {
        matches!(self, FuzzOutcome::Ok)
    }
    pub fn is_interesting(&self) -> bool {
        matches!(self, FuzzOutcome::BoundaryHit(_))
    }
    pub fn is_disabled(&self) -> bool {
        matches!(self, FuzzOutcome::SkippedDisabled)
    }
}

/// Type alias for a fuzz target function.
pub type TargetFn = fn(&[u8]) -> FuzzOutcome;

/// Static descriptor for one entry in the registry.
#[derive(Clone, Copy)]
pub struct TargetInfo {
    pub name: &'static str,
    pub func: TargetFn,
    /// Subdirectory of `fuzz/seeds/` used as the default corpus for
    /// this target.
    pub default_seed: &'static str,
}

/// Returns the full registry of fuzz targets. Always includes
/// `dummy` plus all contract targets; with crate features off, the
/// contract targets return `FuzzOutcome::SkippedDisabled`.
pub fn registry() -> Vec<TargetInfo> {
    vec![
        TargetInfo {
            name: "dummy",
            func: fuzz_targets::dummy::run,
            default_seed: "dummy",
        },
        TargetInfo {
            name: "fuzz_dex_header",
            func: fuzz_targets::fuzz_dex_header::run,
            default_seed: "dex_minimal",
        },
        TargetInfo {
            name: "fuzz_uleb128",
            func: fuzz_targets::fuzz_uleb128::run,
            default_seed: "uleb_runs",
        },
        TargetInfo {
            name: "fuzz_mutf8",
            func: fuzz_targets::fuzz_mutf8::run,
            default_seed: "mutf8_truncated",
        },
        TargetInfo {
            name: "fuzz_class_data",
            func: fuzz_targets::fuzz_class_data::run,
            default_seed: "class_data_blob",
        },
        TargetInfo {
            name: "fuzz_code_item",
            func: fuzz_targets::fuzz_code_item::run,
            default_seed: "code_item_blob",
        },
        TargetInfo {
            name: "fuzz_ref_walker",
            func: fuzz_targets::fuzz_ref_walker::run,
            default_seed: "bytecode_blob",
        },
        TargetInfo {
            name: "fuzz_encoded_value",
            func: fuzz_targets::fuzz_encoded_value::run,
            default_seed: "encoded_value_blob",
        },
        TargetInfo {
            name: "fuzz_annotations",
            func: fuzz_targets::fuzz_annotations::run,
            default_seed: "annotations_blob",
        },
        TargetInfo {
            name: "fuzz_dex041",
            func: fuzz_targets::fuzz_dex041::run,
            default_seed: "dex041_two_header",
        },
        TargetInfo {
            name: "fuzz_zip_directory",
            func: fuzz_targets::fuzz_zip_directory::run,
            default_seed: "zip_eocd_only",
        },
        TargetInfo {
            name: "fuzz_rebuild",
            func: fuzz_targets::fuzz_rebuild::run,
            default_seed: "dex_minimal",
        },
    ]
}

// =====================================================================
// Shared helpers used by targets AND by the runner binaries.
// =====================================================================

/// FNV-1a 64-bit hash. Std-only, deterministic, plenty collision-free
/// for crash-filename disambiguation within one process.
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// Format the canonical crash file name:
/// `crashes/<target>-<fnv1a_hex16>.bin`
pub fn crash_path(crash_dir: &Path, target: &str, input: &[u8]) -> PathBuf {
    let hex = format!("{:016x}", fnv1a_64(input));
    crash_dir.join(format!("{}-{}.bin", target, hex))
}

/// Write `input` to `crashes/<target>-<fnv1a_hex16>.bin`. Creates the
/// directory if missing. Returns the written path. Idempotent: if the
/// file already exists, leaves it alone (deterministic — same input
/// always writes the same name).
pub fn write_crash(crash_dir: &Path, target: &str, input: &[u8]) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(crash_dir)?;
    let p = crash_path(crash_dir, target, input);
    match std::fs::write(&p, input) {
        Ok(()) => Ok(p),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(p),
        Err(e) => Err(e),
    }
}

// -------- Panic hook machinery --------
//
// The runner installs ONE process-wide panic hook. Each iteration
// writes the candidate input into `PANIC_INPUT` *before* invoking the
// target; if the target panics, the hook grabs the input, writes it
// to `crashes/`, and lets Rust abort the process. The outer shell loop
// then restarts the runner.

static PANIC_TARGET: OnceLock<String> = OnceLock::new();
static PANIC_CRASH_DIR: OnceLock<PathBuf> = OnceLock::new();
static PANIC_INPUT: OnceLock<Mutex<Option<Vec<u8>>>> = OnceLock::new();

/// Install the panic hook. `target` and `crash_dir` are remembered for
/// the lifetime of the process. Calling more than once is a no-op for
/// the hook (we don't double-install) but still updates the
/// remembered target / crash dir so a long-lived runner that switched
/// targets still dumps correctly. In practice the runner spawns a
/// fresh process per `--target`, so this is mostly defensive.
pub fn install_panic_hook(target: &str, crash_dir: &Path) {
    let _ = PANIC_TARGET.set(target.to_string());
    let _ = PANIC_CRASH_DIR.set(crash_dir.to_path_buf());
    PANIC_INPUT.get_or_init(|| Mutex::new(None));

    // set_hook returns Err if a hook is already installed; that is
    // fine — the FIRST installation wins for the process lifetime.
    let _ = std::panic::set_hook(Box::new(|info| {
        let payload = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => s.as_str(),
                None => "<non-string panic payload>",
            },
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_string());
        eprintln!(
            "PANIC caught by asc-fuzz hook: {payload} at {location}"
        );

        if let (Some(target), Some(crash_dir), Some(slot)) = (
            PANIC_TARGET.get(),
            PANIC_CRASH_DIR.get(),
            PANIC_INPUT.get(),
        ) {
            if let Some(input) = slot.lock().ok().and_then(|g| g.clone()) {
                match write_crash(crash_dir, target, &input) {
                    Ok(path) => eprintln!("Saved crashing input to {}", path.display()),
                    Err(e) => eprintln!("Failed to save crashing input: {e}"),
                }
            } else {
                eprintln!("No input captured at panic time.");
            }
        }
        // Re-emit the default Rust abort behaviour so the process exits
        // with a non-zero code (the outer shell loop notices).
    }));
}

/// Store the candidate input so a subsequent panic can dump it.
/// Called once per mutation before invoking the target.
pub fn set_panic_input(input: &[u8]) {
    if let Some(slot) = PANIC_INPUT.get() {
        if let Ok(mut g) = slot.lock() {
            *g = Some(input.to_vec());
        }
    }
}

// -------- Operation budget --------

/// Hard upper bound on the number of `RefWalker::next` steps one input
/// may consume. RefWalker is linear in the code-item length; a 100MB
/// input divided by 2-byte units = 50M iterations. We cap at 10M to
/// bound per-input wall time while still exploring large adversarial
/// cases. If the walker signals "step limit reached" the target
/// reports `BoundaryHit` (still safe to retain).
pub const REF_WALKER_STEP_BUDGET: u64 = 10_000_000;

/// Hard upper bound on the total bytes a single uleb128 decode loop
/// will read before it gives up. ULEB is 5 bytes max in spec; we
/// generously allow 16 to defend against malicious encodings that
/// would otherwise hang on `while byte & 0x80 != 0`.
pub const ULEB_MAX_BYTES: usize = 16;
// =====================================================================
// Seed generation
// =====================================================================
//
// The seed-emission logic is exposed from the library so the
// `gen-seeds` binary AND the integration tests can both call it
// without duplicating the byte-construction code.

pub mod seeds;
