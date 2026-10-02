//! fuzz-runner: deterministic, seeded, corpus-driven mutation fuzzer.
//!
//! See `fuzz/README.md` for the high-level design. Highlights:
//!
//! - **Determinism.** `splitmix64` seeded from a CLI flag (default
//!   `0xA5A5_C0DE_BEEF`) — same seed always produces the same
//!   mutation sequence. The seed is logged to stderr at startup.
//! - **Panic handling.** A process-wide panic hook (installed via
//!   `asc_fuzz::install_panic_hook`) captures the input bytes that
//!   were live at the moment of panic, writes them to
//!   `crashes/<target>-<fnv1a_hex>.bin`, and lets Rust abort. An
//!   outer shell loop (`run.sh` / `run.ps1`) restarts the runner.
//! - **Mutation set.** bit flip, byte substitution, chunk splice
//!   (from another seed), truncate, extend with magic dictionaries
//!   (DEX 035, DEX 041, ZIP local, ZIP central, ULEB edge cases).
//! - **Outcome-aware retention.** Targets return `FuzzOutcome`;
//!   outcomes tagged `BoundaryHit` retain their input to
//!   `corpus-out/`. Plain `Ok` and `SkippedDisabled` are dropped.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;

use asc_fuzz::{
    FuzzOutcome, TargetInfo, crash_path, fnv1a_64, install_panic_hook, registry, set_panic_input,
};

// =====================================================================
// CLI
// =====================================================================

#[derive(Parser, Debug)]
#[command(
    name = "fuzz-runner",
    about = "Deterministic mutation fuzzer for ASC-RS targets",
    version
)]
struct Args {
    /// Target name (use `--list` to enumerate).
    #[arg(long)]
    target: Option<String>,

    /// Print the registry and exit.
    #[arg(long, default_value_t = false)]
    list: bool,

    /// Wall-time budget for this process invocation (seconds).
    /// The outer restart loop sets this to the remaining budget on
    /// each restart, so a panic never costs more than a few seconds
    /// of unobserved time.
    #[arg(long, default_value_t = 60)]
    seconds: u64,

    /// Maximum number of mutations per invocation (0 = unlimited).
    /// Useful in tests so the smoke run terminates promptly.
    #[arg(long, default_value_t = 0)]
    max_iters: u64,

    /// Directory containing seed inputs (files; one input per file).
    #[arg(long)]
    seeds: Option<PathBuf>,

    /// Where to retain interesting inputs (those that triggered a
    /// `BoundaryHit`). Created if absent.
    #[arg(long)]
    corpus_out: Option<PathBuf>,

    /// If set, replay every file under this directory through the
    /// target exactly once. Exit code is 0 only if every replay
    /// completed without panic.
    #[arg(long)]
    regress: Option<PathBuf>,

    /// RNG seed for deterministic mutation order. Same seed →
    /// same sequence.
    #[arg(long, default_value_t = DEFAULT_SEED)]
    seed: u64,

    /// Where to dump panicking inputs.
    #[arg(long, default_value = "crashes", value_parser = clap::value_parser!(PathBuf))]
    crash_dir: PathBuf,

    /// Verbosity: 0 = summary only, 1 = periodic progress, 2 = every
    /// mutation.
    #[arg(long, default_value_t = 1)]
    verbose: u8,

    /// When `--target` is omitted AND `--list` is not set, the
    /// runner defaults to the `dummy` target (which always panics
    /// on non-empty input). Makes `cargo run --bin fuzz-runner`
    /// self-test the harness.
    #[arg(long, default_value_t = false)]
    allow_default_dummy: bool,
}
#[allow(dead_code)]
fn default_crash_dir() -> PathBuf {
    PathBuf::from("crashes")
}

const DEFAULT_SEED: u64 = 0xA5A5_C0DE_BEEF_u64;

// =====================================================================
// main
// =====================================================================

fn main() {
    let args = Args::parse();

    if args.list {
        print_registry();
        std::process::exit(0);
    }

    let target_name = match &args.target {
        Some(t) => t.clone(),
        None if args.allow_default_dummy => "dummy".to_string(),
        None => {
            eprintln!("error: --target <name> is required (or pass --list)");
            std::process::exit(2);
        }
    };

    let target = match registry().into_iter().find(|t| t.name == target_name) {
        Some(t) => t,
        None => {
            eprintln!("error: unknown target '{target_name}'; pass --list to see options");
            std::process::exit(2);
        }
    };

    if args.regress.is_some() {
        let exit = run_regress(target, &args);
        std::process::exit(exit);
    }

    let exit_code = run_mutation_loop(target, &args);
    std::process::exit(exit_code);
}

// =====================================================================
// Registry listing
// =====================================================================

fn print_registry() {
    println!("Registered fuzz targets ({}):", registry().len());
    for t in registry() {
        println!("  {:<24} seed: seeds/{}", t.name, t.default_seed);
    }
}

// =====================================================================
// Regress mode
// =====================================================================

/// Replay every file under `dir` through `target` once. Returns the
/// desired process exit code (0 if no panics). On panic, the panic
/// hook dumps the crashing input and aborts — the outer shell loop
/// notices the nonzero exit and reports RED.
fn run_regress(target: TargetInfo, args: &Args) -> i32 {
    let dir = args.regress.as_ref().expect("set by caller");
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect(),
        Err(e) => {
            eprintln!("regress: cannot read directory {}: {e}", dir.display());
            return 2;
        }
    };
    entries.sort();

    eprintln!(
        "regress: replaying {} file(s) from {} through target '{}'",
        entries.len(),
        dir.display(),
        target.name
    );

    install_panic_hook(target.name, &args.crash_dir);
    for (i, path) in entries.iter().enumerate() {
        let input = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("regress[{}]: cannot read {}: {e}", i, path.display());
                std::process::exit(2);
            }
        };
        set_panic_input(&input);
        let outcome = (target.func)(&input);
        let status = if outcome.is_disabled() {
            "DISABLED"
        } else if outcome.is_interesting() {
            "boundary"
        } else {
            "ok"
        };
        eprintln!(
            "regress[{:04}/{}] {} -> {}",
            i + 1,
            entries.len(),
            path.display(),
            status
        );
    }
    0
}

// =====================================================================
// Mutation loop
// =====================================================================

/// Global "stop after current input" flag — flipped by SIGINT so a
/// Ctrl-C in the middle of a long mutation exits cleanly with stats.
static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
fn install_signal_handler() {
    use std::os::raw::c_int;
    extern "C" fn handler(_sig: c_int) {
        STOP.store(true, Ordering::SeqCst);
    }
    // SAFETY: signal() is async-signal-unsafe in general, but we
    // only set an atomic bool. Best-effort "graceful stop"; the
    // outer shell loop also bounds wall time.
    unsafe {
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
    }
}

#[cfg(not(unix))]
fn install_signal_handler() {
    // No portable signal handler in std for Windows; the outer
    // shell loop bounds wall time, which is the primary safety net.
}

#[derive(Default, Debug, Clone, Copy)]
struct Stats {
    executions: u64,
    ok: u64,
    boundary: u64,
    skipped: u64,
}

impl Stats {
    fn record(&mut self, o: &FuzzOutcome) {
        self.executions += 1;
        match o {
            FuzzOutcome::Ok => self.ok += 1,
            FuzzOutcome::BoundaryHit(_) => self.boundary += 1,
            FuzzOutcome::SkippedDisabled => self.skipped += 1,
        }
    }

    fn summary(&self) -> String {
        format!(
            "executions={} ok={} boundary={} skipped_disabled={}",
            self.executions, self.ok, self.boundary, self.skipped
        )
    }
}

fn run_mutation_loop(target: TargetInfo, args: &Args) -> i32 {
    install_panic_hook(target.name, &args.crash_dir);
    install_signal_handler();

    let seeds = load_seeds(args.seeds.as_deref(), target.default_seed);
    if seeds.is_empty() {
        eprintln!(
            "warning: no seeds found; using a single 16-byte zero seed (results not meaningful)"
        );
    }
    eprintln!(
        "fuzz-runner: target='{}' seed={:#x} seconds={} max_iters={} seeds={} crash_dir={}",
        target.name,
        args.seed,
        args.seconds,
        if args.max_iters == 0 {
            "unbounded".to_string()
        } else {
            args.max_iters.to_string()
        },
        seeds.len(),
        args.crash_dir.display(),
    );

    let mut rng = Splitmix64::new(args.seed);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(args.seconds);
    let report_interval = Duration::from_secs(2);

    let mut stats = Stats::default();
    let mut last_report = Instant::now();

    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        if args.max_iters != 0 && stats.executions >= args.max_iters {
            break;
        }

        // Pick a base seed.
        let base_idx = rng.next_usize(seeds.len().max(1));
        let base = if seeds.is_empty() {
            &EMPTY_SEED[..]
        } else {
            &seeds[base_idx]
        };

        // Mutate.
        let mutated = mutate(base, &seeds, &mut rng);

        // Make the candidate input visible to the panic hook.
        set_panic_input(&mutated);

        // Run. A panic here aborts the process; the hook has
        // already saved the crashing input.
        let outcome = (target.func)(&mutated);

        stats.record(&outcome);
        if outcome.is_interesting() {
            if let Some(out_dir) = &args.corpus_out {
                if let Err(e) = save_corpus_hit(out_dir, target.name, &mutated, &outcome) {
                    eprintln!("warning: could not write corpus hit: {e}");
                }
            }
        }

        if args.verbose >= 2 {
            eprintln!(
                "exec {:08} base={:04} -> outcome={:?} len={}",
                stats.executions,
                base_idx,
                outcome,
                mutated.len()
            );
        }

        if args.verbose >= 1 && last_report.elapsed() >= report_interval {
            eprintln!(
                "[{:>6.1}s] {}",
                start.elapsed().as_secs_f64(),
                stats.summary()
            );
            last_report = Instant::now();
        }
    }

    eprintln!("=== fuzz-runner summary ===");
    eprintln!(
        "target='{}' seed={:#x} elapsed={:.2}s {}",
        target.name,
        args.seed,
        start.elapsed().as_secs_f64(),
        stats.summary()
    );
    0
}

static EMPTY_SEED: [u8; 16] = [0u8; 16];

// =====================================================================
// Seeds
// =====================================================================

fn load_seeds(dir: Option<&Path>, default_subdir: &str) -> Vec<Vec<u8>> {
    let dir = dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("seeds").join(default_subdir));

    let mut out = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&path) {
            // Cap individual seed size to 16 MiB so a stray huge
            // file doesn't dominate the mutation loop.
            if bytes.len() <= 16 * 1024 * 1024 {
                out.push(bytes);
            }
        }
    }
    out.sort_by(|a, b| a.len().cmp(&b.len()));
    out
}

// =====================================================================
// Corpus hit retention
// =====================================================================

fn save_corpus_hit(
    out_dir: &Path,
    target: &str,
    input: &[u8],
    outcome: &FuzzOutcome,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(out_dir)?;
    let tag = match outcome {
        FuzzOutcome::BoundaryHit(s) => *s,
        _ => "hit",
    };
    let name = format!("{}-{}-{:016x}.bin", target, tag, fnv1a_64(input));
    let path = out_dir.join(name);
    std::fs::write(&path, input)?;
    Ok(path)
}

// =====================================================================
// Splitmix64 PRNG
// =====================================================================

struct Splitmix64 {
    state: u64,
}

impl Splitmix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn next_usize(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() as usize) % n
        }
    }
    #[allow(dead_code)]
    fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) != 0
    }
    #[allow(dead_code)]
    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

// =====================================================================
// Mutation strategies
// =====================================================================

/// Magic dictionary: small, format-relevant byte sequences. Inserted
/// whole-cloth during the "extend" mutation so the fuzzer quickly
/// learns DEX/ZIP/ULEB prefixes.
const MAGIC_DICT: &[&[u8]] = &[
    b"dex\n035\x00",
    b"dex\n037\x00",
    b"dex\n038\x00",
    b"dex\n039\x00",
    b"dex\n040\x00",
    b"dex\n041\x00",
    b"PK\x03\x04",
    b"PK\x01\x02",
    b"PK\x05\x06",
    // ULEB edge cases:
    &[0x80, 0x80, 0x80, 0x80, 0x01], // 5-byte ULEB(1)
    &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F], // 5-byte ULEB max
    &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01], // 9-byte corrupt
    &[0x00],
    &[0x7F], // 1-byte ULEB max
];

const MAX_OUTPUT_LEN: usize = 256 * 1024;

fn mutate(base: &[u8], corpus: &[Vec<u8>], rng: &mut Splitmix64) -> Vec<u8> {
    // Pick one of six strategies, weighted.
    let r = rng.next_u8() % 10;
    let mut out = match r {
        0..=3 => mutate_bit_flip(base, rng),
        4..=5 => mutate_byte_substitute(base, rng),
        6 => mutate_truncate(base, rng),
        7 => mutate_extend(base, rng),
        8 => mutate_splice(base, corpus, rng),
        _ => mutate_chunk_overwrite(base, rng),
    };
    if out.len() > MAX_OUTPUT_LEN {
        out.truncate(MAX_OUTPUT_LEN);
    }
    out
}

fn mutate_bit_flip(base: &[u8], rng: &mut Splitmix64) -> Vec<u8> {
    if base.is_empty() {
        return vec![rng.next_u8()];
    }
    let mut out = base.to_vec();
    let flips = 1 + (rng.next_u8() % 4) as usize;
    for _ in 0..flips {
        let idx = rng.next_usize(out.len());
        let bit = rng.next_u8() & 7;
        out[idx] ^= 1 << bit;
    }
    out
}

fn mutate_byte_substitute(base: &[u8], rng: &mut Splitmix64) -> Vec<u8> {
    if base.is_empty() {
        return vec![rng.next_u8()];
    }
    let mut out = base.to_vec();
    let subs = 1 + (rng.next_u8() % 4) as usize;
    for _ in 0..subs {
        let idx = rng.next_usize(out.len());
        out[idx] = rng.next_u8();
    }
    out
}

fn mutate_truncate(base: &[u8], rng: &mut Splitmix64) -> Vec<u8> {
    if base.is_empty() {
        return Vec::new();
    }
    let len = base.len();
    let new_len = if len == 1 { 0 } else { rng.next_usize(len) };
    base[..new_len].to_vec()
}

fn mutate_extend(base: &[u8], rng: &mut Splitmix64) -> Vec<u8> {
    // Pick a magic token; append.
    let token = MAGIC_DICT[rng.next_usize(MAGIC_DICT.len())];
    let mut out = base.to_vec();
    out.extend_from_slice(token);
    // Optionally follow with a few random bytes.
    let tail = (rng.next_u8() % 8) as usize;
    for _ in 0..tail {
        out.push(rng.next_u8());
    }
    out
}

fn mutate_splice(base: &[u8], corpus: &[Vec<u8>], rng: &mut Splitmix64) -> Vec<u8> {
    if corpus.len() < 2 || base.is_empty() {
        return mutate_byte_substitute(base, rng);
    }
    let donor = &corpus[rng.next_usize(corpus.len())];
    if donor.is_empty() {
        return base.to_vec();
    }
    let self_off = rng.next_usize(base.len());
    let donor_off = rng.next_usize(donor.len());
    let donor_take = rng.next_usize(donor.len() - donor_off) + 1;
    let mut out = base.to_vec();
    let insertion_len = donor_take.min(MAX_OUTPUT_LEN.saturating_sub(self_off));
    if insertion_len == 0 {
        return out;
    }
    let donor_end = donor_off + insertion_len;
    let splice: Vec<u8> = donor[donor_off..donor_end].to_vec();
    out.splice(self_off..self_off, splice);
    out
}

fn mutate_chunk_overwrite(base: &[u8], rng: &mut Splitmix64) -> Vec<u8> {
    if base.is_empty() {
        return vec![rng.next_u8(); 8];
    }
    let mut out = base.to_vec();
    let start = rng.next_usize(out.len());
    let chunk = 1 + rng.next_usize(8);
    for i in 0..chunk {
        if start + i < out.len() {
            out[start + i] = rng.next_u8();
        }
    }
    out
}

// =====================================================================
// Crash path re-export (used by asc_fuzz::write_crash already).
// =====================================================================

#[allow(dead_code)]
fn _path_for_doc(crash_dir: &Path, target: &str, input: &[u8]) -> PathBuf {
    crash_path(crash_dir, target, input)
}
