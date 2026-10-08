//! # asc-cli
//!
//! CLI parity frontend for `asc-rs`: `asc-rs getclass <apk> <class>`,
//! `asc-rs disasm <apk|dex> <class> [--method NAME]`,
//! `asc-rs findrefs <apk> {string|type|method|field} ...`, and
//! `asc-rs listclass <apk> [--prefix P]`, `asc-rs manifest <apk>`,
//! `asc-rs inspect <apk|dex>`, `asc-rs native <apk|dex>`, `asc-rs cert <apk>`, and
//! `asc-rs resources <apk>`,
//! with `--format text|json`, `-o/--output`, `--threads`, `--debug`.
//!
//! All engine logic lives in `asc-core`; this binary is a thin
//! arg-parsing / output-routing wrapper. Exit codes:
//!
//! - 0 — success (findrefs with zero hits is still success, as long as
//!   every DEX entry was scanned).
//! - 1 — class-not-found (`getclass`, `disasm`), method-not-found
//!   (`disasm --method`), or input validation error
//!   (`findrefs method` with neither name nor `--class`, empty
//!   `listclass --prefix`, `--threads 0`, etc.).
//! - 2 — internal / unexpected error (APK parse, rebuild, decompile),
//!   or a findrefs run in which at least one DEX entry failed to scan.
//!   Partial findrefs results are still printed in full (stdout) with
//!   per-DEX failure warnings on stderr; the JSON body keeps
//!   `complete: false` and the `errors` list.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Args, Parser, Subcommand, ValueEnum};

use asc_core::{
    CoreError, DisasmJob, DisasmOptions, FindRefsJob, FindRefsOptions, GetClassJob,
    GetClassOptions, ListClassesJob, ListClassesOptions, ResourcesQuery, format_cert_text,
    format_getclass_json, format_getclass_text, format_inspect_text, format_listclasses_json_opt,
    format_listclasses_text_opt, format_native_text, format_resources_text,
    format_search_report_json, format_search_report_text, run_cert, run_disasm, run_findrefs,
    run_getclass, run_inspect, run_listclasses, run_native, run_resources,
};
use asc_query::{ClassConstraint, Query};

/// CLI exit codes.
const EXIT_OK: u8 = 0;
const EXIT_USER_ERROR: u8 = 1;
const EXIT_INTERNAL: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Cmd::Manifest { apk, match_uri } = &cli.cmd {
        return run_manifest_cmd(
            apk,
            cli.shared.output.as_deref(),
            cli.shared.format,
            match_uri.as_deref(),
        );
    }
    if let Cmd::Cert { apk } = &cli.cmd {
        return run_cert_cmd(apk, cli.shared.output.as_deref(), cli.shared.format);
    }
    if let Cmd::Findrefs { apk, kind } = &cli.cmd {
        return run_findrefs_cmd(
            cli.shared.decode_xor,
            apk,
            kind,
            cli.shared.output.as_deref(),
            cli.shared.threads,
            cli.shared.debug,
            cli.shared.paranoid,
            cli.shared.format,
        );
    }
    if let Cmd::Resources {
        apk,
        id,
        strings,
        limit,
    } = &cli.cmd
    {
        return run_resources_cmd(
            apk,
            id.as_deref(),
            strings.as_deref(),
            *limit,
            cli.shared.output.as_deref(),
            cli.shared.format,
        );
    }
    if let Cmd::Strings {
        apk,
        substring,
        limit,
    } = &cli.cmd
    {
        return run_strings_cmd(
            apk,
            substring.as_deref(),
            *limit,
            cli.shared.output.as_deref(),
            cli.shared.format,
        );
    }
    if let Cmd::Extract {
        apk,
        entry,
        verify_crc,
    } = &cli.cmd
    {
        return run_extract_cmd(apk, entry, *verify_crc, cli.shared.output.as_deref());
    }
    if let Cmd::Axml { apk, entry } = &cli.cmd {
        return run_axml_cmd(apk, entry, cli.shared.output.as_deref(), cli.shared.format);
    }
    if let Cmd::Hermes {
        apk,
        pattern,
        limit,
    } = &cli.cmd
    {
        return run_hermes_cmd(
            apk,
            pattern.as_deref(),
            *limit,
            cli.shared.output.as_deref(),
            cli.shared.format,
        );
    }
    if let Cmd::Xapk { apk } = &cli.cmd {
        return run_xapk_cmd(apk, cli.shared.output.as_deref(), cli.shared.format);
    }
    match dispatch(&cli) {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            // Errors of the "user did something wrong" class
            // (ClassNotFound, Usage) print a clean message and exit 1;
            // everything else is exit 2.
            let code = match &e {
                CoreError::ClassNotFound(_)
                | CoreError::MethodNotFound(_)
                | CoreError::Usage(_)
                | CoreError::Class(_) => EXIT_USER_ERROR,
                _ => EXIT_INTERNAL,
            };
            // Match the oracle's `Error: …` stderr shape (see BEHAVIOR.md §7).
            eprintln!("Error: {e}");
            ExitCode::from(code)
        }
    }
}

/// Output format selector for `--format`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, Default)]
enum OutputFormat {
    /// Human-readable text format (the default; mirrors the oracle).
    #[default]
    Text,
    /// JSON-ready value emitted via `serde_json`.
    Json,
}

/// Flags that are accepted in any position — before or after the APK
/// positional — on every subcommand. Mirrors the Python oracle's
/// permissive `argparse` (`reference/asc/main.py:60-150`). `global = true`
/// makes clap scan the parent's flags from the subcommand's argv too.
#[derive(Args, Debug, Clone, Default)]
struct SharedFlags {
    /// Write the result to this file in addition to stdout.
    /// `-o/--output` is exclusive on `listclass` (matches the oracle's
    /// `cli.py:99`); the other subcommands append.
    #[arg(short = 'o', long = "output", global = true)]
    output: Option<PathBuf>,
    /// Number of worker threads (default 8).
    #[arg(long = "threads", default_value_t = 8, global = true)]
    threads: usize,
    /// Emit per-stage timing information to stderr.
    #[arg(long = "debug", default_value_t = false, global = true)]
    debug: bool,
    /// Output format (text | json). Default: text.
    /// Honored by every subcommand.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text, global = true)]
    format: OutputFormat,
    /// Decode Paranoid/LSParanoid-obfuscated strings: `getclass` shows
    /// literals, `findrefs string` also matches decoded values.
    /// Ignored by other subcommands.
    #[arg(long = "paranoid", default_value_t = false, global = true)]
    paranoid: bool,
    /// Decode XOR-obfuscated strings (const-array + literal-key decoder
    /// built in bytecode): `getclass` shows literals, `findrefs string`
    /// also matches decoded values. Ignored by other subcommands.
    #[arg(long = "decode-xor", default_value_t = false, global = true)]
    decode_xor: bool,
}

/// Per-subcommand shared args.
#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    #[command(flatten)]
    shared: SharedFlags,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Decompile a single class from an APK.
    Getclass {
        /// Path to the APK.
        apk: PathBuf,
        /// Class descriptor (`Lcom/poc/Main;` or `com.poc.Main`).
        class: String,
    },
    /// Disassemble a single class to a smali-syntax listing.
    ///
    /// Unlike `getclass` this does NOT rebuild a minimal DEX: the
    /// whole class-defining DEX is handed to the backend, so
    /// cross-class references and method bodies stay verbatim.
    /// Annotations, static values and debug info are not emitted.
    Disasm {
        /// Path to the APK or raw DEX.
        apk: PathBuf,
        /// Class descriptor (`Lcom/poc/Main;` or `com.poc.Main`).
        class: String,
        /// Emit only methods with this exact name (all overloads).
        #[arg(long = "method", value_name = "NAME")]
        method: Option<String>,
    },
    /// Find every caller of a matching reference in the APK.
    Findrefs {
        /// Path to the APK.
        apk: PathBuf,
        #[command(subcommand)]
        kind: FindRefsKind,
    },
    /// List every class defined in the APK (in DEX-definition order).
    Listclass {
        /// Path to the APK.
        apk: PathBuf,
        /// Only emit classes whose descriptor starts with this prefix.
        /// Accepts `Lcom/foo`, `Lcom/foo/Bar;`, `com.foo`, `com.foo.Bar;`.
        #[arg(long = "prefix")]
        prefix: Option<String>,
        /// Prefix each class with its defining DEX (`<dex> <descriptor>`);
        /// JSON gains a parallel `class_dex` array.
        #[arg(long = "with-dex")]
        with_dex: bool,
    },
    /// Dump AndroidManifest.xml: package, SDKs, permissions, components.
    Manifest {
        /// Path to the APK.
        apk: PathBuf,
        /// Also evaluate every intent filter's (API 35) URI-relative match
        /// surface against this URI — a component may have a reachable
        /// deep-link surface its declared scheme/host alone does not show.
        /// Verdicts are three-valued: matches / cannot match / unknown.
        #[arg(long = "match-uri")]
        match_uri: Option<String>,
    },
    /// Inventory an APK/DEX and report packer signals and anomalies.
    Inspect {
        /// Path to the APK or raw DEX.
        apk: PathBuf,
    },
    /// List native libraries (lib/, assets/*.so) and DEX native methods,
    /// joined by JNI export name.
    Native {
        /// Path to the APK or raw DEX.
        apk: PathBuf,
    },
    /// Display signing certificates (JAR v1, APK Signature Scheme v2/v3).
    /// Nothing is verified.
    Cert {
        /// Path to the APK.
        apk: PathBuf,
    },
    /// Inspect resources.arsc: inventory, lookup by ID, key/value search.
    Resources {
        /// Path to the APK.
        apk: PathBuf,
        /// Show every config variant of this resource ID (`0x7f020000`).
        #[arg(long, conflicts_with = "strings")]
        id: Option<String>,
        /// Substring (case-sensitive) over key names and string values.
        #[arg(long)]
        strings: Option<String>,
        /// Maximum hits printed.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Dump every DEX string-pool entry (multidex + DEX-041 aware),
    /// not just strings referenced by code.
    Strings {
        /// Path to the APK or raw DEX.
        apk: PathBuf,
        /// Case-sensitive substring filter.
        #[arg(long)]
        substring: Option<String>,
        /// Maximum strings emitted.
        #[arg(long, default_value_t = 100_000)]
        limit: usize,
    },
    /// Extract one archive entry to a file.
    Extract {
        /// Path to the APK.
        apk: PathBuf,
        /// Entry name (e.g. `assets/index.android.bundle`).
        entry: String,
        /// Verify the stored CRC-32 while reading.
        #[arg(long)]
        verify_crc: bool,
    },
    /// Decode an arbitrary compiled binary-XML entry (e.g.
    /// `res/xml/network_security_config.xml`) to text/JSON.
    Axml {
        /// Path to the APK.
        apk: PathBuf,
        /// Entry name inside the APK.
        entry: String,
    },
    /// Structured string-table extraction from Hermes bytecode bundles
    /// (version 96 only; other versions are reported unsupported).
    Hermes {
        /// Path to the APK.
        apk: PathBuf,
        /// Case-sensitive substring filter (e.g. a URL fragment).
        #[arg(long)]
        pattern: Option<String>,
        /// Maximum strings emitted per bundle.
        #[arg(long, default_value_t = 100_000)]
        limit: usize,
    },
    /// Inventory an XAPK (ZIP-of-APKs) container: member APKs,
    /// manifests, DEX class counts and native libs — analyzed per
    /// member, never merged.
    Xapk {
        /// Path to the XAPK.
        apk: PathBuf,
    },
}

/// The four findrefs query kinds.
#[derive(Subcommand, Debug)]
enum FindRefsKind {
    /// Substring match over string pool entries.
    String {
        /// Substring pattern (literal, never a regex).
        value: String,
    },
    /// Substring match over type descriptor text.
    Type {
        /// Substring pattern over the descriptor.
        value: String,
    },
    /// Find callers of methods matching `name` (and optional class).
    Method {
        /// Substring pattern over the method name. Optional if `--class` given.
        name: Option<String>,
        /// Restrict to one class. Accepts `L…;` or `dotted`.
        #[arg(long = "class")]
        class: Option<String>,
        /// Treat `--class` as a fuzzy substring instead of exact descriptor.
        #[arg(long = "fuzzy-class", default_value_t = false)]
        fuzzy_class: bool,
    },
    /// Find callers of fields matching `name` (and optional class).
    Field {
        /// Substring pattern over the field name. Optional if `--class` given.
        name: Option<String>,
        /// Restrict to one class.
        #[arg(long = "class")]
        class: Option<String>,
        #[arg(long = "fuzzy-class", default_value_t = false)]
        fuzzy_class: bool,
    },
}

fn dispatch(cli: &Cli) -> Result<(), CoreError> {
    let shared = &cli.shared;
    // The oracle rejects `--threads 0` with exit 1 for every command
    // (`ThreadPoolExecutor(max_workers=0)` / `list_classes`).
    if shared.threads == 0 {
        return Err(CoreError::Usage(
            "Worker count must be greater than zero".into(),
        ));
    }
    match &cli.cmd {
        Cmd::Getclass { apk, class } => run_getclass_cmd(
            apk,
            class,
            shared.output.as_deref(),
            shared.threads,
            shared.debug,
            shared.paranoid,
            shared.decode_xor,
            shared.format,
        ),
        Cmd::Disasm { apk, class, method } => run_disasm_cmd(
            apk,
            class,
            method.as_deref(),
            shared.output.as_deref(),
            shared.threads,
            shared.debug,
        ),
        // Handled in `main` (needs partial-result output + exit-code control).
        Cmd::Findrefs { .. } => unreachable!("handled in main"),
        Cmd::Listclass {
            apk,
            prefix,
            with_dex,
        } => run_listclass_cmd(
            apk,
            prefix.as_deref(),
            *with_dex,
            shared.output.as_deref(),
            shared.threads,
            shared.debug,
            shared.format,
        ),
        Cmd::Manifest { .. }
        | Cmd::Cert { .. }
        | Cmd::Resources { .. }
        | Cmd::Strings { .. }
        | Cmd::Extract { .. }
        | Cmd::Axml { .. }
        | Cmd::Hermes { .. }
        | Cmd::Xapk { .. } => {
            unreachable!("handled in main")
        }
        Cmd::Inspect { apk } => run_inspect_cmd(apk, shared.output.as_deref(), shared.format),
        Cmd::Native { apk } => run_native_cmd(apk, shared.output.as_deref(), shared.format),
    }
}

#[allow(clippy::too_many_arguments)] // flat CLI plumbing, mirrors the other cmds
fn run_getclass_cmd(
    apk: &std::path::Path,
    class: &str,
    output: Option<&std::path::Path>,
    threads: usize,
    debug: bool,
    paranoid: bool,
    decode_xor: bool,
    format: OutputFormat,
) -> Result<(), CoreError> {
    let started = Instant::now();
    let target = asc_core::normalize_class_name(class).map_err(CoreError::Class)?;
    let opts = GetClassOptions {
        threads,
        debug,
        paranoid,
        decode_xor,
        scan_budget_bytes: 0, // engine default
    };
    let job = GetClassJob::new(apk.to_path_buf(), target.clone());
    let result = run_getclass(&job, &opts)?;
    let source = match format {
        OutputFormat::Text => format_getclass_text(&result.source),
        OutputFormat::Json => to_json(&format_getclass_json(&result)),
    };
    let unbound = asc_core::unbound_locals(&result.source);
    if !unbound.is_empty() {
        eprintln!(
            "warning: decompiled Java may be incorrect: {} local(s) read but never assigned: {}",
            unbound.len(),
            unbound.join(", ")
        );
    }
    let dup_catches = asc_core::duplicated_catch_bodies(&result.source);
    if dup_catches >= 2 {
        eprintln!(
            "warning: decompiled Java may be incorrect: {dup_catches} identical catch bodies \
             (the DEX likely encodes several guarded ranges whose handlers converge into one \
             shared tail; the structurer copied it per catch; cross-check with `disasm`)"
        );
    }
    if debug {
        eprintln!(
            "[DEBUG] Hit DEX: {} (class_def_off=0x{:x})",
            result.dex_name, result.class_def_off
        );
        eprintln!(
            "[DEBUG] Total Execution Time: {} us",
            started.elapsed().as_micros()
        );
        eprintln!("----------------------------------------");
    }
    if let Some(out_path) = output {
        std::fs::write(out_path, source.as_bytes())
            .map_err(|e| CoreError::Usage(format!("write {out_path:?}: {e}")))?;
    }
    print!("{source}");
    std::io::stdout().flush().ok();
    Ok(())
}

/// `asc-rs disasm <apk|dex> <class>`: smali-syntax listing. `-o` is
/// additive (same contract as `getclass`): the listing goes to stdout
/// and, when set, also to the file.
fn run_disasm_cmd(
    apk: &std::path::Path,
    class: &str,
    method: Option<&str>,
    output: Option<&std::path::Path>,
    threads: usize,
    debug: bool,
) -> Result<(), CoreError> {
    let target = asc_core::normalize_class_name(class).map_err(CoreError::Class)?;
    let opts = DisasmOptions {
        threads,
        debug,
        scan_budget_bytes: 0, // engine default
    };
    let job = DisasmJob::new(apk.to_path_buf(), target, method);
    let result = run_disasm(&job, &opts)?;
    let listing = result.listing;
    if let Some(out_path) = output {
        std::fs::write(out_path, listing.as_bytes())
            .map_err(|e| CoreError::Usage(format!("write {out_path:?}: {e}")))?;
    }
    print!("{listing}");
    std::io::stdout().flush().ok();
    Ok(())
}

#[allow(clippy::too_many_arguments)] // flat CLI plumbing, mirrors the other cmds
fn run_findrefs_cmd(
    decode_xor: bool,
    apk: &std::path::Path,
    kind: &FindRefsKind,
    output: Option<&std::path::Path>,
    threads: usize,
    debug: bool,
    paranoid: bool,
    format: OutputFormat,
) -> ExitCode {
    let started = Instant::now();
    if threads == 0 {
        // Same oracle-parity check `dispatch` enforces for the other
        // subcommands (ThreadPoolExecutor(max_workers=0) rejects 0).
        eprintln!("Error: Worker count must be greater than zero");
        return ExitCode::from(EXIT_USER_ERROR);
    }
    let query = match build_query(kind) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(EXIT_USER_ERROR);
        }
    };
    let opts = FindRefsOptions {
        threads,
        debug,
        paranoid,
        decode_xor,
        scan_budget_bytes: 0, // engine default
    };
    let job = FindRefsJob::new(apk.to_path_buf(), query);
    let report = match run_findrefs(&job, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };

    if debug {
        eprintln!(
            "[DEBUG] APK Scan Time: {} us ({} dex results)",
            started.elapsed().as_micros(),
            report.results.len()
        );
        eprintln!(
            "[DEBUG] Total Execution Time: {} us",
            started.elapsed().as_micros()
        );
    }

    let text = format_search_report_text(&report);
    let rendered = match format {
        OutputFormat::Text => {
            if text.is_empty() {
                String::new()
            } else {
                text + "\n"
            }
        }
        OutputFormat::Json => {
            let json = format_search_report_json(&report);
            serde_json::to_string_pretty(&json).unwrap_or_default()
        }
    };

    if let Some(out_path) = output {
        match std::fs::write(out_path, rendered.as_bytes()) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error: write {out_path:?}: {e}");
                return ExitCode::from(EXIT_INTERNAL);
            }
        }
    }
    print!("{rendered}");
    std::io::stdout().flush().ok();

    // A scan that failed on one or more DEX entries still prints every
    // hit it found, but must not report success: warn on stderr (both
    // output modes — the JSON body carries `complete`/`errors`, text
    // does not) and exit 2 like `cert`/`resources` do for the same
    // "printed in full, incomplete" situation.
    if !report.complete {
        for e in &report.errors {
            eprintln!("warning: scan incomplete: {e}");
        }
    } else {
        // `complete` is false only for a *failed* scan. An entry we
        // declined to decode (a `classes*.dex` whose bytes are not a
        // DEX) leaves the run "complete" but partially covered, and
        // has to surface somewhere other than the exit code.
        for e in &report.errors {
            eprintln!("warning: {e}");
        }
    }
    ExitCode::from(if report.complete {
        EXIT_OK
    } else {
        EXIT_INTERNAL
    })
}

fn run_listclass_cmd(
    apk: &std::path::Path,
    prefix: Option<&str>,
    with_dex: bool,
    output: Option<&std::path::Path>,
    threads: usize,
    debug: bool,
    format: OutputFormat,
) -> Result<(), CoreError> {
    let started = Instant::now();
    // `ListClassesJob::new` rejects empty prefixes via
    // `DecompileError::ClassNotFound`; map that into a clean exit-1
    // `CoreError::Usage` so the CLI prints `Error: ...` like the oracle.
    let job = match ListClassesJob::new(apk.to_path_buf(), prefix) {
        Ok(j) => j,
        Err(_) if prefix == Some("") || prefix.map(str::trim) == Some("") => {
            return Err(CoreError::Usage("Class prefix cannot be empty".into()));
        }
        Err(e) => return Err(CoreError::Class(e)),
    };
    let opts = ListClassesOptions { threads, debug };
    let result = run_listclasses(&job, &opts)?;
    let rendered = match format {
        OutputFormat::Text => {
            let text = format_listclasses_text_opt(&result, with_dex);
            // `format_listclasses_text` strips the trailing newline; the CLI
            // writes one trailing newline. Empty results emit nothing
            // (matches the oracle's zero-iteration writer in
            // `cli.py:_handle_listclass`).
            if text.is_empty() {
                String::new()
            } else {
                text + "\n"
            }
        }
        OutputFormat::Json => to_json(&format_listclasses_json_opt(&result, with_dex)),
    };

    if debug {
        for (entry, n) in &result.per_dex_counts {
            eprintln!("[APK] '{entry}' class_count={n}");
        }
        eprintln!(
            "[APK] listclass total={} us count={}",
            started.elapsed().as_micros(),
            result.names.len()
        );
        eprintln!("----------------------------------------");
    }

    // Oracle: when `-o` is set, output goes to the file *instead of*
    // stdout (`cli.py:99`: `out = output_fp if output_fp is not None
    // else sys.stdout`). We honor that contract — `-o` is exclusive,
    // not additive.
    match output {
        Some(out_path) => std::fs::write(out_path, rendered.as_bytes())
            .map_err(|e| CoreError::Usage(format!("write {out_path:?}: {e}")))?,
        None => {
            print!("{rendered}");
            std::io::stdout().flush().ok();
        }
    }
    Ok(())
}

/// `asc-rs inspect <apk|dex>`: `-o` is exclusive like `listclass`.
fn run_inspect_cmd(
    apk: &std::path::Path,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> Result<(), CoreError> {
    let report = run_inspect(apk)?;
    let rendered = match format {
        OutputFormat::Text => format_inspect_text(&report),
        OutputFormat::Json => to_json(&report),
    };
    match output {
        Some(p) => std::fs::write(p, rendered.as_bytes())
            .map_err(|e| CoreError::Usage(format!("write {p:?}: {e}")))?,
        None => {
            print!("{rendered}");
            std::io::stdout().flush().ok();
        }
    }
    Ok(())
}

/// `asc-rs native <apk|dex>`: `-o` is exclusive like `inspect`.
fn run_native_cmd(
    apk: &std::path::Path,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> Result<(), CoreError> {
    let report = run_native(apk)?;
    let rendered = match format {
        OutputFormat::Text => format_native_text(&report),
        OutputFormat::Json => to_json(&report),
    };
    match output {
        Some(p) => std::fs::write(p, rendered.as_bytes())
            .map_err(|e| CoreError::Usage(format!("write {p:?}: {e}")))?,
        None => {
            print!("{rendered}");
            std::io::stdout().flush().ok();
        }
    }
    Ok(())
}

/// `asc-rs cert <apk>`: display-only signing inventory. `-o` is exclusive.
/// Raw DEX / unreadable input exits 2, like `manifest`; an incomplete report
/// (malformed signing data) is still printed in full and exits 2.
fn run_cert_cmd(
    apk: &std::path::Path,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> ExitCode {
    let report = match run_cert(apk) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let rendered = match format {
        OutputFormat::Text => format_cert_text(&report),
        OutputFormat::Json => to_json(&report),
    };
    match output {
        Some(p) => {
            if let Err(e) = std::fs::write(p, rendered.as_bytes()) {
                eprintln!("Error: write {p:?}: {e}");
                return ExitCode::from(EXIT_INTERNAL);
            }
        }
        None => {
            print!("{rendered}");
            std::io::stdout().flush().ok();
        }
    }
    ExitCode::from(if report.complete {
        EXIT_OK
    } else {
        EXIT_INTERNAL
    })
}

/// `asc-rs resources <apk>`: `resources.arsc` inventory / lookup / search.
/// `-o` is exclusive; every error and an incomplete table exit 2 (output
/// is still printed for an incomplete table), like `cert`.
fn run_resources_cmd(
    apk: &std::path::Path,
    id: Option<&str>,
    pattern: Option<&str>,
    limit: usize,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> ExitCode {
    let id = match id.map(parse_resource_id).transpose() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let q = ResourcesQuery {
        id,
        pattern: pattern.map(str::to_owned),
        limit,
    };
    let report = match run_resources(apk, &q) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let rendered = match format {
        OutputFormat::Text => format_resources_text(&report, id.is_some() || pattern.is_some()),
        OutputFormat::Json => to_json(&report),
    };
    match output {
        Some(p) => {
            if let Err(e) = std::fs::write(p, rendered.as_bytes()) {
                eprintln!("Error: write {p:?}: {e}");
                return ExitCode::from(EXIT_INTERNAL);
            }
        }
        None => {
            print!("{rendered}");
            std::io::stdout().flush().ok();
        }
    }
    ExitCode::from(if report.complete {
        EXIT_OK
    } else {
        EXIT_INTERNAL
    })
}

/// `0x7f020000` (hex) or plain decimal.
fn parse_resource_id(s: &str) -> Result<u32, String> {
    let r = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u32::from_str_radix(h, 16),
        None => s.parse(),
    };
    r.map_err(|_| format!("invalid resource id {s:?} (expected 0x7f020000 or decimal)"))
}

/// `asc-rs manifest <apk>`: text dump of the parsed manifest. Parse
/// failure exits 2 (engine error); `-o` is exclusive like `listclass`.
fn run_manifest_cmd(
    apk: &std::path::Path,
    output: Option<&std::path::Path>,
    format: OutputFormat,
    match_uri: Option<&str>,
) -> ExitCode {
    let m = match asc_manifest::parse_from_apk(apk) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: manifest: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let text = match format {
        OutputFormat::Text => format_manifest_text(&m, match_uri),
        OutputFormat::Json => match match_uri {
            Some(uri) => to_json(&format_manifest_match_json(&m, uri)),
            None => to_json(&m),
        },
    };
    match output {
        Some(p) => {
            if let Err(e) = std::fs::write(p, text.as_bytes()) {
                eprintln!("Error: write {p:?}: {e}");
                return ExitCode::from(EXIT_USER_ERROR);
            }
        }
        None => {
            print!("{text}");
            std::io::stdout().flush().ok();
        }
    }
    ExitCode::from(EXIT_OK)
}

/// `asc-rs strings <apk>`: dump DEX string pools. Incomplete reports
/// (per-string or per-DEX failures) still print in full and exit 2.
fn run_strings_cmd(
    apk: &std::path::Path,
    substring: Option<&str>,
    limit: usize,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> ExitCode {
    let opts = asc_core::strings::StringsOptions {
        filter: substring.map(str::to_string),
        limit,
    };
    let report = match asc_core::strings::run_strings(apk, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: strings: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    for e in &report.errors {
        eprintln!("warning: {e}");
    }
    let text = match format {
        OutputFormat::Text => asc_core::strings::format_strings_text(&report),
        OutputFormat::Json => to_json(&report),
    };
    match output {
        Some(p) => {
            if let Err(e) = std::fs::write(p, text.as_bytes()) {
                eprintln!("Error: write {p:?}: {e}");
                return ExitCode::from(EXIT_USER_ERROR);
            }
        }
        None => {
            print!("{text}");
            std::io::stdout().flush().ok();
        }
    }
    ExitCode::from(if report.complete {
        EXIT_OK
    } else {
        EXIT_INTERNAL
    })
}

/// `asc-rs hermes <apk>`: extract Hermes bundle string tables. Partial
/// reports (unsupported version, decode failure) print in full and exit 2.
fn run_hermes_cmd(
    apk: &std::path::Path,
    pattern: Option<&str>,
    limit: usize,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> ExitCode {
    let opts = asc_core::hermes::HermesOptions {
        pattern: pattern.map(str::to_string),
        limit,
    };
    let report = match asc_core::hermes::run_hermes(apk, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: hermes: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    for e in &report.errors {
        eprintln!("warning: {e}");
    }
    let text = match format {
        OutputFormat::Text => asc_core::hermes::format_hermes_text(&report),
        OutputFormat::Json => to_json(&report),
    };
    match output {
        Some(p) => {
            if let Err(e) = std::fs::write(p, text.as_bytes()) {
                eprintln!("Error: write {p:?}: {e}");
                return ExitCode::from(EXIT_USER_ERROR);
            }
        }
        None => {
            print!("{text}");
            std::io::stdout().flush().ok();
        }
    }
    ExitCode::from(if report.complete {
        EXIT_OK
    } else {
        EXIT_INTERNAL
    })
}

/// `asc-rs xapk <file>`: member-by-member inventory. Partial reports
/// (unreadable member or member ZIP, cap exceeded, DEX read failure)
/// print in full and exit 2; corrupt DEX content stays a member-level
/// `error:` line and exits 0.
fn run_xapk_cmd(
    apk: &std::path::Path,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> ExitCode {
    let report = match asc_core::xapk::run_xapk(apk) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: xapk: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    for e in &report.errors {
        eprintln!("warning: {e}");
    }
    let text = match format {
        OutputFormat::Text => asc_core::xapk::format_xapk_text(&report),
        OutputFormat::Json => to_json(&report),
    };
    match output {
        Some(p) => {
            if let Err(e) = std::fs::write(p, text.as_bytes()) {
                eprintln!("Error: write {p:?}: {e}");
                return ExitCode::from(EXIT_USER_ERROR);
            }
        }
        None => {
            print!("{text}");
            std::io::stdout().flush().ok();
        }
    }
    ExitCode::from(if report.complete {
        EXIT_OK
    } else {
        EXIT_INTERNAL
    })
}

/// `asc-rs extract <apk> <entry>`: write one entry to disk. Without
/// `-o`, the output name is the entry's sanitized basename (never a
/// path — no ZIP-slip). `--verify-crc` fails on CRC mismatch (exit 2).
fn run_extract_cmd(
    apk: &std::path::Path,
    entry: &str,
    verify_crc: bool,
    output: Option<&std::path::Path>,
) -> ExitCode {
    let a = match asc_apk::Apk::open(apk) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: open {apk:?}: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let e = match a.entry(entry) {
        Some(e) => e,
        None => {
            eprintln!("Error: entry not found: {entry}");
            return ExitCode::from(EXIT_USER_ERROR);
        }
    };
    let bytes = if verify_crc {
        a.read_entry_verified(&e)
    } else {
        a.read_entry(&e)
    };
    let bytes = match bytes {
        Ok(b) => b,
        Err(x) => {
            eprintln!("Error: read {entry}: {x}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let out = match output {
        Some(p) => p.to_path_buf(),
        None => {
            // Never derive a path from the entry name beyond its final
            // component; refuse anything that could escape the cwd.
            match std::path::Path::new(entry)
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .filter(|s| {
                    !s.is_empty()
                        && *s != "."
                        && *s != ".."
                        && !s.contains('/')
                        && !s.contains('\\')
                        && !s.contains(':')
                }) {
                Some(base) => std::path::PathBuf::from(base),
                None => {
                    eprintln!("Error: refusing to derive an output name from {entry:?}; pass -o");
                    return ExitCode::from(EXIT_USER_ERROR);
                }
            }
        }
    };
    let n = bytes.as_slice().len();
    if let Err(x) = std::fs::write(&out, bytes.as_slice()) {
        eprintln!("Error: write {}: {x}", out.display());
        return ExitCode::from(EXIT_USER_ERROR);
    }
    let method = if e.method == asc_apk::Compression::Stored {
        "stored"
    } else {
        "deflated"
    };
    println!(
        "extracted {} -> {} ({} bytes, {}, crc {})",
        entry,
        out.display(),
        n,
        method,
        e.crc32
    );
    ExitCode::from(EXIT_OK)
}

/// `asc-rs axml <apk> <entry>`: decode any compiled binary-XML entry.
fn run_axml_cmd(
    apk: &std::path::Path,
    entry: &str,
    output: Option<&std::path::Path>,
    format: OutputFormat,
) -> ExitCode {
    let a = match asc_apk::Apk::open(apk) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: open {apk:?}: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let e = match a.entry(entry) {
        Some(e) => e,
        None => {
            eprintln!("Error: entry not found: {entry}");
            return ExitCode::from(EXIT_USER_ERROR);
        }
    };
    let bytes = match a.read_entry(&e) {
        Ok(b) => b,
        Err(x) => {
            eprintln!("Error: read {entry}: {x}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let doc = match asc_manifest::axml::parse_axml(bytes.as_slice()) {
        Ok(d) => d,
        Err(x) => {
            eprintln!("Error: axml: {x}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let text = match format {
        OutputFormat::Text => asc_manifest::axml::format_axml_text(&doc),
        OutputFormat::Json => to_json(&doc),
    };
    match output {
        Some(p) => {
            if let Err(x) = std::fs::write(p, text.as_bytes()) {
                eprintln!("Error: write {p:?}: {x}");
                return ExitCode::from(EXIT_USER_ERROR);
            }
        }
        None => {
            print!("{text}");
            std::io::stdout().flush().ok();
        }
    }
    ExitCode::from(EXIT_OK)
}
/// Pretty JSON plus a trailing newline (parse-safe for `-o` files).
fn to_json<T: serde::Serialize>(v: &T) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.push('\n');
    s
}

fn format_manifest_text(m: &asc_manifest::ManifestInfo, match_uri: Option<&str>) -> String {
    use std::fmt::Write as _;
    let opt = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".into());
    let num = |v: Option<u32>| v.map_or_else(|| "-".into(), |n| n.to_string());
    let mut s = String::new();
    let _ = writeln!(s, "package: {}", opt(&m.package));
    let _ = writeln!(
        s,
        "version: {} ({})",
        opt(&m.version_name),
        num(m.version_code)
    );
    let _ = writeln!(
        s,
        "sdk: min={} target={} compile={}",
        num(m.min_sdk),
        num(m.target_sdk),
        num(m.compile_sdk)
    );
    if m.has_invalid_exported() {
        let _ = writeln!(
            s,
            "warning: android:exported missing on a filtered component — targetSdk>=31 \
             (Android 12+) rejects this manifest at install time"
        );
    }
    // Split markers (only when the manifest declares any).
    let mut split = Vec::new();
    let push_split = |out: &mut Vec<String>, k: &str, v: &Option<String>| {
        // Empty declarations (bundletool writes `splitTypes=""`) are noise
        // in text; JSON keeps them verbatim.
        if let Some(v) = v
            && !v.is_empty()
        {
            out.push(format!("{k}={v}"));
        }
    };
    push_split(&mut split, "split", &m.split);
    push_split(&mut split, "configForSplit", &m.config_for_split);
    push_split(&mut split, "splitTypes", &m.split_types);
    push_split(&mut split, "requiredSplitTypes", &m.required_split_types);
    if m.is_split_required == Some(true) {
        split.push("isSplitRequired".into());
    }
    if m.is_feature_split == Some(true) {
        split.push("isFeatureSplit".into());
    }
    if !split.is_empty() {
        let _ = writeln!(s, "split: {}", split.join(" "));
    }

    // Application attributes (declared vs effective distinguished).
    let a = &m.application;
    let _ = writeln!(s, "application:");
    let _ = writeln!(s, "  label: {}", opt(&a.label));
    let declared_or_default = |v: Option<bool>, eff: bool| match v {
        Some(x) => x.to_string(),
        None => format!("{eff}(default)"),
    };
    let _ = writeln!(
        s,
        "  allowBackup={} debuggable={} testOnly={}",
        declared_or_default(a.allow_backup, m.effective_allow_backup()),
        declared_or_default(a.debuggable, false),
        declared_or_default(a.test_only, false),
    );
    let _ = writeln!(
        s,
        "  usesCleartextTraffic={} networkSecurityConfig={} fullBackupContent={} dataExtractionRules={}",
        declared_or_default(
            a.uses_cleartext_traffic,
            m.effective_uses_cleartext_traffic()
        ),
        opt(&a.network_security_config),
        opt(&a.full_backup_content),
        opt(&a.data_extraction_rules),
    );
    let _ = writeln!(
        s,
        "  hasCode={} extractNativeLibs={} requestLegacyExternalStorage={}",
        declared_or_default(a.has_code, true),
        declared_or_default(a.extract_native_libs, true),
        declared_or_default(a.request_legacy_external_storage, false),
    );
    for md in &a.meta_data {
        write_meta_data(&mut s, "  ", md);
    }

    let _ = writeln!(s, "permissions ({}):", m.permissions.len());
    for p in &m.permissions {
        let mut note = String::new();
        match p.decl {
            "declares" => {
                note.push_str(" [declared");
                if let Some(pl) = &p.protection_level {
                    note.push_str(&format!(", protectionLevel={pl}"));
                }
                note.push(']');
            }
            "uses-sdk-23" => note.push_str(" [sdk-23]"),
            _ => {}
        }
        if let Some(v) = p.max_sdk {
            note.push_str(&format!(" (maxSdk={v})"));
        }
        let _ = writeln!(s, "  {}{}", p.name, note);
    }

    if !m.uses_features.is_empty() {
        let _ = writeln!(s, "uses-features ({}):", m.uses_features.len());
        for f in &m.uses_features {
            let req = match f.required {
                Some(false) => " required=false",
                Some(true) => " required=true",
                None => " required=true(default)",
            };
            let gl = f
                .gl_es_version
                .as_ref()
                .map(|v| format!(" glEsVersion={v}"))
                .unwrap_or_default();
            let _ = writeln!(s, "  {}{}{}", opt(&f.name), req, gl);
        }
    }

    if let Some(q) = &m.queries {
        let _ = writeln!(s, "queries:");
        for p in &q.packages {
            let _ = writeln!(s, "  package {p}");
        }
        for prov in &q.providers {
            let _ = writeln!(s, "  provider authorities={prov}");
        }
        for f in &q.intents {
            let _ = write!(s, "  intent:");
            for a in &f.actions {
                let _ = write!(s, " action {a}");
            }
            for c in &f.categories {
                let _ = write!(s, " category {c}");
            }
            if f.effective_data.has_uri() || !f.effective_data.mime_types.is_empty() {
                let _ = write!(
                    s,
                    " {}",
                    render_effective_data(&f.effective_data, f.data.len() > 1)
                );
            }
            let _ = writeln!(s);
        }
    }

    for (label, list) in [
        ("activities", &m.activities),
        ("services", &m.services),
        ("receivers", &m.receivers),
    ] {
        let _ = writeln!(s, "{label} ({}):", list.len());
        for c in list {
            write_component(&mut s, c, match_uri);
        }
    }
    let _ = writeln!(s, "activity-alias ({}):", m.activity_aliases.len());
    for alias in &m.activity_aliases {
        let c = &alias.component;
        let _ = write!(
            s,
            "  {} -> {}{}",
            c.name,
            opt(&alias.target_activity),
            render_exported(c)
        );
        if let Some(p) = &c.permission {
            let _ = write!(s, " perm={p}");
        }
        let _ = writeln!(s);
        for f in &c.intent_filters {
            write_filter(&mut s, f, match_uri);
        }
        for md in &c.meta_data {
            write_meta_data(&mut s, "    ", md);
        }
    }
    let _ = writeln!(s, "providers ({}):", m.providers.len());
    for p in &m.providers {
        let _ = writeln!(
            s,
            "  {} auth={}{}{}",
            p.name,
            opt(&p.authorities),
            render_exported_raw(p.exported, p.exported_explicit),
            p.permission
                .as_ref()
                .map(|v| format!(" perm={v}"))
                .unwrap_or_default(),
        );
        for md in &p.meta_data {
            write_meta_data(&mut s, "  ", md);
        }
    }
    s
}

/// `[exported=…]` annotation for a provider (no intent filters, so the
/// API 31 explicit-attribute rule never applies).
fn render_exported_raw(exported: bool, explicit: Option<bool>) -> String {
    match explicit {
        Some(_) => format!(" [exported={exported}]"),
        None if exported => " [exported=true(auto)]".into(),
        None => String::new(),
    }
}

/// `[exported=…]` annotation for a filter-bearing component, driven by the
/// parse-time [`asc_manifest::ExportedState`] so an install-invalid
/// manifest is never reported as a usable `(auto)` inference.
fn render_exported(c: &asc_manifest::ComponentEntry) -> String {
    use asc_manifest::ExportedState;
    match c.exported_state {
        ExportedState::Explicit => format!(" [exported={}]", c.exported),
        ExportedState::LegacyInferred if c.exported => " [exported=true(auto)]".into(),
        ExportedState::LegacyInferred => String::new(),
        ExportedState::MissingRequired => {
            " [exported=? invalid: android:exported required for targetSdk>=31]".into()
        }
    }
}

/// `<data>` attribute name for a path-matcher kind (shared by the pooled
/// match line and the raw `<uri-relative-filter-group>` lines).
fn path_kind_name(kind: asc_manifest::PathMatchKind) -> &'static str {
    use asc_manifest::PathMatchKind;
    match kind {
        PathMatchKind::Exact => "path",
        PathMatchKind::Prefix => "pathPrefix",
        PathMatchKind::Pattern => "pathPattern",
        PathMatchKind::AdvancedPattern => "pathAdvancedPattern",
        PathMatchKind::Suffix => "pathSuffix",
    }
}

/// `<data>` attribute name of a `<uri-relative-filter-group>` matcher:
/// `path*` / `fragment*` / `query*` share the five attribute shapes, so the
/// URI part picks the prefix and the kind the suffix.
fn uri_part_kind_name(part: asc_manifest::UriPart, kind: asc_manifest::PathMatchKind) -> String {
    use asc_manifest::{PathMatchKind, UriPart};
    let prefix = match part {
        UriPart::Path => "path",
        UriPart::Fragment => "fragment",
        UriPart::Query => "query",
    };
    let suffix = match kind {
        PathMatchKind::Exact => "",
        PathMatchKind::Prefix => "Prefix",
        PathMatchKind::Pattern => "Pattern",
        PathMatchKind::AdvancedPattern => "AdvancedPattern",
        PathMatchKind::Suffix => "Suffix",
    };
    format!("{prefix}{suffix}")
}

/// `host[:port]` list.
fn render_hosts(list: &[asc_manifest::Authority]) -> String {
    list.iter()
        .map(|a| match &a.port {
            Some(port) => format!("{}:{port}", a.host),
            None => a.host.clone(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// `path=/x,pathPrefix=/y` list.
fn render_paths(list: &[asc_manifest::PathMatcher]) -> String {
    list.iter()
        .map(|m| format!("{}={}", path_kind_name(m.kind), m.value))
        .collect::<Vec<_>>()
        .join(",")
}

/// Render one filter's match set: the **effective** dimensions first, then
/// (audit F1) anything that was declared but that Android never consults.
/// Pooling is the whole point — Android matches each dimension independently
/// across every `<data>` element of the filter — but the dimensions are
/// *dependent*, so a host without a scheme and a path without scheme+host
/// must never read as an active restriction. Nothing declared is dropped:
/// inert attributes are printed and labelled instead.
fn render_effective_data(eff: &asc_manifest::EffectiveData, pooled: bool) -> String {
    let effective_hosts = eff.effective_authorities();
    let effective_paths = eff.effective_paths();

    let mut parts = Vec::new();
    if !eff.schemes.is_empty() {
        parts.push(format!("schemes=[{}]", eff.schemes.join(",")));
    }
    if !effective_hosts.is_empty() {
        parts.push(format!("authorities=[{}]", render_hosts(effective_hosts)));
    }
    if !effective_paths.is_empty() {
        parts.push(format!("paths=[{}]", render_paths(effective_paths)));
    }
    if !eff.mime_types.is_empty() {
        parts.push(format!("mimeTypes=[{}]", eff.mime_types.join(",")));
    }

    let mut line = if parts.is_empty() {
        // Nothing effective: `matchData` falls back to "no data constraint",
        // which only matches an intent carrying neither a type nor a URI.
        "match: none (only intents without a data URI or type can match)".to_string()
    } else {
        format!("match: {}", parts.join(" "))
    };
    if pooled {
        line.push_str(" (pooled across <data> elements: every dimension is matched independently)");
    }
    if !eff.implicit_schemes().is_empty() {
        line.push_str(" (MIME type without a scheme: content: and file: URIs also match)");
    }

    let mut ignored = Vec::new();
    if effective_hosts.len() != eff.authorities.len() {
        ignored.push(format!("authorities=[{}]", render_hosts(&eff.authorities)));
    }
    if effective_paths.len() != eff.paths.len() {
        ignored.push(format!("paths=[{}]", render_paths(&eff.paths)));
    }
    if !ignored.is_empty() {
        // Inert iff the filter declares no scheme anywhere (then hosts,
        // ports and paths all fall away) or a scheme but no host (then ports
        // and paths do).
        let why = if eff.schemes.is_empty() {
            "no android:scheme is declared, so hosts, ports and paths are ignored"
        } else {
            "no android:host is declared, so ports and paths are ignored"
        };
        line.push_str(&format!(
            " [declared but ignored by Android: {} — {why}]",
            ignored.join(" ")
        ));
    }
    line
}

/// One-line render of a three-valued match verdict with its reasons.
fn match_verdict_line(uri: &str, v: &asc_manifest::uri_match::Verdict) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "match-uri {uri}: {} (assumed flag={})",
        match v.outcome {
            asc_manifest::uri_match::UriMatchVerdict::Matches => "matches",
            asc_manifest::uri_match::UriMatchVerdict::CannotMatch => "cannot match",
            asc_manifest::uri_match::UriMatchVerdict::Unknown => "unknown",
        },
        if v.assumed_flag_on { "on" } else { "off" }
    );
    if !v.reasons.is_empty() {
        let _ = write!(out, " — {}", v.reasons.join("; "));
    }
    out
}

fn write_filter(s: &mut String, f: &asc_manifest::IntentFilter, match_uri: Option<&str>) {
    use std::fmt::Write as _;
    let mut flags = Vec::new();
    if let Some(v) = f.auto_verify {
        flags.push(format!("autoVerify={v}"));
    }
    if let Some(v) = f.priority {
        flags.push(format!("priority={v}"));
    }
    if flags.is_empty() {
        let _ = writeln!(s, "    filter:");
    } else {
        let _ = writeln!(s, "    filter ({}):", flags.join(" "));
    }
    for a in &f.actions {
        let _ = writeln!(s, "      action {a}");
    }
    for c in &f.categories {
        let _ = writeln!(s, "      category {c}");
    }
    if f.effective_data.has_uri() || !f.effective_data.mime_types.is_empty() {
        let _ = writeln!(
            s,
            "      {}",
            render_effective_data(&f.effective_data, f.data.len() > 1)
        );
    }
    // API 35 groups are preserved verbatim; the pooled line above does not
    // model them, so say so instead of implying the filter was fully read.
    for g in &f.uri_relative_groups {
        let matchers = g
            .data
            .iter()
            .flat_map(|d| d.parts.iter())
            .map(|m| format!("{}={}", uri_part_kind_name(m.part, m.kind), m.value))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(
            s,
            "      {}",
            format!("uri-relative-filter-group allow={}: {matchers}", g.allow).trim_end()
        );
    }
    match match_uri {
        Some(uri) => {
            // A concrete URI converts the "NOT evaluated" warning into a
            // verdict (research doc §4), defaulting to the platform group
            // flag ON (the API 35 feature enabled).
            let v = asc_manifest::uri_match::evaluate_filter_uri(f, uri, true);
            let _ = writeln!(s, "      {}", match_verdict_line(uri, &v));
        }
        None if f.has_uri_relative_groups() => {
            let _ = writeln!(
                s,
                "      warning: <uri-relative-filter-group> (API 35) is reported as declared and \
                 NOT evaluated — this filter's URI match surface is incomplete"
            );
        }
        None => {}
    }
}

fn write_component(s: &mut String, c: &asc_manifest::ComponentEntry, match_uri: Option<&str>) {
    use std::fmt::Write as _;
    let _ = write!(s, "  {}{}", c.name, render_exported(c));
    if let Some(p) = &c.permission {
        let _ = write!(s, " perm={p}");
    }
    if let Some(p) = &c.process {
        let _ = write!(s, " process={p}");
    }
    if let Some(l) = &c.label {
        let _ = write!(s, " label={l}");
    }
    let _ = writeln!(s);
    for f in &c.intent_filters {
        write_filter(s, f, match_uri);
    }
    for md in &c.meta_data {
        write_meta_data(s, "    ", md);
    }
}

fn write_meta_data(s: &mut String, indent: &str, md: &asc_manifest::MetaDataEntry) {
    use std::fmt::Write as _;
    let value = md
        .value
        .clone()
        .map(|v| format!(" = {v}"))
        .unwrap_or_default();
    let resource = md
        .resource
        .clone()
        .map(|r| format!(" resource={r}"))
        .unwrap_or_default();
    let _ = writeln!(s, "{indent}meta-data: {}{value}{resource}", md.name);
}

/// Additive JSON for `manifest --match-uri <uri>`: the full parsed manifest
/// (every existing key, unchanged) plus a new top-level `uri_match` report.
/// Existing consumers that read the manifest keys are not affected.
#[derive(serde::Serialize)]
struct ManifestMatchJson<'a> {
    #[serde(flatten)]
    info: &'a asc_manifest::ManifestInfo,
    uri_match: MatchReport<'a>,
}

#[derive(serde::Serialize)]
struct MatchReport<'a> {
    uri: &'a str,
    /// The assumed value of `FLAG_RELATIVE_REFERENCE_INTENT_FILTERS`.
    assumed_flag_on: bool,
    /// One entry per intent filter of every activity/service/receiver, in
    /// document order.
    results: Vec<MatchReportEntry>,
}

#[derive(serde::Serialize)]
struct MatchReportEntry {
    component: String,
    filter_index: usize,
    verdict: &'static str,
    reasons: Vec<String>,
}

fn match_report_entry(
    c_component: &str,
    f: &asc_manifest::IntentFilter,
    i: usize,
    uri: &str,
) -> MatchReportEntry {
    let v = asc_manifest::uri_match::evaluate_filter_uri(f, uri, true);
    MatchReportEntry {
        component: c_component.to_string(),
        filter_index: i,
        verdict: match v.outcome {
            asc_manifest::uri_match::UriMatchVerdict::Matches => "matches",
            asc_manifest::uri_match::UriMatchVerdict::CannotMatch => "cannot_match",
            asc_manifest::uri_match::UriMatchVerdict::Unknown => "unknown",
        },
        reasons: v.reasons,
    }
}

/// `--match-uri` JSON payload builder (activities / services / receivers).
fn format_manifest_match_json<'a>(
    m: &'a asc_manifest::ManifestInfo,
    uri: &'a str,
) -> ManifestMatchJson<'a> {
    let mut results = Vec::new();
    for list in [&m.activities, &m.services, &m.receivers] {
        for c in list {
            for (i, f) in c.intent_filters.iter().enumerate() {
                results.push(match_report_entry(&c.name, f, i, uri));
            }
        }
    }
    ManifestMatchJson {
        info: m,
        uri_match: MatchReport {
            uri,
            assumed_flag_on: true,
            results,
        },
    }
}

/// Translate the CLI `FindRefsKind` into an [`Query`]. For method/field
/// queries with both `name == None` and `class == None`, returns
/// `CoreError::Usage` (matches the oracle's
/// `_build_member_find` ValueError).
fn build_query(kind: &FindRefsKind) -> Result<Query, CoreError> {
    let q = match kind {
        FindRefsKind::String { value } => Query::string(value.clone()),
        FindRefsKind::Type { value } => Query::type_(value.clone()),
        FindRefsKind::Method {
            name,
            class,
            fuzzy_class,
        } => {
            if name.is_none() && class.is_none() {
                return Err(CoreError::Usage(
                    "method query needs at least one of class or method name".into(),
                ));
            }
            let class = class.as_ref().map(|c| {
                if *fuzzy_class {
                    ClassConstraint::new(c.clone())
                } else {
                    ClassConstraint::new_exact(c.clone())
                }
            });
            Query::method(name.clone(), class)
        }
        FindRefsKind::Field {
            name,
            class,
            fuzzy_class,
        } => {
            if name.is_none() && class.is_none() {
                return Err(CoreError::Usage(
                    "field query needs at least one of class or field name".into(),
                ));
            }
            let class = class.as_ref().map(|c| {
                if *fuzzy_class {
                    ClassConstraint::new(c.clone())
                } else {
                    ClassConstraint::new_exact(c.clone())
                }
            });
            Query::field(name.clone(), class)
        }
    };
    Ok(q)
}

#[cfg(test)]
mod tests {
    //! Manifest text rendering: the pooled match set (audit F1) and the
    //! install-invalid `android:exported` marker (audit F4). Rendering is
    //! pinned here so a change to the output cannot silently resurrect the
    //! per-`<data>` "independent URI" reading.

    use super::{format_manifest_match_json, format_manifest_text, to_json};
    use asc_manifest::{
        ComponentEntry, DataSpec, ExportedState, IntentFilter, ManifestInfo, ProviderEntry,
    };

    fn data(
        scheme: Option<&str>,
        host: Option<&str>,
        path_prefix: Option<&str>,
        mime: Option<&str>,
    ) -> DataSpec {
        DataSpec {
            scheme: scheme.map(str::to_string),
            host: host.map(str::to_string),
            path_prefix: path_prefix.map(str::to_string),
            mime_type: mime.map(str::to_string),
            ..DataSpec::default()
        }
    }

    /// Build a filter and pool it the way `parse_manifest` does.
    fn filter(data: Vec<DataSpec>) -> IntentFilter {
        let mut f = IntentFilter {
            actions: vec!["android.intent.action.VIEW".into()],
            data,
            ..IntentFilter::default()
        };
        f.effective_data = f.effective_data();
        f
    }

    fn activity(
        name: &str,
        state: ExportedState,
        exported: bool,
        filters: Vec<IntentFilter>,
    ) -> ComponentEntry {
        ComponentEntry {
            name: name.into(),
            exported,
            exported_explicit: (state == ExportedState::Explicit).then_some(exported),
            exported_state: state,
            permission: None,
            label: None,
            process: None,
            intent_filters: filters,
            meta_data: Vec::new(),
        }
    }

    /// Audit F1: two `<data>` elements render as one pooled match set, never
    /// as two independent URIs.
    #[test]
    fn manifest_text_pools_filter_data() {
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(30),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::LegacyInferred,
                true,
                vec![filter(vec![
                    data(Some("https"), Some("a.example.com"), None, None),
                    data(
                        Some("myapp"),
                        Some("b.example.com"),
                        Some("/deep"),
                        Some("image/*"),
                    ),
                ])],
            )],
            ..ManifestInfo::default()
        };
        let text = format_manifest_text(&m, None);
        assert!(
            text.contains(
                "match: schemes=[https,myapp] authorities=[a.example.com,b.example.com] \
                 paths=[pathPrefix=/deep] mimeTypes=[image/*]"
            ),
            "pooled match line missing/incomplete:\n{text}"
        );
        assert!(
            text.contains("pooled across <data>"),
            "pooling must be called out when the filter has >1 <data>:\n{text}"
        );
        assert!(
            !text.contains("data scheme="),
            "raw per-<data> lines imply alternatives and must be gone:\n{text}"
        );
    }

    /// A single `<data>` needs no pooling caveat.
    #[test]
    fn manifest_text_single_data_has_no_pooling_note() {
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(30),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::LegacyInferred,
                true,
                vec![filter(vec![data(
                    Some("https"),
                    Some("a.example.com"),
                    None,
                    None,
                )])],
            )],
            ..ManifestInfo::default()
        };
        let text = format_manifest_text(&m, None);
        assert!(
            text.contains("match: schemes=[https] authorities=[a.example.com]"),
            "{text}"
        );
        assert!(!text.contains("pooled across <data>"), "{text}");
    }

    /// Audit F4: targetSdk>=31 + filter + no explicit exported renders as
    /// install-invalid, not as a usable `(auto)` inference.
    #[test]
    fn manifest_text_flags_missing_required_exported() {
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(31),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::MissingRequired,
                true,
                vec![filter(vec![data(Some("https"), None, None, None)])],
            )],
            ..ManifestInfo::default()
        };
        let text = format_manifest_text(&m, None);
        assert!(
            text.contains("android:exported required for targetSdk>=31"),
            "component marker missing:\n{text}"
        );
        assert!(
            text.contains("warning: android:exported missing"),
            "summary warning missing:\n{text}"
        );
        assert!(
            !text.contains("exported=true(auto)"),
            "must not read as installable:\n{text}"
        );
    }

    /// Below API 31 the legacy `(auto)` inference renders as before.
    #[test]
    fn manifest_text_keeps_legacy_auto_below_api_31() {
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(30),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::LegacyInferred,
                true,
                vec![filter(vec![data(Some("https"), None, None, None)])],
            )],
            ..ManifestInfo::default()
        };
        let text = format_manifest_text(&m, None);
        assert!(text.contains("[exported=true(auto)]"), "{text}");
        assert!(!text.contains("invalid"), "{text}");
    }

    /// Providers keep their own rule (no intent filters → never invalid).
    #[test]
    fn manifest_text_provider_exported_rendering_unchanged() {
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(33),
            providers: vec![ProviderEntry {
                name: "com.example.P".into(),
                authorities: Some("com.example.p".into()),
                exported: true,
                exported_explicit: Some(true),
                permission: None,
                read_permission: None,
                write_permission: None,
                grant_uri_permissions: false,
                label: None,
                meta_data: Vec::new(),
            }],
            ..ManifestInfo::default()
        };
        let text = format_manifest_text(&m, None);
        assert!(text.contains("providers (1):"), "{text}");
        assert!(text.contains(" [exported=true]"), "{text}");
        assert!(!text.contains("warning:"), "{text}");
    }

    /// Audit F1.1/F1.2: a declared-but-inert URI dimension is labelled, so
    /// the output never reads as a restriction Android does not apply.
    #[test]
    fn manifest_text_flags_inert_uri_dimensions() {
        // A path without a host: `https://example.com/public` still matches.
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(30),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::LegacyInferred,
                true,
                vec![filter(vec![data(
                    Some("https"),
                    None,
                    Some("/private"),
                    None,
                )])],
            )],
            ..ManifestInfo::default()
        };
        let text = format_manifest_text(&m, None);
        assert!(
            text.contains("match: schemes=[https]"),
            "the effective scheme stays visible:\n{text}"
        );
        assert!(
            text.contains(
                "[declared but ignored by Android: paths=[pathPrefix=/private] — \
                 no android:host is declared, so ports and paths are ignored]"
            ),
            "an inert path must be named, not dropped:\n{text}"
        );

        // A host without a scheme: every URI attribute is ignored.
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(30),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::LegacyInferred,
                true,
                vec![filter(vec![data(None, Some("example.com"), None, None)])],
            )],
            ..ManifestInfo::default()
        };
        let text = format_manifest_text(&m, None);
        assert!(
            text.contains(
                "match: none (only intents without a data URI or type can match) \
                 [declared but ignored by Android: authorities=[example.com] — no android:scheme \
                 is declared, so hosts, ports and paths are ignored]"
            ),
            "a host without a scheme must be named as inert:\n{text}"
        );
    }

    /// Audit F1.3: a MIME-only filter also matches `content:` / `file:`.
    #[test]
    fn manifest_text_reports_implicit_content_and_file_schemes() {
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(30),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::LegacyInferred,
                true,
                vec![filter(vec![data(None, None, None, Some("image/*"))])],
            )],
            ..ManifestInfo::default()
        };
        let text = format_manifest_text(&m, None);
        assert!(
            text.contains(
                "match: mimeTypes=[image/*] (MIME type without a scheme: \
                           content: and file: URIs also match)"
            ),
            "{text}"
        );
    }

    /// Audit F3: an API 35 `<uri-relative-filter-group>` is reported raw
    /// **and** warned about, in text and in JSON — never silently ignored.
    #[test]
    fn manifest_text_and_json_report_uri_relative_filter_groups() {
        use asc_manifest::{
            PathMatchKind, RelativeDataSpec, UriPart, UriPartMatcher, UriRelativeFilterGroup,
        };
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(35),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::LegacyInferred,
                true,
                vec![{
                    let mut f = filter(vec![data(Some("https"), Some("example.com"), None, None)]);
                    f.uri_relative_groups = vec![
                        UriRelativeFilterGroup {
                            allow: false,
                            data: vec![
                                RelativeDataSpec {
                                    parts: vec![UriPartMatcher {
                                        part: UriPart::Path,
                                        kind: PathMatchKind::Exact,
                                        value: "/private".into(),
                                    }],
                                },
                                RelativeDataSpec {
                                    parts: vec![UriPartMatcher {
                                        part: UriPart::Query,
                                        kind: PathMatchKind::Exact,
                                        value: "token=1".into(),
                                    }],
                                },
                            ],
                        },
                        UriRelativeFilterGroup::default(),
                    ];
                    f
                }],
            )],
            ..ManifestInfo::default()
        };
        let text = format_manifest_text(&m, None);
        assert!(
            text.contains("uri-relative-filter-group allow=false: path=/private,query=token=1"),
            "the group's own matchers must be reported:\n{text}"
        );
        assert!(
            text.contains("warning: <uri-relative-filter-group> (API 35)"),
            "an unevaluated group must warn:\n{text}"
        );
        assert_eq!(
            m.activities[0].intent_filters[0].uri_relative_groups.len(),
            2
        );

        let json = to_json(&m);
        assert!(json.contains("\"uri_relative_groups\""), "{json}");
        assert!(json.contains("\"allow\": false"), "{json}");
        assert!(json.contains("\"part\": \"query\""), "{json}");
        assert!(
            json.contains("\"dependency\": \"complete\""),
            "the JSON match set must carry the dependency verdict too:\n{json}"
        );
    }

    /// Audit F1: a JSON consumer sees the dependency verdict next to the
    /// pools, so an inert host/path cannot be read as active.
    #[test]
    fn manifest_json_exposes_uri_dependency() {
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(30),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::LegacyInferred,
                true,
                vec![filter(vec![data(
                    Some("https"),
                    None,
                    Some("/private"),
                    None,
                )])],
            )],
            ..ManifestInfo::default()
        };
        let json = to_json(&m);
        assert!(json.contains("\"dependency\": \"no_host\""), "{json}");
        assert_eq!(
            m.activities[0].intent_filters[0]
                .effective_data
                .effective_paths()
                .len(),
            0
        );
    }

    /// Audit F2 (roadmap 5.5): `manifest --match-uri <uri>` evaluates the
    /// filter's path/group layer through the production evaluator and emits
    /// three-valued verdict lines (text) and an additive `uri_match` JSON
    /// report; the "NOT evaluated" warning is suppressed once a URI decides.
    #[test]
    fn manifest_match_uri_emits_verdicts_and_additive_json() {
        use asc_manifest::{
            PathMatchKind, RelativeDataSpec, UriPart, UriPartMatcher, UriRelativeFilterGroup,
        };
        let m = ManifestInfo {
            package: Some("com.example.app".into()),
            target_sdk: Some(35),
            activities: vec![activity(
                "com.example.Main",
                ExportedState::LegacyInferred,
                true,
                vec![{
                    let mut f = filter(vec![
                        data(Some("https"), Some("example.com"), None, None),
                        data(None, None, Some("/public"), None), // sibling pathPrefix
                    ]);
                    f.uri_relative_groups = vec![UriRelativeFilterGroup {
                        allow: false,
                        data: vec![RelativeDataSpec {
                            parts: vec![UriPartMatcher {
                                part: UriPart::Path,
                                kind: PathMatchKind::Exact,
                                value: "/private".into(),
                            }],
                        }],
                    }];
                    f
                }],
            )],
            ..ManifestInfo::default()
        };

        // Sibling <data pathPrefix=/public> matches in the OR (R5) →
        // matches even with the block group present.
        let text = format_manifest_text(&m, Some("https://example.com/public"));
        assert!(
            text.contains("match-uri https://example.com/public: matches (assumed flag=on)"),
            "{text}"
        );
        assert!(
            !text.contains("NOT evaluated"),
            "the warning is replaced by a verdict:\n{text}"
        );

        // A bare /private hits the allow=false group → cannot match.
        let text2 = format_manifest_text(&m, Some("https://example.com/private"));
        assert!(
            text2.contains("match-uri https://example.com/private: cannot match (assumed flag=on) — first matching group has android:allow=false"),
            "{text2}"
        );

        // JSON is additive: existing manifest keys + a new `uri_match` report.
        let json = to_json(&format_manifest_match_json(
            &m,
            "https://example.com/public",
        ));
        assert!(json.contains("\"uri_match\""), "{json}");
        assert!(json.contains("\"verdict\": \"matches\""), "{json}");
        assert!(
            json.contains("\"component\": \"com.example.Main\""),
            "{json}"
        );
        assert!(json.contains("\"assumed_flag_on\": true"), "{json}");
    }
}
