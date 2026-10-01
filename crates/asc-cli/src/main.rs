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
//! - 0 — success (findrefs with zero hits is still success).
//! - 1 — class-not-found (`getclass`, `disasm`), method-not-found
//!   (`disasm --method`), or input validation error
//!   (`findrefs method` with neither name nor `--class`, empty
//!   `listclass --prefix`, etc.).
//! - 2 — internal / unexpected error (APK parse, rebuild, decompile).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Args, Parser, Subcommand, ValueEnum};

use asc_core::{
    CoreError, DisasmJob, DisasmOptions, FindRefsJob, FindRefsOptions, GetClassJob,
    GetClassOptions, ListClassesJob, ListClassesOptions, ResourcesQuery, format_cert_text,
    format_getclass_json, format_getclass_text, format_inspect_text, format_listclasses_json,
    format_listclasses_text, format_native_text, format_resources_text, format_search_report_json,
    format_search_report_text, run_cert, run_disasm, run_findrefs, run_getclass, run_inspect,
    run_listclasses, run_native, run_resources,
};
use asc_query::{ClassConstraint, Query};

/// CLI exit codes.
const EXIT_OK: u8 = 0;
const EXIT_USER_ERROR: u8 = 1;
const EXIT_INTERNAL: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Cmd::Manifest { apk } = &cli.cmd {
        return run_manifest_cmd(apk, cli.shared.output.as_deref(), cli.shared.format);
    }
    if let Cmd::Cert { apk } = &cli.cmd {
        return run_cert_cmd(apk, cli.shared.output.as_deref(), cli.shared.format);
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
    },
    /// Dump AndroidManifest.xml: package, SDKs, permissions, components.
    Manifest {
        /// Path to the APK.
        apk: PathBuf,
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
        Cmd::Findrefs { apk, kind } => run_findrefs_cmd(
            shared.decode_xor,
            apk,
            kind,
            shared.output.as_deref(),
            shared.threads,
            shared.debug,
            shared.paranoid,
            shared.format,
        ),
        Cmd::Listclass { apk, prefix } => run_listclass_cmd(
            apk,
            prefix.as_deref(),
            shared.output.as_deref(),
            shared.threads,
            shared.debug,
            shared.format,
        ),
        Cmd::Manifest { .. } | Cmd::Cert { .. } | Cmd::Resources { .. } => {
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
    let opts = DisasmOptions { threads, debug };
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
) -> Result<(), CoreError> {
    let started = Instant::now();
    let query = build_query(kind)?;
    let opts = FindRefsOptions {
        threads,
        debug,
        paranoid,
        decode_xor,
    };
    let job = FindRefsJob::new(apk.to_path_buf(), query);
    let report = run_findrefs(&job, &opts)?;

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
        std::fs::write(out_path, rendered.as_bytes())
            .map_err(|e| CoreError::Usage(format!("write {out_path:?}: {e}")))?;
    }
    print!("{rendered}");
    std::io::stdout().flush().ok();

    if !report.complete && debug {
        // Print errors to stderr in debug mode.
        for e in &report.errors {
            eprintln!("[DEBUG] {e}");
        }
    }
    Ok(())
}

fn run_listclass_cmd(
    apk: &std::path::Path,
    prefix: Option<&str>,
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
            let text = format_listclasses_text(&result);
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
        OutputFormat::Json => to_json(&format_listclasses_json(&result)),
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
) -> ExitCode {
    let m = match asc_manifest::parse_from_apk(apk) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error: manifest: {e}");
            return ExitCode::from(EXIT_INTERNAL);
        }
    };
    let text = match format {
        OutputFormat::Text => format_manifest_text(&m),
        OutputFormat::Json => to_json(&m),
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

/// Pretty JSON plus a trailing newline (parse-safe for `-o` files).
fn to_json<T: serde::Serialize>(v: &T) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.push('\n');
    s
}

fn format_manifest_text(m: &asc_manifest::ManifestInfo) -> String {
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
    let _ = writeln!(s, "permissions ({}):", m.permissions.len());
    for p in &m.permissions {
        let _ = writeln!(s, "  {}", p.name);
    }
    for (label, list) in [
        ("activities", &m.activities),
        ("services", &m.services),
        ("receivers", &m.receivers),
    ] {
        let _ = writeln!(s, "{label} ({}):", list.len());
        for c in list {
            let exported = if c.exported { " [exported]" } else { "" };
            let _ = writeln!(s, "  {}{exported}", c.name);
            for f in &c.intent_filters {
                for a in &f.actions {
                    let _ = writeln!(s, "    action {a}");
                }
            }
        }
    }
    let _ = writeln!(s, "providers ({}):", m.providers.len());
    for p in &m.providers {
        let exported = if p.exported { " [exported]" } else { "" };
        let _ = writeln!(s, "  {} auth={}{exported}", p.name, opt(&p.authorities));
    }
    s
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
