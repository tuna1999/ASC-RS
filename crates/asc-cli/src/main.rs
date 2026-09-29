//! # asc-cli
//!
//! CLI parity frontend for `asc-rs`: `asc-rs getclass <apk> <class>`,
//! `asc-rs findrefs <apk> {string|type|method|field} ...`, and
//! `asc-rs listclass <apk> [--prefix P]` with `--format text|json`,
//! `-o/--output`, `--threads`, `--debug`.
//!
//! All engine logic lives in `asc-core`; this binary is a thin
//! arg-parsing / output-routing wrapper. Exit codes:
//!
//! - 0 — success (findrefs with zero hits is still success).
//! - 1 — class-not-found (getclass), or input validation error
//!   (`findrefs method` with neither name nor `--class`, empty
//!   `listclass --prefix`, etc.).
//! - 2 — internal / unexpected error (APK parse, rebuild, decompile).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Args, Parser, Subcommand, ValueEnum};

use asc_core::{
    CoreError, FindRefsJob, FindRefsOptions, GetClassJob, GetClassOptions, ListClassesJob,
    ListClassesOptions, format_getclass_text, format_listclasses_text, format_search_report_json,
    format_search_report_text, run_findrefs, run_getclass, run_listclasses,
};
use asc_query::{ClassConstraint, Query};

/// CLI exit codes.
const EXIT_OK: u8 = 0;
const EXIT_USER_ERROR: u8 = 1;
const EXIT_INTERNAL: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(&cli) {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(e) => {
            // Errors of the "user did something wrong" class
            // (ClassNotFound, Usage) print a clean message and exit 1;
            // everything else is exit 2.
            let code = match &e {
                CoreError::ClassNotFound(_) | CoreError::Usage(_) | CoreError::Class(_) => {
                    EXIT_USER_ERROR
                }
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
    /// Only honored by `findrefs`; other subcommands ignore.
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text, global = true)]
    format: OutputFormat,
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
        ),
        Cmd::Findrefs { apk, kind } => run_findrefs_cmd(
            apk,
            kind,
            shared.output.as_deref(),
            shared.threads,
            shared.debug,
            shared.format,
        ),
        Cmd::Listclass { apk, prefix } => run_listclass_cmd(
            apk,
            prefix.as_deref(),
            shared.output.as_deref(),
            shared.threads,
            shared.debug,
        ),
    }
}

fn run_getclass_cmd(
    apk: &std::path::Path,
    class: &str,
    output: Option<&std::path::Path>,
    threads: usize,
    debug: bool,
) -> Result<(), CoreError> {
    let started = Instant::now();
    let target = asc_core::normalize_class_name(class).map_err(CoreError::Class)?;
    let opts = GetClassOptions { threads, debug };
    let job = GetClassJob::new(apk.to_path_buf(), target.clone());
    let result = run_getclass(&job, &opts)?;
    let source = format_getclass_text(&result.source);
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

fn run_findrefs_cmd(
    apk: &std::path::Path,
    kind: &FindRefsKind,
    output: Option<&std::path::Path>,
    threads: usize,
    debug: bool,
    format: OutputFormat,
) -> Result<(), CoreError> {
    let started = Instant::now();
    let query = build_query(kind)?;
    let opts = FindRefsOptions { threads, debug };
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
    let text = format_listclasses_text(&result);
    // `format_listclasses_text` strips the trailing newline; the CLI
    // writes one trailing newline. Empty results emit nothing (matches
    // the oracle's zero-iteration writer in `cli.py:_handle_listclass`).
    let rendered = if text.is_empty() {
        String::new()
    } else {
        text + "\n"
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
