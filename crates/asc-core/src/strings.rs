//! `strings`: dump the DEX string pool across every DEX entry — not
//! just strings referenced by code (that is `findrefs string`'s job).
//!
//! Walks the same entry set as the other pipelines (`classes*.dex`,
//! DEX-041 logical containers included). A single malformed string
//! record is counted per DEX and skipped; it never drops the rest of
//! the pool.

use std::path::Path;

use asc_apk::InflateLimits;
use asc_dex::DexView;
use asc_dex::ids::StringIdx;
use serde::Serialize;

use crate::pipeline::{CoreError, logical_dex_name};

/// Largest DEX read in full (same cap as `inspect`).
const DEX_CAP: usize = 64 << 20;
/// Default and hard maximum number of emitted strings.
pub const MAX_STRINGS: usize = 100_000;

#[derive(Debug, Clone)]
pub struct StringsOptions {
    /// Case-sensitive substring filter; `None` dumps the whole pool.
    pub filter: Option<String>,
    /// Maximum number of hits to return.
    pub limit: usize,
}

impl Default for StringsOptions {
    fn default() -> Self {
        Self {
            filter: None,
            limit: MAX_STRINGS,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StringHit {
    /// Logical DEX name (`classes.dex`, or `entry!classes2.dex` for
    /// DEX-041 containers).
    pub dex: String,
    /// Index into that DEX's `string_ids`.
    pub index: u32,
    /// Decoded (lossy) string data.
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexStringsSummary {
    pub dex_name: String,
    /// Pool size from the header.
    pub string_count: usize,
    /// Hits emitted for this DEX (already limited).
    pub emitted: usize,
    /// String records that failed to decode.
    pub errors: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringsReport {
    pub hits: Vec<StringHit>,
    pub per_dex: Vec<DexStringsSummary>,
    /// Total matches found ignoring the limit.
    pub total_matched: usize,
    /// True when `limit` cut the result short.
    pub truncated: bool,
    /// Non-fatal problems (per-string decode failures, DEX read/parse
    /// failures, deliberately skipped non-DEX entries — same F06
    /// policy as findrefs: a deliberate skip is recorded but does not
    /// flip `complete`). `complete` is false whenever a real scan
    /// failure was recorded.
    pub errors: Vec<String>,
    pub complete: bool,
}

/// Dump string pools for every DEX entry in `path` (APK/ZIP or raw DEX).
pub fn run_strings(path: &Path, opts: &StringsOptions) -> Result<StringsReport, CoreError> {
    let apk = asc_apk::Apk::open(path)?;
    let mut report = StringsReport {
        hits: Vec::new(),
        per_dex: Vec::new(),
        total_matched: 0,
        truncated: false,
        errors: Vec::new(),
        complete: true,
    };
    for_each_dex_view(&apk, |name, view| match view {
        DexScan::View(view) => collect_view(name, view, opts, &mut report),
        DexScan::Skipped(why) => report.errors.push(format!("{name}: {why}")),
        DexScan::Failed(why) => {
            report.errors.push(format!("{name}: {why}"));
            report.complete = false;
        }
    });
    report.truncated = report.total_matched > report.hits.len();
    Ok(report)
}

/// One step of [`for_each_dex_view`].
pub(crate) enum DexScan<'v, 'a> {
    /// A parsed DEX (or one logical DEX of a DEX-041 container).
    View(&'v DexView<'a>),
    /// An entry deliberately not decoded (not a DEX). Audit F06: a
    /// deliberate skip is reported but is not a failed scan.
    Skipped(String),
    /// An entry that should have been scanned but could not be.
    Failed(String),
}

/// Walk every `classes*.dex` entry of `apk` (DEX-041 containers split
/// into their logical DEXes, each read capped at [`DEX_CAP`]) and hand
/// each to `f` with its logical name. Never stops early: one bad entry
/// is reported through `f` and the walk continues.
pub(crate) fn for_each_dex_view(apk: &asc_apk::Apk, mut f: impl FnMut(&str, DexScan<'_, '_>)) {
    let cap = InflateLimits::with_max_output(DEX_CAP);
    for e in apk.dex_entries() {
        if e.uncompressed_size as usize > DEX_CAP {
            f(
                &e.name,
                DexScan::Failed(format!("exceeds {} MiB DEX cap", DEX_CAP >> 20)),
            );
            continue;
        }
        let bytes = match apk.read_entry_with_limits(&e, cap.unwrap_or_default()) {
            Ok(b) => b,
            Err(x) => {
                f(&e.name, DexScan::Failed(format!("read failed: {x}")));
                continue;
            }
        };
        let b = bytes.as_slice();
        if b.len() < 8 || !b.starts_with(b"dex\n") {
            f(
                &e.name,
                DexScan::Skipped("skipped: entry is not a DEX".into()),
            );
            continue;
        }
        if &b[4..8] == b"041\0" {
            let offsets = match DexView::logical_header_offsets(b) {
                Ok(o) => o,
                Err(x) => {
                    f(
                        &e.name,
                        DexScan::Failed(format!("logical_header_offsets failed: {x}")),
                    );
                    continue;
                }
            };
            for (i, off) in offsets.iter().enumerate() {
                let name = logical_dex_name(&e.name, offsets.len(), i);
                match DexView::parse_at(b, *off) {
                    Ok(v) => f(&name, DexScan::View(&v)),
                    Err(x) => f(
                        &name,
                        DexScan::Failed(format!("DexView::parse_at failed: {x}")),
                    ),
                }
            }
        } else {
            match DexView::parse(b) {
                Ok(v) => f(&e.name, DexScan::View(&v)),
                Err(x) => f(&e.name, DexScan::Failed(format!("parse failed: {x}"))),
            }
        }
    }
}

fn collect_view(name: &str, view: &DexView<'_>, opts: &StringsOptions, report: &mut StringsReport) {
    let mut summary = DexStringsSummary {
        dex_name: name.to_string(),
        string_count: view.string_count() as usize,
        emitted: 0,
        errors: 0,
    };
    for i in 0..view.string_count() {
        match view.string(StringIdx(i)) {
            Ok(s) => {
                let text = s.decode_lossy();
                let matches = opts.filter.as_deref().is_none_or(|f| text.contains(f));
                if matches {
                    report.total_matched += 1;
                    if report.hits.len() < opts.limit {
                        report.hits.push(StringHit {
                            dex: name.to_string(),
                            index: i,
                            text: text.into_owned(),
                        });
                        summary.emitted += 1;
                    }
                }
            }
            Err(_) => {
                summary.errors += 1;
                if report.errors.len() < 100 {
                    report
                        .errors
                        .push(format!("{name}: string #{i} failed to decode"));
                }
            }
        }
    }
    if summary.errors > 0 {
        report.complete = false;
    }
    report.per_dex.push(summary);
}

/// Text rendering: one `<dex> #<index> <text>` line per hit, plus a
/// per-DEX summary tail.
pub fn format_strings_text(r: &StringsReport) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    for h in &r.hits {
        let _ = writeln!(s, "{} #{} {}", h.dex, h.index, h.text);
    }
    if r.truncated {
        let _ = writeln!(
            s,
            "... truncated: {} matches, limit {} (raise --limit or filter with --substring)",
            r.total_matched,
            r.hits.len()
        );
    }
    for d in &r.per_dex {
        let _ = writeln!(
            s,
            "# {}: {} strings in pool, {} emitted, {} errors",
            d.dex_name, d.string_count, d.emitted, d.errors
        );
    }
    let _ = writeln!(s, "# complete: {}", r.complete);
    s
}
