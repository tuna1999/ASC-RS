//! Output formatting for the findrefs / getclass pipelines.
//!
//! Two emitters are exposed:
//!
//! - [`format_search_report_text`] — produces the exact per-DEX line
//!   format described in `reference/BEHAVIOR.md` §2:
//!   `{dex_name} | {caller.fullname}->{caller.name} | matched=(...)`.
//!   DEXes with no hits emit no lines (per `main.py:99-100`). The
//!   pipeline pre-renders hits while the borrowed `DexView` is alive
//!   and stores owned strings; this emitter just joins them.
//! - [`format_search_report_json`] — produces a JSON-ready value
//!   suitable for `--format json`. The shape mirrors [`SearchReport`]
//!   plus an aggregated `matched_method_count` / `line_count` for
//!   consumers that don't want to walk `results`.
//! - [`format_getclass_text`] — thin wrapper: the decompiler emits the
//!   source body, and we trim / add a trailing newline (the oracle
//!   prints the source via `print(source)` which adds the trailing
//!   newline).
//!
//! ## Matched-side format
//!
//! The text emitter joins matched entities with `;`. The python
//! oracle's `str(...)` rendering is byte-identical to our lossy decode
//! for ASCII inputs (every captured golden case is ASCII). For the
//! differential runner the parsing regex (`run_differential.py:52-56`)
//! treats the matched payload as opaque text — quotes and escapes are
//! not part of the contract.

use serde::Serialize;

use crate::pipeline::{GetClassResult, ListClassesResult};
use crate::report::{DexResults, SearchReport};

/// Format a [`SearchReport`] into the oracle's per-DEX text format.
///
/// Output rules (see `BEHAVIOR.md` §2):
///
/// - One line per caller.
/// - DEXes with no caller matches emit no lines.
/// - Caller lines inside a DEX are sorted by caller id (the pipeline
///   pre-sorts them via [`BTreeMap`]).
/// - The result is the concatenation of every emitted line joined by
///   `\n`. The CLI is responsible for the outer trailing newline.
pub fn format_search_report_text(report: &SearchReport) -> String {
    let mut out = String::new();
    let mut first_dex = true;
    for dex in &report.results {
        if dex.matches.is_empty() {
            continue;
        }
        if !first_dex {
            // The oracle inserts a newline between per-DEX blocks
            // only when both blocks have hits; our per-line join
            // already separates them by `\n` after the previous
            // block's last line.
            out.push('\n');
        }
        first_dex = false;
        for (i, m) in dex.matches.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            // Oracle uses `"; ".join(...)` (semicolon + space).
            let joined = m.matched.join("; ");
            out.push_str(&format!(
                "{} | {} | matched=({})",
                dex.dex_name, m.caller, joined
            ));
        }
    }
    out
}

/// Serializable JSON shape emitted by `--format json`.
#[derive(Debug, Clone, Serialize)]
pub struct JsonReport {
    /// `true` iff every per-DEX scan finished without errors.
    pub complete: bool,
    /// Total matched callers (one per emitted line).
    pub matched_method_count: usize,
    /// Total emitted line count.
    pub line_count: usize,
    /// Per-DEX results (in central-directory order).
    pub results: Vec<JsonDexResults>,
    /// Errors aggregated across every DEX.
    pub errors: Vec<crate::report::SearchError>,
}

/// One DEX's contribution to a [`JsonReport`].
#[derive(Debug, Clone, Serialize)]
pub struct JsonDexResults {
    /// DEX display name (see [`crate::report::DexResults::dex_name`]).
    pub dex_name: String,
    /// `true` iff this DEX's scan finished cleanly.
    pub complete: bool,
    /// Per-caller matched lines.
    pub matches: Vec<JsonMatch>,
    /// Errors recorded while scanning this DEX.
    pub errors: Vec<crate::report::SearchError>,
}

/// One caller line: `{caller.fullname}->{caller.name}` plus the
/// matched entity list (sorted, dedup'd).
#[derive(Debug, Clone, Serialize)]
pub struct JsonMatch {
    /// `Lcom/foo/Bar;->name` form.
    pub caller: String,
    /// Decoded matched entity strings.
    pub matched: Vec<String>,
}

/// Format a [`SearchReport`] as a JSON-ready value.
pub fn format_search_report_json(report: &SearchReport) -> JsonReport {
    let mut line_count = 0usize;
    let mut json_results: Vec<JsonDexResults> = Vec::with_capacity(report.results.len());
    for dex in &report.results {
        let matches: Vec<JsonMatch> = dex
            .matches
            .iter()
            .map(|m| {
                line_count += 1;
                JsonMatch {
                    caller: m.caller.clone(),
                    matched: m.matched.clone(),
                }
            })
            .collect();
        json_results.push(JsonDexResults {
            dex_name: dex.dex_name.clone(),
            complete: dex.complete,
            matches,
            errors: dex.errors.clone(),
        });
    }
    JsonReport {
        complete: report.complete,
        matched_method_count: line_count,
        line_count,
        results: json_results,
        errors: report.errors.clone(),
    }
}

/// Format the decompiled source for getclass. The decompiler produces
/// a `String`; we ensure exactly one trailing newline so the CLI can
/// write it directly.
pub fn format_getclass_text(source: &str) -> String {
    let mut s = String::with_capacity(source.len() + 1);
    s.push_str(source);
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Convenience helper for callers that want to drop the `search_report`
/// metadata when assembling a summary footer.
#[allow(dead_code)]
pub fn total_line_count(report: &SearchReport) -> usize {
    report
        .results
        .iter()
        .map(|d: &DexResults| d.matches.len())
        .sum()
}

/// Format a [`ListClassesResult`] as the oracle's text emitter:
///
/// - One descriptor per line.
/// - No trailing newline on the final descriptor (the CLI handles
///   the outer trailing newline).
/// - Empty result emits the empty string (matching the oracle, which
///   emits nothing when the APK contains zero matching classes).
///
/// Mirrors `droidasc/cli.py:_handle_listclass` — the oracle writes
/// chunks of up to 8192 descriptors per `"\n".join` call. The chunked
/// write is a streaming optimization and produces byte-identical
/// output to a single pass; we use a single pass for simplicity.
pub fn format_listclasses_text(result: &ListClassesResult) -> String {
    format_listclasses_text_opt(result, false)
}

/// Like [`format_listclasses_text`], but with `with_dex` each line is
/// `<dex> <descriptor>` — the defining DEX (logical name) per class.
/// The default (`false`) stays byte-identical to the oracle.
pub fn format_listclasses_text_opt(result: &ListClassesResult, with_dex: bool) -> String {
    let total: usize = result.names.iter().map(|n| n.len() + 1).sum::<usize>()
        + if with_dex {
            result.dexes.iter().map(|d| d.len() + 1).sum()
        } else {
            0
        };
    let mut out = String::with_capacity(total);
    for (i, name) in result.names.iter().enumerate() {
        if with_dex {
            out.push_str(result.dexes.get(i).map(String::as_str).unwrap_or("?"));
            out.push(' ');
        }
        out.push_str(name);
        out.push('\n');
    }
    // Strip the trailing newline so the CLI can re-add exactly one
    // (matches how `format_search_report_text` is consumed).
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// `listclass --format json` payload.
#[derive(Debug, Clone, Serialize)]
pub struct JsonListClasses {
    /// Number of descriptors in `classes`.
    pub total: usize,
    /// Per-DEX class counts, in DEX order.
    pub per_dex: Vec<JsonDexCount>,
    /// Descriptors, DEX-definition order.
    pub classes: Vec<String>,
    /// Logical DEX name per class, parallel to `classes` (only when
    /// `--with-dex` was requested; absent otherwise).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_dex: Option<Vec<String>>,
}

/// One row of [`JsonListClasses::per_dex`].
#[derive(Debug, Clone, Serialize)]
pub struct JsonDexCount {
    /// DEX name.
    pub dex_name: String,
    /// Matching classes in that DEX.
    pub count: usize,
}

/// Build the `listclass` JSON payload. `with_dex` adds the parallel
/// `class_dex` array; without it the payload is unchanged.
pub fn format_listclasses_json_opt(result: &ListClassesResult, with_dex: bool) -> JsonListClasses {
    JsonListClasses {
        total: result.names.len(),
        per_dex: result
            .per_dex_counts
            .iter()
            .map(|(dex_name, count)| JsonDexCount {
                dex_name: dex_name.clone(),
                count: *count,
            })
            .collect(),
        classes: result.names.clone(),
        class_dex: with_dex.then(|| result.dexes.clone()),
    }
}

/// Backward-compatible wrapper (no `class_dex` array).
pub fn format_listclasses_json(result: &ListClassesResult) -> JsonListClasses {
    format_listclasses_json_opt(result, false)
}

/// `getclass --format json` payload.
#[derive(Debug, Clone, Serialize)]
pub struct JsonGetClass<'a> {
    /// Winning DEX name.
    pub dex_name: &'a str,
    /// `class_def` offset used for the rebuild.
    pub class_def_off: u32,
    /// Decompiled source, unmodified.
    pub source: &'a str,
}

/// Build the `getclass` JSON payload.
pub fn format_getclass_json(result: &GetClassResult) -> JsonGetClass<'_> {
    JsonGetClass {
        dex_name: &result.dex_name,
        class_def_off: result.class_def_off,
        source: &result.source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listclasses_json_shape_is_stable() {
        let r = ListClassesResult {
            names: vec!["LA;".into(), "LB;".into(), "LC;".into()],
            dexes: vec![
                "classes.dex".into(),
                "classes.dex".into(),
                "classes2.dex".into(),
            ],
            per_dex_counts: vec![("classes.dex".into(), 2), ("classes2.dex".into(), 1)],
        };
        let v = serde_json::to_value(format_listclasses_json(&r)).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "total": 3,
                "per_dex": [
                    {"dex_name": "classes.dex", "count": 2},
                    {"dex_name": "classes2.dex", "count": 1}
                ],
                "classes": ["LA;", "LB;", "LC;"]
            })
        );
    }

    #[test]
    fn getclass_json_keeps_source_verbatim() {
        let r = GetClassResult {
            dex_name: "classes.dex".into(),
            class_def_off: 112,
            source: "class A {\n\t\"q\"\n}".into(),
        };
        let s = serde_json::to_string(&format_getclass_json(&r)).unwrap();
        let back: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back["source"], r.source.as_str());
        assert_eq!(back["class_def_off"], 112);
    }
}
