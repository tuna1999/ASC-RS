//! Orchestration pipelines: `FindRefsJob` and `GetClassJob`.
//!
//! ## findrefs (§25)
//!
//! 1. Open the APK once via [`asc_apk::Apk::open`].
//! 2. Iterate `classes*.dex` entries in central-directory offset order.
//! 3. For each entry:
//!    a. Read the entry bytes (mmap slice for `Stored`, inflated
//!    `Vec<u8>` for `Deflated`).
//!    b. Determine whether the entry is a DEX-041 container:
//!    check the 8-byte magic. If so, expand it into one or more
//!    logical DEX views via
//!    [`asc_dex::DexView::logical_header_offsets`] +
//!    [`asc_dex::DexView::parse_at`]. Each logical DEX of a multi-member
//!    container is named `name!classes{i+1}.dex` per `BEHAVIOR.md` §2 /
//!    `dex_container.py:142-149`.
//!    c. Otherwise, parse a single [`asc_dex::DexView`] at offset 0.
//!    d. Call [`asc_query::find_refs`] on each view.
//!    e. Render each `RefHit` to `(caller_string, matched_strings)`
//!    while the borrow is alive (the report owns only owned
//!    strings; see [`crate::report::SearchReport`]). Malformed
//!    parse / engine errors are recorded; the scan continues.
//! 4. Return a [`SearchReport`] with `complete = false` iff any per-DEX
//!    scan or parse failed.
//!
//! ## getclass (§17)
//!
//! 1. Open the APK once.
//! 2. Bounded parallel scan ([`find_defining_dex`]): N worker threads
//!    share an `AtomicUsize` work cursor and an `AtomicBool` "found"
//!    flag.
//! 3. Each worker dequeues the next dex entry, inflates it, runs a
//!    type-idx / class-def lookup via [`asc_query::class_defines`].
//!    On a hit, the worker records it in a best-hit cell that keeps
//!    the LOWEST entry index (duplicate classes across DEXes resolve
//!    like Android's classloader order: `classes.dex` shadows
//!    `classes2.dex`) and sets the flag; other workers stop pulling
//!    new entries. The result is scheduling-independent.
//! 4. Winner's bytes → [`asc_rebuild::rebuild`] →
//!    [`asc_decompile::ClassDecompiler::decompile`] → source string.
//! 5. Return a [`GetClassResult`] with `dex_name` and `source`.
//!
//! ## disasm
//!
//! Same class-defining-DEX scan as `getclass` ([`find_defining_dex`],
//! same `CoreError::ClassNotFound` on a miss), but the winning
//! DEX is handed whole to
//! [`asc_decompile::ClassDecompiler::disassemble`] — no
//! `asc-rebuild` closure and no minimal-DEX rewrite — which keeps
//! cross-class references and method bodies verbatim.
//!
//! ## Cancellation
//!
//! The worker pool checks `found` between entries (not inside an
//! entry's processing — a pulled entry always runs to completion so
//! the lowest-index winner cannot be skipped). When the winner is
//! recorded, other workers stop pulling new work; their in-flight
//! processing (a single `apk.read_entry + dex parse + class_defines`
//! check) completes naturally. Total cost is bounded by the
//! next-to-finish in-flight entry's processing time. An entry whose
//! memory-budget reservation was refused mid-race is deferred and
//! rescanned sequentially after the pool joins (see
//! [`find_defining_dex`]) — it is never silently treated as a miss.
//!

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
#[cfg(test)]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use asc_apk::{Apk, ApkError, DexEntry};
use asc_bytecode::DexRef;
use asc_decompile::{ClassDecompiler, DecompileError};
use asc_dex::view::DexView;
use asc_query::{Query, RefHit, class_defines, find_refs as engine_find_refs};

use crate::report::{DexResults, RenderedMatch, SearchError, SearchReport};
use crate::worker::WorkerPool;

/// Top-level error type for asc-core orchestration.
#[derive(Debug)]
pub enum CoreError {
    /// The APK could not be opened / parsed.
    Apk(ApkError),
    /// The supplied class name is empty / invalid.
    Class(DecompileError),
    /// The rebuild step failed (closure / layout / checksum).
    Rebuild(asc_rebuild::RebuildError),
    /// The decompiler returned an error after a successful rebuild.
    Decompile(DecompileError),
    /// The class was not defined in any of the APK's DEX entries.
    ClassNotFound(String),
    /// The `disasm --method` filter matched no method of the class.
    MethodNotFound(String),
    /// The process-wide scan-memory budget was exceeded (see
    /// [`crate::budget`]). Structured, recoverable-by-caller: no
    /// panic, no abort.
    MemoryBudget(String),
    /// A `getclass` worker thread unwound. The entries those workers
    /// owned were never scanned, so their absence of the target class
    /// is unproven — this must never be reported as `ClassNotFound`.
    WorkerPanicked(String),
    /// The binary's CLI received bad input (e.g. neither `--class` nor
    /// `<name>` for `findrefs method`).
    Usage(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Apk(e) => write!(f, "apk error: {e}"),
            CoreError::Class(e) => write!(f, "{e}"),
            CoreError::Rebuild(e) => write!(f, "rebuild error: {e}"),
            CoreError::Decompile(e) => write!(f, "{e}"),
            CoreError::ClassNotFound(c) => {
                write!(f, "Class {c} not found in APK.")
            }
            CoreError::MethodNotFound(m) => {
                write!(f, "Method {m} not found in class.")
            }
            CoreError::Usage(m) => write!(f, "{m}"),
            CoreError::MemoryBudget(m) => write!(f, "{m}"),
            CoreError::WorkerPanicked(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<ApkError> for CoreError {
    fn from(e: ApkError) -> Self {
        CoreError::Apk(e)
    }
}

impl From<asc_dex::error::DexError> for CoreError {
    fn from(_e: asc_dex::error::DexError) -> Self {
        // A DEX parse failure is a structural problem with the
        // archive's content; surface as `Apk(Truncated)` so the
        // existing `Error` impl carries a useful message.
        CoreError::Apk(ApkError::Truncated("dex parse failed"))
    }
}

/// One findrefs run.
#[derive(Debug, Clone)]
pub struct FindRefsJob {
    /// Path to the APK.
    pub apk: std::path::PathBuf,
    /// The query.
    pub query: Query,
}

impl FindRefsJob {
    /// Convenience constructor.
    pub fn new(apk: impl Into<std::path::PathBuf>, query: Query) -> Self {
        Self {
            apk: apk.into(),
            query,
        }
    }
}

/// Options for `run_findrefs`.
#[derive(Debug, Clone, Default)]
pub struct FindRefsOptions {
    /// Threading is currently a no-op for `findrefs` (each DEX is
    /// processed sequentially; the engine itself is per-DEX). We keep
    /// the field for symmetry with `GetClassOptions` and to leave room
    /// for a future per-DEX parallel mode.
    pub threads: usize,
    /// Emit per-stage timing information to stderr.
    pub debug: bool,
    /// `string` queries also match Paranoid-obfuscated literals (the
    /// decoded value is reported in `matched`). Off by default: the
    /// oracle has no such mode.
    pub paranoid: bool,
    /// `string` queries also match XOR-obfuscated literals (const-array
    /// + literal-key decoder, decoded from bytecode). Off by default.
    pub decode_xor: bool,
    /// Total bytes of DEX entries this process may hold concurrently
    /// across all scans (worker pools, GUI tasks, …). `0` = engine
    /// default ([`crate::budget::DEFAULT_SCAN_BUDGET`]).
    pub scan_budget_bytes: usize,
}

/// One getclass run.
#[derive(Debug, Clone)]
pub struct GetClassJob {
    /// Path to the APK.
    pub apk: std::path::PathBuf,
    /// Class descriptor (already normalized — accept `L…;` or `dotted`).
    pub target: String,
}

impl GetClassJob {
    /// Convenience constructor.
    pub fn new(apk: impl Into<std::path::PathBuf>, target: impl Into<String>) -> Self {
        Self {
            apk: apk.into(),
            target: target.into(),
        }
    }
}

/// Options for `run_getclass`.
#[derive(Debug, Clone)]
pub struct GetClassOptions {
    /// Worker count (default 8).
    pub threads: usize,
    /// Emit per-stage timing information to stderr.
    pub debug: bool,
    /// Replace resolvable Paranoid `getString(id)` calls in the target
    /// class with the decoded literal before decompiling.
    pub paranoid: bool,
    /// Replace provable XOR-decoder calls (const-array + literal key,
    /// no aliasing) in the target class with the decoded literal.
    pub decode_xor: bool,
    /// Total bytes of DEX entries this process may hold concurrently
    /// across all scans (worker pools, GUI tasks, …). `0` = engine
    /// default ([`crate::budget::DEFAULT_SCAN_BUDGET`]).
    pub scan_budget_bytes: usize,
}

impl Default for GetClassOptions {
    fn default() -> Self {
        Self {
            threads: 8,
            debug: false,
            paranoid: false,
            decode_xor: false,
            scan_budget_bytes: 0,
        }
    }
}

/// Output of a successful `run_getclass`.
#[derive(Debug, Clone)]
pub struct GetClassResult {
    /// Display name of the winning DEX (`classes.dex`,
    /// `classes2.dex`, `classes.dex!classes2.dex`, …).
    pub dex_name: String,
    /// `class_def` off the winner used during the rebuild.
    pub class_def_off: u32,
    /// The decompiled Java-like source.
    pub source: String,
}

/// One disasm run.
#[derive(Debug, Clone)]
pub struct DisasmJob {
    /// Path to the APK or raw `.dex`.
    pub apk: std::path::PathBuf,
    /// Class descriptor (already normalized — accept `L…;` or `dotted`).
    pub target: String,
    /// Optional exact method-name filter (every overload is emitted).
    pub method: Option<String>,
}

impl DisasmJob {
    /// Convenience constructor.
    pub fn new(
        apk: impl Into<std::path::PathBuf>,
        target: impl Into<String>,
        method: Option<&str>,
    ) -> Self {
        Self {
            apk: apk.into(),
            target: target.into(),
            method: method.map(str::to_owned),
        }
    }
}

/// Options for [`run_disasm`].
#[derive(Debug, Clone)]
pub struct DisasmOptions {
    /// Worker count used to locate the class-defining DEX.
    pub threads: usize,
    /// Emit the winning DEX name + timings to stderr.
    pub debug: bool,
    /// Total bytes of DEX entries this process may hold concurrently
    /// across all scans (worker pools, GUI tasks, …). `0` = engine
    /// default ([`crate::budget::DEFAULT_SCAN_BUDGET`]).
    pub scan_budget_bytes: usize,
}

impl Default for DisasmOptions {
    fn default() -> Self {
        Self {
            threads: 8,
            debug: false,
            scan_budget_bytes: 0,
        }
    }
}

/// Output of a successful [`run_disasm`].
#[derive(Debug, Clone)]
pub struct DisasmResult {
    /// Display name of the winning DEX (`classes.dex`, `classes2.dex`, …).
    pub dex_name: String,
    /// The smali-syntax listing.
    pub listing: String,
}

// --------------------- findrefs pipeline ---------------------

/// Open the APK once, iterate `classes*.dex` in central-directory
/// offset order, expand each entry (handling DEX-041 containers),
/// run `find_refs` per view, and aggregate into a [`SearchReport`].
pub fn run_findrefs(job: &FindRefsJob, opts: &FindRefsOptions) -> Result<SearchReport, CoreError> {
    let apk = Apk::open(&job.apk)?;
    check_raw_dex(&apk)?;
    let entries = apk.dex_entries();
    let deobs = match &job.query {
        Query::String { pattern } if opts.paranoid => {
            Some((crate::paranoid::collect(&apk), pattern.as_str()))
        }
        _ => None,
    };
    let paranoid = deobs.as_ref().map(|(d, p)| (d.as_slice(), *p));
    let xor_decoders = match &job.query {
        Query::String { .. } if opts.decode_xor => Some(crate::paranoid::collect_xor(&apk)),
        _ => None,
    };
    let xor = xor_decoders.as_deref();
    let mut report = SearchReport::empty();
    let budget = effective_budget(opts.scan_budget_bytes);
    for entry in entries {
        // Process-wide budget: reserve the declared entry size for as
        // long as this entry's bytes are alive. A budget failure is a
        // per-DEX error (recorded, scan continues with the remaining
        // entries) — never a panic or an abort.
        let _guard = match crate::budget::acquire(budget, entry.uncompressed_size as usize) {
            Ok(g) => g,
            Err(e) => {
                let msg = format!("{}: {}", entry.name, e);
                report.errors.push(SearchError::from_apk(&entry.name, &msg));
                report.complete = false;
                continue;
            }
        };
        // Parse straight from the EntryBytes view: mmap-backed for
        // STORED entries (zero copy), inflated Vec for DEFLATED ones.
        let bytes = match apk.read_entry(&entry) {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("{}: read_entry failed: {e}", entry.name);
                report.errors.push(SearchError::from_apk(&entry.name, &msg));
                report.complete = false;
                continue;
            }
        };
        scan_entry_bytes(
            &entry.name,
            bytes.as_slice(),
            &job.query,
            paranoid,
            xor,
            &mut report,
        );
    }
    Ok(report)
}

/// Deobfuscator tables plus the string pattern for a `--paranoid` scan.
type Paranoid<'a> = Option<(&'a [asc_paranoid::Deobfuscator], &'a str)>;

/// Scan one entry's bytes: detect a DEX-041 container or a single
/// DEX, run `find_refs` per logical view, aggregate into `report`.
fn scan_entry_bytes(
    entry_name: &str,
    bytes: &[u8],
    query: &Query,
    paranoid: Paranoid<'_>,
    xor: Option<&[asc_paranoid::XorDecoder]>,
    report: &mut SearchReport,
) {
    if bytes.len() < 8 {
        report.errors.push(SearchError::from_parse(
            entry_name,
            "entry too short to inspect (need 8 bytes for magic)",
        ));
        report.complete = false;
        report.results.push(DexResults::empty(entry_name));
        return;
    }
    let magic = &bytes[..8];
    if magic == b"dex\n041\0" {
        // DEX-041 container: walk logical headers.
        let Ok(offsets) = DexView::logical_header_offsets(bytes) else {
            report.errors.push(SearchError::from_parse(
                entry_name,
                "logical_header_offsets failed",
            ));
            report.complete = false;
            report.results.push(DexResults::empty(entry_name));
            return;
        };
        for (i, off) in offsets.iter().enumerate() {
            let name = logical_dex_name(entry_name, offsets.len(), i);
            let view = match DexView::parse_at(bytes, *off) {
                Ok(v) => v,
                Err(e) => {
                    report.errors.push(SearchError::from_parse(
                        &name,
                        format!("DexView::parse_at failed: {e}"),
                    ));
                    report.complete = false;
                    report.results.push(DexResults::empty(&name));
                    continue;
                }
            };
            run_engine_for_view(&name, &view, query, paranoid, xor, report);
        }
    } else if magic.starts_with(b"dex\n") {
        // Single DEX entry.
        let view = match DexView::parse(bytes) {
            Ok(v) => v,
            Err(e) => {
                report.errors.push(SearchError::from_parse(
                    entry_name,
                    format!("DexView::parse failed: {e}"),
                ));
                report.complete = false;
                report.results.push(DexResults::empty(entry_name));
                return;
            }
        };
        run_engine_for_view(entry_name, &view, query, paranoid, xor, report);
    } else {
        // Not a DEX. The oracle is *louder* here, not compatible:
        // `_findrefs_worker` (apk_handler.py:290-308) hands the raw
        // buffer to `tinydex.DEX.parse`, which unpacks u32s at fixed
        // offsets with no magic check, so a bogus entry aborts the
        // whole oracle run with exit 1 (main.py:179-184).
        //
        // Record the skip, but do NOT flip `complete`: an entry we
        // deliberately declined to decode is not a failed scan, and
        // exit 2 must keep meaning "the scan ran and hit an error".
        // The error list is what the CLI prints on stderr and what
        // JSON carries, so a user (or a script) can see that the
        // archive was not fully covered. (Audit F06.)
        report.errors.push(SearchError::from_parse(
            entry_name,
            "skipped: entry is not a DEX (bad magic) and was not scanned",
        ));
    }
}

/// Run the query engine on a single DEX view and append the result
/// to the report.
fn run_engine_for_view(
    dex_name: &str,
    view: &DexView<'_>,
    query: &Query,
    paranoid: Paranoid<'_>,
    xor: Option<&[asc_paranoid::XorDecoder]>,
    report: &mut SearchReport,
) {
    let engine_report = engine_find_refs(view, query);
    if !engine_report.errors.is_empty() {
        report.complete = false;
    }
    // Engine errors belong in BOTH views: the per-DEX `DexResults.errors`
    // and the report-wide `SearchReport.errors` the CLI prints as
    // warnings. Recording them only per-DEX left the aggregated list
    // empty while `complete` was already `false` (audit F04).
    for e in &engine_report.errors {
        report.errors.push(SearchError::from_engine(dex_name, e));
    }
    let decoded = paranoid
        .map(|(deobs, pattern)| crate::paranoid::decoded_hits(view, deobs, pattern))
        .unwrap_or_default();
    let pattern = match query {
        Query::String { pattern } => pattern.as_str(),
        _ => "",
    };
    let decoded = if let Some(decoders) = xor {
        decoded
            .into_iter()
            .chain(crate::paranoid::xor_decoded_hits(view, decoders, pattern))
            .collect()
    } else {
        decoded
    };
    let rendered = render_hits(view, &engine_report.hits, &decoded);
    let engine_errors: Vec<SearchError> = engine_report
        .errors
        .iter()
        .map(|e| SearchError::from_engine(dex_name, e))
        .collect();
    report.results.push(DexResults {
        dex_name: dex_name.to_string(),
        matches: rendered,
        errors: engine_errors,
        complete: engine_report.complete,
    });
}

/// Render raw [`RefHit`]s (plus `--paranoid` decoded-string hits as
/// `(caller, offset, value)`) into owned [`RenderedMatch`]es.
///
/// Group by caller method id, de-duplicate and sort matched refs,
/// render each caller / matched pair into strings while the borrowed
/// `view` is alive. Also resolves the smallest matched code-unit
/// offset to a 1-indexed source line via `debug_info` (None when the
/// method has no debug stream).
fn render_hits(
    view: &DexView<'_>,
    hits: &[RefHit],
    decoded: &[(u32, u32, String)],
) -> Vec<RenderedMatch> {
    if hits.is_empty() && decoded.is_empty() {
        return Vec::new();
    }
    // caller -> (matched refs, decoded strings, minimum code_off).
    type Caller<'d> = (Vec<DexRef>, Vec<&'d str>, Option<u32>);
    let mut by_caller: BTreeMap<u32, Caller<'_>> = BTreeMap::new();
    let offsets = hits
        .iter()
        .map(|h| (h.method.0, h.offset))
        .chain(decoded.iter().map(|(m, off, _)| (*m, *off)));
    for (method, offset) in offsets {
        let entry = by_caller.entry(method).or_default();
        entry.2 = Some(entry.2.map_or(offset, |prev| prev.min(offset)));
    }
    for h in hits {
        by_caller.entry(h.method.0).or_default().0.push(h.dex_ref);
    }
    for (m, _, value) in decoded {
        by_caller.entry(*m).or_default().1.push(value);
    }
    let mut out: Vec<RenderedMatch> = Vec::with_capacity(by_caller.len());
    // `resolve_first_line` needs each caller's source-side `code_off`.
    // Looking it up per match re-scans every class_def, which is
    // O(callers × class_defs) — measured at 14–84% of findrefs wall
    // time on the corpus.
    //
    // One index pass costs a full class_def walk; the per-caller scan
    // stops at the first match, so it averages half that. The index
    // therefore only pays off past a couple of callers — below that we
    // keep the scan, which is measurably faster for narrow queries
    // (e.g. 1 hit on workload.apk: 43.6 ms scanned vs 46.4 ms indexed).
    let indexed: Option<HashMap<u32, u32>> =
        (by_caller.len() > LINEAR_SCAN_CALLER_LIMIT).then(|| source_code_off_index(view));
    for (mid, (matched, decoded, min_code_off)) in &by_caller {
        let Some(caller_str) = render_caller(view, mid) else {
            continue;
        };
        let mut sorted = matched.clone();
        // Order: by discriminant tag (String < Type < Field < Method)
        // then by index. This matches the oracle's "sorted matched
        // entity ids" semantic: the python implementation sorts by
        // numeric id per kind; per-kind the natural numeric sort and
        // the kind-then-id sort produce identical line ordering for
        // any single query result. Across kinds the per-kind ids
        // are dense in [0..count) so cross-kind order is irrelevant
        // for parity (the differential runner parses matched=(...)
        // as opaque text).
        sorted.sort_by_key(|r| match r {
            DexRef::String(i) => (0u8, i.0),
            DexRef::Type(i) => (1, i.0),
            DexRef::Field(i) => (2, i.0),
            DexRef::Method(i) => (3, i.0),
            DexRef::Proto(i) => (4, i.0),
            DexRef::CallSite(i) => (5, i.0),
            DexRef::MethodHandle(i) => (6, i.0),
        });
        sorted.dedup();
        let mut matched_strs: Vec<String> = sorted
            .iter()
            .filter_map(|r| render_dex_ref(view, r))
            .collect();
        let mut decoded = decoded.clone();
        decoded.sort_unstable();
        decoded.dedup();
        matched_strs.extend(decoded.iter().map(|s| s.to_string()));
        // Resolve the smallest matched offset to a 1-indexed source
        // line. None when the body has no debug_info_item; we do not
        // fail the match on malformed debug streams — we just skip
        // the line number (the GUI then opens at line 0 / start).
        let first_line = min_code_off.and_then(|off| {
            let abs = match &indexed {
                Some(index) => index.get(mid).copied(),
                None => scan_source_code_off(view, *mid),
            }?;
            resolve_first_line(view, abs, off)
        });
        out.push(RenderedMatch {
            caller: caller_str,
            matched: matched_strs,
            first_line,
        });
    }
    out
}

/// Caller count above which [`source_code_off_index`] beats a per-caller
/// linear scan. Both were measured on the corpus; 2 callers is where the
/// one-time full walk overtakes repeated early-exit scans.
const LINEAR_SCAN_CALLER_LIMIT: usize = 2;

/// Scan the class-defs for a single method's source-side `code_off`,
/// stopping at the first match. Used for narrow queries where building
/// [`source_code_off_index`] would cost more than it saves.
fn scan_source_code_off(view: &DexView<'_>, mid: u32) -> Option<u32> {
    for ci in 0..view.class_def_count() {
        let Ok(def) = view.class_def(ci) else {
            continue;
        };
        if def.class_data_off == 0 {
            continue;
        }
        let Ok(Some(data)) = view.class_data(def.class_data_off) else {
            continue;
        };
        for m in data
            .direct_methods
            .iter()
            .chain(data.virtual_methods.iter())
        {
            if m.method_idx.0 == mid {
                return Some(m.code_off);
            }
        }
    }
    None
}

/// Index every source-side method's `code_off` in one pass over the
/// class-defs: `method_idx → code_off`.
///
/// First class-def wins for a duplicated `method_idx`, matching the
/// linear scan this replaces. Malformed class-defs / class_data are
/// skipped rather than aborting the walk, exactly as before.
fn source_code_off_index(view: &DexView<'_>) -> HashMap<u32, u32> {
    let mut index = HashMap::new();
    for ci in 0..view.class_def_count() {
        let Ok(def) = view.class_def(ci) else {
            continue;
        };
        if def.class_data_off == 0 {
            continue;
        }
        let Ok(Some(data)) = view.class_data(def.class_data_off) else {
            continue;
        };
        for m in data
            .direct_methods
            .iter()
            .chain(data.virtual_methods.iter())
        {
            index.entry(m.method_idx.0).or_insert(m.code_off);
        }
    }
    index
}

/// Resolve the 1-indexed source line of the smallest matched code
/// offset in a caller method. Returns `None` when the body has no
/// `debug_info_item` (or the offset lands on a malformed stream).
///
/// `code_off_abs` is the caller's source-side `code_off`, from
/// [`source_code_off_index`].
fn resolve_first_line(view: &DexView<'_>, code_off_abs: u32, code_off: u32) -> Option<u32> {
    if code_off_abs == 0 {
        return None;
    }
    // Read the code_item header to fetch debug_info_off.
    let code_item = view.code_item(code_off_abs).ok()??;
    let dbg_off = code_item.debug_info_off;
    if dbg_off == 0 {
        return None;
    }
    view.line_for_code_unit(dbg_off, code_off).ok().flatten()
}

/// Render a caller method `Lcom/foo/Bar;->name` for a given method id.
fn render_caller(view: &DexView<'_>, mid: &u32) -> Option<String> {
    let m = view.method(asc_dex::ids::MethodIdx(*mid)).ok()?;
    let cls_sidx = view.type_(m.class).ok()?;
    let cls = view.string(cls_sidx).ok()?;
    let name = view.string(m.name).ok()?;
    Some(format!(
        "{}->{}",
        cls.decode_lossy().into_owned(),
        name.decode_lossy().into_owned()
    ))
}

/// Render a `DexRef` into the matched-side string the oracle puts
/// inside `matched=(...)`.
fn render_dex_ref(view: &DexView<'_>, r: &DexRef) -> Option<String> {
    match r {
        DexRef::String(idx) => view
            .string(*idx)
            .ok()
            .map(|s| s.decode_lossy().into_owned()),
        DexRef::Type(idx) => {
            let sidx = view.type_(*idx).ok()?;
            view.string(sidx)
                .ok()
                .map(|s| s.decode_lossy().into_owned())
        }
        DexRef::Method(idx) => {
            let m = view.method(*idx).ok()?;
            let cls_sidx = view.type_(m.class).ok()?;
            let cls = view.string(cls_sidx).ok()?;
            let name = view.string(m.name).ok()?;
            Some(format!(
                "{}->{}",
                cls.decode_lossy().into_owned(),
                name.decode_lossy().into_owned()
            ))
        }
        DexRef::Field(idx) => {
            let f = view.field(*idx).ok()?;
            let cls_sidx = view.type_(f.class).ok()?;
            let cls = view.string(cls_sidx).ok()?;
            let name = view.string(f.name).ok()?;
            Some(format!(
                "{}->{}",
                cls.decode_lossy().into_owned(),
                name.decode_lossy().into_owned()
            ))
        }
        DexRef::Proto(_) | DexRef::CallSite(_) | DexRef::MethodHandle(_) => None,
    }
}

// --------------------- getclass pipeline ---------------------

/// Open the APK, scan every `classes*.dex` in parallel for `target`,
/// rebuild the winning DEX into a minimal standalone, decompile the
/// target class, and return the source.
pub fn run_getclass(
    job: &GetClassJob,
    opts: &GetClassOptions,
) -> Result<GetClassResult, CoreError> {
    let target = job.target.clone();
    let apk = Arc::new(Apk::open(&job.apk)?);
    check_raw_dex(&apk)?;
    let entries = apk.dex_entries();
    let n = entries.len();

    if n == 0 {
        return Err(CoreError::ClassNotFound(target));
    }

    let hit = find_defining_dex(
        &apk,
        &entries,
        opts.threads.max(1),
        &target,
        opts.scan_budget_bytes,
    )?;
    decompile_winner(hit, &target, opts, &apk)
}

/// `0` means "engine default budget".
fn effective_budget(n: usize) -> usize {
    if n == 0 {
        crate::budget::DEFAULT_SCAN_BUDGET
    } else {
        n
    }
}

/// Scan `entries` (already in `classes*.dex` numeric order) for the DEX
/// that defines `target` and return the hit from the **lowest entry
/// index** that defines it.
///
/// ## Determinism
///
/// The pool's work cursor hands out entries in index order and every
/// pulled entry is processed to completion before the pool joins, so
/// "lowest pulled index that hit" is also the lowest index overall —
/// the winner cannot depend on worker scheduling. This matches
/// Android's multidex classloader order (`classes.dex` shadows
/// `classes2.dex` for a duplicate class) and the oracle's sequential
/// submission order. Within one DEX-041 container the first logical
/// header wins (see [`scan_one_for_class`]).
///
/// ## Memory budget
///
/// A worker that cannot reserve the process-wide scan budget for its
/// entry (other workers are mid-scan holding theirs) must NOT decide
/// that the entry lacks the class — that would let a higher-index DEX
/// win or produce a spurious `MemoryBudget` error purely from worker
/// scheduling. Such entries are **deferred** and rescanned
/// sequentially after the pool joins, when at most one guard is held
/// at a time, so same-run contention is impossible. An entry larger
/// than the whole budget can never be scanned; that permanent failure
/// is recorded and surfaces only when no lower DEX defines the class.
///
/// ## Error handling
///
/// Read/parse failures are recorded and only surface when no DEX
/// defines the class (the oracle lets them escape `get_class_dex`
/// only in that situation too).
fn find_defining_dex(
    apk: &Arc<Apk>,
    entries: &[DexEntry],
    threads: usize,
    target: &str,
    scan_budget_bytes: usize,
) -> Result<ClassHit, CoreError> {
    let budget = effective_budget(scan_budget_bytes);
    // Single-dex fast path: skip the worker pool entirely.
    if entries.len() == 1 {
        let entry = &entries[0];
        let _guard = crate::budget::acquire(budget, entry.uncompressed_size as usize)?;
        let eb = apk.read_entry(entry)?;
        return match scan_one_for_class(&entry.name, eb.as_slice(), target)? {
            Some(mut hit) => {
                hit.bytes = eb.into_vec();
                Ok(hit)
            }
            None => Err(CoreError::ClassNotFound(target.to_string())),
        };
    }

    let pool = WorkerPool::new(threads.max(1));
    let found = Arc::new(AtomicBool::new(false));
    // Best hit so far, by entry index. First writer does not win: a
    // lower-index hit must replace a higher one recorded earlier.
    let best: Arc<std::sync::Mutex<Option<(usize, ClassHit)>>> =
        Arc::new(std::sync::Mutex::new(None));
    // Entry indexes whose budget reservation was refused while other
    // workers held theirs — unproven, to be rescanned after the join.
    let deferred: Arc<std::sync::Mutex<Vec<usize>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    // First read/parse failure; only matters when nothing was found.
    let first_err: Arc<OnceLock<CoreError>> = Arc::new(OnceLock::new());
    let target_arc = Arc::new(target.to_owned());
    let apk_clone = Arc::clone(apk);
    let best_clone = Arc::clone(&best);
    let deferred_clone = Arc::clone(&deferred);
    let err_clone = Arc::clone(&first_err);

    let scan_for_class = move |i: usize, entry: &DexEntry| -> Option<()> {
        #[cfg(test)]
        test_faults::pool_gate(i);
        // Deliberately NO `found` check here: an entry that was already
        // pulled must run to completion, or a lower-index winner could
        // be skipped because a higher-index worker finished first.
        // The pool itself stops pulling new entries once `found` is set.
        //
        // Memory: reserve the entry against the process-wide budget,
        // then parse straight from the EntryBytes view (mmap-backed
        // for STORED entries) and materialize a Vec ONLY on a hit —
        // misses (the common multidex case) copy nothing.
        let _guard = match crate::budget::acquire(budget, entry.uncompressed_size as usize) {
            Ok(g) => g,
            Err(e) => {
                // Entry bigger than the whole budget: no scheduling
                // can ever scan it — a permanent failure. Anything
                // else is same-pool contention: defer, never decide.
                if entry.uncompressed_size as usize > budget {
                    let _ = err_clone.set(e);
                } else {
                    #[cfg(test)]
                    test_faults::note_deferred();
                    deferred_clone
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(i);
                }
                return None;
            }
        };
        #[cfg(test)]
        test_faults::hold_gate(i);
        let eb = match apk_clone.read_entry(entry) {
            Ok(b) => b,
            Err(e) => {
                let _ = err_clone.set(e.into());
                return None;
            }
        };
        match scan_one_for_class(&entry.name, eb.as_slice(), &target_arc) {
            Ok(Some(mut hit)) => {
                hit.bytes = eb.into_vec();
                {
                    let mut g = best_clone
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if g.as_ref().is_none_or(|(bi, _)| i < *bi) {
                        *g = Some((i, hit));
                    }
                }
                found.store(true, Ordering::Release);
                Some(())
            }
            Ok(None) => None,
            Err(e) => {
                let _ = err_clone.set(e);
                None
            }
        }
    };

    let outcome = pool.run(entries, scan_for_class);
    // A worker that unwound took the entry it owned with it: that entry
    // is *unscanned*, not proven to lack the class. Its index is now
    // known (`WorkerOutcome::unscanned`), so instead of a blanket
    // panic veto we rescan those entries in phase 2 like budget-deferred
    // ones; only entries that stay unscannable (panic again on the
    // sequential rescan) can still invalidate the winner.
    let panicked_workers = outcome.panicked;
    // Phase 2: the pool has joined, so this run's workers hold no
    // guards anymore. Rescan the budget-deferred AND panic-orphaned
    // entries sequentially — at most one guard at a time — in index
    // order, stopping above the current best (a higher index cannot
    // win). A budget refusal here means budget held by OTHER tasks in
    // the process: the answer cannot be proven, so fail with the
    // structured error instead of guessing.
    let mut requeue = std::mem::take(
        &mut *deferred
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    requeue.extend(outcome.unscanned.iter().copied());
    // Entries that panicked again during the sequential rescan: their
    // content stays unproven, so they may still invalidate a winner.
    let mut panic_pending: Vec<usize> = Vec::new();
    if !requeue.is_empty() {
        requeue.sort_unstable();
        requeue.dedup();
        for i in requeue {
            let entry = &entries[i];
            {
                let g = best
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if g.as_ref().is_some_and(|(bi, _)| i >= *bi) {
                    continue; // cannot beat the recorded winner
                }
            }
            // Budget refusal stays a hard `?` (above): it means some
            // OTHER task holds the bytes, so the answer cannot be
            // proven. A *read* failure is this entry's own, and phase 1
            // records it and moves on (`scan_for_class`, above).
            // Propagating it here instead would abandon every entry
            // still queued behind it, making the outcome depend on
            // which phase happened to pick the broken entry up.
            // Budget refusal stays a hard `?` (above): it means some
            // OTHER task holds the bytes, so the answer cannot be
            // proven. A *read* failure is this entry's own, and phase 1
            // records it and moves on (`scan_for_class`, above).
            // Propagating it here instead would abandon every entry
            // still queued behind it, making the outcome depend on
            // which phase happened to pick the broken entry up.
            let _guard = crate::budget::acquire(budget, entry.uncompressed_size as usize)?;
            let eb = match apk.read_entry(entry) {
                Ok(b) => b,
                Err(e) => {
                    let _ = first_err.set(e.into());
                    continue;
                }
            };
            // catch_unwind: a panic on the rescan path must surface as
            // `WorkerPanicked`, not unwind out of the API. The budget
            // guard above is released by unwinding (Drop) — no leak.
            let scanned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #[cfg(test)]
                test_faults::note_rescan(i);
                #[cfg(test)]
                test_faults::rescan_gate(i);
                scan_one_for_class(&entry.name, eb.as_slice(), target)
            }));
            match scanned {
                Err(_) => panic_pending.push(i),
                Ok(Ok(Some(mut hit))) => {
                    hit.bytes = eb.into_vec();
                    let mut g = best
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if g.as_ref().is_none_or(|(bi, _)| i < *bi) {
                        *g = Some((i, hit));
                    }
                }
                Ok(Ok(None)) => {}
                Ok(Err(e)) => {
                    let _ = first_err.set(e);
                }
            }
        }
    }

    // Only still-unproven entries BELOW the winner (or all of them when
    // there is no winner) can change the answer: an unscanned index
    // above the winner could never have won anyway (the pool stops
    // pulling entries above a hit by design).
    let best_idx = best
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(|(bi, _)| *bi);
    panic_pending.retain(|&i| best_idx.is_none_or(|b| i < b));

    let winner = best
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .map(|(_, hit)| hit);
    // Decision is state-based, not history-based: only entries that are
    // still unproven BELOW the winner (or with no winner at all) block
    // the answer. A worker that panicked but whose entries were all
    // rescanned clean does not poison the result — the miss is proven.
    if !panic_pending.is_empty() {
        return Err(CoreError::WorkerPanicked(format!(
            "{panicked_workers} getclass worker(s) panicked (unproven entries \
             {panic_pending:?}); the scan is incomplete and Class {target} \
             cannot be ruled out"
        )));
    }
    match winner {
        // A winner is a real hit and every entry below it is proven
        // (scanned, or rescanned clean): it outranks any recorded
        // error, exactly as the budget-deferral fix established.
        // A panic above the winner never invalidates it.
        Some(w) => Ok(w),
        None => Err(
            match Arc::try_unwrap(first_err)
                .ok()
                .and_then(OnceLock::into_inner)
            {
                Some(e) => e,
                None => CoreError::ClassNotFound(target.to_string()),
            },
        ),
    }
}

/// Test-only fault injection for the panic-provenance path of
/// [`find_defining_dex`]. Both gates are `usize::MAX` (off) outside a
/// test that sets them; [`test_faults::ALL`] panics on every entry.
#[cfg(test)]
mod test_faults {
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub const ALL: usize = usize::MAX - 1;
    pub static POOL_PANIC_AT: AtomicUsize = AtomicUsize::new(usize::MAX);
    pub static RESCAN_PANIC_AT: AtomicUsize = AtomicUsize::new(usize::MAX);
    /// Entry whose worker blocks (after taking its budget guard) until
    /// an injected panic has actually fired.
    pub static HOLD_AT: AtomicUsize = AtomicUsize::new(usize::MAX);
    // Counters so tests can prove the injected fault actually fired.
    pub static PANIC_HITS: AtomicUsize = AtomicUsize::new(0);
    pub static DEFERRED_HITS: AtomicUsize = AtomicUsize::new(0);
    pub static RESCAN_ENTRIES: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

    pub fn pool_gate(i: usize) {
        let v = POOL_PANIC_AT.load(Ordering::Relaxed);
        if v == ALL || v == i {
            PANIC_HITS.fetch_add(1, Ordering::Relaxed);
            panic!("injected worker panic at entry {i}");
        }
    }

    /// Entry `HOLD_AT`'s worker blocks until an injected panic has
    /// actually fired — deterministic "the panicking worker claimed its
    /// entry and entered the panic branch while the holder's entry was
    /// still unscanned" ordering. The panic gate runs before any
    /// blocking, so the wait always ends.
    pub fn hold_gate(i: usize) {
        if HOLD_AT.load(Ordering::Relaxed) == i {
            while PANIC_HITS.load(Ordering::Acquire) == 0 {
                std::hint::spin_loop();
            }
        }
    }

    pub fn rescan_gate(i: usize) {
        let v = RESCAN_PANIC_AT.load(Ordering::Relaxed);
        if v == ALL || v == i {
            panic!("injected rescan panic at entry {i}");
        }
    }

    pub fn note_deferred() {
        DEFERRED_HITS.fetch_add(1, Ordering::Relaxed);
    }

    pub fn note_rescan(i: usize) {
        RESCAN_ENTRIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(i);
    }

    fn reset_counters() {
        PANIC_HITS.store(0, Ordering::Relaxed);
        DEFERRED_HITS.store(0, Ordering::Relaxed);
        HOLD_AT.store(usize::MAX, Ordering::Relaxed);
        RESCAN_ENTRIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Resets all gates/counters when dropped, so a failing assertion
    /// cannot poison later tests in the same binary.
    pub struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            POOL_PANIC_AT.store(usize::MAX, Ordering::Relaxed);
            RESCAN_PANIC_AT.store(usize::MAX, Ordering::Relaxed);
            reset_counters();
        }
    }

    pub fn set(pool: usize, rescan: usize) -> Reset {
        reset_counters();
        POOL_PANIC_AT.store(pool, Ordering::Relaxed);
        RESCAN_PANIC_AT.store(rescan, Ordering::Relaxed);
        Reset
    }

    /// `set` + deterministic ordering: entry `hold`'s worker blocks
    /// until the injected panic has fired (see [`hold_gate`]).
    pub fn set_with_hold(pool: usize, rescan: usize, hold: usize) -> Reset {
        let r = set(pool, rescan);
        HOLD_AT.store(hold, Ordering::Relaxed);
        r
    }
}

/// A class-defining DEX found by `getclass`: the display name, the entry
/// bytes (whole container for DEX-041), and the logical header offset.
#[derive(Clone, Debug)]
struct ClassHit {
    name: String,
    /// The resolved class descriptor, so the disassembler can be handed
    /// the same spelling `class_defines` matched on.
    class: String,
    bytes: Vec<u8>,
    header_off: usize,
}

/// Display name of logical DEX `i` of `count` in entry `name`
/// (oracle: `iter_logical_dex_buffers`).
pub fn logical_dex_name(name: &str, count: usize, i: usize) -> String {
    if count <= 1 {
        name.to_string()
    } else {
        format!("{name}!classes{}.dex", i + 1)
    }
}

/// Run the class-idx / class-def lookup for `target` on every logical DEX
/// of `bytes` (which already came from `apk.read_entry`). Returns the hit
/// on success, `None` on miss, `Err` on parse failure.
fn scan_one_for_class(
    entry_name: &str,
    bytes: &[u8],
    target: &str,
) -> Result<Option<ClassHit>, CoreError> {
    // Reject obviously-bad entry bytes (matches oracle's
    // `_inflate_and_hit` early-return on magic != `dex\n0..\x00`).
    if bytes.len() < 8 || !bytes.starts_with(b"dex\n") {
        return Ok(None);
    }
    let offsets = if bytes.starts_with(b"dex\n041\0") {
        DexView::logical_header_offsets(bytes)?
    } else {
        vec![0]
    };
    for (i, &header_off) in offsets.iter().enumerate() {
        let view = DexView::parse_at(bytes, header_off)?;
        if class_defines(&view, target) {
            return Ok(Some(ClassHit {
                name: logical_dex_name(entry_name, offsets.len(), i),
                class: target.to_owned(),
                // Caller attaches the entry bytes (copy-on-hit; see
                // find_defining_dex / run_callees).
                bytes: Vec::new(),
                header_off,
            }));
        }
    }
    Ok(None)
}

/// Rebuild the winning DEX into a minimal standalone and decompile
/// `target`. With `opts.paranoid`, Paranoid call sites in the class are
/// patched to literals using deobfuscators from any DEX of `apk`.
///
/// When `opts.debug` is true, per-phase microsecond timings are written to
/// stderr as `[DEBUG] phase=X us=Y` lines so callers can see how the
/// wall time decomposes across (1) DexView parse for the rebuild,
/// (2) asc-rebuild closure/remap/rewrite/layout, and (3) droidsaw-dex
/// parse + census + emit.
fn decompile_winner(
    hit: ClassHit,
    target: &str,
    opts: &GetClassOptions,
    apk: &Apk,
) -> Result<GetClassResult, CoreError> {
    let debug = opts.debug;
    let started = std::time::Instant::now();
    let view = DexView::parse_at(&hit.bytes, hit.header_off)?;
    let parse_us = started.elapsed().as_micros();
    let mut patches = if opts.paranoid {
        crate::paranoid::class_patches(&view, target, &crate::paranoid::collect(apk))
    } else {
        Vec::new()
    };
    if opts.decode_xor {
        patches.extend(crate::paranoid::xor_class_patches(
            &view,
            target,
            &crate::paranoid::collect_xor(apk),
        ));
    }
    let rebuilt =
        asc_rebuild::rebuild_patched(&view, target, &patches).map_err(CoreError::Rebuild)?;
    let rebuild_us = started.elapsed().as_micros() - parse_us;
    let backend = asc_decompile::droidsaw::DroidsawBackend::new();
    let source = backend
        .decompile(&rebuilt.bytes, target)
        .map_err(CoreError::Decompile)?;
    let decompile_us = started.elapsed().as_micros() - parse_us - rebuild_us;
    if debug {
        eprintln!("[DEBUG] phase=dex_view_parse us={parse_us}");
        eprintln!("[DEBUG] phase=rebuild us={rebuild_us}");
        eprintln!("[DEBUG] phase=decompile us={decompile_us}");
        eprintln!("[DEBUG] phase=rebuilt_bytes bytes={}", rebuilt.bytes.len());
    }
    Ok(GetClassResult {
        dex_name: hit.name,
        class_def_off: rebuilt.class_def_off,
        source,
    })
}

// --------------------- disasm pipeline ---------------------

/// Locate the DEX that defines `target` (same bounded scan as
/// [`run_getclass`]) and return its smali-syntax listing.
///
/// Unlike `getclass` the winning DEX is handed to
/// [`ClassDecompiler::disassemble`] **whole** — no `asc-rebuild` closure
/// and no minimal-DEX rewrite — so cross-class references and method
/// bodies survive verbatim. `ClassHit::header_off` locates the class
/// inside a DEX-041 container; for a single-DEX entry the whole entry
/// is the DEX.
pub fn run_disasm(job: &DisasmJob, opts: &DisasmOptions) -> Result<DisasmResult, CoreError> {
    let target = job.target.clone();
    let started = std::time::Instant::now();
    let apk = Arc::new(Apk::open(&job.apk)?);
    check_raw_dex(&apk)?;
    let entries = apk.dex_entries();
    if entries.is_empty() {
        return Err(CoreError::ClassNotFound(target));
    }

    let hit = find_defining_dex(
        &apk,
        &entries,
        opts.threads.max(1),
        &target,
        opts.scan_budget_bytes,
    )?;
    disasm_winner(hit, &job.method, opts, started)
}

/// Feed the winning DEX to the backend and render the listing.
fn disasm_winner(
    hit: ClassHit,
    method: &Option<String>,
    opts: &DisasmOptions,
    started: std::time::Instant,
) -> Result<DisasmResult, CoreError> {
    // A DEX-041 container packs several logical DEXes into one entry;
    // droidsaw-dex parses a single file from offset 0, so hand it just
    // the member that defines the class. Single-DEX entries (`header_off
    // == 0`) are passed through with no copy.
    let dex_bytes: Cow<'_, [u8]> = if hit.header_off == 0 {
        Cow::Borrowed(&hit.bytes)
    } else {
        let member = &hit.bytes[hit.header_off..];
        let size = DexView::parse_at(member, 0)?.header().file_size as usize;
        Cow::Owned(member[..size].to_vec())
    };
    let backend = asc_decompile::droidsaw::DroidsawBackend::new();
    let listing = backend
        .disassemble(&dex_bytes, &hit.class, method.as_deref())
        .map_err(map_disasm_error)?;
    if opts.debug {
        eprintln!("[DEBUG] Hit DEX: {}", hit.name);
        eprintln!(
            "[DEBUG] Total Execution Time: {} us",
            started.elapsed().as_micros()
        );
    }
    Ok(DisasmResult {
        dex_name: hit.name,
        listing,
    })
}

/// Class absent / method filter matched nothing are "not found" (exit
/// 1, same class of user error `getclass` reports); everything the
/// renderer could not resolve is an engine error (exit 2).
fn map_disasm_error(e: DecompileError) -> CoreError {
    match e {
        DecompileError::ClassNotFound(c) => CoreError::ClassNotFound(c),
        DecompileError::MethodNotFound(m) => CoreError::MethodNotFound(m),
        other => CoreError::Decompile(other),
    }
}

// --------------------- callees pipeline ---------------------

/// One one-hop callee run: which methods does `target::method` invoke.
#[derive(Debug, Clone)]
pub struct CalleesJob {
    /// Path to the APK or raw `.dex`.
    pub apk: std::path::PathBuf,
    /// Class descriptor (`Lcom/foo/Bar;`).
    pub target: String,
    /// Method name (every overload is scanned).
    pub method: String,
}

impl CalleesJob {
    pub fn new(
        apk: impl Into<std::path::PathBuf>,
        target: impl Into<String>,
        method: impl Into<String>,
    ) -> Self {
        Self {
            apk: apk.into(),
            target: target.into(),
            method: method.into(),
        }
    }
}

/// Output of a successful [`run_callees`].
#[derive(Debug, Clone)]
pub struct CalleesResult {
    /// Display name of the DEX that defines the class.
    pub dex_name: String,
    /// Distinct invoked methods, first-encounter order.
    pub callees: Vec<asc_query::Callee>,
}

/// Locate the class-defining DEX (same scan as [`run_disasm`], run
/// sequentially — one-shot lookup, no pool) and collect every method
/// its `method` overloads invoke.
pub fn run_callees(job: &CalleesJob) -> Result<CalleesResult, CoreError> {
    let apk = Apk::open(&job.apk)?;
    check_raw_dex(&apk)?;
    for entry in apk.dex_entries() {
        // Sequential one-shot lookup: budget with the engine default,
        // copy only the winning entry.
        let _guard = crate::budget::acquire(effective_budget(0), entry.uncompressed_size as usize)?;
        let eb = apk.read_entry(&entry)?;
        let Some(mut hit) = scan_one_for_class(&entry.name, eb.as_slice(), &job.target)? else {
            continue;
        };
        hit.bytes = eb.into_vec();
        // DEX-041 containers: `header_off` points at the logical
        // member that defines the class (same as `decompile_winner`).
        let view = DexView::parse_at(&hit.bytes, hit.header_off)?;
        let callees = asc_query::callees_of(&view, &hit.class, &job.method)
            .map_err(|e| CoreError::Usage(format!("callees: {e}")))?;
        return Ok(CalleesResult {
            dex_name: hit.name,
            callees,
        });
    }
    Err(CoreError::ClassNotFound(job.target.clone()))
}

// ------------------- class-strings pipeline -------------------

/// One class-scoped string run: which string literals does `target`'s
/// own code load (ASC-RS-GUI-006).
#[derive(Debug, Clone)]
pub struct ClassStringsJob {
    /// Path to the APK or raw `.dex`.
    pub apk: std::path::PathBuf,
    /// Class descriptor (`Lcom/foo/Bar;`).
    pub target: String,
}

impl ClassStringsJob {
    pub fn new(apk: impl Into<std::path::PathBuf>, target: impl Into<String>) -> Self {
        Self {
            apk: apk.into(),
            target: target.into(),
        }
    }
}

/// Output of a successful [`run_class_strings`].
#[derive(Debug, Clone)]
pub struct ClassStringsResult {
    /// Display name of the DEX that defines the class.
    pub dex_name: String,
    /// Distinct string constants, first-encounter order.
    pub strings: Vec<asc_query::ClassString>,
}

/// Locate the class-defining DEX (same sequential scan as
/// [`run_callees`]) and collect every string constant the class's
/// code-bearing methods load.
pub fn run_class_strings(job: &ClassStringsJob) -> Result<ClassStringsResult, CoreError> {
    let apk = Apk::open(&job.apk)?;
    check_raw_dex(&apk)?;
    for entry in apk.dex_entries() {
        let _guard = crate::budget::acquire(effective_budget(0), entry.uncompressed_size as usize)?;
        let eb = apk.read_entry(&entry)?;
        let Some(mut hit) = scan_one_for_class(&entry.name, eb.as_slice(), &job.target)? else {
            continue;
        };
        hit.bytes = eb.into_vec();
        let view = DexView::parse_at(&hit.bytes, hit.header_off)?;
        let strings = asc_query::strings_of_class(&view, &hit.class)
            .map_err(|e| CoreError::Usage(format!("class strings: {e}")))?;
        return Ok(ClassStringsResult {
            dex_name: hit.name,
            strings,
        });
    }
    Err(CoreError::ClassNotFound(job.target.clone()))
}

// --------------------- listclass pipeline ---------------------

/// One listclass run.
///
/// Mirrors the oracle's `droidasc listclass <apk> [--prefix P]`
/// (see `MG1937/ASC @ 5395f17`, `droidasc/cli.py:_handle_listclass`,
/// `droidasc/asc_client/apk_handler.py:list_classes`). Walks every
/// `classes*.dex` entry (with DEX-041 logical-header expansion),
/// enumerates `class_def_item.class_idx → type_ids →
/// string_ids → MUTF-8` descriptors in DEX-definition order, and
/// optionally filters by an ASCII package/class prefix.
#[derive(Debug, Clone)]
pub struct ListClassesJob {
    /// Path to the APK.
    pub apk: std::path::PathBuf,
    /// Optional ASCII prefix filter, already normalized to the oracle's
    /// canonical form (`L...` slash-separated; dotted form is OK at
    /// construction time via [`Self::new`]).
    pub prefix: Option<String>,
}

impl ListClassesJob {
    /// Convenience constructor. The supplied prefix is normalized via
    /// [`normalize_class_prefix`] before storage.
    pub fn new(
        apk: impl Into<std::path::PathBuf>,
        prefix: Option<&str>,
    ) -> Result<Self, DecompileError> {
        let normalized = match prefix {
            None => None,
            Some(p) => Some(normalize_class_prefix(p)?),
        };
        Ok(Self {
            apk: apk.into(),
            prefix: normalized,
        })
    }
}

/// Options for [`run_listclasses`]. `threads` is unused for now (the
/// pipeline walks DEXes sequentially to keep the surface small); kept
/// for symmetry with the other pipelines and for future fan-out.
#[derive(Debug, Clone)]
pub struct ListClassesOptions {
    /// Reserved for future parallel enumeration. Currently ignored, but
    /// must be non-zero (oracle rejects a zero worker count).
    pub threads: usize,
    /// Reserved for future instrumentation.
    pub debug: bool,
}

impl Default for ListClassesOptions {
    fn default() -> Self {
        Self {
            threads: 8,
            debug: false,
        }
    }
}

/// Output of [`run_listclasses`].
#[derive(Debug, Clone)]
pub struct ListClassesResult {
    /// Descriptors in central-directory order, then class_def order
    /// within each DEX entry. Empty when no classes matched (or when
    /// the APK contains no DEX entries).
    pub names: Vec<String>,
    /// Logical DEX name per descriptor, parallel to `names` (e.g.
    /// `classes.dex`, `entry!classes2.dex` for DEX-041 containers). Lets
    /// consumers trace every class to its source DEX; same-length
    /// duplicate descriptors across DEXes stay distinguishable.
    pub dexes: Vec<String>,
    /// Per-DEX entry: `(entry_name, descriptor_count_within_this_entry)`.
    /// Used by `--debug` instrumentation. Sum across the whole list
    /// equals `names.len()`.
    pub per_dex_counts: Vec<(String, usize)>,
}

/// A bare `.dex` input has no APK-level fallback: unlike a `classes*.dex`
/// entry (which the oracle skips silently), an unparseable raw file must
/// fail loudly instead of yielding an empty successful result.
fn check_raw_dex(apk: &Apk) -> Result<(), CoreError> {
    if !apk.is_raw_dex() {
        return Ok(());
    }
    const BAD: CoreError = CoreError::Apk(ApkError::Truncated("raw DEX failed to parse"));
    for entry in apk.dex_entries() {
        let bytes = apk.read_entry(&entry)?;
        let bytes = bytes.as_slice();
        if bytes.starts_with(b"dex\n041\0") {
            let offsets = DexView::logical_header_offsets(bytes).map_err(|_| BAD)?;
            for off in offsets.iter() {
                DexView::parse_at(bytes, *off).map_err(|_| BAD)?;
            }
        } else {
            DexView::parse(bytes).map_err(|_| BAD)?;
        }
    }
    Ok(())
}

/// List every class defined in any DEX of the APK, optionally filtered
/// by `prefix`.
pub fn run_listclasses(
    job: &ListClassesJob,
    opts: &ListClassesOptions,
) -> Result<ListClassesResult, CoreError> {
    // Oracle's `apk_handler.list_classes:418` rejects `max_workers <= 0`
    // with `ValueError("Worker count must be greater than zero")` —
    // surface the same contract at the core layer so GUI/library
    // callers can't bypass it.
    if opts.threads == 0 {
        return Err(CoreError::Usage(
            "Worker count must be greater than zero".into(),
        ));
    }
    let apk = Apk::open(&job.apk)?;
    check_raw_dex(&apk)?;
    let prefix_bytes: Option<&[u8]> = job.prefix.as_deref().map(str::as_bytes);
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut per_dex_counts: Vec<(String, usize)> = Vec::with_capacity(apk.dex_entries().len());
    for entry in apk.dex_entries() {
        // Borrow the inflated/borrowed bytes directly (no `.to_vec()`);
        // `EntryBytes` is a borrowed view of the APK's mmap or the
        // per-entry inflate buffer.
        let bytes = match apk.read_entry(&entry) {
            Ok(b) => b,
            Err(_e) => continue, // ignore per-DEX inflate failures (matches the oracle's silent skip on non-DEX entries).
        };
        let before = pairs.len();
        collect_classes_from_bytes(bytes.as_slice(), prefix_bytes, &entry.name, &mut pairs)?;
        per_dex_counts.push((entry.name.clone(), pairs.len() - before));
    }
    let names = pairs.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    let dexes = pairs.iter().map(|(_, d)| d.clone()).collect::<Vec<_>>();
    Ok(ListClassesResult {
        names,
        dexes,
        per_dex_counts,
    })
}

/// Walk one entry's bytes: detect a DEX-041 container or a single DEX,
/// then collect `(descriptor, logical DEX name)` pairs into `out`
/// (filtered by `prefix`). The logical name is `entry_name` for plain
/// DEX entries and `entry_name!classesN.dex` for DEX-041 containers.
///
/// Per-class-index failures propagate (matches the oracle's
/// `ValueError("bad class_def->type_idx")` exit-1 path); per-DEX
/// parse failures are silently skipped (matches the oracle's `_inflate_dex`
/// try/except).
pub(crate) fn collect_classes_from_bytes(
    bytes: &[u8],
    prefix: Option<&[u8]>,
    entry_name: &str,
    out: &mut Vec<(String, String)>,
) -> Result<(), CoreError> {
    match collect_classes_coverage(bytes, prefix, entry_name, out) {
        ClassCoverage::Partial(e) => Err(e),
        _ => Ok(()),
    }
}

/// Outcome of a class-collection pass over one DEX entry. `Unknown` covers
/// every path that historically returned `Ok(())` with zero classes
/// (non-DEX magic, unparseable header, failed container walk); `Partial`
/// is a mid-walk index error (the descriptors collected so far are an
/// unknown subset). Inspect uses this to qualify its manifest
/// cross-check; `collect_classes_from_bytes` keeps the oracle-compatible
/// Result shape for the other callers.
pub(crate) enum ClassCoverage {
    Complete,
    Partial(CoreError),
    Unknown(String),
}

pub(crate) fn collect_classes_coverage(
    bytes: &[u8],
    prefix: Option<&[u8]>,
    entry_name: &str,
    out: &mut Vec<(String, String)>,
) -> ClassCoverage {
    if bytes.len() < 8 || !bytes.starts_with(b"dex\n") {
        return ClassCoverage::Unknown("entry does not start with the DEX magic".into());
    }
    if bytes.starts_with(b"dex\n041\0") {
        // DEX-041 container: walk logical headers (mirrors
        // `scan_entry_bytes` in the findrefs pipeline above).
        let Ok(offsets) = DexView::logical_header_offsets(bytes) else {
            return ClassCoverage::Unknown("DEX-041 logical header walk failed".into());
        };
        let mut coverage = ClassCoverage::Complete;
        for (i, off) in offsets.iter().enumerate() {
            // The oracle skips an entire logical member on parse failure
            // (`apk_handler.list_classes:478-501`); mirror that here, but
            // remember it so inspect can qualify downstream conclusions.
            match DexView::parse_at(bytes, *off) {
                Ok(view) => {
                    if let Err(e) = collect_from_view(
                        &view,
                        prefix,
                        out,
                        &logical_dex_name(entry_name, offsets.len(), i),
                    ) {
                        return ClassCoverage::Partial(e);
                    }
                }
                Err(_) => {
                    coverage =
                        ClassCoverage::Unknown(format!("logical member {i} failed to parse"));
                }
            }
        }
        coverage
    } else if let Ok(view) = DexView::parse(bytes) {
        match collect_from_view(&view, prefix, out, entry_name) {
            Ok(()) => ClassCoverage::Complete,
            Err(e) => ClassCoverage::Partial(e),
        }
    } else {
        ClassCoverage::Unknown("DEX header did not parse".into())
    }
}

/// Walk every class-def of `view` and append `(descriptor, dex_label)`
/// to `out`. Returns `Err` on the first malformed index (matches the
/// oracle's `ValueError("bad class_def->type_idx")` exit-1 path).
fn collect_from_view(
    view: &DexView<'_>,
    prefix: Option<&[u8]>,
    out: &mut Vec<(String, String)>,
    dex_label: &str,
) -> Result<(), CoreError> {
    // Pre-pull counts so we can produce oracle-identical error messages
    // (`bad class_def->type_idx`, `bad type_id->string_idx`, …) instead
    // of leaking DexError internals.
    let type_count = view.type_count();
    let string_count = view.string_count();
    let n = view.class_def_count();
    for i in 0..n {
        let def = view
            .class_def(i)
            .map_err(|e| CoreError::Usage(format!("bad class_defs range: {e}")))?;
        if def.class.0 >= type_count {
            return Err(CoreError::Usage("bad class_def->type_idx".into()));
        }
        let sidx = view
            .type_(def.class)
            .map_err(|_| CoreError::Usage("bad class_def->type_idx".into()))?;
        if sidx.0 >= string_count {
            return Err(CoreError::Usage("bad type_id->string_idx".into()));
        }
        let sref = view
            .string(sidx)
            .map_err(|_| CoreError::Usage("bad string_data_off".into()))?;
        if let Some(p) = prefix {
            // The oracle compares on raw MUTF-8 bytes when the prefix
            // is ASCII (`apk_handler.py:426`); for non-ASCII prefixes it
            // does Unicode comparison after decoding. We match the
            // ASCII path; non-ASCII prefixes are rejected by the
            // oracle's own validation and never reach here.
            if !sref.mutf8.starts_with(p) {
                continue;
            }
        }
        // Decode the descriptor for the owned output. ASCII descriptors
        // are borrowed without allocation; non-ASCII descriptors
        // allocate via the lossy Cow fallback.
        out.push((sref.decode_lossy().into_owned(), dex_label.to_string()));
    }
    Ok(())
}

/// Normalize a user-typed class prefix into the canonical oracle form
/// (`Lcom/foo`, `Lcom/foo/Bar;`, or `Lcom/foo;`).
///
/// Mirrors `apk_handler.py:list_classes` lines 419-424 — if the input
/// does not start with `L`, prepend `L` and replace `.` with `/`.
/// Already-canonical inputs (`Lcom/foo`) are kept verbatim. Empty
/// input is rejected with `DecompileError::ClassNotFound` (matches the
/// oracle's `ValueError("Class prefix cannot be empty")`).
pub fn normalize_class_prefix(input: &str) -> Result<String, DecompileError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(DecompileError::ClassNotFound(
            "Class prefix cannot be empty".into(),
        ));
    }
    if s.starts_with('L') {
        return Ok(s.to_owned());
    }
    let mut out = String::with_capacity(s.len() + 1);
    out.push('L');
    for ch in s.chars() {
        if ch == '.' {
            out.push('/');
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dex_view_round_trips_after_parse() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpus/apk/workload.apk"
        ));
        let Ok(apk) = Apk::open(path) else { return };
        let entries = apk.dex_entries();
        if entries.is_empty() {
            return;
        }
        let entry = &entries[0];
        let bytes = apk.read_entry(entry).unwrap();
        let view = DexView::parse(bytes.as_slice()).unwrap();
        assert!(view.string_count() > 0);
    }

    #[test]
    fn normalize_class_prefix_accepts_dotted_and_descriptor_forms() {
        assert_eq!(
            normalize_class_prefix("com.foo").unwrap(),
            "Lcom/foo".to_string()
        );
        assert_eq!(
            normalize_class_prefix("Lcom/foo").unwrap(),
            "Lcom/foo".to_string()
        );
        assert_eq!(
            normalize_class_prefix("com.foo.Bar;").unwrap(),
            "Lcom/foo/Bar;".to_string()
        );
        assert_eq!(
            normalize_class_prefix("Lcom/foo/Bar;").unwrap(),
            "Lcom/foo/Bar;".to_string()
        );
        // Slashes pass through unchanged; only dots are converted.
        assert_eq!(
            normalize_class_prefix("com/foo").unwrap(),
            "Lcom/foo".to_string()
        );
        // Whitespace is trimmed.
        assert_eq!(
            normalize_class_prefix("  com.foo  ").unwrap(),
            "Lcom/foo".to_string()
        );
    }

    #[test]
    fn normalize_class_prefix_rejects_empty_input() {
        match normalize_class_prefix("") {
            Err(DecompileError::ClassNotFound(msg)) => assert!(msg.contains("empty")),
            other => panic!("expected ClassNotFound, got {other:?}"),
        }
        match normalize_class_prefix("   ") {
            Err(DecompileError::ClassNotFound(_)) => {}
            other => panic!("expected ClassNotFound for whitespace, got {other:?}"),
        }
    }

    #[test]
    fn run_listclasses_enumerates_workload_classes() {
        // Smoke test against the corpus APK: every name must start
        // with `L` and end with `;`, and the full enumeration must be
        // non-empty and stable across repeated runs. Skips when the
        // corpus APK is unavailable (CI without checked-in fixtures).
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpus/apk/workload.apk"
        ));
        if !path.exists() {
            return;
        }
        let job = ListClassesJob::new(path, None).unwrap();
        let result = run_listclasses(&job, &ListClassesOptions::default()).unwrap();
        assert!(
            !result.names.is_empty(),
            "expected at least one class in workload.apk, got 0"
        );
        for name in &result.names {
            assert!(
                name.starts_with('L') && name.ends_with(';'),
                "malformed descriptor: {name}"
            );
        }
        // Repeat: enumeration must be deterministic.
        let again = run_listclasses(&job, &ListClassesOptions::default()).unwrap();
        assert_eq!(result.names, again.names);
    }

    #[test]
    fn run_listclasses_prefix_filter_keeps_matches_only() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpus/apk/workload.apk"
        ));
        if !path.exists() {
            return;
        }
        let job = ListClassesJob::new(path, Some("Lcom/google")).unwrap();
        let result = run_listclasses(&job, &ListClassesOptions::default()).unwrap();
        assert!(!result.names.is_empty(), "expected matches for Lcom/google");
        for name in &result.names {
            assert!(name.starts_with("Lcom/google"), "filter leak: {name}");
        }
        // Prefix in dotted form should normalize identically.
        let job_dotted = ListClassesJob::new(path, Some("com.google")).unwrap();
        let result_dotted = run_listclasses(&job_dotted, &ListClassesOptions::default()).unwrap();
        assert_eq!(result.names, result_dotted.names);
    }

    #[test]
    fn run_listclasses_rejects_empty_prefix() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpus/apk/workload.apk"
        ));
        if !path.exists() {
            return;
        }
        let job = ListClassesJob::new(path, Some(""));
        assert!(job.is_err());
    }

    #[test]
    fn run_listclasses_rejects_zero_threads() {
        // Mirrors oracle's `apk_handler.list_classes:418` rejection.
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../corpus/apk/workload.apk"
        ));
        if !path.exists() {
            return;
        }
        let job = ListClassesJob::new(path, None).unwrap();
        let opts = ListClassesOptions {
            threads: 0,
            debug: false,
        };
        match run_listclasses(&job, &opts) {
            Err(CoreError::Usage(msg)) => {
                assert!(msg.contains("greater than zero"), "msg: {msg}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    /// Stored-only ZIP (CRC left 0: the production read path does not check it).
    fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (name, data) in entries {
            let off = out.len() as u32;
            let (nl, dl) = (name.len() as u16, data.len() as u32);
            out.extend_from_slice(&[0x50, 0x4b, 3, 4, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&dl.to_le_bytes());
            out.extend_from_slice(&dl.to_le_bytes());
            out.extend_from_slice(&nl.to_le_bytes());
            out.extend_from_slice(&[0, 0]);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            cd.extend_from_slice(&[
                0x50, 0x4b, 1, 2, 20, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]);
            cd.extend_from_slice(&dl.to_le_bytes());
            cd.extend_from_slice(&dl.to_le_bytes());
            cd.extend_from_slice(&nl.to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&off.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(&[0x50, 0x4b, 5, 6, 0, 0, 0, 0]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// The phase-2 rescan of budget-deferred entries applies the same
    /// parse-error policy as the parallel phase, and releases every
    /// guard it takes (audit F08).
    ///
    /// This is a **regression guard, not a reproduction.** The
    /// asymmetry that was real — phase 2 `?`-propagating a read error
    /// and abandoning every entry still queued behind it — needs a
    /// *deferred* entry whose bytes fail to read, and that pairing is
    /// not constructible from outside the call: a corrupt local header
    /// (or a CRC / inflate failure) would do it, but deferral only
    /// happens when the budget is contended, and the contention is
    /// released the moment the pool joins — there is no hook between
    /// the two phases to hand the entry its error. So no fixture can
    /// make the two policies disagree observably, and this test pins
    /// the shared outcome instead of pretending to discriminate.
    /// Deferral here is forced, not hoped for: the test holds one
    /// entry's worth of a two-entry cap, so the pool's workers are
    /// refused and the broken second entry is carried by the rescan.
    #[test]
    fn deferred_rescan_reports_the_broken_entry_and_releases_its_guards() {
        let _lock = fault_lock();
        // classes.dex parses; classes2.dex is unreadable (valid magic,
        // unparseable body) and is the one the rescan has to carry.
        let bad: &[u8] = b"dex\n035\0\0\0\0\0";
        const DEX_LEN: usize = 0xA0;
        let plain = {
            let mut b = vec![0u8; DEX_LEN];
            b[..8].copy_from_slice(b"dex\n035\0");
            b[0x20..0x24].copy_from_slice(&(DEX_LEN as u32).to_le_bytes());
            b[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
            b[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes()); // 1 string
            b[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // 1 type
            b[0x60..0x64].copy_from_slice(&1u32.to_le_bytes()); // 1 class_def
            b[0x70..0x74].copy_from_slice(&(DEX_LEN as u32).to_le_bytes());
            b
        };
        let dir = std::env::temp_dir();
        let path = dir.join(format!("asc_phase_err_{}.apk", std::process::id()));
        std::fs::write(
            &path,
            stored_zip(&[("classes.dex", &plain), ("classes2.dex", bad)]),
        )
        .unwrap();
        let job = GetClassJob::new(&path, "Lcom/x/Missing;");
        let cap = DEX_LEN * 2;

        // One entry's worth is held here, so the pool cannot serve the
        // second entry and must defer it to the rescan.
        let held = crate::budget::acquire(cap, DEX_LEN).expect("budget must start free");
        let err = run_getclass(
            &job,
            &GetClassOptions {
                threads: 4,
                scan_budget_bytes: cap,
                ..Default::default()
            },
        );
        // Every guard the run took is back by the time it returns.
        assert_eq!(
            crate::budget::in_flight(),
            DEX_LEN,
            "getclass must not leak scan budget"
        );
        drop(held);
        let _ = std::fs::remove_file(&path);

        let err = err.expect_err("an unreadable DEX must be an error, not a hit");
        assert!(
            matches!(err, CoreError::Apk(_)),
            "the rescan must surface the broken entry, got {err:?}"
        );
    }

    #[test]
    fn getclass_reports_corrupt_dex_on_single_and_multi_paths() {
        let _lock = fault_lock();
        // Header bytes only: magic OK, but far too short to parse.
        let bad: &[u8] = b"dex\n035\0\0\0\0\0";
        let dir = std::env::temp_dir();
        for (tag, names) in [
            ("one", &["classes.dex"][..]),
            ("two", &["classes.dex", "classes2.dex"][..]),
        ] {
            let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (*n, bad)).collect();
            let path = dir.join(format!("asc_corrupt_dex_{tag}_{}.apk", std::process::id()));
            std::fs::write(&path, stored_zip(&entries)).unwrap();
            let r = run_getclass(
                &GetClassJob::new(&path, "Lcom/x/Y;"),
                &GetClassOptions::default(),
            );
            let _ = std::fs::remove_file(&path);
            assert!(
                matches!(r, Err(CoreError::Apk(_))),
                "{tag}: corrupt DEX must be an engine error, got {r:?}"
            );
        }
    }

    #[test]
    fn collect_from_view_propagates_bad_class_type_index() {
        // Mirrors oracle's `test_bad_class_type_index_is_a_clean_error`:
        // build a DEX with `class_def->class_idx = 0xFFFFFFFF`, expect
        // exit-1 with the exact message `bad class_def->type_idx`.
        let mut buf = vec![0u8; 0xA0];
        // Magic + version.
        buf[..8].copy_from_slice(b"dex\n035\0");
        // file_size at 0x20, header_size at 0x24, endian_tag at 0x28.
        buf[0x20..0x24].copy_from_slice(&0xA0u32.to_le_bytes());
        buf[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
        buf[0x28..0x2C].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        // class_defs_size = 1, class_defs_off = 0x70 (one class_def
        // occupies 32 bytes, ending at 0x90, well inside file_size=0xA0).
        buf[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
        buf[0x64..0x68].copy_from_slice(&0x70u32.to_le_bytes());
        // type_ids_size = 0, string_ids_size = 0 (defaults — already zero).
        // class_def[0] at 0x70: class_idx = 0xFFFFFFFF (out of bounds).
        buf[0x70..0x74].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let view = DexView::parse(&buf).expect("parse should succeed");
        let mut out = Vec::new();
        match collect_from_view(&view, None, &mut out, "classes.dex") {
            Err(CoreError::Usage(msg)) => {
                assert_eq!(msg, "bad class_def->type_idx");
            }
            other => panic!("expected Usage(bad class_def->type_idx), got {other:?}"),
        }
    }

    // ---- panic provenance in find_defining_dex (winner masking) ----
    //
    // The pool reports which entry indexes a panicking worker owned
    // (`WorkerOutcome::unscanned`); phase 2 rescans them sequentially
    // like budget-deferred entries. A winner may only be returned when
    // every entry BELOW it is proven (scanned or rescanned clean). The
    // gates in `test_faults` inject panics at a fixed ENTRY index, so
    // every scenario below is deterministic without sleeps: whoever
    // owns the gated entry dies, the other entries are always scanned.
    // NOTE: no `#[path]` include of `tests/common` here — rustfmt on
    // POSIX resolves such an attr through the synthetic (nonexistent)
    // `src/pipeline/tests/` directory and cannot collapse the `..`,
    // so CI's `rustfmt --check` fails even though rustc accepts it.
    // House style is per-suite builders anyway.

    /// Fault-gate and budget tests in this module serialize on this
    /// lock: the gates are process-wide statics and `in_flight` is
    /// process-wide, while cargo runs tests in parallel threads.
    static FAULT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fault_lock() -> std::sync::MutexGuard<'static, ()> {
        FAULT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// One-string/one-type DEX whose single class_def (when `define` is
    /// set) resolves to `class`. Same byte length for both variants so
    /// budget-cap math in TEST-06 is exact.
    fn unit_dex(class: &str, define: bool) -> Vec<u8> {
        const IDS_LEN: usize = 0x98; // string_ids + type_ids + class_def
        let mut b = vec![0u8; IDS_LEN + 64];
        b[..8].copy_from_slice(b"dex\n035\0");
        b[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes()); // header_size
        b[0x28..0x2C].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // endian
        b[0x38..0x3C].copy_from_slice(&1u32.to_le_bytes()); // string_ids_size
        b[0x3C..0x40].copy_from_slice(&0x70u32.to_le_bytes()); // string_ids_off
        b[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // type_ids_size
        b[0x44..0x48].copy_from_slice(&0x74u32.to_le_bytes()); // type_ids_off
        b[0x70..0x74].copy_from_slice(&(IDS_LEN as u32).to_le_bytes()); // -> string data
        b[0x74..0x78].copy_from_slice(&0u32.to_le_bytes()); // type[0] -> string[0]
        if define {
            b[0x60..0x64].copy_from_slice(&1u32.to_le_bytes()); // class_defs_size
            b[0x64..0x68].copy_from_slice(&0x78u32.to_le_bytes()); // class_defs_off
            let mut cd = [0u8; 32];
            cd[4..8].copy_from_slice(&1u32.to_le_bytes()); // access_flags
            cd[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // super = none
            cd[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // source_file = none
            b[0x78..0x98].copy_from_slice(&cd);
        }
        // string_data_item at IDS_LEN: uleb128 len + MUTF-8 + NUL.
        b[IDS_LEN] = class.len() as u8;
        b[IDS_LEN + 1..IDS_LEN + 1 + class.len()].copy_from_slice(class.as_bytes());
        let size = b.len() as u32;
        b[0x20..0x24].copy_from_slice(&size.to_le_bytes()); // file_size
        b[0x68..0x6C].copy_from_slice(&(size - IDS_LEN as u32).to_le_bytes()); // data_size
        b[0x6C..0x70].copy_from_slice(&(IDS_LEN as u32).to_le_bytes()); // data_off
        b
    }

    fn defining_dex_buf(class: &str) -> Vec<u8> {
        unit_dex(class, true)
    }

    fn scan_fixture(tag: &str, classes: &[Option<&str>]) -> (std::sync::Arc<Apk>, Vec<DexEntry>) {
        let bufs: Vec<(String, Vec<u8>)> = classes
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let name = if i == 0 {
                    "classes.dex".to_string()
                } else {
                    format!("classes{}.dex", i + 1)
                };
                let bytes = match c {
                    Some(cls) => unit_dex(cls, true),
                    None => unit_dex(A, false),
                };
                (name, bytes)
            })
            .collect();
        let refs: Vec<(&str, &[u8])> = bufs
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let path =
            std::env::temp_dir().join(format!("asc_panic_prov_{tag}_{}.apk", std::process::id()));
        std::fs::write(&path, stored_zip(&refs)).unwrap();
        let apk = std::sync::Arc::new(Apk::open(&path).unwrap());
        let list = apk.dex_entries();
        (apk, list)
    }

    const A: &str = "Lp/A;";
    const B: &str = "Lp/B;";

    /// TEST-01: the entry-0 worker dies before proving anything; the
    /// hit in entry 1 is only trustworthy after entry 0 is rescanned
    /// clean. The rescan must actually run (pre-fix code returned the
    /// entry-1 hit with entry 0 unproven).
    #[test]
    fn panic_in_higher_priority_dex_rescans_before_trusting_the_winner() {
        let _lock = fault_lock();
        let _g = test_faults::set(0, usize::MAX);
        let (apk, entries) = scan_fixture("panic01", &[None, Some(A)]);
        for threads in [1usize, 2, 4, 8] {
            let hit = find_defining_dex(&apk, &entries, threads, A, 0)
                .unwrap_or_else(|e| panic!("threads={threads}: {e:?}"));
            assert_eq!(hit.name, "classes2.dex", "threads={threads}");
        }
        // Prove the fault actually fired once per thread sweep.
        assert_eq!(
            test_faults::PANIC_HITS.load(std::sync::atomic::Ordering::Relaxed),
            4
        );
    }

    /// TEST-01b (the pre-fix failure mode): entry 0 cannot be proven
    /// (panics on the pool AND on the rescan), so the entry-1 hit MUST
    /// NOT be returned as a certain winner — pre-fix code did exactly
    /// that, silently masking the interrupted scan of `classes.dex`.
    #[test]
    fn unprovable_higher_priority_dex_is_a_structured_error_not_a_hit() {
        let _lock = fault_lock();
        let _g = test_faults::set(0, 0);
        let (apk, entries) = scan_fixture("panic01b", &[None, Some(A)]);
        for threads in [1usize, 2, 4, 8] {
            let r = find_defining_dex(&apk, &entries, threads, A, 0);
            assert!(
                matches!(r, Err(CoreError::WorkerPanicked(_))),
                "threads={threads}: masked winner must be a structured error, got {r:?}"
            );
        }
        assert!(test_faults::PANIC_HITS.load(std::sync::atomic::Ordering::Relaxed) >= 4);
    }

    /// TEST-02: entry 0 finds the class; a panic in entry 1 (above the
    /// winner) can never change the answer and must not veto the hit.
    #[test]
    fn panic_below_the_winner_does_not_veto_it() {
        let _lock = fault_lock();
        // Deterministic ordering: entry 0's worker BLOCKS (holding its
        // budget guard) until the injected panic on entry 1 has fired,
        // so the panicking worker provably claimed its entry and died
        // while the winner was still unproven. threads=1 cannot use the
        // hold (the single worker would block on itself), and the inline
        // loop stops at the winner anyway.
        let (apk, entries) = scan_fixture("panic02", &[Some(A), Some(B)]);
        for threads in [2usize, 4] {
            // Fresh gates per call: the holder must block until THIS
            // call's panic fired (counters are cumulative otherwise).
            let _g = test_faults::set_with_hold(1, usize::MAX, 0);
            let hit = find_defining_dex(&apk, &entries, threads, A, 0)
                .unwrap_or_else(|e| panic!("threads={threads}: {e:?}"));
            assert_eq!(hit.name, "classes.dex", "threads={threads}");
            assert_eq!(
                test_faults::PANIC_HITS.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "threads={threads}: the panic branch must have executed"
            );
        }
    }

    /// TEST-03: with every entry unscannable in both phases, neither a
    /// hit nor `ClassNotFound` may be reported.
    #[test]
    fn all_workers_panicking_is_not_class_not_found() {
        let _lock = fault_lock();
        let _g = test_faults::set(test_faults::ALL, test_faults::ALL);
        let (apk, entries) = scan_fixture("panic03", &[None, None]);
        for threads in [1usize, 2, 4] {
            let r = find_defining_dex(&apk, &entries, threads, A, 0);
            assert!(
                matches!(r, Err(CoreError::WorkerPanicked(_))),
                "threads={threads}: got {r:?}"
            );
        }
    }

    /// TEST-04: inline path (`--threads 1`). The panic is caught, and
    /// the entries behind it are still rescanned; a rescan panic
    /// surfaces as the same structured error, never an unwind.
    #[test]
    fn inline_panic_becomes_a_result_not_an_unwind() {
        let _lock = fault_lock();
        let _g = test_faults::set(0, usize::MAX);
        let (apk, entries) = scan_fixture("panic04a", &[None, Some(A)]);
        let hit = find_defining_dex(&apk, &entries, 1, A, 0).expect("inline panic is caught");
        assert_eq!(hit.name, "classes2.dex");
        drop(_g);

        // Rescan also panics -> structured error, no unwind out of the API.
        let _g = test_faults::set(0, 0);
        let (apk, entries) = scan_fixture("panic04b", &[None, Some(A)]);
        assert!(matches!(
            find_defining_dex(&apk, &entries, 1, A, 0),
            Err(CoreError::WorkerPanicked(_))
        ));
    }

    /// TEST-05: no panics — priority and determinism are unchanged.
    #[test]
    fn no_panic_keeps_dex_priority_and_not_found() {
        let _lock = fault_lock();
        let (apk, entries) = scan_fixture("panic05", &[Some(A), Some(A)]);
        for threads in [1usize, 2, 4, 8] {
            let hit = find_defining_dex(&apk, &entries, threads, A, 0).unwrap();
            assert_eq!(hit.name, "classes.dex", "threads={threads}");
        }
        assert!(matches!(
            find_defining_dex(&apk, &entries, 4, "Lp/Nope;", 0),
            Err(CoreError::ClassNotFound(_))
        ));
    }

    /// TEST-06: budget deferral + a panicking worker + a hit elsewhere,
    /// with the contention PROVEN, not hoped for.
    ///
    /// Part A holds the budget from the TEST side: with the guard held,
    /// every phase-1 acquire is refused, so ALL entries defer — the
    /// deferral path fires deterministically (no schedule can avoid
    /// it), and the phase-2 rescan then hits the still-held budget and
    /// returns the structured MemoryBudget error (documented policy:
    /// "held by another task -> the answer cannot be proven").
    ///
    /// Part B (guard released) mixes a real panic with the same tight
    /// budget: whatever deferred or panicked funnels into the rescan,
    /// the class in the LAST entry wins, and no guard leaks.
    #[test]
    fn panic_with_budget_contention_is_schedule_independent() {
        use std::sync::atomic::Ordering;
        let _lock = fault_lock();
        let entry_len = defining_dex_buf(A).len();

        // --- Part A: forced, deterministic deferral proof. ---
        let _g = test_faults::set(usize::MAX, usize::MAX);
        let (apk, entries) = scan_fixture("panic06a", &[None, None, Some(B)]);
        let cap = entry_len * 3;
        let held =
            crate::budget::acquire(cap, cap - entry_len + 1).expect("budget must start free");
        let r = find_defining_dex(&apk, &entries, 2, B, cap);
        assert_eq!(
            test_faults::DEFERRED_HITS.load(Ordering::Relaxed),
            3,
            "with the test holding the budget, every entry must defer"
        );
        assert!(matches!(r, Err(CoreError::MemoryBudget(_))), "got {r:?}");
        drop(held);
        drop(_g);

        // --- Part B: panic + contention + hit, schedule-independent. ---
        let _g = test_faults::set(1, usize::MAX);
        let (apk, entries) = scan_fixture("panic06b", &[None, None, Some(B)]);
        let cap = entry_len * 2;
        for _ in 0..10 {
            let hit = find_defining_dex(&apk, &entries, 2, B, cap)
                .unwrap_or_else(|e| panic!("every entry is proven by scan or rescan: {e:?}"));
            assert_eq!(hit.name, "classes3.dex");
            assert_eq!(crate::budget::in_flight(), 0, "guard leaked");
        }
        assert_eq!(test_faults::PANIC_HITS.load(Ordering::Relaxed), 10);
        // The panicked entry provably went through the phase-2 rescan.
        let rescanned = test_faults::RESCAN_ENTRIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            rescanned.contains(&1),
            "orphaned entry 1 must be rescanned, got {rescanned:?}"
        );
    }

    /// T01: panic in phase 1, but the sequential rescan proves EVERY
    /// orphaned entry clean and no DEX defines the class. The answer is
    /// a proven negative: `ClassNotFound`, not a "someone once
    /// panicked" error.
    #[test]
    fn t01_clean_rescan_after_panic_is_class_not_found() {
        let _lock = fault_lock();
        let _g = test_faults::set(0, usize::MAX);
        let (apk, entries) = scan_fixture("t01", &[None, None]);
        for threads in [1usize, 2, 4, 8] {
            let r = find_defining_dex(&apk, &entries, threads, A, 0);
            assert!(
                matches!(r, Err(CoreError::ClassNotFound(_))),
                "threads={threads}: fully rescanned miss must be ClassNotFound, got {r:?}"
            );
        }
        assert_eq!(
            test_faults::PANIC_HITS.load(std::sync::atomic::Ordering::Relaxed),
            4,
            "fault injection must have fired once per thread count"
        );
    }

    /// T04 (case B): more entries than workers and every worker dies on
    /// its FIRST claim — entries 2 and 3 are never handed out; they land
    /// in `WorkerOutcome::unscanned` only via the post-join
    /// `cursor..len` tail. They must still reach the phase-2 rescan;
    /// otherwise a class living only in an unclaimed entry becomes a
    /// false `ClassNotFound` (silent negative).
    #[test]
    fn t04_unclaimed_entries_reach_the_rescan() {
        use std::sync::atomic::Ordering;
        let _lock = fault_lock();
        // Both workers die on their first claim; cursor stops at 2, so
        // entries 2 and 3 were never handed to anyone.
        let _g = test_faults::set(test_faults::ALL, usize::MAX);
        let (apk, entries) = scan_fixture("t04hit", &[None, None, None, Some(B)]);
        let hit = find_defining_dex(&apk, &entries, 2, B, 0)
            .expect("unclaimed entries must be rescanned, not skipped");
        assert_eq!(hit.name, "classes4.dex");
        // Proof both that the panics fired and that the UNCLAIMED tail
        // (indexes 2, 3) actually went through the phase-2 rescan.
        assert_eq!(test_faults::PANIC_HITS.load(Ordering::Relaxed), 2);
        let mut rescanned = test_faults::RESCAN_ENTRIES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        rescanned.sort_unstable();
        assert!(
            rescanned.contains(&2) && rescanned.contains(&3),
            "unclaimed entries 2,3 must be rescanned, got {rescanned:?}"
        );
        drop(_g);

        // No class anywhere and a clean rescan of everything: proven miss
        // on every thread count (threads=1 exercises the inline path).
        for threads in [1usize, 2, 4, 8] {
            let _g = test_faults::set(test_faults::ALL, usize::MAX);
            let (apk, entries) = scan_fixture("t04miss", &[None, None, None, None]);
            let r = find_defining_dex(&apk, &entries, threads, A, 0);
            assert!(
                matches!(r, Err(CoreError::ClassNotFound(_))),
                "threads={threads}: got {r:?}"
            );
        }

        // Rescan cannot prove the unclaimed entries either: structured
        // error, never a guess.
        let _g = test_faults::set(test_faults::ALL, test_faults::ALL);
        let (apk, entries) = scan_fixture("t04panic", &[None, None, None, None]);
        assert!(matches!(
            find_defining_dex(&apk, &entries, 2, A, 0),
            Err(CoreError::WorkerPanicked(_))
        ));
    }
}
