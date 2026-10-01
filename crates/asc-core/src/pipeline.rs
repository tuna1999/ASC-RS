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
//! next-to-finish in-flight entry's processing time.
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
}

impl Default for GetClassOptions {
    fn default() -> Self {
        Self {
            threads: 8,
            debug: false,
            paranoid: false,
            decode_xor: false,
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
}

impl Default for DisasmOptions {
    fn default() -> Self {
        Self {
            threads: 8,
            debug: false,
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
    for entry in entries {
        // `into_owned` is implicit: we always copy to a `Vec<u8>` so
        // the borrow lifetime is decoupled from the APK's mmap. The
        // apksigner-produced corpus is small (≤ 64 MiB per DEX), so
        // the per-entry allocation is bounded.
        let bytes = match apk.read_entry(&entry) {
            Ok(b) => b.as_slice().to_vec(),
            Err(e) => {
                let msg = format!("{}: read_entry failed: {e}", entry.name);
                report.errors.push(SearchError::from_apk(&entry.name, &msg));
                report.complete = false;
                continue;
            }
        };
        scan_entry_bytes(&entry.name, &bytes, &job.query, paranoid, xor, &mut report);
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
        // Not a DEX; skip silently (the oracle's `_inflate_and_hit`
        // also rejects non-`dex\n0..\0` magic). We do not record this
        // as an error — non-DEX entries with a `.dex` suffix are
        // extremely rare in real APKs.
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

    let hit = find_defining_dex(&apk, &entries, opts.threads.max(1), &target)?;
    decompile_winner(hit, &target, opts, &apk)
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
) -> Result<ClassHit, CoreError> {
    // Single-dex fast path: skip the worker pool entirely.
    if entries.len() == 1 {
        let entry = &entries[0];
        let bytes = apk.read_entry(entry)?.as_slice().to_vec();
        return scan_one_for_class(&entry.name, &bytes, target)?
            .ok_or_else(|| CoreError::ClassNotFound(target.to_string()));
    }

    let pool = WorkerPool::new(threads.max(1));
    let found = Arc::new(AtomicBool::new(false));
    // Best hit so far, by entry index. First writer does not win: a
    // lower-index hit must replace a higher one recorded earlier.
    let best: Arc<std::sync::Mutex<Option<(usize, ClassHit)>>> =
        Arc::new(std::sync::Mutex::new(None));
    // First read/parse failure; only matters when nothing was found.
    let first_err: Arc<OnceLock<CoreError>> = Arc::new(OnceLock::new());
    let target_arc = Arc::new(target.to_owned());
    let apk_clone = Arc::clone(apk);
    let best_clone = Arc::clone(&best);
    let err_clone = Arc::clone(&first_err);

    let scan_for_class = move |i: usize, entry: &DexEntry| -> Option<()> {
        // Deliberately NO `found` check here: an entry that was already
        // pulled must run to completion, or a lower-index winner could
        // be skipped because a higher-index worker finished first.
        // The pool itself stops pulling new entries once `found` is set.
        let bytes = match apk_clone.read_entry(entry) {
            Ok(b) => b.as_slice().to_vec(),
            Err(e) => {
                let _ = err_clone.set(e.into());
                return None;
            }
        };
        match scan_one_for_class(&entry.name, &bytes, &target_arc) {
            Ok(Some(hit)) => {
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

    let _outcome = pool.run(entries, scan_for_class);
    let winner = best
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .map(|(_, hit)| hit);
    match winner {
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

/// A class-defining DEX found by `getclass`: the display name, the entry
/// bytes (whole container for DEX-041), and the logical header offset.
#[derive(Clone)]
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
                bytes: bytes.to_vec(),
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

    let hit = find_defining_dex(&apk, &entries, opts.threads.max(1), &target)?;
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
        let bytes = apk.read_entry(&entry)?.as_slice().to_vec();
        let Some(hit) = scan_one_for_class(&entry.name, &bytes, &job.target)? else {
            continue;
        };
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
    let mut names: Vec<String> = Vec::new();
    let mut per_dex_counts: Vec<(String, usize)> = Vec::with_capacity(apk.dex_entries().len());
    for entry in apk.dex_entries() {
        // Borrow the inflated/borrowed bytes directly (no `.to_vec()`);
        // `EntryBytes` is a borrowed view of the APK's mmap or the
        // per-entry inflate buffer.
        let bytes = match apk.read_entry(&entry) {
            Ok(b) => b,
            Err(_e) => continue, // ignore per-DEX inflate failures (matches the oracle's silent skip on non-DEX entries).
        };
        let before = names.len();
        collect_classes_from_bytes(bytes.as_slice(), prefix_bytes, &mut names)?;
        per_dex_counts.push((entry.name.clone(), names.len() - before));
    }
    Ok(ListClassesResult {
        names,
        per_dex_counts,
    })
}

/// Walk one entry's bytes: detect a DEX-041 container or a single DEX,
/// then collect descriptors into `out` (filtered by `prefix`).
///
/// Per-class-index failures propagate (matches the oracle's
/// `ValueError("bad class_def->type_idx")` exit-1 path); per-DEX
/// parse failures are silently skipped (matches the oracle's `_inflate_dex`
/// try/except).
pub(crate) fn collect_classes_from_bytes(
    bytes: &[u8],
    prefix: Option<&[u8]>,
    out: &mut Vec<String>,
) -> Result<(), CoreError> {
    if bytes.len() < 8 || !bytes.starts_with(b"dex\n") {
        return Ok(());
    }
    if bytes.starts_with(b"dex\n041\0") {
        // DEX-041 container: walk logical headers (mirrors
        // `scan_entry_bytes` in the findrefs pipeline above).
        let Ok(offsets) = DexView::logical_header_offsets(bytes) else {
            return Ok(());
        };
        for off in offsets.iter() {
            // The oracle skips an entire logical member on parse failure
            // (`apk_handler.list_classes:478-501`); mirror that here.
            if let Ok(view) = DexView::parse_at(bytes, *off) {
                collect_from_view(&view, prefix, out)?;
            }
        }
        Ok(())
    } else if let Ok(view) = DexView::parse(bytes) {
        collect_from_view(&view, prefix, out)
    } else {
        Ok(())
    }
}

/// Walk every class-def of `view` and append its descriptor to `out`.
/// Returns `Err` on the first malformed index (matches the oracle's
/// `ValueError("bad class_def->type_idx")` exit-1 path).
fn collect_from_view(
    view: &DexView<'_>,
    prefix: Option<&[u8]>,
    out: &mut Vec<String>,
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
        out.push(sref.decode_lossy().into_owned());
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

    #[test]
    fn getclass_reports_corrupt_dex_on_single_and_multi_paths() {
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
        match collect_from_view(&view, None, &mut out) {
            Err(CoreError::Usage(msg)) => {
                assert_eq!(msg, "bad class_def->type_idx");
            }
            other => panic!("expected Usage(bad class_def->type_idx), got {other:?}"),
        }
    }
}
