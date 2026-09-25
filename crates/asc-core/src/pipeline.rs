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
//!    [`asc_dex::DexView::parse_at`]. Each logical DEX is named
//!    `name[i]` per `BEHAVIOR.md` §2 / `dex_container.py:142-149`.
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
//! 2. Bounded parallel scan: spawn N worker threads sharing one
//!    `AtomicUsize` work cursor and one `AtomicBool` "found" flag.
//! 3. Each worker dequeues the next dex entry, inflates it, runs a
//!    type-idx / class-def lookup via [`asc_query::class_defines`].
//!    On a hit, the worker stores the entry name + bytes in an
//!    `OnceLock` and sets the flag; other workers stop pulling new
//!    entries.
//! 4. Winner's bytes → [`asc_rebuild::rebuild`] →
//!    [`asc_decompile::ClassDecompiler::decompile`] → source string.
//! 5. Return a [`GetClassResult`] with `dex_name` and `source`.
//!
//! ## Cancellation
//!
//! The `getclass` worker pool checks `found` between entries (not
//! inside an entry's processing). When the winner is recorded, other
//! workers stop pulling new work; their in-flight processing (a single
//! `apk.read_entry + dex parse + class_defines check`) completes
//! naturally. Total cost is bounded by the next-to-finish in-flight
//! entry's processing time.

use std::collections::BTreeMap;
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
}

impl Default for GetClassOptions {
    fn default() -> Self {
        Self {
            threads: 8,
            debug: false,
        }
    }
}

/// Output of a successful `run_getclass`.
#[derive(Debug, Clone)]
pub struct GetClassResult {
    /// Display name of the winning DEX (`classes.dex`,
    /// `classes2.dex`, `classes.dex[0]`, …).
    pub dex_name: String,
    /// `class_def` off the winner used during the rebuild.
    pub class_def_off: u32,
    /// The decompiled Java-like source.
    pub source: String,
}

// --------------------- findrefs pipeline ---------------------

/// Open the APK once, iterate `classes*.dex` in central-directory
/// offset order, expand each entry (handling DEX-041 containers),
/// run `find_refs` per view, and aggregate into a [`SearchReport`].
pub fn run_findrefs(job: &FindRefsJob, _opts: &FindRefsOptions) -> Result<SearchReport, CoreError> {
    let apk = Apk::open(&job.apk)?;
    let entries = apk.dex_entries();
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
        scan_entry_bytes(&entry.name, &bytes, &job.query, &mut report);
    }
    Ok(report)
}

/// Scan one entry's bytes: detect a DEX-041 container or a single
/// DEX, run `find_refs` per logical view, aggregate into `report`.
fn scan_entry_bytes(entry_name: &str, bytes: &[u8], query: &Query, report: &mut SearchReport) {
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
            let name = if offsets.len() == 1 {
                entry_name.to_string()
            } else {
                format!("{entry_name}[{i}]")
            };
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
            run_engine_for_view(&name, &view, query, report);
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
        run_engine_for_view(entry_name, &view, query, report);
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
    report: &mut SearchReport,
) {
    let engine_report = engine_find_refs(view, query);
    if !engine_report.errors.is_empty() {
        report.complete = false;
    }
    let rendered = render_hits(view, &engine_report.hits);
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

/// Render raw [`RefHit`]s into owned [`RenderedMatch`]es.
///
/// Group by caller method id, de-duplicate and sort matched refs,
/// render each caller / matched pair into strings while the borrowed
/// `view` is alive. Also resolves the smallest matched code-unit
/// offset to a 1-indexed source line via `debug_info` (None when the
/// method has no debug stream).
fn render_hits(view: &DexView<'_>, hits: &[RefHit]) -> Vec<RenderedMatch> {
    if hits.is_empty() {
        return Vec::new();
    }
    // caller -> (sorted, dedup'd matched refs) + minimum code_off.
    let mut by_caller: BTreeMap<u32, (Vec<DexRef>, Option<u32>)> = BTreeMap::new();
    for h in hits {
        let entry = by_caller.entry(h.method.0).or_default();
        entry.0.push(h.dex_ref);
        entry.1 = Some(match entry.1 {
            Some(prev) => prev.min(h.offset),
            None => h.offset,
        });
    }
    let mut out: Vec<RenderedMatch> = Vec::with_capacity(by_caller.len());
    for (mid, (matched, min_code_off)) in &by_caller {
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
        let matched_strs: Vec<String> = sorted
            .iter()
            .filter_map(|r| render_dex_ref(view, r))
            .collect();
        // Resolve the smallest matched offset to a 1-indexed source
        // line. None when the body has no debug_info_item; we do not
        // fail the match on malformed debug streams — we just skip
        // the line number (the GUI then opens at line 0 / start).
        let first_line = min_code_off
            .and_then(|off| resolve_first_line(view, *mid, off));
        out.push(RenderedMatch {
            caller: caller_str,
            matched: matched_strs,
            first_line,
        });
    }
    out
}

/// Resolve the 1-indexed source line of the smallest matched code
/// offset in a caller method. Returns `None` when the body has no
/// `debug_info_item` (or the offset lands on a malformed stream).
fn resolve_first_line(view: &DexView<'_>, mid: u32, code_off: u32) -> Option<u32> {
    // Walk every class_data_item once, picking the `code_off` for the
    // matching `method_idx`. For the typical 64 MiB corpus this is
    // < 1ms; if it ever becomes hot we'll cache it on the worker.
    let n = view.class_def_count();
    let mut found_code_off: Option<u32> = None;
    for ci in 0..n {
        let Ok(def) = view.class_def(ci) else { continue };
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
                found_code_off = Some(m.code_off);
                break;
            }
        }
        if found_code_off.is_some() {
            break;
        }
    }
    let code_off_abs = found_code_off?;
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
    let entries = apk.dex_entries();
    let n = entries.len();

    if n == 0 {
        return Err(CoreError::ClassNotFound(target));
    }

    // Single-dex fast path: skip the worker pool entirely.
    if n == 1 {
        let entry = &entries[0];
        let bytes = apk.read_entry(entry)?.as_slice().to_vec();
        if let Some((name, data)) = scan_one_for_class(&entry.name, &bytes, &target)? {
            return decompile_winner(name, data, &target);
        }
        return Err(CoreError::ClassNotFound(target));
    }

    // Bounded worker pool: each worker pulls the next entry index,
    // reads + parses it, and runs class_defines. On a hit, the worker
    // publishes to the OnceLock winner cell and sets `found`.
    let pool = WorkerPool::new(opts.threads.max(1));
    let found = Arc::new(AtomicBool::new(false));
    let cell: Arc<OnceLock<(String, Vec<u8>)>> = Arc::new(OnceLock::new());
    let target_arc = Arc::new(target.clone());
    let apk_clone = Arc::clone(&apk);
    let cell_clone = Arc::clone(&cell);

    let scan_for_class = move |_: usize, entry: &DexEntry| -> Option<()> {
        if found.load(Ordering::Acquire) {
            return None;
        }
        // Read the entry (clones the inflated bytes for independent
        // ownership — bounded by the per-entry cap).
        let bytes = apk_clone.read_entry(entry).ok()?.as_slice().to_vec();
        match scan_one_for_class(&entry.name, &bytes, &target_arc) {
            Ok(Some((name, data))) => {
                let _ = cell_clone.set((name, data));
                found.store(true, Ordering::Release);
                Some(())
            }
            _ => None,
        }
    };

    let _outcome = pool.run(&entries, scan_for_class);
    let winner = cell
        .get()
        .map(|(name, data)| (name.clone(), data.clone()))
        .ok_or_else(|| CoreError::ClassNotFound(target.clone()))?;
    decompile_winner(winner.0, winner.1, &target)
}

/// Inflate `bytes` (which already came from `apk.read_entry`) and run
/// the class-idx / class-def lookup for `target`. Returns
/// `Some((display_name, inflated_bytes))` on hit, `None` on miss,
/// `Err` on parse failure.
fn scan_one_for_class(
    entry_name: &str,
    bytes: &[u8],
    target: &str,
) -> Result<Option<(String, Vec<u8>)>, CoreError> {
    // Reject obviously-bad entry bytes (matches oracle's
    // `_inflate_and_hit` early-return on magic != `dex\n0..\x00`).
    if bytes.len() < 8 || !bytes.starts_with(b"dex\n") {
        return Ok(None);
    }
    let view = DexView::parse(bytes)?;
    if class_defines(&view, target) {
        Ok(Some((entry_name.to_string(), bytes.to_vec())))
    } else {
        Ok(None)
    }
}

/// Rebuild the winning DEX into a minimal standalone and decompile
/// `target`.
fn decompile_winner(
    winner_name: String,
    winner_bytes: Vec<u8>,
    target: &str,
) -> Result<GetClassResult, CoreError> {
    // Parse the winning DEX once for the rebuild step.
    let view = DexView::parse(&winner_bytes)?;
    let rebuilt = asc_rebuild::rebuild(&view, target).map_err(CoreError::Rebuild)?;
    let backend = asc_decompile::droidsaw::DroidsawBackend::new();
    let source = backend
        .decompile(&rebuilt.bytes, target)
        .map_err(CoreError::Decompile)?;
    Ok(GetClassResult {
        dex_name: winner_name,
        class_def_off: rebuilt.class_def_off,
        source,
    })
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
#[derive(Debug, Clone, Default)]
pub struct ListClassesOptions {
    /// Reserved for future parallel enumeration. Currently ignored.
    pub threads: usize,
    /// Reserved for future instrumentation.
    pub debug: bool,
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
fn collect_classes_from_bytes(
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
        let path = Path::new("corpus/apk/workload.apk");
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
        let path = Path::new("corpus/apk/workload.apk");
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
        let path = Path::new("corpus/apk/workload.apk");
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
        let path = Path::new("corpus/apk/workload.apk");
        if !path.exists() {
            return;
        }
        let job = ListClassesJob::new(path, Some(""));
        assert!(job.is_err());
    }

    #[test]
    fn run_listclasses_rejects_zero_threads() {
        // Mirrors oracle's `apk_handler.list_classes:418` rejection.
        let path = Path::new("corpus/apk/workload.apk");
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
