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
/// `view` is alive.
fn render_hits(view: &DexView<'_>, hits: &[RefHit]) -> Vec<RenderedMatch> {
    if hits.is_empty() {
        return Vec::new();
    }
    // caller -> sorted, dedup'd matched refs.
    let mut by_caller: BTreeMap<u32, Vec<DexRef>> = BTreeMap::new();
    for h in hits {
        by_caller.entry(h.method.0).or_default().push(h.dex_ref);
    }
    let mut out: Vec<RenderedMatch> = Vec::with_capacity(by_caller.len());
    for (mid, matched) in &by_caller {
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
        out.push(RenderedMatch {
            caller: caller_str,
            matched: matched_strs,
        });
    }
    out
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
}
