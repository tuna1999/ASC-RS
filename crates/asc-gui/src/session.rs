//! `WorkspaceSession`: the GUI's stateful handle to a single open APK.
//!
//! Holds:
//!
//! - The [`asc_apk::Apk`] (mmap-backed, `Send + Sync`).
//! - A lazy per-DEX class list cache: built once on first request,
//!   then reused (this is the GUI's caching license per
//!   `reference/BEHAVIOR.md` §36 — unlike the stateless CLI, the GUI
//!   is a long-lived interactive process).
//! - A bounded LRU cache of open source tabs (default cap
//!   [`MAX_OPEN_TABS`]; oldest tab evicted on insert when full).
//! - A small history of recent findrefs queries.
//!
//! The session itself does no engine work — callers invoke
//! [`asc_core::run_findrefs`] / [`asc_core::run_getclass`] on a worker
//! thread and post results back via [`crate::worker::Job`].
//!
//! All caches are behind [`std::sync::Mutex`]es so the session can be
//! shared with worker threads without an `Arc<Mutex<…>>` wrapper at
//! the call site.

use asc_apk::Apk;
use asc_dex::DexView;
use asc_query;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

/// Maximum number of source tabs kept open in memory. When a new tab
/// is inserted beyond this cap, the **oldest** tab (lowest insert
/// order) is evicted. The cap is intentionally small: each tab holds
/// a fully decompiled class source (potentially megabytes for huge
/// classes), so an unbounded tab list would pin the mmap's worth of
/// class data and balloon the process.
pub const MAX_OPEN_TABS: usize = 8;

/// Maximum number of findrefs entries retained in the history list.
pub const MAX_FINDREFS_HISTORY: usize = 32;

/// Errors that can arise while opening or querying a session.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Underlying APK file could not be opened or parsed.
    #[error("apk open: {0}")]
    Apk(#[from] asc_apk::ApkError),

    /// A requested class / dex was not present.
    #[error("not found: {0}")]
    NotFound(String),
}

/// Result alias for session-returning operations.
pub type SessionResult<T> = Result<T, SessionError>;

/// A single class descriptor, surfaced by the lazy class list cache.
///
/// `descriptor` is the Dalvik form (`Lcom/foo/Bar;`). `dex_name` is
/// the entry name the APK's central directory reports for the DEX
/// file that defines this class (e.g. `classes.dex`, `classes2.dex`,
/// or `classes.dex[i]` for a logical-DEX inside a DEX-041 container).
#[derive(Debug, Clone)]
pub struct ClassEntry {
    pub descriptor: String,
    pub dex_name: String,
}

/// One open source tab. The cache holds fully decompiled source text;
/// if memory pressure forces eviction, the tab can be re-opened on
/// demand.
#[derive(Debug, Clone)]
pub struct SourceTab {
    /// Stable identity: `<dex_name>::<descriptor>`.
    pub key: String,
    pub dex_name: String,
    pub descriptor: String,
    pub source: String,
    /// Insertion order (monotonically increasing counter); used for
    /// LRU eviction.
    pub opened_at: u64,
}

/// One history entry — a query that was actually run to completion.
/// (In-flight or failed queries are kept in the worker layer, not
/// here.)
#[derive(Debug, Clone)]
pub struct FindRefsHistoryEntry {
    /// Human-readable summary of the query, e.g. `string "onCreate"`.
    pub label: String,
    /// Number of caller lines in the resulting report.
    pub line_count: usize,
    /// True if every per-DEX scan finished without error.
    pub complete: bool,
}

/// The GUI's stateful handle to a single open APK.
pub struct WorkspaceSession {
    path: PathBuf,
    apk: Apk,
    /// One entry per central-directory `classes*.dex` (in numeric
    /// order). Used to enumerate the winning DEX and to give a
    /// stable identity for caches.
    dex_entries: Vec<asc_apk::DexEntry>,
    /// Per-dex class list cache, indexed by dex position in
    /// `dex_entries`. Lazily filled on first request; `None` slot
    /// means "not built yet".
    class_cache: Mutex<Vec<Option<Vec<ClassEntry>>>>,
    /// Open source tabs (LRU-bounded).
    tabs: Mutex<VecDeque<SourceTab>>,
    /// Findrefs history (most-recent at the back).
    findrefs_history: Mutex<VecDeque<FindRefsHistoryEntry>>,
    /// Monotonic counter for tab insertion order.
    next_tab_id: Mutex<u64>,
}

impl WorkspaceSession {
    /// Open an APK by path.
    pub fn open(path: &Path) -> SessionResult<Self> {
        let apk = Apk::open(path)?;
        let dex_entries = apk.dex_entries();
        let cache = (0..dex_entries.len()).map(|_| None).collect();
        Ok(Self {
            path: path.to_path_buf(),
            apk,
            dex_entries,
            class_cache: Mutex::new(cache),
            tabs: Mutex::new(VecDeque::with_capacity(MAX_OPEN_TABS)),
            findrefs_history: Mutex::new(VecDeque::with_capacity(MAX_FINDREFS_HISTORY)),
            next_tab_id: Mutex::new(0),
        })
    }

    /// Path the session was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// All `classes*.dex` entries, in numeric order (matching
    /// `asc_apk::Apk::dex_entries()`).
    pub fn dex_entries(&self) -> &[asc_apk::DexEntry] {
        &self.dex_entries
    }

    /// Name of the DEX that "wins" the class lookup for `descriptor`
    /// (i.e. the first one whose `class_def`s contain it). Returns
    /// `None` if no DEX defines the class.
    ///
    /// Used by the GUI to route a `<descriptor>` click to the
    /// correct entry tab when the same class happens to be defined
    /// in more than one DEX.
    pub fn winning_dex_for(&self, descriptor: &str) -> Option<String> {
        // Walk entries without locking the cache (a cache miss just
        // falls through to a linear scan).
        for entry in &self.dex_entries {
            if let Some(name) = self.try_class_in_dex(entry, descriptor) {
                return Some(name);
            }
        }
        None
    }

    /// Linear class lookup against one DEX. Returns the dex name if
    /// `descriptor` is defined here.
    fn try_class_in_dex(&self, entry: &asc_apk::DexEntry, descriptor: &str) -> Option<String> {
        let bytes = self.apk.read_entry(entry).ok()?;
        let view = DexView::parse(bytes.as_slice()).ok()?;
        if asc_query::class_defines(&view, descriptor) {
            Some(entry.name.clone())
        } else {
            None
        }
    }

    /// Build (or return cached) class list for `dex_idx`. Returns
    /// `Err(NotFound)` if `dex_idx` is out of range.
    pub fn classes_for_dex(&self, dex_idx: usize) -> SessionResult<Vec<ClassEntry>> {
        if dex_idx >= self.dex_entries.len() {
            return Err(SessionError::NotFound(format!(
                "dex index {dex_idx} (have {})",
                self.dex_entries.len()
            )));
        }
        if let Some(cached) = self.class_cache.lock()[dex_idx].clone() {
            return Ok(cached);
        }
        // Cache miss: build the list by walking class_defs.
        let entry = &self.dex_entries[dex_idx];
        let bytes = self.apk.read_entry(entry)?;
        let classes = build_class_list(&entry.name, bytes.as_slice())?;
        self.class_cache.lock()[dex_idx] = Some(classes.clone());
        Ok(classes)
    }

    /// Build a complete class list for every DEX, returning the
    /// concatenated (sorted, deduped-by-name) set. This is what the
    /// left-panel tree view shows.
    pub fn all_classes(&self) -> SessionResult<Vec<ClassEntry>> {
        let mut out = Vec::new();
        for i in 0..self.dex_entries.len() {
            out.extend(self.classes_for_dex(i)?);
        }
        // Sort by descriptor for stable display.
        out.sort_by(|a, b| a.descriptor.cmp(&b.descriptor));
        Ok(out)
    }

    /// Insert (or refresh) a source tab. If the cap is full, the
    /// oldest tab is evicted.
    pub fn open_tab(
        &self,
        dex_name: String,
        descriptor: String,
        source: String,
    ) -> SessionResult<()> {
        let key = format!("{dex_name}::{descriptor}");
        let mut next_id = self.next_tab_id.lock();
        let opened_at = *next_id;
        *next_id += 1;
        let mut tabs = self.tabs.lock();
        // If a tab with this key already exists, refresh and move-to-back.
        if let Some(pos) = tabs.iter().position(|t| t.key == key) {
            let mut t = tabs.remove(pos).unwrap();
            t.source = source;
            t.opened_at = opened_at;
            tabs.push_back(t);
            return Ok(());
        }
        // Evict oldest if over cap.
        while tabs.len() >= MAX_OPEN_TABS {
            tabs.pop_front();
        }
        tabs.push_back(SourceTab {
            key,
            dex_name,
            descriptor,
            source,
            opened_at,
        });
        Ok(())
    }

    /// Snapshot of open tabs (most-recent at the back).
    pub fn open_tabs(&self) -> Vec<SourceTab> {
        self.tabs.lock().iter().cloned().collect()
    }

    /// Remove a tab by descriptor (tab close button). No-op when the
    /// descriptor has no open tab.
    pub fn close_tab(&self, descriptor: &str) {
        let mut tabs = self.tabs.lock();
        if let Some(pos) = tabs.iter().position(|t| t.descriptor == descriptor) {
            tabs.remove(pos);
        }
    }

    /// Record a completed findrefs run.
    pub fn push_findrefs_history(&self, entry: FindRefsHistoryEntry) {
        let mut h = self.findrefs_history.lock();
        while h.len() >= MAX_FINDREFS_HISTORY {
            h.pop_front();
        }
        h.push_back(entry);
    }

    /// Snapshot of findrefs history.
    pub fn findrefs_history(&self) -> Vec<FindRefsHistoryEntry> {
        self.findrefs_history.lock().iter().cloned().collect()
    }
}

/// Walk `bytes` (one DEX) and emit a list of `[descriptor, dex_name]`
/// pairs by iterating `class_defs`. Returns an empty list if the
/// DEX header is malformed (defensive — `read_entry` should already
/// have rejected those).
fn build_class_list(dex_name: &str, bytes: &[u8]) -> SessionResult<Vec<ClassEntry>> {
    let view = match DexView::parse(bytes) {
        Ok(v) => v,
        Err(_) => {
            return Err(SessionError::NotFound(format!(
                "failed to parse {dex_name} as DEX"
            )));
        }
    };
    let count = view.class_def_count();
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let def = match view.class_def(i) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let sidx = match view.type_(def.class) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let sref = match view.string(sidx) {
            Ok(s) => s,
            Err(_) => continue,
        };
        out.push(ClassEntry {
            descriptor: sref.decode_lossy().into_owned(),
            dex_name: dex_name.to_string(),
        });
    }
    Ok(out)
}
