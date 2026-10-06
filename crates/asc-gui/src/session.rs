//! `WorkspaceSession`: the GUI's stateful handle to a single open APK.
//!
//! Holds:
//!
//! - The [`asc_apk::Apk`] (mmap-backed, `Send + Sync`).
//! - A lazy per-DEX class list cache: built once on first request,
//!   then reused (this is the GUI's caching license per
//!   `reference/BEHAVIOR.md` §36 — unlike the stateless CLI, the GUI
//!   is a long-lived interactive process).
//! - A small history of recent findrefs queries.
//!
//! Source documents (decompiled classes) are no longer stored here —
//! see [`crate::state::documents`] for the byte-budgeted cache that
//! replaced the old LRU tab store.
//!
//! The session itself does no engine work — callers invoke
//! [`asc_core::run_findrefs`] / [`asc_core::run_getclass`] on a worker
//! thread via [`crate::task::TaskManager`] and apply results on the
//! UI thread.
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
    /// What the class-def's access flags say it is (drives the
    /// jadx-style source-file icon).
    pub kind: ClassKind,
}

/// Class taxonomy derived from `class_def.access_flags` — zero extra
/// parsing, the flags are already loaded during enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClassKind {
    #[default]
    Class,
    Interface,
    Enum,
    Annotation,
}

impl ClassKind {
    /// Map Dalvik access flags to the coarse taxonomy (order matters:
    /// annotation ⊂ interface, so test it first).
    pub fn from_flags(flags: u32) -> Self {
        const ACC_INTERFACE: u32 = 0x0200;
        const ACC_ANNOTATION: u32 = 0x2000;
        const ACC_ENUM: u32 = 0x4000;
        if flags & ACC_ANNOTATION != 0 {
            Self::Annotation
        } else if flags & ACC_ENUM != 0 {
            Self::Enum
        } else if flags & ACC_INTERFACE != 0 {
            Self::Interface
        } else {
            Self::Class
        }
    }
}

/// Result of enumerating classes: the readable entries plus human-readable
/// warnings for every DEX (or class_def) that had to be skipped. A non-empty
/// `warnings` means the list is PARTIAL, never "complete".
#[derive(Debug, Clone, Default)]
pub struct ClassList {
    pub classes: Vec<ClassEntry>,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ClassKind::from_flags` maps the four access-flag patterns
    /// to the four variants. Alias for ASC-GUI-031.
    #[test]
    fn class_kind_from_flags_classify() {
        const ACC_CLASS: u32 = 0x0001;
        const ACC_INTERFACE: u32 = 0x0200;
        const ACC_ANNOTATION: u32 = 0x2000;
        const ACC_ENUM: u32 = 0x4000;
        assert_eq!(ClassKind::from_flags(ACC_CLASS), ClassKind::Class);
        assert_eq!(ClassKind::from_flags(ACC_INTERFACE), ClassKind::Interface);
        assert_eq!(ClassKind::from_flags(ACC_ENUM), ClassKind::Enum);
        // Annotation trumps Interface (annotation ⊂ interface).
        assert_eq!(
            ClassKind::from_flags(ACC_INTERFACE | ACC_ANNOTATION),
            ClassKind::Annotation
        );
    }
    /// Minimal hand-built DEX: header + strings + type_ids + class_defs
    /// (one per descriptor). `bad_type_idx` corrupts index 0 to exercise
    /// the PARTIAL path.
    fn tiny_dex(descriptors: &[&str], bad_type_idx: bool) -> Vec<u8> {
        const NO_INDEX: u32 = 0xFFFF_FFFF;
        let mut strings: Vec<Vec<u8>> = Vec::new(); // uleb len + mutf8 + NUL
        for d in descriptors {
            let mut s = vec![d.len() as u8];
            s.extend_from_slice(d.as_bytes());
            s.push(0);
            strings.push(s);
        }
        let header_size = 112usize;
        let string_ids_size = strings.len();
        let string_ids_off = header_size;
        let type_ids_off = string_ids_off + string_ids_size * 4;
        let type_ids_size = string_ids_size;
        let class_defs_off = type_ids_off + type_ids_size * 4;
        let class_defs_size = string_ids_size;
        let string_data_off = class_defs_off + class_defs_size * 32;
        let mut string_data = Vec::new();
        let mut offsets = Vec::new();
        for s in &strings {
            offsets.push((string_data_off + string_data.len()) as u32);
            string_data.extend_from_slice(s);
        }
        let file_size = string_data_off + string_data.len();
        let mut b = Vec::new();
        b.extend_from_slice(b"dex\n035\0");
        b.extend_from_slice(&[0u8; 24]); // checksum + signature (unchecked)
        b.extend_from_slice(&(file_size as u32).to_le_bytes());
        b.extend_from_slice(&112u32.to_le_bytes());
        b.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // link_size
        b.extend_from_slice(&0u32.to_le_bytes()); // link_off
        b.extend_from_slice(&0u32.to_le_bytes()); // map_off
        for (off, size) in [
            (string_ids_off, string_ids_size),
            (type_ids_off, type_ids_size),
            (0, 0), // proto
            (0, 0), // field
            (0, 0), // method
            (class_defs_off, class_defs_size),
        ] {
            b.extend_from_slice(&(size as u32).to_le_bytes());
            b.extend_from_slice(&(off as u32).to_le_bytes());
        }
        b.extend_from_slice(&0u32.to_le_bytes()); // data_size
        b.extend_from_slice(&0u32.to_le_bytes()); // data_off
        debug_assert_eq!(b.len(), header_size);
        for o in offsets {
            b.extend_from_slice(&o.to_le_bytes());
        }
        for i in 0..type_ids_size {
            let idx = if bad_type_idx && i == 0 {
                NO_INDEX
            } else {
                i as u32
            };
            b.extend_from_slice(&idx.to_le_bytes());
        }
        for i in 0..class_defs_size {
            let ty = if bad_type_idx && i == 0 {
                NO_INDEX
            } else {
                i as u32
            };
            b.extend_from_slice(&ty.to_le_bytes()); // class_idx
            b.extend_from_slice(&0x0001u32.to_le_bytes()); // access_flags
            b.extend_from_slice(&NO_INDEX.to_le_bytes()); // superclass
            b.extend_from_slice(&0u32.to_le_bytes()); // interfaces_off
            b.extend_from_slice(&NO_INDEX.to_le_bytes()); // source_file_idx
            b.extend_from_slice(&0u32.to_le_bytes()); // annotations_off
            b.extend_from_slice(&0u32.to_le_bytes()); // class_data_off
            b.extend_from_slice(&0u32.to_le_bytes()); // static_values_off
        }
        b.extend_from_slice(&string_data);
        b
    }

    #[test]
    fn valid_dex_enumerates_without_warnings() {
        let bytes = tiny_dex(&["LFoo;", "LBar;"], false);
        let list = build_class_list("classes.dex", &bytes);
        assert_eq!(list.classes.len(), 2);
        assert!(list.warnings.is_empty(), "{:?}", list.warnings);
    }

    #[test]
    fn unresolvable_class_def_is_partial_with_warning() {
        let bytes = tiny_dex(&["LFoo;", "LBar;"], true);
        let list = build_class_list("classes.dex", &bytes);
        assert_eq!(list.classes.len(), 1, "readable class must survive");
        assert_eq!(list.classes[0].descriptor, "LBar;");
        assert_eq!(list.warnings.len(), 1, "{:?}", list.warnings);
        assert!(list.warnings[0].contains("1/2 class_defs skipped"));
    }

    #[test]
    fn garbage_dex_is_warning_not_error() {
        let list = build_class_list("classes.dex", b"not a dex");
        assert!(list.classes.is_empty());
        assert_eq!(list.warnings.len(), 1);
        assert!(list.warnings[0].contains("parse failed"));
    }
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
    class_cache: Mutex<Vec<Option<ClassList>>>,
    /// Findrefs history (most-recent at the back).
    findrefs_history: Mutex<VecDeque<FindRefsHistoryEntry>>,
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
            findrefs_history: Mutex::new(VecDeque::with_capacity(MAX_FINDREFS_HISTORY)),
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

    /// Linear class lookup against one DEX entry (every logical DEX of a
    /// DEX-041 container). Returns the logical dex name if `descriptor` is
    /// defined here.
    fn try_class_in_dex(&self, entry: &asc_apk::DexEntry, descriptor: &str) -> Option<String> {
        let bytes = self.apk.read_entry(entry).ok()?;
        let mut warnings = Vec::new();
        logical_views(&entry.name, bytes.as_slice(), &mut warnings)
            .into_iter()
            .find(|(_, view)| asc_query::class_defines(view, descriptor))
            .map(|(name, _)| name)
    }

    /// Build (or return cached) class list for `dex_idx`. Returns
    /// `Err(NotFound)` if `dex_idx` is out of range. Parse failures are
    /// PARTIAL: readable classes are returned with a warning per skipped
    /// DEX / class_def.
    pub fn classes_for_dex(&self, dex_idx: usize) -> SessionResult<ClassList> {
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
        let mut list = match self.apk.read_entry(entry) {
            Ok(bytes) => build_class_list(&entry.name, bytes.as_slice()),
            Err(e) => ClassList {
                classes: Vec::new(),
                warnings: vec![format!("{}: unreadable ({e})", entry.name)],
            },
        };
        list.classes.shrink_to_fit();
        self.class_cache.lock()[dex_idx] = Some(list.clone());
        Ok(list)
    }

    /// Build a complete class list for every DEX, returning the
    /// concatenated (sorted, deduped-by-name) set. This is what the
    /// left-panel tree view shows. A DEX that fails to parse degrades to
    /// a warning + the classes of every other DEX (never a total failure).
    pub fn all_classes(&self) -> SessionResult<ClassList> {
        let mut out = ClassList::default();
        for i in 0..self.dex_entries.len() {
            let list = self.classes_for_dex(i)?;
            out.classes.extend(list.classes);
            out.warnings.extend(list.warnings);
        }
        // Sort by descriptor for stable display.
        out.classes.sort_by(|a, b| a.descriptor.cmp(&b.descriptor));
        Ok(out)
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

/// Parse every logical DEX of one entry: a single view for DEX ≤040, one
/// per logical header for a DEX-041 container (named like the CLI does).
/// A logical DEX that fails to parse is skipped with a warning pushed to
/// `warnings` (partial result, not an error).
fn logical_views<'a>(
    entry_name: &str,
    bytes: &'a [u8],
    warnings: &mut Vec<String>,
) -> Vec<(String, DexView<'a>)> {
    if bytes.starts_with(b"dex\n041\0") {
        let offsets = match DexView::logical_header_offsets(bytes) {
            Ok(o) => o,
            Err(e) => {
                warnings.push(format!("{entry_name}: no logical DEX headers ({e})"));
                return Vec::new();
            }
        };
        let count = offsets.len();
        offsets
            .into_iter()
            .enumerate()
            .filter_map(|(i, off)| {
                let name = asc_core::logical_dex_name(entry_name, count, i);
                match DexView::parse_at(bytes, off) {
                    Ok(v) => Some((name, v)),
                    Err(e) => {
                        warnings.push(format!("{name}: parse failed ({e})"));
                        None
                    }
                }
            })
            .collect()
    } else {
        match DexView::parse(bytes) {
            Ok(view) => vec![(entry_name.to_string(), view)],
            Err(e) => {
                warnings.push(format!("{entry_name}: parse failed ({e})"));
                Vec::new()
            }
        }
    }
}

/// Walk `bytes` (one DEX entry) and emit `[descriptor, dex_name]` pairs by
/// iterating `class_defs` of every logical DEX. class_defs whose type or
/// string index does not resolve are counted and reported as ONE warning
/// per logical DEX (partial result, not an error).
fn build_class_list(dex_name: &str, bytes: &[u8]) -> ClassList {
    let mut out = ClassList::default();
    for (name, view) in logical_views(dex_name, bytes, &mut out.warnings) {
        let count = view.class_def_count();
        out.classes.reserve(count as usize);
        let mut skipped = 0u32;
        for i in 0..count {
            let resolved = view.class_def(i).ok().and_then(|def| {
                view.type_(def.class)
                    .ok()
                    .and_then(|sidx| view.string(sidx).ok().map(|sref| (def, sref)))
            });
            match resolved {
                Some((def, sref)) => out.classes.push(ClassEntry {
                    descriptor: sref.decode_lossy().into_owned(),
                    dex_name: name.clone(),
                    kind: ClassKind::from_flags(def.access_flags),
                }),
                None => skipped += 1,
            }
        }
        if skipped > 0 {
            out.warnings.push(format!(
                "{name}: {skipped}/{} class_defs skipped (unresolvable type/string index)",
                count
            ));
        }
    }
    out
}
