//! `Apk` (mmap) and `ZipView` (borrowed buffer) wrappers around the shared
//! directory parser.

use std::fs::File;
use std::path::Path;

use crate::entry::{Compression, DexEntry, EntryBytes};
use crate::error::ApkError;
use crate::inflate::{InflateLimits, inflate_into_vec, verify_crc32};
use memmap2::Mmap;

/// Read-only mmap APK/ZIP engine.
///
/// Holds an OS memory mapping of the file (read-only) and the parsed
/// central-directory entries. STORED entries are extracted as borrowed
/// slices; DEFLATED entries are inflated into freshly allocated
/// [`EntryBytes::Inflated`] payloads.
///
/// `Apk` is `Send + Sync`: the mmap is `Send + Sync` (read-only) and
/// every internal field is `Sync`. All operations are synchronous per
/// entry; parallel orchestration lives in `asc-core`.
#[derive(Debug)]
pub struct Apk {
    /// Backing memory map. Lives as long as the `File` we opened it from,
    /// which is captured inside the `Mmap` via internal `Arc<()>` semantics.
    mmap: Mmap,
    /// Parsed central-directory entries in directory order.
    entries: Vec<DexEntry>,
    /// Indices into `entries` for `classes*.dex` matches (rooted, no `/`,
    /// suffix `.dex`), sorted numerically: `classes.dex`, `classes2.dex`,
    /// `classes10.dex`, …
    dex_indices: Vec<usize>,
}

impl Apk {
    /// Open an APK/ZIP file by memory-mapping it read-only.
    ///
    /// The mapping is created with the OS-default `Mmap::map` call; no
    /// prefaulting, no write-back. The file is opened with `read` access
    /// only, so the mapping cannot be dirtied and the kernel will not
    /// write back to the file even if we ever did.
    pub fn open(path: &Path) -> Result<Apk, ApkError> {
        let file = File::open(path)?;
        // SAFETY (Lead-approved; documented next to the call):
        //   * the file is opened read-only above;
        //   * we never call any external writer API on `file`;
        //   * `Mmap::map` does not promise isolation from concurrent
        //     external writers; the rest of ASC-Rust runs from worker
        //     threads spawned by the same process and reads the mapping
        //     once before returning a `&[u8]` slice. We accept the standard
        //     mmap caveat that an external writer (e.g. another process
        //     replacing the file via rename) can produce a torn read; this
        //     matches the Python oracle's behaviour.
        //   * `Apk::drop` will run `Mmap::drop` before `File::drop`, so the
        //     mapping cannot outlive its file.
        let mmap = unsafe { Mmap::map(&file) }?;
        let entries = crate::zip::parse_directory(&mmap)?;
        let dex_indices = discover_dex_indices(&entries);
        Ok(Apk {
            mmap,
            entries,
            dex_indices,
        })
    }

    /// All `classes*.dex` entries at the archive root, sorted in numeric
    /// order (`classes.dex` is group 1, `classes2.dex` is group 2, …).
    ///
    /// Non-matching decoys are excluded: subdirectory `classes.dex`,
    /// case-variant `Classes.dex`, and `classesx.dex` (no `.dex` suffix)
    /// are all skipped.
    pub fn dex_entries(&self) -> Vec<DexEntry> {
        self.dex_indices
            .iter()
            .map(|&i| self.entries[i].clone())
            .collect()
    }

    /// Total number of central-directory entries (not just dex entries).
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Iterate every central-directory entry in directory order.
    pub fn entries(&self) -> impl Iterator<Item = DexEntry> + '_ {
        self.entries.iter().cloned()
    }

    /// Look up an entry by exact name. Returns `None` if no entry matches.
    pub fn entry(&self, name: &str) -> Option<DexEntry> {
        self.entries.iter().find(|e| e.name == name).cloned()
    }

    /// Read the bytes of `entry`. STORED entries are returned as borrowed
    /// slices pointing into the mmap; DEFLATED entries are inflated into a
    /// fresh `Vec<u8>` (cap: [`crate::inflate::DEFAULT_MAX_OUTPUT`]).
    pub fn read_entry(&self, entry: &DexEntry) -> Result<EntryBytes<'_>, ApkError> {
        self.read_entry_with_limits(entry, InflateLimits::default())
    }

    /// Like [`Self::read_entry`], but additionally verifies CRC-32 of the
    /// inflated bytes against the central-directory field. Returns
    /// [`ApkError::SizeMismatch`] if the CRC does not match, to give
    /// callers a distinct signal.
    pub fn read_entry_verified(&self, entry: &DexEntry) -> Result<EntryBytes<'_>, ApkError> {
        let bytes = self.read_entry(entry)?;
        if !verify_crc32(bytes.as_slice(), entry.crc32) {
            return Err(ApkError::SizeMismatch {
                declared: entry.uncompressed_size,
                produced: entry.crc32 as u64, // sentinel: CRC of the entry
            });
        }
        Ok(bytes)
    }

    /// Read with a custom inflate cap. Used internally by tests and by
    /// callers that need to enforce a tighter bound.
    pub fn read_entry_with_limits(
        &self,
        entry: &DexEntry,
        limits: InflateLimits,
    ) -> Result<EntryBytes<'_>, ApkError> {
        read_entry_inner(&self.mmap, entry, limits)
    }
}

// SAFETY: `Mmap` is `Send + Sync` when read-only; `Vec<DexEntry>` is too.
// Both are `Sync`/`Send` for the same reasons.
unsafe impl Send for Apk {}
unsafe impl Sync for Apk {}

/// In-memory ZIP view over a borrowed byte slice.
///
/// `ZipView` is the fuzzing / differential-test counterpart of `Apk`: it
/// operates on a caller-supplied buffer (no filesystem, no mmap). It
/// carries the same accessors minus `open`/`path`.
#[derive(Debug)]
pub struct ZipView<'a> {
    bytes: &'a [u8],
    entries: Vec<DexEntry>,
    dex_indices: Vec<usize>,
}

impl<'a> ZipView<'a> {
    /// Parse a borrowed buffer as a ZIP/APK archive. No I/O is performed.
    pub fn parse(bytes: &'a [u8]) -> Result<ZipView<'a>, ApkError> {
        let entries = crate::zip::parse_directory(bytes)?;
        let dex_indices = discover_dex_indices(&entries);
        Ok(ZipView {
            bytes,
            entries,
            dex_indices,
        })
    }

    /// All `classes*.dex` entries at the archive root, in numeric order.
    pub fn dex_entries(&self) -> Vec<DexEntry> {
        self.dex_indices
            .iter()
            .map(|&i| self.entries[i].clone())
            .collect()
    }

    /// Total number of central-directory entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Iterate every central-directory entry in directory order.
    pub fn entries(&self) -> impl Iterator<Item = DexEntry> + '_ {
        self.entries.iter().cloned()
    }

    /// Look up an entry by exact name. Returns `None` if no entry matches.
    pub fn entry(&self, name: &str) -> Option<DexEntry> {
        self.entries.iter().find(|e| e.name == name).cloned()
    }

    /// Read the bytes of `entry`. STORED entries are borrowed from the
    /// input buffer; DEFLATED entries are inflated into a fresh `Vec<u8>`.
    pub fn read_entry(&self, entry: &DexEntry) -> Result<EntryBytes<'a>, ApkError> {
        read_entry_inner(self.bytes, entry, InflateLimits::default())
    }

    /// Like [`Self::read_entry`], but with a custom inflate cap. Used by
    /// tests and by callers that need a tighter bound than the default
    /// 1 GiB.
    pub fn read_entry_with_limits(
        &self,
        entry: &DexEntry,
        limits: InflateLimits,
    ) -> Result<EntryBytes<'a>, ApkError> {
        read_entry_inner(self.bytes, entry, limits)
    }
}

// SAFETY: `&'a [u8]` is `Send + Sync` for any `'a`; `Vec<DexEntry>` is too.
unsafe impl<'a> Send for ZipView<'a> {}
unsafe impl<'a> Sync for ZipView<'a> {}

/// Shared read logic for both `Apk` and `ZipView`.
fn read_entry_inner<'a>(
    buf: &'a [u8],
    entry: &DexEntry,
    limits: InflateLimits,
) -> Result<EntryBytes<'a>, ApkError> {
    let data_off = crate::zip::resolve_local_data_offset(buf, entry)? as usize;
    let csize = entry.compressed_size as usize;
    let usize = entry.uncompressed_size as usize;
    let archive_len = buf.len();

    // Bounds-check the requested window before slicing.
    let comp_end = data_off
        .checked_add(csize)
        .ok_or(ApkError::Truncated("compressed offset+size overflow"))?;
    if comp_end > archive_len {
        return Err(ApkError::Truncated("compressed payload overruns EOF"));
    }

    match entry.method {
        Compression::Stored => {
            if csize != usize {
                return Err(ApkError::SizeMismatch {
                    declared: entry.uncompressed_size,
                    produced: csize as u64,
                });
            }
            Ok(EntryBytes::Borrowed(&buf[data_off..comp_end]))
        }
        Compression::Deflated => {
            let compressed = &buf[data_off..comp_end];
            let inflated = inflate_into_vec(compressed, usize, limits)?;
            Ok(EntryBytes::Inflated(inflated))
        }
    }
}

/// Compute the index list of `classes*.dex` entries, sorted in numeric
/// order.
///
/// Rules (matching the Python oracle's `_parse_cd_dex_entries`):
///   * must end with `.dex`;
///   * must contain no `/` (root-only);
///   * must match `^classes(\d*)\.dex$` literally (no regex; case‑sensitive);
///   * group 1 is missing → group 1 (so `classes.dex` sorts first);
///   * groups with digits sort numerically.
///
/// Indices refer to `entries`; callers project out clones.
fn discover_dex_indices(entries: &[DexEntry]) -> Vec<usize> {
    // The oracle keeps only the first central-directory record per name
    // (`seen_names` in `_parse_cd_dex_entries`).
    let mut seen = std::collections::HashSet::new();
    let mut pairs: Vec<(u64, usize)> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            let group = parse_classes_dex_group(&e.name)?;
            seen.insert(e.name.as_str()).then_some((group, i))
        })
        .collect();
    pairs.sort_by_key(|(g, _)| *g);
    pairs.into_iter().map(|(_, i)| i).collect()
}

/// Parse a single name and return its numeric group on match.
///
/// Returns `None` for non-matches: non-root, wrong case, wrong extension,
/// or any non-`classes` prefix.
fn parse_classes_dex_group(name: &str) -> Option<u64> {
    if name.is_empty() || name.contains('/') {
        return None;
    }
    let suffix = ".dex";
    if !name.ends_with(suffix) {
        return None;
    }
    let stem = &name[..name.len() - suffix.len()];
    if stem == "classes" {
        return Some(1);
    }
    let rest = stem.strip_prefix("classes")?;
    if rest.is_empty() {
        // Already matched "classes" above; defensive.
        return Some(1);
    }
    // ASCII digits only.
    if !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // u64 parse; overflow → reject (no APKs have >10^18 classes files).
    rest.parse::<u64>().ok()
}
