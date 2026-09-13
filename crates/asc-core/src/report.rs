//! Public report types for the findrefs pipeline.
//!
//! The text emitter (`format::format_search_report_text`) consumes the
//! [`SearchReport`] and emits lines exactly per
//! `reference/BEHAVIOR.md` §2.
//!
//! ## Completeness model (§25)
//!
//! - `complete = true` — every per-DEX scan finished without errors.
//! - `complete = false` — at least one per-DEX scan reported errors; the
//!   per-DEX `matches` are preserved, the failures land in `errors`.
//! - `matches` is in caller-id order (sorted). The caller line is the
//!   emitted oracle shape; `matched` is the sorted, de-duplicated list
//!   of matched entity strings.
//!
//! ## Why pre-rendered matches?
//!
//! The pipeline scans with a borrowed `&DexView`. Once the borrow
//! ends, raw `RefHit`s cannot be re-rendered (they hold typed pool
//! indices only). The pipeline renders each hit into
//! `(caller_string, matched_strings)` while the borrow is alive and
//! stores those owned strings. This keeps the report lifetime-free:
//! the text / JSON emitters only read owned `String`s.

use std::fmt;

use serde::{Deserialize, Serialize};

use asc_query::SearchError as EngineSearchError;

/// One caller line: the caller method descriptor (`Lcom/foo/Bar;->name`)
/// plus the sorted, de-duplicated matched entity list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenderedMatch {
    /// Caller method (`{class.fullname}->{name}`).
    pub caller: String,
    /// Sorted, de-duplicated matched entity strings.
    pub matched: Vec<String>,
}

/// Per-DEX subset of a [`SearchReport`].
///
/// `dex_name` follows `reference/BEHAVIOR.md` §2:
/// `classes.dex` (literal entry name) for ordinary entries; for
/// DEX-041 containers, `name[i]` where `name` is the entry name and
/// `i` is the logical-DEX index inside the container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DexResults {
    /// Display name of this DEX.
    pub dex_name: String,
    /// Caller matches sorted by caller id.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub matches: Vec<RenderedMatch>,
    /// Errors observed while scanning this DEX. When non-empty the
    /// parent [`SearchReport::complete`] is `false`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<SearchError>,
    /// `true` iff this DEX's scan finished without errors.
    pub complete: bool,
}

/// One failure recorded by the pipeline.
///
/// This is the asc-core view of an engine error, with additional
/// context the CLI / JSON consumer wants (the owning DEX name, a
/// human-readable summary, optional descriptor / offset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchError {
    /// Display name of the DEX the error was observed against
    /// (`classes.dex`, `classes2.dex`, `classes.dex[1]`, …).
    pub dex_name: String,
    /// Coarse category (`engine`, `apk`, `parse`).
    pub kind: SearchErrorKind,
    /// Human-readable message (the inner `Display` impl of the source
    /// error).
    pub message: String,
}

/// Coarse category for a [`SearchError`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SearchErrorKind {
    /// Engine-side error: locator, walker, or code-item parse failure.
    Engine,
    /// APK / DEX container parse error.
    Apk,
    /// DEX header / pool extent error.
    Parse,
}

impl fmt::Display for SearchErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SearchErrorKind::Engine => f.write_str("engine"),
            SearchErrorKind::Apk => f.write_str("apk"),
            SearchErrorKind::Parse => f.write_str("parse"),
        }
    }
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.kind, self.dex_name, self.message)
    }
}

impl SearchError {
    /// Build from an engine [`EngineSearchError`] and the owning DEX name.
    pub(crate) fn from_engine(dex_name: impl Into<String>, e: &EngineSearchError) -> Self {
        Self {
            dex_name: dex_name.into(),
            kind: SearchErrorKind::Engine,
            message: e.to_string(),
        }
    }

    /// Build from an `apk`/`dex`-side error string (the orchestration
    /// layer never panics on untrusted input, so any IO / inflate /
    /// header-parse failure is recorded as a string).
    pub(crate) fn from_apk(dex_name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            dex_name: dex_name.into(),
            kind: SearchErrorKind::Apk,
            message: message.into(),
        }
    }

    /// Build from a DEX parse error (header / pool extent).
    pub(crate) fn from_parse(dex_name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            dex_name: dex_name.into(),
            kind: SearchErrorKind::Parse,
            message: message.into(),
        }
    }
}

/// Aggregated findrefs report across every DEX in the APK.
///
/// `complete` is `false` iff at least one per-DEX scan or one DEX parse
/// failed. `errors` carries every recorded failure with its owning
/// `dex_name`. The JSON consumer uses `complete` to decide whether to
/// trust the hits; the text consumer prints hits regardless and leaves
/// diagnostics to stderr.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchReport {
    /// Per-DEX results in central-directory offset order.
    pub results: Vec<DexResults>,
    /// Flat list of every failure (every per-DEX error appears once
    /// per occurrence).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<SearchError>,
    /// `true` iff every step finished without error.
    pub complete: bool,
}

impl SearchReport {
    /// Construct an empty report (no DEX entries found in the APK).
    pub fn empty() -> Self {
        Self {
            results: Vec::new(),
            errors: Vec::new(),
            complete: true,
        }
    }

    /// Total emitted-line count across all DEX results.
    pub fn total_lines(&self) -> usize {
        self.results.iter().map(|r| r.matches.len()).sum()
    }

    /// Total matched-method count (one per caller line, already
    /// deduplicated by the pipeline).
    pub fn matched_methods_total(&self) -> usize {
        self.results.iter().map(|r| r.matches.len()).sum()
    }
}

impl DexResults {
    /// Build an empty (zero-hit, complete) result.
    pub(crate) fn empty(dex_name: impl Into<String>) -> Self {
        Self {
            dex_name: dex_name.into(),
            matches: Vec::new(),
            errors: Vec::new(),
            complete: true,
        }
    }
}
