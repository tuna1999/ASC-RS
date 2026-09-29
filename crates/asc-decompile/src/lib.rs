//! # asc-decompile
//!
//! Backend-neutral decompiler abstraction (`ClassDecompiler` trait) plus the
//! `DroidsawBackend` adapter over the `droidsaw-dex` crate. Backend-specific
//! types NEVER leak into asc-core/asc-cli/asc-gui — the public surface is
//! just the trait, [`DecompileError`], and the chosen backend's
//! constructor + `ClassDecompiler` impl.
//!
//! ## Pipeline contract
//!
//! A `ClassDecompiler::decompile(dex, target)` call:
//!
//! 1. Parses the DEX bytes (tolerant of `droidsaw_dex::DexError`).
//! 2. Resolves `target` (accepts both `Lcom/foo/Bar;` Dalvik descriptor and
//!    `com.foo.Bar` Java dotted form — normalised the same way the rest of
//!    asc-rs does).
//! 3. Locates the matching `class_def`.
//! 4. Hands the class def to the backend and returns its emitted Java
//!    source as a single `String`.
//!
//! Errors are classified into the [`DecompileError`] taxonomy:
//!
//! - [`DecompileError::ClassNotFound`] — descriptor resolved to a `type_id`
//!   but no `class_def` recognised it. Returned as `Err`, never `Ok("")`.
//! - [`DecompileError::MalformedDex`] — header missing or zero-bytes input.
//! - [`DecompileError::UnsupportedVersion`] — DEX magic not in 035..=041.
//! - [`DecompileError::BackendError`] — anything the upstream crate surfaces
//!   (panic-safe wrapper). Wrapped as `String`; never panics on untrusted
//!   input.
//!
//! ## Wave-2 scaffold
//!
//! Adapter over `droidsaw-dex = "1.0.0"` (pinned exact). See
//! [`crate::droidsaw::DroidsawBackend`] for the implementation.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod droidsaw;

use thiserror::Error;

/// Backend-neutral error taxonomy for class decompilation.
#[derive(Debug, Error)]
pub enum DecompileError {
    /// The supplied class descriptor does not correspond to any class
    /// defined in the DEX.
    #[error("class not found: {0}")]
    ClassNotFound(String),

    /// The supplied bytes are not a recognisable DEX (missing magic, too
    /// short, header bytes that fail the format invariants).
    #[error("malformed dex: {0}")]
    MalformedDex(String),

    /// DEX magic reports a version outside the supported range (035..=041).
    #[error("unsupported dex version: {0}")]
    UnsupportedVersion(String),

    /// The backend encountered an internal error (parse failure on a
    /// subset of the input, emit failure, etc.). The backend adapter
    /// MUST classify as much as possible into the specific variants above;
    /// this variant is the catch-all for whatever remains.
    #[error("backend error: {0}")]
    BackendError(String),
}

/// Normalise an arbitrary class name into Dalvik descriptor form
/// (`Lcom/foo/Bar;`). Accepts both `Lcom/foo/Bar;` and `com.foo.Bar`.
///
/// Mirrors the Python oracle's `_format_class_name` (see
/// `reference/BEHAVIOR.md` §1) so callers can pass either form.
///
/// Returns `Err(DecompileError::ClassNotFound)` (with empty name) only for
/// the empty-string input that would otherwise round-trip to `L;`.
pub fn normalize_class_name(input: &str) -> Result<String, DecompileError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(DecompileError::ClassNotFound(
            "Class name cannot be empty".into(),
        ));
    }
    if s.starts_with('L') && s.ends_with(';') && s.contains('/') {
        return Ok(s.to_owned());
    }
    let mut out = s.replace('.', "/");
    if !out.starts_with('L') {
        out.insert(0, 'L');
    }
    if !out.ends_with(';') {
        out.push(';');
    }
    Ok(out)
}

/// Backend-neutral class decompiler contract.
///
/// Implementations take the raw DEX bytes (the full per-entry payload —
/// no inflation needed, since asc-apk already returned the
/// already-inflated buffer) and a class descriptor, and return the
/// decompiled Java source as one `String`.
///
/// Implementations MUST:
///
/// - Never panic on untrusted input (wrap upstream `catch_unwind`).
/// - Return `Err(DecompileError::ClassNotFound)` when the class is
///   absent, never `Ok(String::new())`.
/// - Treat empty bytes as [`DecompileError::MalformedDex`].
pub trait ClassDecompiler: Send + Sync {
    /// Decompile `target` from `dex_bytes` to Java source.
    ///
    /// `target` accepts both Dalvik descriptor (`Lcom/foo/Bar;`) and Java
    /// dotted (`com.foo.Bar`) form.
    fn decompile(&self, dex_bytes: &[u8], target: &str) -> Result<String, DecompileError>;
}
