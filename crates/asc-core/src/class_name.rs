//! Class-name normalization shared between pipelines.
//!
//! Wraps [`asc_decompile::normalize_class_name`] so the orchestration
//! layer has a single canonical entry point for "user-typed class
//! name → Dalvik descriptor". Both `Lcom/poc/Main;` and `com.poc.Main`
//! are accepted; an empty / whitespace-only input is an error
//! (`ClassNotFound`), matching the Python oracle's
//! `_format_class_name` (`main.py:10-20`).
//!
//! See `reference/BEHAVIOR.md` §1 for the exact rules.

use asc_decompile::DecompileError;

/// Normalize an arbitrary class name into Dalvik descriptor form.
///
/// Returns the descriptor string on success. On empty / whitespace
/// input returns `Err(DecompileError::ClassNotFound(...))`. Any other
/// shape (`Lcom/poc/Main;`, `com.poc.Main`, `[I`, etc.) is normalized
/// according to `BEHAVIOR.md` §1.
#[inline]
pub fn normalize_class_name(input: &str) -> Result<String, DecompileError> {
    asc_decompile::normalize_class_name(input)
}
