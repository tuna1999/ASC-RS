//! Query resolution: walk pools sequentially, return id sets.
//!
//! All locators take a borrowed `&DexView` and return id vectors
//! (typed `SmallVec` per kind, or empty on error / no match). The
//! scan in [`crate::scan`] converts the resulting [`ResolvedTargets`]
//! to a [`crate::TargetSets`] with sorted membership.
//!
//! No global indexes are built: each locator does one or two passes
//! over its pool. The string locator uses an ASCII fast path
//! (`bytes::contains` over the raw MUTF-8 payload) before falling back
//! to a lossy decode for non-ASCII patterns.

use smallvec::SmallVec;

use asc_dex::ids::{FieldIdx, MethodIdx, StringIdx, TypeIdx};
use asc_dex::view::DexView;

use crate::error::SearchError;
use crate::query::{ClassConstraint, Query, ResolvedTargets};

/// Upper bound for a "small" pool result. Real DEXes hold tens of
/// thousands of strings but the matched subset for a typical
/// substring query is rarely larger than a handful.
const SMALL_HINT: usize = 8;

/// Normalizes a class pattern to the Dalvik descriptor form.
///
/// `com.poc.Main` → `Lcom/poc/Main;`. Already-descriptor inputs
/// (`Lcom/poc/Main;` or `Lcom/poc/Main`) are preserved (the trailing
/// `;` is appended if missing; leading `L` is added if missing).
///
/// Returns `None` for an empty / whitespace-only pattern.
fn normalize_descriptor(pattern: &str) -> Option<String> {
    let mut s = pattern.trim().to_string();
    if s.is_empty() {
        return None;
    }
    // Replace dotted separators with slashes (the only normalization
    // the oracle applies).
    s = s.replace('.', "/");
    if !s.starts_with('L') {
        s.insert(0, 'L');
    }
    if !s.ends_with(';') {
        s.push(';');
    }
    Some(s)
}

/// `true` when the pattern is ASCII (every byte < 0x80). The string
/// fast path can run directly on the MUTF-8 payload without decoding.
#[inline]
fn is_ascii(pattern: &[u8]) -> bool {
    pattern.iter().all(|b| b.is_ascii())
}

/// Returns `true` when `haystack` (MUTF-8 payload, no terminator)
/// contains `needle` as a substring. For ASCII `needle` we operate on
/// the raw bytes (no decode needed because every ASCII byte is its own
/// UTF-8 codepoint and MUTF-8 only differs from UTF-8 for 0x00, which
/// we never see inside a payload — the NUL terminates the record).
fn mutf8_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if is_ascii(needle) {
        return memchr_substring(haystack, needle);
    }
    // Non-ASCII pattern: decode the haystack lossily and look up the
    // substring on the resulting `str`. We don't decode the needle
    // (the caller is already a Rust `String`).
    let haystack_str = asc_dex::mutf8::decode_lossy(haystack, 0);
    let needle_str = match std::str::from_utf8(needle) {
        Ok(s) => s,
        Err(_) => return false,
    };
    haystack_str.contains(needle_str)
}

/// Plain substring search without `regex`. Implemented as a rolling
/// `memchr` over the first byte plus slice comparison for the rest.
fn memchr_substring(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    if needle.len() == 1 {
        return memchr_byte(haystack, needle[0]).is_some();
    }
    let first = needle[0];
    let mut start = 0;
    while let Some(pos) = memchr_byte(&haystack[start..], first) {
        let abs = start + pos;
        let end = abs + needle.len();
        if end > haystack.len() {
            return false;
        }
        if &haystack[abs..end] == needle {
            return true;
        }
        start = abs + 1;
    }
    false
}

/// Byte search equivalent of `memchr::memchr` (avoids the dependency).
#[inline]
fn memchr_byte(hay: &[u8], needle: u8) -> Option<usize> {
    hay.iter().position(|&b| b == needle)
}

// --------------------- string locator ---------------------

/// Resolves a `Query::String` pattern to a set of `StringIdx` whose
/// MUTF-8 payload contains `pattern` as a literal substring. Returns
/// an empty vector (not an error) when nothing matches.
fn resolve_string_pattern(
    view: &DexView,
    pattern: &str,
) -> Result<SmallVec<[StringIdx; SMALL_HINT]>, SearchError> {
    let needle = pattern.as_bytes();
    let mut out: SmallVec<[StringIdx; SMALL_HINT]> = SmallVec::new();
    for (idx, s) in view.strings() {
        if mutf8_contains(s.mutf8, needle) {
            out.push(idx);
        }
    }
    Ok(out)
}

// --------------------- type locator ---------------------

/// Resolves a `Query::Type` pattern to a set of `TypeIdx` whose
/// descriptor string contains `pattern`. Returns an empty vector when
/// nothing matches.
fn resolve_type_pattern(
    view: &DexView,
    pattern: &str,
) -> Result<SmallVec<[TypeIdx; SMALL_HINT]>, SearchError> {
    let needle = pattern.as_bytes();
    let mut out: SmallVec<[TypeIdx; SMALL_HINT]> = SmallVec::new();
    for (idx, descriptor_sidx) in view.types() {
        let sref = view
            .string(descriptor_sidx)
            .map_err(|e| SearchError::Locator {
                pool: "string_ids",
                source: e,
            })?;
        if mutf8_contains(sref.mutf8, needle) {
            out.push(idx);
        }
    }
    Ok(out)
}

/// Resolves a class pattern (substring by default, exact when
/// `exact == true`) to a set of `TypeIdx`.
fn resolve_class_constraint(
    view: &DexView,
    class: &ClassConstraint,
) -> Result<SmallVec<[TypeIdx; SMALL_HINT]>, SearchError> {
    if class.pattern.is_empty() {
        return Ok(SmallVec::new());
    }
    if class.exact {
        let descr = match normalize_descriptor(&class.pattern) {
            Some(d) => d,
            None => return Ok(SmallVec::new()),
        };
        // Binary search type descriptors by string-id.
        // (Type ids are stored in index order; matching the Python
        // `_find_type_idx_precisely` semantics.)
        let needle = descr.as_bytes();
        let mut out: SmallVec<[TypeIdx; SMALL_HINT]> = SmallVec::new();
        for (idx, descriptor_sidx) in view.types() {
            let sref = view
                .string(descriptor_sidx)
                .map_err(|e| SearchError::Locator {
                    pool: "string_ids",
                    source: e,
                })?;
            if sref.mutf8 == needle {
                out.push(idx);
            }
        }
        Ok(out)
    } else {
        resolve_type_pattern(view, &class.pattern)
    }
}

// --------------------- field / method locators ---------------------

/// Resolves a field query to a set of `FieldIdx`.
///
/// `name`: substring pattern over the field name. `None` matches every
/// field name. `class`: optional class filter (exact or fuzzy).
fn resolve_field_query(
    view: &DexView,
    name: Option<&str>,
    class: Option<&ClassConstraint>,
) -> Result<SmallVec<[FieldIdx; SMALL_HINT]>, SearchError> {
    if name.is_none_or(str::is_empty) && class.is_none() {
        return Ok(SmallVec::new());
    }
    let allowed_classes: Option<SmallVec<[TypeIdx; SMALL_HINT]>> = match class {
        Some(c) => {
            let s = resolve_class_constraint(view, c)?;
            if s.is_empty() {
                return Ok(SmallVec::new());
            }
            Some(s)
        }
        None => None,
    };
    let needle = name.filter(|s| !s.is_empty()).map(str::as_bytes);
    let mut out: SmallVec<[FieldIdx; SMALL_HINT]> = SmallVec::new();
    for (idx, field) in view.fields() {
        if let Some(allowed) = allowed_classes.as_ref()
            && !allowed.contains(&field.class)
        {
            continue;
        }
        if let Some(n) = needle {
            let sref = view.string(field.name).map_err(|e| SearchError::Locator {
                pool: "string_ids",
                source: e,
            })?;
            if !mutf8_contains(sref.mutf8, n) {
                continue;
            }
        }
        out.push(idx);
    }
    Ok(out)
}

/// Resolves a method query to a set of `MethodIdx`.
fn resolve_method_query(
    view: &DexView,
    name: Option<&str>,
    class: Option<&ClassConstraint>,
) -> Result<SmallVec<[MethodIdx; SMALL_HINT]>, SearchError> {
    if name.is_none_or(str::is_empty) && class.is_none() {
        return Ok(SmallVec::new());
    }
    let allowed_classes: Option<SmallVec<[TypeIdx; SMALL_HINT]>> = match class {
        Some(c) => {
            let s = resolve_class_constraint(view, c)?;
            if s.is_empty() {
                return Ok(SmallVec::new());
            }
            Some(s)
        }
        None => None,
    };
    let mut out: SmallVec<[MethodIdx; SMALL_HINT]> = SmallVec::new();
    let needle = name.filter(|s| !s.is_empty()).map(str::as_bytes);
    for (idx, method) in view.methods() {
        if let Some(allowed) = allowed_classes.as_ref()
            && !allowed.contains(&method.class)
        {
            continue;
        }
        if let Some(n) = needle {
            let sref = view.string(method.name).map_err(|e| SearchError::Locator {
                pool: "string_ids",
                source: e,
            })?;
            if !mutf8_contains(sref.mutf8, n) {
                continue;
            }
        }
        out.push(idx);
    }
    Ok(out)
}

// --------------------- public API ---------------------

/// Resolves a `Query` to the per-kind id sets the scan will match
/// against.
///
/// The returned [`ResolvedTargets`] may be empty (no id matched), in
/// which case the scan short-circuits and produces no hits. Errors are
/// non-fatal at the engine level: they are recorded as
/// [`SearchError::Locator`] and the corresponding kind's set is left
/// empty.
pub fn resolve_target_ids(view: &DexView, query: &Query) -> Result<ResolvedTargets, SearchError> {
    let mut out = ResolvedTargets::default();
    match query {
        Query::String { pattern } => {
            if pattern.is_empty() {
                return Ok(out);
            }
            out.strings = resolve_string_pattern(view, pattern)?;
        }
        Query::Type { pattern } => {
            if pattern.is_empty() {
                return Ok(out);
            }
            out.types = resolve_type_pattern(view, pattern)?;
        }
        Query::Method { name, class } => {
            if name.as_ref().is_none_or(|n| n.is_empty()) && class.is_none() {
                return Ok(out);
            }
            out.methods = resolve_method_query(view, name.as_deref(), class.as_ref())?;
        }
        Query::Field { name, class } => {
            if name.as_ref().is_none_or(|n| n.is_empty()) && class.is_none() {
                return Ok(out);
            }
            out.fields = resolve_field_query(view, name.as_deref(), class.as_ref())?;
        }
    }
    Ok(out)
}

/// Returns `true` when the supplied class descriptor (in any of
/// `com.poc.Main`, `Lcom/poc/Main;`, or `Lcom/poc/Main` form) is
/// defined in this DEX.
///
/// "Defined" means the type appears in the `type_ids` table **and**
/// the type id is used by some `class_def_item`'s `class_idx` field
/// (matching `apk_handler.py::_class_defs_contains_type_idx` from the
/// oracle). Returns `false` for an empty / invalid descriptor.
pub fn class_defines(view: &DexView, descriptor: &str) -> bool {
    let normalized = match normalize_descriptor(descriptor) {
        Some(d) => d,
        None => return false,
    };
    let needle = normalized.as_bytes();

    // Find the first TypeIdx whose descriptor matches.
    let mut target: Option<TypeIdx> = None;
    for (idx, descriptor_sidx) in view.types() {
        let sref = match view.string(descriptor_sidx) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if sref.mutf8 == needle {
            target = Some(idx);
            break;
        }
    }
    let Some(target) = target else {
        return false;
    };

    // Walk class_defs; a match means the class is defined in this DEX.
    let n = view.class_def_count();
    for i in 0..n {
        let def = match view.class_def(i) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if def.class == target {
            return true;
        }
    }
    false
}

// --------------------- tests ---------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_descriptor_dotted() {
        assert_eq!(
            normalize_descriptor("com.poc.Main"),
            Some("Lcom/poc/Main;".to_string())
        );
    }

    #[test]
    fn normalize_descriptor_already_descriptor() {
        assert_eq!(
            normalize_descriptor("Lcom/poc/Main;"),
            Some("Lcom/poc/Main;".to_string())
        );
    }

    #[test]
    fn normalize_descriptor_no_semicolon() {
        assert_eq!(
            normalize_descriptor("Lcom/poc/Main"),
            Some("Lcom/poc/Main;".to_string())
        );
    }

    #[test]
    fn normalize_descriptor_empty() {
        assert_eq!(normalize_descriptor(""), None);
        assert_eq!(normalize_descriptor("   "), None);
    }

    #[test]
    fn normalize_descriptor_primitive_array_passthrough() {
        // `[I` is an int-array descriptor; normalization prepends `L`
        // and appends `;`. The oracle applies the same transform.
        assert_eq!(normalize_descriptor("[I"), Some("L[I;".to_string()));
    }

    #[test]
    fn ascii_contains_basic() {
        assert!(memchr_substring(b"hello world", b"world"));
        assert!(memchr_substring(b"abc", b"a"));
        assert!(!memchr_substring(b"abc", b"d"));
    }

    #[test]
    fn ascii_contains_overlapping() {
        // First byte appears many times; verify we don't stop at the
        // first mismatch.
        assert!(memchr_substring(b"aaaaab", b"aab"));
    }

    #[test]
    fn mutf8_contains_empty_pattern_matches_everything() {
        assert!(mutf8_contains(b"hello", b""));
    }

    #[test]
    fn mutf8_contains_non_ascii_pattern_decodes_haystack() {
        // Payload contains a 2-byte UTF-8 sequence (U+00E9 = é).
        // The MUTF-8 decoder handles 2-byte sequences like standard
        // UTF-8, so the lossy decode round-trips and the substring
        // lookup succeeds.
        let haystack: &[u8] = "caf\u{00E9}".as_bytes();
        let emoji: &[u8] = "\u{00E9}".as_bytes();
        assert!(mutf8_contains(haystack, emoji));
        let needle2: &[u8] = "af\u{00E9}".as_bytes();
        assert!(mutf8_contains(haystack, needle2));
    }
    #[test]
    fn mutf8_contains_non_ascii_pattern_uses_bytes_needle() {
        // A non-ASCII pattern given as raw bytes (the byte path the
        // engine actually takes when the caller hands in a pattern
        // containing a non-ASCII codepoint) still triggers the
        // decode-haystack branch.
        let haystack: &[u8] = "caf\u{00E9}".as_bytes();
        let needle: &[u8] = "\u{00E9}".as_bytes();
        assert!(mutf8_contains(haystack, needle));
    }
    #[test]
    fn mutf8_contains_non_ascii_pattern_3byte() {
        // A 3-byte UTF-8 sequence (U+4E2D = 中) also round-trips
        // through MUTF-8 decoding.
        let haystack: &[u8] = "a\u{4E2D}b".as_bytes();
        let needle: &[u8] = "\u{4E2D}".as_bytes();
        assert!(mutf8_contains(haystack, needle));
    }
}
