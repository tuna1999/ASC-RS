//! Heuristic diagnostics over decompiled Java text.
//!
//! droidsaw-dex 2.0.0's structurer can drop phi nodes at non-loop-header
//! merge points, leaving SSA locals (`vN_M`) that are read but never
//! assigned or declared. [`unbound_locals`] flags those names.
//!
//! Ceiling: this is a name heuristic. It does NOT detect the sibling
//! defect where a loop body is emitted twice (every name stays bound), and
//! an empty result is not evidence that the source is correct.

use std::collections::{BTreeMap, BTreeSet};

/// Identifiers that can precede an expression without declaring it.
const EXPR_KEYWORDS: &[&str] = &[
    "return",
    "throw",
    "new",
    "else",
    "case",
    "do",
    "assert",
    "yield",
    "instanceof",
];

/// SSA-local names (`v<reg>_<n>`) that occur in `src` (outside comments and
/// string/char literals) but are never assigned nor declared. Sorted, unique.
pub fn unbound_locals(src: &str) -> Vec<String> {
    let b = src.as_bytes();
    let mut bound: BTreeSet<&str> = BTreeSet::new();
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    let mut prev_ident: Option<&str> = None;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i = src[i + 2..].find("*/").map_or(b.len(), |p| i + 2 + p + 2);
            prev_ident = None;
        } else if c == b'"' || c == b'\'' {
            i += 1;
            while i < b.len() && b[i] != c {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
            prev_ident = None;
        } else if c.is_ascii_alphabetic() || c == b'_' || c == b'$' {
            let s = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                i += 1;
            }
            let id = &src[s..i];
            if is_local(id) {
                seen.insert(id, ());
                let rest = src[i..].trim_start();
                let assigned = rest.starts_with('=') && !rest.starts_with("==");
                let declared = prev_ident.is_some_and(|p| !EXPR_KEYWORDS.contains(&p));
                if assigned || declared {
                    bound.insert(id);
                }
            }
            prev_ident = Some(id);
        } else {
            if !c.is_ascii_whitespace() {
                prev_ident = None;
            }
            i += 1;
        }
    }
    seen.into_keys()
        .filter(|n| !bound.contains(n))
        .map(String::from)
        .collect()
}

fn is_local(id: &str) -> bool {
    let Some(r) = id.strip_prefix('v') else {
        return false;
    };
    let Some((reg, n)) = r.split_once('_') else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    digits(reg) && digits(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_read_without_binding() {
        let src =
            "void f() {\n  int v1_0 = 1;\n  if (v2_3 == null) { g(v1_0); }\n  return v4_1;\n}";
        assert_eq!(unbound_locals(src), ["v2_3", "v4_1"]);
    }

    #[test]
    fn declarations_params_and_assignments_bind() {
        let src = "void f(int v1_0, String v2_0) {\n  String v3_0;\n  v3_0 = v2_0;\n  for (Object v4_0 : xs) {}\n  catch (Exception v5_0) {}\n  use(v1_0, v3_0, v4_0, v5_0);\n}";
        assert!(unbound_locals(src).is_empty());
    }

    #[test]
    fn comments_and_strings_do_not_count() {
        let src = "// v9_9 here\n/* v8_8 */ String s = \"v7_7 \\\" v6_6\"; char c = 'v';\nint v1_0 = 0; use(v1_0);";
        assert!(unbound_locals(src).is_empty());
    }

    #[test]
    fn duplicated_loop_body_is_not_detected() {
        // Documented ceiling: every name stays bound.
        let src = "int v1_0 = 0;\nwhile (v1_0 < 3) { v1_0 = v1_0 + 1; v1_0 = v1_0 + 1; }";
        assert!(unbound_locals(src).is_empty());
    }
}
