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

/// SSA-local names (`v<reg>_<n>`) that are read in `src` (outside comments and
/// string/char literals) before any binding of the same name in the same
/// method. Sorted, unique.
///
/// A read only counts when no assignment or declaration precedes it *in the
/// method that contains it*: droidsaw numbering restarts per method, and a
/// dropped phi shows up exactly as a use emitted above its definition.
pub fn unbound_locals(src: &str) -> Vec<String> {
    let b = src.as_bytes();
    let mut first_bind: BTreeMap<(u32, &str), usize> = BTreeMap::new();
    let mut first_read: BTreeMap<(u32, &str), usize> = BTreeMap::new();
    let mut prev_ident: Option<&str> = None;
    let mut scope = 0u32;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'\n' {
            i += 1;
            if method_header(&src[i..]) {
                scope += 1;
                prev_ident = None;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
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
                let rest = src[i..].trim_start();
                let r = rest.as_bytes();
                let assigns = rest.starts_with('=') && !rest.starts_with("==");
                let compound =
                    r.get(1) == Some(&b'=') && r.first().is_some_and(|c| b"+-*/%&|^".contains(c));
                let inc_dec = rest.starts_with("++") || rest.starts_with("--");
                let declared = prev_ident.is_some_and(|p| !EXPR_KEYWORDS.contains(&p));
                let key = (scope, id);
                if assigns || compound || inc_dec || declared {
                    first_bind.entry(key).or_insert(s);
                } else {
                    first_read.entry(key).or_insert(s);
                }
            }
            prev_ident = Some(id);
        } else {
            if c == b']' || c == b'>' {
                prev_ident = Some("");
            } else if !c.is_ascii_whitespace() {
                prev_ident = None;
            }
            i += 1;
        }
    }
    let mut out: BTreeSet<&str> = BTreeSet::new();
    for (key, read) in &first_read {
        if first_bind.get(key).is_none_or(|bind| bind > read) {
            out.insert(key.1);
        }
    }
    out.into_iter().map(String::from).collect()
}

/// True when `rest` starts with the body of a method signature
/// (`Type name(params) {`, a constructor, or `name(params) throws … {`).
fn method_header(rest: &str) -> bool {
    let line = rest.split('\n').next().unwrap_or("");
    if !line.starts_with("    ") || !line.trim_end().ends_with('{') {
        return false;
    }
    let head = match line.trim_start().split_once('(') {
        Some((head, _)) => head,
        None => return false,
    };
    if head.split_whitespace().next().is_some_and(|w| {
        matches!(
            w,
            "if" | "for" | "while" | "switch" | "catch" | "else" | "do" | "try" | "synchronized"
        )
    }) {
        return false;
    }
    head.bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"_$.,<>[]? ".contains(&c))
}

/// Size of the largest group of structurally identical `catch` bodies
/// in `src` (whitespace-normalized), or 0 when every body is unique.
/// Bodies under 48 chars are ignored — trivial rethrows legitimately
/// repeat.
///
/// droidsaw-dex 2.0.0 can copy a *shared* handler tail (the DEX encodes
/// several guarded ranges whose handler stubs converge into one tail
/// that the normal path also reaches) into each emitted `catch`. The
/// result reads as N nested catches with identical bodies. This
/// heuristic flags exactly that shape; a `0` is not proof of absence.
pub fn duplicated_catch_bodies(src: &str) -> usize {
    let b = src.as_bytes();
    let mut bodies: Vec<String> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        // Skip comments and string/char literals so a "catch" inside
        // text never counts.
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i = src[i + 2..].find("*/").map_or(b.len(), |p| i + 2 + p + 2);
        } else if c == b'"' || c == b'\'' {
            let q = c;
            i += 1;
            while i < b.len() && b[i] != q {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
        } else if c.is_ascii_alphabetic() {
            let s = i;
            while i < b.len() && b[i].is_ascii_alphanumeric() {
                i += 1;
            }
            if &src[s..i] == "catch"
                && let Some(open) = src[i..].find('{')
                && src[i..i + open].contains(')')
            {
                // Balanced-brace body extraction.
                let start = i + open;
                let mut depth = 0usize;
                let mut j = start;
                while j < b.len() {
                    match b[j] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                if j < b.len() {
                    let normalized = src[start + 1..j]
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    if normalized.len() >= 48 {
                        bodies.push(normalized);
                    }
                    i = j + 1;
                    continue;
                }
            }
        } else {
            i += 1;
        }
    }
    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for body in &bodies {
        *counts.entry(body.as_str()).or_default() += 1;
    }
    counts
        .values()
        .copied()
        .filter(|c| *c >= 2)
        .max()
        .unwrap_or(0)
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
    fn read_before_assignment_is_flagged() {
        // Real shape (org.bouncycastle.jce.spec.ECNamedCurveSpec): the int is
        // read by a `super(...)` argument and only assigned afterwards.
        let src = "    public ECNamedCurveSpec(String v1, BigInteger v5) {\n        super(v2, v3, v4, v5_6);\n        int v5_6 = v5.intValue();\n    }";
        assert_eq!(unbound_locals(src), ["v5_6"]);
    }

    #[test]
    fn assignment_in_another_method_does_not_bind() {
        let src = "    void a() {\n        int v1_0 = 1;\n        use(v1_0);\n    }\n    void b() {\n        use(v1_0);\n    }";
        assert_eq!(unbound_locals(src), ["v1_0"]);
    }

    #[test]
    fn array_and_generic_declarations_bind() {
        let src = "    void f(int[] v1_0, java.util.Map<String, Integer> v2_0) {\n        use(v1_0, v2_0);\n        long[] v3_4;\n        use(v3_4);\n    }";
        assert!(unbound_locals(src).is_empty());
    }

    #[test]
    fn compound_and_incdec_assignments_bind() {
        let src = "    void f() {\n        int v1_0 = 0;\n        v1_0 += 2;\n        v1_0++;\n        use(v1_0);\n    }";
        assert!(unbound_locals(src).is_empty());
    }

    #[test]
    fn loop_header_read_after_declaration_is_bound() {
        let src = "    void f() {\n        int v1_0 = 0;\n        while (v1_0 < 3) { v1_0 = v1_0 + 1; }\n    }";
        assert!(unbound_locals(src).is_empty());
    }

    #[test]
    fn method_header_skips_control_statements() {
        assert!(method_header("    public void f() {"));
        assert!(method_header("    ECNamedCurveSpec(String v1) throws X {"));
        assert!(!method_header("        if (v1 == null) {"));
        assert!(!method_header("        synchronized (this) {"));
        assert!(!method_header("    private int x = 1;"));
    }

    #[test]
    fn duplicated_loop_body_is_not_detected() {
        // Documented ceiling: every name stays bound.
        let src = "int v1_0 = 0;\nwhile (v1_0 < 3) { v1_0 = v1_0 + 1; v1_0 = v1_0 + 1; }";
        assert!(unbound_locals(src).is_empty());
    }
    #[test]
    fn identical_catch_bodies_are_counted() {
        let body = " Log.get().e(\"tag\", \"msg\", v0_1); v0_2.recordException(v0_1); int v3 = fallback(); return render(v3); ";
        let src = format!(
            "void f() {{ try {{ a(); }} catch (Exception e) {{{body}}} try {{ b(); }} catch (Exception e) {{{body}}} try {{ c(); }} catch (Exception e) {{{body}}} }}"
        );
        assert_eq!(duplicated_catch_bodies(&src), 3);
    }

    #[test]
    fn distinct_catch_bodies_are_not_flagged() {
        let src = "void f() { try { a(); } catch (A e) { doA(e); } catch (B e) { doB(e); } }";
        assert_eq!(duplicated_catch_bodies(src), 0);
    }

    #[test]
    fn catch_keyword_in_text_is_ignored() {
        let src =
            "String s = \"catch (Exception e) { identical identical identical }\"; char c = 'x';";
        assert_eq!(duplicated_catch_bodies(src), 0);
    }

    #[test]
    fn trivial_short_bodies_are_ignored() {
        let src = "void f() { try { a(); } catch (A e) { } catch (B e) { } }";
        assert_eq!(duplicated_catch_bodies(src), 0);
    }
}
