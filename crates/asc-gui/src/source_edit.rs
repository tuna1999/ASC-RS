//! Method-scoped Java source editing — port of the oracle's
//! `asc_client/gui/source_edit.py` (identifier lookup, enclosing-method
//! detection, in-method rename / occurrence scan).
//!
//! All offsets are BYTE offsets into the document source. Identifiers
//! are ASCII `[A-Za-z_$][A-Za-z0-9_$]*` (the oracle also accepted
//! Unicode alphanumerics; droidsaw emits ASCII, so byte scanning is
//! safe — UTF-8 continuation bytes never collide with ASCII tests).

/// Prefixes that mark a `{` as a control-flow block, not a method body.
const BLOCK_PREFIXES: [&str; 13] = [
    "if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(", "catch ", "catch(",
    "else", "try", "do",
];

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$'
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn rfind_byte(bytes: &[u8], needle: u8, upto: usize) -> Option<usize> {
    (0..upto).rev().find(|&i| bytes[i] == needle)
}

fn find_byte(bytes: &[u8], needle: u8, from: usize, to: usize) -> Option<usize> {
    (from..to).find(|&i| bytes[i] == needle)
}

/// Whether `s` is a plain Java identifier.
pub fn is_identifier(s: &str) -> bool {
    let b = s.as_bytes();
    match b.first() {
        Some(&c) if is_ident_start(c) => {}
        _ => return false,
    }
    b[1..].iter().all(|&c| is_ident(c))
}

/// Identifier (byte range) containing `off`. When `off` sits on a
/// non-identifier byte, steps back one byte (Tk cursor semantics).
pub fn token_at(text: &str, off: usize) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    if b.is_empty() {
        return None;
    }
    let mut off = off.min(b.len() - 1);
    if !is_ident(b[off]) {
        if off > 0 && is_ident(b[off - 1]) {
            off -= 1;
        } else {
            return None;
        }
    }
    let mut start = off;
    while start > 0 && is_ident(b[start - 1]) {
        start -= 1;
    }
    let mut end = off + 1;
    while end < b.len() && is_ident(b[end]) {
        end += 1;
    }
    if !is_ident_start(b[start]) {
        return None;
    }
    Some((start, end))
}

/// Close brace for the `{` at `open`, skipping comments, strings and
/// char literals. Port of `_matching_brace`.
pub fn matching_brace(text: &str, open: usize) -> Option<usize> {
    #[derive(PartialEq)]
    enum St {
        Code,
        LineComment,
        BlockComment,
        Str,
        Char,
    }
    let b = text.as_bytes();
    let mut depth = 0i32;
    let mut state = St::Code;
    let mut i = open;
    while i < b.len() {
        let ch = b[i];
        let nxt = b.get(i + 1).copied();
        match state {
            St::Code => {
                if ch == b'/' && nxt == Some(b'/') {
                    state = St::LineComment;
                    i += 2;
                    continue;
                }
                if ch == b'/' && nxt == Some(b'*') {
                    state = St::BlockComment;
                    i += 2;
                    continue;
                }
                if ch == b'"' {
                    state = St::Str;
                    i += 1;
                    continue;
                }
                if ch == b'\'' {
                    state = St::Char;
                    i += 1;
                    continue;
                }
                if ch == b'{' {
                    depth += 1;
                } else if ch == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
            }
            St::LineComment => {
                if ch == b'\n' {
                    state = St::Code;
                }
            }
            St::BlockComment => {
                if ch == b'*' && nxt == Some(b'/') {
                    state = St::Code;
                    i += 2;
                    continue;
                }
            }
            St::Str | St::Char => {
                let close = if state == St::Str { b'"' } else { b'\'' };
                if ch == b'\\' {
                    i += 2;
                    continue;
                }
                if ch == close {
                    state = St::Code;
                }
            }
        }
        i += 1;
    }
    None
}

fn looks_like_method_prefix(prefix: &str) -> bool {
    if prefix.is_empty() || BLOCK_PREFIXES.iter().any(|p| prefix.starts_with(p)) {
        return false;
    }
    if !prefix.contains('(') || !prefix.contains(')') {
        return false;
    }
    if prefix.ends_with('=') || prefix.ends_with('.') || prefix.ends_with(',') {
        return false;
    }
    true
}

/// Fast path: `off` sits on a method's signature line.
fn method_range_from_signature_line(text: &str, off: usize) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    let line_start = rfind_byte(b, b'\n', off).map_or(0, |i| i + 1);
    let line_end = find_byte(b, b'\n', off, b.len()).unwrap_or(b.len());
    let current_line = &text[line_start..line_end];
    if !current_line.contains('(') || !current_line.contains(')') {
        return None;
    }

    let search_end = (line_end + 1).min(b.len());
    let mut open_brace = find_byte(b, b'{', line_start, search_end);
    if open_brace.is_none() {
        // Brace alone on the next line.
        let next_line_end = find_byte(b, b'\n', line_end + 1, b.len()).unwrap_or(b.len());
        if text[line_end + 1..next_line_end].trim() != "{" {
            return None;
        }
        open_brace = find_byte(b, b'{', line_end + 1, (next_line_end + 1).min(b.len()));
    }
    let open_brace = open_brace?;
    let prefix = text[line_start..open_brace].trim();
    if !looks_like_method_prefix(prefix) {
        return None;
    }
    let end = matching_brace(text, open_brace)?;
    Some((line_start, end + 1))
}

/// Byte range of the method enclosing `off` (signature line start …
/// closing brace + 1). Port of `find_method_range`.
pub fn find_method_range(text: &str, off: usize) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    let off = off.min(b.len());
    if let Some(r) = method_range_from_signature_line(text, off) {
        return Some(r);
    }
    let mut brace = rfind_byte(b, b'{', off + 1);
    while let Some(br) = brace {
        // Prefix on the brace's line (or the previous non-empty line).
        let line_start = rfind_byte(b, b'\n', br).map_or(0, |i| i + 1);
        let mut prefix = text[line_start..br].trim().to_string();
        if prefix.is_empty() {
            if line_start == 0 {
                return None;
            }
            let prev_end = line_start - 1;
            let prev_start = rfind_byte(b, b'\n', prev_end).map_or(0, |i| i + 1);
            prefix = text[prev_start..prev_end].trim().to_string();
        }
        if looks_like_method_prefix(&prefix) {
            if let Some(end) = matching_brace(text, br) {
                if br <= off && off <= end {
                    return Some((line_start, end + 1));
                }
            }
        }
        brace = if br == 0 {
            None
        } else {
            rfind_byte(b, b'{', br)
        };
    }
    None
}

/// Identifier tokens in `start..end` that live in real code (skips
/// comments, strings and char literals). Port of the shared scan loop
/// of `identifier_occurrences_in_range` / `rename_identifier_in_range`.
fn ident_tokens_in_range(text: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    #[derive(PartialEq)]
    enum St {
        Code,
        LineComment,
        BlockComment,
        Str,
        Char,
    }
    let b = text.as_bytes();
    let end = end.min(b.len());
    let start = start.min(end);
    let mut out = Vec::new();
    let mut state = St::Code;
    let mut i = start;
    while i < end {
        let ch = b[i];
        let nxt = b.get(i + 1).copied();
        match state {
            St::Code => {
                if ch == b'/' && nxt == Some(b'/') {
                    state = St::LineComment;
                    i += 2;
                    continue;
                }
                if ch == b'/' && nxt == Some(b'*') {
                    state = St::BlockComment;
                    i += 2;
                    continue;
                }
                if ch == b'"' {
                    state = St::Str;
                    i += 1;
                    continue;
                }
                if ch == b'\'' {
                    state = St::Char;
                    i += 1;
                    continue;
                }
                if is_ident_start(ch) {
                    let tok_start = i;
                    i += 1;
                    while i < end && is_ident(b[i]) {
                        i += 1;
                    }
                    out.push((tok_start, i));
                    continue;
                }
            }
            St::LineComment => {
                if ch == b'\n' {
                    state = St::Code;
                }
            }
            St::BlockComment => {
                if ch == b'*' && nxt == Some(b'/') {
                    state = St::Code;
                    i += 2;
                    continue;
                }
            }
            St::Str | St::Char => {
                let close = if state == St::Str { b'"' } else { b'\'' };
                if ch == b'\\' {
                    i += 2;
                    continue;
                }
                if ch == close {
                    state = St::Code;
                }
            }
        }
        i += 1;
    }
    out
}

/// Byte ranges of `name` occurrences (code state only) in `start..end`.
pub fn occurrences_in_range(
    text: &str,
    start: usize,
    end: usize,
    name: &str,
) -> Vec<(usize, usize)> {
    ident_tokens_in_range(text, start, end)
        .into_iter()
        .filter(|&(s, e)| &text[s..e] == name)
        .collect()
}

/// Rename every code-state occurrence of `old` inside `start..end` to
/// `new`. `None` when the range contains no occurrence.
pub fn rename_in_range(
    text: &str,
    start: usize,
    end: usize,
    old: &str,
    new: &str,
) -> Option<String> {
    let hits = occurrences_in_range(text, start, end, old);
    if hits.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..start]);
    let mut last = start;
    for (s, e) in hits {
        out.push_str(&text[last..s]);
        out.push_str(new);
        last = e;
    }
    out.push_str(&text[last..end]);
    out.push_str(&text[end..]);
    Some(out)
}

/// Append a `// <comment>` note to the end of the line starting at
/// `line_start` (F26 per-line annotation; persisted by rebuilding the
/// document).
pub fn append_line_comment(source: &str, line_start: usize, comment: &str) -> String {
    let b = source.as_bytes();
    let line_start = line_start.min(b.len());
    let line_end = b[line_start..]
        .iter()
        .position(|&c| c == b'\n')
        .map(|i| line_start + i)
        .unwrap_or(b.len());
    let content_end = source[..line_end].trim_end().len();
    let mut out = String::with_capacity(source.len() + comment.len() + 6);
    out.push_str(&source[..content_end]);
    out.push_str("  // ");
    out.push_str(comment);
    out.push_str(&source[line_end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "public class A {\n    int field;\n    void run(int px) {\n        int q = px + 1;\n        log(\"px in string\"); // px in comment\n    }\n}\n";

    #[test]
    fn token_at_finds_full_identifier() {
        // "px" parameter use on line 3: "        int q = px + 1;"
        let line3 = SRC.lines().nth(3).unwrap();
        let off = line3.find("px").unwrap();
        assert_eq!(token_at(line3, off + 1), Some((off, off + 2)));
    }

    #[test]
    fn token_at_steps_back_on_punctuation() {
        let line3 = SRC.lines().nth(3).unwrap();
        let off = line3.find("px").unwrap();
        assert_eq!(token_at(line3, off + 2), Some((off, off + 2))); // on the space after
        assert_eq!(token_at(line3, 0), None); // on whitespace at line start
    }

    #[test]
    fn is_identifier_rules() {
        assert!(is_identifier("foo"));
        assert!(is_identifier("$bar_1"));
        assert!(!is_identifier("1foo"));
        assert!(!is_identifier(""));
        assert!(!is_identifier("a-b"));
    }

    #[test]
    fn matching_brace_skips_strings_and_comments() {
        let t = "void m() { s(\"}{\"); /* } */ if (x) { } } tail";
        let open = t.find('{').unwrap();
        let close = matching_brace(t, open).unwrap();
        assert_eq!(&t[close..close + 6], "} tail");
    }

    #[test]
    fn find_method_range_prefers_innermost_method_not_blocks() {
        let t = "class C {\n    void m() {\n        if (x) {\n            foo();\n        }\n    }\n}\n";
        let off = t.find("foo").unwrap();
        let (start, end) = find_method_range(t, off).unwrap();
        assert!(t[start..].starts_with("    void m()"));
        assert_eq!(&t[end - 1..end], "}");
    }
    #[test]
    fn matching_brace_nested_and_line_comment() {
        let t = "a { b { c } // }\n} done";
        let open = t.find('{').unwrap();
        let close = matching_brace(t, open).unwrap();
        assert_eq!(&t[close..close + 1], "}");
    }

    #[test]
    fn find_method_range_from_body() {
        // Offset inside the method body (the "log(" call line).
        let off = SRC.find("log(").unwrap();
        let (start, end) = find_method_range(SRC, off).unwrap();
        assert!(SRC[start..].starts_with("    void run("));
        assert_eq!(&SRC[end - 5..end], "    }"); // range ends just past the closing brace
    }

    #[test]
    fn find_method_range_from_signature_line() {
        let off = SRC.find("void run").unwrap();
        let (start, _) = find_method_range(SRC, off).unwrap();
        assert!(SRC[start..].starts_with("    void run("));
    }

    #[test]
    fn occurrences_skip_strings_and_comments() {
        let (start, end) = find_method_range(SRC, SRC.find("log(").unwrap()).unwrap();
        let occ = occurrences_in_range(SRC, start, end, "px");
        // Parameter decl + real use; NOT the string literal or comment.
        assert_eq!(occ.len(), 2);
        assert_eq!(&SRC[occ[0].0..occ[0].1], "px");
    }

    #[test]
    fn rename_only_within_range_and_code_state() {
        let (start, end) = find_method_range(SRC, SRC.find("log(").unwrap()).unwrap();
        let renamed = rename_in_range(SRC, start, end, "px", "width").unwrap();
        assert!(renamed.contains("void run(int width)"));
        assert!(renamed.contains("int q = width + 1;"));
        assert!(renamed.contains("\"px in string\"")); // string untouched
        assert!(renamed.contains("// px in comment")); // comment untouched
        assert!(renamed.contains("int field;")); // outside range untouched
    }

    #[test]
    fn rename_no_occurrence_is_none() {
        assert!(rename_in_range(SRC, 0, SRC.len(), "zzz", "q").is_none());
    }

    #[test]
    fn append_comment_preserves_following_lines() {
        let line3 = SRC.lines().nth(3).unwrap();
        let start = SRC.find(line3).unwrap();
        let out = append_line_comment(SRC, start, "note");
        assert!(out.contains("int q = px + 1;  // note\n"));
        assert!(out.ends_with("}\n"));
    }
}
