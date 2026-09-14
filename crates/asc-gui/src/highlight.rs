//! Java-ish syntax highlighting and class-outline extraction for the
//! decompiled source view (jadx-style code panel).
//!
//! droidsaw emits plain Java-like text. We color it with a small
//! line-local tokenizer — good enough for reading, no full parser:
//! `//` and `/* */` comments, string/char literals, `@Annotations`,
//! keywords, modifiers, numeric literals, and capitalized type names.
//! Block comments spanning lines are tracked across lines.
//!
//! [`outline`] extracts the class structure (fields, constructors,
//! methods, nested classes) with their line numbers for the right-hand
//! outline panel and click-to-jump navigation.

/// Syntax flavor of a token span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    Keyword,
    Modifier,
    Type,
    Annotation,
    String,
    Number,
    Comment,
    Plain,
}

/// One syntax span: byte range within a line + token flavor.
pub type Span = (usize, usize, Token);

/// Java keywords (types like `int` count as keywords; identifiers that
/// happen to be lowercase stay plain).
const KEYWORDS: &[&str] = &[
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    "true",
    "false",
    "null",
];

/// Tokenize one line into spans (byte ranges + flavor). `in_block_comment`
/// carries `/* */` state across lines (updated in place).
pub fn tokenize_line(line: &str, in_block_comment: &mut bool) -> Vec<(usize, usize, Token)> {
    let b = line.as_bytes();
    let mut spans: Vec<(usize, usize, Token)> = Vec::new();
    let mut i = 0usize;
    let mut plain_start = 0usize;
    let flush_plain = |spans: &mut Vec<(usize, usize, Token)>, end: usize, start: usize| {
        if end > start {
            spans.push((start, end, Token::Plain));
        }
    };

    while i < b.len() {
        if *in_block_comment {
            // Inside `/* … */`: the rest of the line is comment unless
            // a `*/` closer appears.
            match find_block_close(b, i) {
                Some(end) => {
                    spans.push((i, end, Token::Comment));
                    i = end;
                    plain_start = i;
                    *in_block_comment = false;
                }
                None => {
                    spans.push((i, b.len(), Token::Comment));
                    return spans; // still inside the block comment
                }
            }
            continue;
        }
        match b[i] {
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                flush_plain(&mut spans, i, plain_start);
                spans.push((i, b.len(), Token::Comment));
                return spans;
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                flush_plain(&mut spans, i, plain_start);
                spans.push((i, b.len(), Token::Comment));
                *in_block_comment = true;
                return spans;
            }
            b'"' => {
                flush_plain(&mut spans, i, plain_start);
                let mut j = i + 1;
                while j < b.len() {
                    if b[j] == b'\\' {
                        j += 2;
                    } else if b[j] == b'"' {
                        j += 1;
                        break;
                    } else {
                        j += 1;
                    }
                }
                let end = j.min(b.len());
                spans.push((i, end, Token::String));
                i = end;
                plain_start = i;
            }
            b'\'' => {
                flush_plain(&mut spans, i, plain_start);
                let mut j = i + 1;
                while j < b.len() {
                    if b[j] == b'\\' {
                        j += 2;
                    } else if b[j] == b'\'' {
                        j += 1;
                        break;
                    } else {
                        j += 1;
                    }
                }
                let end = j.min(b.len());
                spans.push((i, end, Token::String));
                i = end;
                plain_start = i;
            }
            b'@' if i + 1 < b.len() && (b[i + 1].is_ascii_alphabetic() || b[i + 1] == b'_') => {
                flush_plain(&mut spans, i, plain_start);
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'.')
                {
                    j += 1;
                }
                spans.push((i, j, Token::Annotation));
                i = j;
                plain_start = i;
            }
            c if c.is_ascii_digit() && (i == 0 || !is_ident_byte(b[i - 1])) => {
                flush_plain(&mut spans, i, plain_start);
                let mut j = i;
                while j < b.len()
                    && (b[j].is_ascii_alphanumeric()
                        || b[j] == b'.'
                        || b[j] == b'_'
                        || b[j] == b'x'
                        || b[j] == b'X'
                        || ((b[j] == b'+' || b[j] == b'-')
                            && j > i
                            && (b[j - 1] == b'e' || b[j - 1] == b'E')))
                {
                    j += 1;
                }
                spans.push((i, j, Token::Number));
                i = j;
                plain_start = i;
            }
            c if c.is_ascii_alphabetic() || c == b'_' || c == b'$' => {
                let mut j = i;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'$')
                {
                    j += 1;
                }
                let word = &line[i..j];
                let tok = if KEYWORDS.contains(&word) {
                    Token::Keyword
                } else if b[i].is_ascii_uppercase() {
                    Token::Type
                } else {
                    Token::Plain
                };
                if tok != Token::Plain {
                    flush_plain(&mut spans, i, plain_start);
                    spans.push((i, j, tok));
                    plain_start = j;
                }
                i = j;
            }
            _ => {
                i += 1;
            }
        }
    }
    flush_plain(&mut spans, b.len(), plain_start);
    spans
}

/// Find the end of a block comment: index just past the first `*/`
/// at or after `from`.
fn find_block_close(b: &[u8], from: usize) -> Option<usize> {
    let mut j = from;
    while j + 1 < b.len() {
        if b[j] == b'*' && b[j + 1] == b'/' {
            return Some(j + 2);
        }
        j += 1;
    }
    None
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

/// One outline entry (method / field / nested class) with its line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutlineEntry {
    /// Display text (`void onClick(View)`, `int mClock`).
    pub text: String,
    /// 0-based line index in the source.
    pub line: usize,
    /// True for fields (no parentheses), false for methods.
    pub is_field: bool,
}

/// Extract a class outline from decompiled source. Heuristic, tuned to
/// droidsaw's output shape: declarations are top-level (indent of 0, 2,
/// or 4 spaces) and contain `(` (methods) or end with `;` (fields).
pub fn outline(source: &str) -> Vec<OutlineEntry> {
    let mut out = Vec::new();
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        // Only shallow indentation (class members; droidsaw indents
        // nested bodies deeper).
        let indent = line.len() - trimmed.len();
        if indent > 4 {
            continue;
        }
        if trimmed.contains('(') {
            // Method-ish: skip control flow and call statements. The
            // leading alphabetic word (`if` from `if (x)`, `if(x)`)
            // decides; the full signature is kept for display.
            let lead: String = trimmed
                .chars()
                .take_while(|c| c.is_ascii_alphabetic())
                .collect();
            if matches!(
                lead.as_str(),
                "if" | "for"
                    | "while"
                    | "switch"
                    | "catch"
                    | "return"
                    | "throw"
                    | "else"
                    | "do"
                    | "try"
                    | "synchronized"
                    | "new"
            ) {
                continue;
            }
            let text = trim_to_width(trimmed.trim_end_matches('{').trim(), 60);
            if text.is_empty() {
                continue;
            }
            out.push(OutlineEntry {
                text,
                line: idx,
                is_field: false,
            });
        } else if trimmed.ends_with(';') && !trimmed.contains('=') {
            // Field: `int mClock;` / `private final String name;`.
            let text = trimmed.trim_end_matches(';').trim().to_string();
            if text.is_empty() || text.starts_with("import") || text.starts_with("package") {
                continue;
            }
            let words: Vec<&str> = text.split_whitespace().collect();
            if words.len() < 2 {
                continue; // lone identifier — likely not a field decl
            }
            out.push(OutlineEntry {
                text: trim_to_width(&text, 60),
                line: idx,
                is_field: true,
            });
        }
    }
    out
}

/// Clamp a display string to `max` chars (ellipsize the head).
fn trim_to_width(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
package com.example;

import java.util.List;
@Deprecated
public class Foo extends Bar {
    private int count;
    static final String NAME = \"x\";

    public Foo(int count) {
        this.count = count;
    }

    public void run(String[] args) throws Exception {
        if (count > 0) {
            doWork(1, 2);
        }
    }

    /* block comment
       spanning lines */
    int after;
}
";

    #[test]
    fn outline_finds_fields_and_methods_not_statements() {
        let o = outline(SAMPLE);
        let texts: Vec<&str> = o.iter().map(|e| e.text.as_str()).collect();
        assert!(
            texts.iter().any(|t| t.ends_with("private int count")),
            "{texts:?}"
        );
        assert!(texts.iter().any(|t| t.ends_with("int after")), "{texts:?}");
        assert!(
            texts.iter().any(|t| t.ends_with("public Foo(int count)")),
            "constructor present: {texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|t| t.contains("public void run(String[] args")),
            "method present: {texts:?}"
        );
        assert!(
            !texts.iter().any(|t| t.contains("doWork")),
            "call not member"
        );
        assert!(
            !texts.iter().any(|t| t.contains("if (count")),
            "control flow skipped"
        );
        assert!(
            !texts.iter().any(|t| t.contains("NAME")),
            "initialized constant skipped"
        );
        assert!(
            !texts.iter().any(|t| t.contains("package com")),
            "package skipped"
        );
    }

    #[test]
    fn outline_lines_index_from_zero() {
        let o = outline(SAMPLE);
        let ctor = o.iter().find(|e| e.text.contains("Foo(int")).unwrap();
        assert_eq!(
            SAMPLE.lines().nth(ctor.line),
            Some("    public Foo(int count) {")
        );
    }

    #[test]
    fn tokenize_colors_the_expected_spans() {
        let mut block = false;
        let spans = tokenize_line("public int x = 42; // tail", &mut block);
        assert!(!block);
        let flavors: Vec<Token> = spans.iter().map(|s| s.2).collect();
        assert!(
            flavors.contains(&Token::Keyword),
            "public/int colored: {flavors:?}"
        );
        assert!(flavors.contains(&Token::Number), "42 colored: {flavors:?}");
        assert!(
            flavors.contains(&Token::Comment),
            "comment colored: {flavors:?}"
        );

        let spans = tokenize_line("@Override", &mut block);
        assert_eq!(spans[0].2, Token::Annotation);

        let spans = tokenize_line("String s = \"hi\";", &mut block);
        let flavors: Vec<Token> = spans.iter().map(|s| s.2).collect();
        assert!(
            flavors.contains(&Token::Type),
            "String is a Type: {flavors:?}"
        );
        assert!(
            flavors.contains(&Token::String),
            "literal colored: {flavors:?}"
        );
    }

    #[test]
    fn block_comment_state_carries_across_lines() {
        let mut block = false;
        let _ = tokenize_line("int a; /* start", &mut block);
        assert!(block, "inside block comment");
        let spans = tokenize_line("still comment", &mut block);
        assert_eq!(spans[0].2, Token::Comment);
        let _ = tokenize_line("end */ int b;", &mut block);
        assert!(!block, "closed");
        let spans = tokenize_line("int c;", &mut block);
        let flavors: Vec<Token> = spans.iter().map(|s| s.2).collect();
        assert!(!flavors.contains(&Token::Comment));
    }

    #[test]
    fn escaped_quote_does_not_end_string() {
        let mut block = false;
        let spans = tokenize_line(r#"String s = "a\"b"; int x;"#, &mut block);
        let flavors: Vec<Token> = spans.iter().map(|s| s.2).collect();
        assert!(flavors.contains(&Token::String));
        assert!(flavors.contains(&Token::Keyword));
    }
}
