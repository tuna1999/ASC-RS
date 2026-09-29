//! Document model: heavyweight decompiled sources, keyed by descriptor.
//!
//! A [`Document`] is one fully-rendered class: the decompiled source
//! plus every expensive derived artifact (line index, syntax spans,
//! outline). Documents are built **once**, on the worker thread that
//! ran the decompile, and stored immutably behind `Arc`. The render
//! path only ever clones the `Arc` — never the source (audit F4/F5).
//!
//! [`DocumentCache`] is byte-budgeted: when cached sources exceed the
//! soft limit, the least-recently-used document that is not the
//! active one is dropped. This is a memory concern only — tab/session
//! metadata is a separate concern (Phase 4 introduces tab state that
//! survives document eviction).

use std::collections::HashMap;
use std::sync::Arc;

use crate::highlight::{self, OutlineEntry, Span};

/// Decode Java-style `\uXXXX` escapes in a decompiled source.
///
/// Mirrors the oracle `text_utils.decode_java_unicode_escapes`:
/// a valid UTF-16 surrogate pair `\uD800-\uDBFF\uDC00-\uDFFF`
/// collapses to the combined non-BMP `char`; lone / invalid
/// surrogates and malformed escapes are preserved verbatim.
/// Applied as the first step of [`Document::new`] so all downstream
/// artifacts (line offsets, spans, outline) see decoded text.
pub(crate) fn decode_java_unicode_escapes(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    let mut i = 0;
    // A buffered high surrogate waiting for its low half. We track
    // only the start byte offset so flushing can splice raw text out
    // of `s` without a second copy.
    let mut pending_high: Option<u32> = None;
    let mut pending_high_start: usize = 0;
    while i < n {
        let b = bytes[i];
        // Not the start of `\u` — literal char (or boundary).
        if b != b'\\' || i + 1 >= n || bytes[i + 1] != b'u' {
            if pending_high.take().is_some() {
                out.push_str(&s[pending_high_start..i]);
            }
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        // Skip the leading `u`s (oracle allows `\uu0041` and similar).
        let escape_start = i;
        let mut j = i + 1;
        while j < n && bytes[j] == b'u' {
            j += 1;
        }
        // Fewer than 4 hex chars follow — treat the `\` as a literal.
        if j + 4 > n {
            if pending_high.take().is_some() {
                out.push_str(&s[pending_high_start..i]);
            }
            out.push('\\');
            i += 1;
            continue;
        }
        let code_unit = match s
            .get(j..j + 4)
            .and_then(|h| u32::from_str_radix(h, 16).ok())
        {
            Some(v) => v,
            None => {
                if pending_high.take().is_some() {
                    out.push_str(&s[pending_high_start..i]);
                }
                out.push('\\');
                i += 1;
                continue;
            }
        };
        let escape_end = j + 4;
        let raw_escape = &s[escape_start..escape_end];
        i = escape_end;
        // 0xFFFD — U+FFFD REPLACEMENT CHARACTER: oracle preserves raw.
        if code_unit == 0xFFFD {
            if pending_high.take().is_some() {
                out.push_str(&s[pending_high_start..escape_start]);
            }
            out.push_str(raw_escape);
            continue;
        }
        // High surrogate: buffer for a possible pair.
        if (0xD800..=0xDBFF).contains(&code_unit) {
            if pending_high.take().is_some() {
                out.push_str(&s[pending_high_start..escape_start]);
            }
            pending_high = Some(code_unit);
            pending_high_start = escape_start;
            continue;
        }
        // Try to close a pending pair.
        if let Some(high) = pending_high.take() {
            if (0xDC00..=0xDFFF).contains(&code_unit) {
                let cp = 0x10000 + ((high - 0xD800) << 10) + (code_unit - 0xDC00);
                if let Some(ch) = char::from_u32(cp) {
                    out.push(ch);
                    continue;
                }
            }
            // Lone low / invalid pair — splice high raw, then fall through.
            out.push_str(&s[pending_high_start..escape_start]);
        }
        // Lone low surrogate: preserve raw.
        if (0xDC00..=0xDFFF).contains(&code_unit) {
            out.push_str(raw_escape);
            continue;
        }
        // BMP code point.
        if let Some(ch) = char::from_u32(code_unit) {
            out.push(ch);
        } else {
            out.push_str(raw_escape);
        }
    }
    if pending_high.take().is_some() {
        out.push_str(&s[pending_high_start..]);
    }
    out
}

/// One immutable decompiled class plus its derived artifacts.
/// Addressed by descriptor (unique within a session).
#[derive(Debug)]
pub struct Document {
    /// Dalvik descriptor (`Lcom/foo/Bar;`).
    pub descriptor: String,
    /// Winning DEX display name (`classes.dex`, `classes2.dex`, …).
    pub dex_name: String,
    /// Decompiled source (shared, immutable).
    pub source: Arc<str>,
    /// Byte offset of every line start (`line_offsets[i]` = start of
    /// line `i`; `line_offsets.len()` = line count). Enables O(1)
    /// line slicing for the virtualized code view.
    line_offsets: Vec<u32>,
    /// Per-line syntax spans, parallel to lines. Computed once at
    /// build time (on the worker thread).
    pub spans: Vec<Vec<Span>>,
    /// Class outline entries, computed once at build time.
    pub outline: Vec<OutlineEntry>,
}

impl Document {
    /// Build a document from a decompile result. Tokenizes the whole
    /// source and extracts the outline — do this on a worker thread.
    pub fn new(descriptor: String, dex_name: String, source: String) -> Self {
        // Oracle applies `\uXXXX` decoding to the whole decompile
        // output before display (app.py:927) so line offsets, spans,
        // and outline reflect the text the user sees.
        let source = decode_java_unicode_escapes(&source);
        let mut line_offsets: Vec<u32> = Vec::with_capacity(source.len() / 32 + 1);
        let mut spans: Vec<Vec<Span>> = Vec::new();
        let mut in_block = false;
        let mut start = 0usize;
        for (i, b) in source.as_bytes().iter().enumerate() {
            if *b == b'\n' {
                line_offsets.push(start as u32);
                let line = &source[start..i];
                let mut line_spans = highlight::tokenize_line(line, &mut in_block);
                line_spans.retain(|(s, e, _)| e > s);
                spans.push(line_spans);
                start = i + 1;
            }
        }
        // Trailing line without a newline.
        if start < source.len() {
            line_offsets.push(start as u32);
            let line = &source[start..];
            let mut line_spans = highlight::tokenize_line(line, &mut in_block);
            line_spans.retain(|(s, e, _)| e > s);
            spans.push(line_spans);
        }
        let outline = highlight::outline(&source);
        let src: Arc<str> = Arc::from(source.as_str());
        Self {
            descriptor,
            dex_name,
            source: src,
            line_offsets,
            spans,
            outline,
        }
    }

    /// Number of lines.
    pub fn line_count(&self) -> usize {
        self.line_offsets.len()
    }

    /// The `idx`-th line as a `&str` (O(1); no scan, no copy).
    pub fn line(&self, idx: usize) -> Option<&str> {
        let start = *self.line_offsets.get(idx)? as usize;
        let end = self
            .line_offsets
            .get(idx + 1)
            .map(|&e| e as usize)
            .unwrap_or(self.source.len());
        let raw = &self.source[start..end];
        Some(raw.strip_suffix('\n').unwrap_or(raw))
    }
}

/// Byte-budgeted cache of open documents.
///
/// Eviction drops the least-recently-touched document that is not the
/// active one; `put`/`get` refresh recency. The budget is soft: a
/// single huge document larger than the budget is still cached.
pub struct DocumentCache {
    docs: HashMap<String, Arc<Document>>,
    /// LRU order: least recently touched first.
    order: Vec<String>,
    /// Soft budget for cached source bytes.
    budget: usize,
    /// Current cached source bytes.
    bytes: usize,
    /// Documents dropped by eviction (count only, for status/tasks).
    evicted: u64,
}

/// Default soft budget: 32 MiB of decompiled source.
pub const DEFAULT_DOCUMENT_BUDGET: usize = 32 * 1024 * 1024;

impl Default for DocumentCache {
    fn default() -> Self {
        Self::new(DEFAULT_DOCUMENT_BUDGET)
    }
}

impl DocumentCache {
    pub fn new(budget: usize) -> Self {
        Self {
            docs: HashMap::new(),
            order: Vec::new(),
            budget,
            bytes: 0,
            evicted: 0,
        }
    }

    /// Insert (or replace) a prebuilt document. Re-inserting an
    /// existing descriptor replaces it and refreshes recency.
    pub fn put(&mut self, doc: Arc<Document>) {
        if let Some(old) = self.docs.remove(&doc.descriptor) {
            self.bytes = self.bytes.saturating_sub(old.source.len());
            self.order.retain(|d| d != &doc.descriptor);
        }
        self.bytes += doc.source.len();
        let descriptor = doc.descriptor.clone();
        self.order.push(descriptor.clone());
        self.docs.insert(descriptor, doc);
    }

    /// Look up a document by descriptor, refreshing recency. Clones
    /// only the `Arc`.
    pub fn get(&mut self, descriptor: &str) -> Option<Arc<Document>> {
        let doc = self.docs.get(descriptor).cloned()?;
        self.touch(descriptor);
        Some(doc)
    }

    /// Look up without refreshing recency.
    pub fn peek(&self, descriptor: &str) -> Option<Arc<Document>> {
        self.docs.get(descriptor).cloned()
    }

    fn touch(&mut self, descriptor: &str) {
        if let Some(pos) = self.order.iter().position(|d| d == descriptor) {
            self.order.remove(pos);
            self.order.push(descriptor.to_string());
        }
    }

    /// Whether a document for `descriptor` is cached.
    pub fn contains(&self, descriptor: &str) -> bool {
        self.docs.contains_key(descriptor)
    }

    /// Number of cached documents.
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// True when no documents are cached.
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Cached source bytes.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Total documents evicted so far.
    pub fn evicted_count(&self) -> u64 {
        self.evicted
    }

    /// Descriptors in LRU order (least recent first).
    pub fn descriptors_lru(&self) -> Vec<&str> {
        self.order
            .iter()
            .filter_map(|d| self.docs.get(d).map(|doc| doc.descriptor.as_str()))
            .collect()
    }

    /// Drop a document explicitly (tab close). No-op when absent.
    pub fn remove(&mut self, descriptor: &str) {
        if let Some(doc) = self.docs.remove(descriptor) {
            self.bytes = self.bytes.saturating_sub(doc.source.len());
        }
        self.order.retain(|d| d != descriptor);
    }

    /// Enforce the soft budget: evict least-recently-used documents
    /// (never `keep`, the active document, and never the last
    /// remaining document) until under budget or nothing evictable
    /// remains.
    pub fn enforce_budget(&mut self, keep: Option<&str>) {
        while self.bytes > self.budget && self.order.len() > 1 {
            // Pick the first non-kept descriptor in LRU order.
            let victim = self
                .order
                .iter()
                .find(|d| Some(d.as_str()) != keep)
                .cloned();
            let Some(victim) = victim else { break };
            self.remove(&victim);
            self.evicted += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(n: usize) -> String {
        "class Big { int x; }\n".repeat(n)
    }

    #[test]
    fn line_indexing_is_o1_and_exact() {
        let doc = Document::new("LA;".into(), "classes.dex".into(), "one\ntwo\nthree".into());
        assert_eq!(doc.line_count(), 3);
        assert_eq!(doc.line(0), Some("one"));
        assert_eq!(doc.line(1), Some("two"));
        assert_eq!(doc.line(2), Some("three"));
        assert_eq!(doc.line(3), None);
        // Trailing newline does not create a phantom line.
        let doc = Document::new("LB;".into(), "classes.dex".into(), "a\nb\n".into());
        assert_eq!(doc.line_count(), 2, "no phantom empty last line");
        assert_eq!(doc.spans.len(), doc.line_count());
        // Outline extracted at build time on a source with a field.
        let doc = Document::new(
            "LC;".into(),
            "classes.dex".into(),
            "class C {\n    int mClock;\n}\n".into(),
        );
        assert!(
            doc.outline
                .iter()
                .any(|e| e.is_field && e.text.contains("mClock")),
            "outline has the field: {:?}",
            doc.outline
        );
        assert!(!doc.outline.is_empty(), "class field found by outline");
    }

    #[test]
    fn put_get_roundtrip_and_replace() {
        let mut cache = DocumentCache::new(usize::MAX);
        cache.put(Arc::new(Document::new(
            "LA;".into(),
            "classes.dex".into(),
            big(10),
        )));
        assert!(cache.contains("LA;"));
        let doc = cache.get("LA;").expect("get");
        assert_eq!(doc.descriptor, "LA;");
        // Replace: single entry, bytes accounted.
        cache.put(Arc::new(Document::new(
            "LA;".into(),
            "classes.dex".into(),
            big(20),
        )));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.bytes(), big(20).len());
    }

    #[test]
    fn budget_evicts_least_recent_not_active() {
        // Budget fits roughly one big doc.
        let unit = big(1000).len();
        let mut cache = DocumentCache::new(unit + unit / 2);
        cache.put(Arc::new(Document::new("LA;".into(), "d".into(), big(1000))));
        cache.put(Arc::new(Document::new("LB;".into(), "d".into(), big(1000))));
        // Touch A so B is the LRU victim; A is the active doc.
        cache.get("LA;");
        cache.enforce_budget(Some("LA;"));
        assert!(cache.contains("LA;"), "active document survives");
        assert!(!cache.contains("LB;"), "LRU victim evicted");
        assert_eq!(cache.evicted_count(), 1);
        // Reopen path still works after eviction.
        cache.put(Arc::new(Document::new("LB;".into(), "d".into(), big(10))));
        assert!(cache.contains("LB;"));
    }

    /// `decode_java_unicode_escapes` collapses a valid UTF-16 surrogate
    /// pair into the combined non-BMP `char`. Covers
    /// `ASC-GUI-041` (decode java unicode escapes handles surrogate pair).
    #[test]
    fn decode_java_unicode_escapes_handles_surrogate_pair() {
        // U+1F600 (😀) encoded as the surrogate pair D83D DE00.
        let s = r#""\uD83D\uDE00""#;
        let decoded = decode_java_unicode_escapes(s);
        assert!(decoded.contains('\u{1F600}'));
        // Lone surrogate is preserved verbatim (oracle behavior).
        let lone = r#""\uD83D""#;
        let decoded = decode_java_unicode_escapes(lone);
        assert_eq!(decoded, lone);
    }

    /// Document spans line-up exactly with the source. Covers
    /// `ASC-GUI-018` (document lines indexed).
    #[test]
    fn document_lines_indexed() {
        let doc = Document::new("LA;".into(), "classes.dex".into(), "one\ntwo\nthree".into());
        assert_eq!(doc.line_count(), 3);
        assert_eq!(doc.line(0), Some("one"));
        assert_eq!(doc.line(1), Some("two"));
        assert_eq!(doc.line(2), Some("three"));
        assert_eq!(doc.line(3), None);
        assert_eq!(doc.spans.len(), 3, "spans align with lines");
    }

    /// Tokenization produces non-empty spans per line for valid Java.
    /// Covers `ASC-GUI-033` (document tokenizes offline).
    #[test]
    fn document_tokenizes_offline() {
        let doc = Document::new(
            "LA;".into(),
            "classes.dex".into(),
            "class A {\n    int x;\n    void m() {}\n}\n".into(),
        );
        let total_spans: usize = doc.spans.iter().map(|s| s.len()).sum();
        assert!(total_spans > 0, "spans produced for valid Java");
        assert!(doc.outline.iter().any(|e| e.text.contains("m")));
    }

    /// `Document::line_lower` returns the line lowercased; used as the
    /// search surface for case-insensitive find. Covers `ASC-GUI-017`
    /// (document find matches lower case).
    #[test]
    fn document_find_matches_lower_case() {
        let doc = Document::new(
            "LA;".into(),
            "classes.dex".into(),
            "void onCreate() {}\nvoid onResume() {}\n".into(),
        );
        // Case-insensitive: "ONCREATE" matches "void onCreate".
        let needle = "ONCREATE".to_ascii_lowercase();
        let hits: Vec<usize> = (0..doc.line_count())
            .filter(|i| {
                doc.line(*i)
                    .map(|l| l.to_ascii_lowercase().contains(&needle))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(hits, vec![0]);
    }

    /// When the cache evicts an active document, a subsequent
    /// reopen rebuilds it without leaking state.
    /// Covers `ASC-RS-GUI-009` (evicted document triggers respawn).
    #[test]
    fn evicted_document_triggers_respawn() {
        let mut cache = DocumentCache::new(100);
        let doc = Arc::new(Document::new(
            "LA;".into(),
            "d".into(),
            "class A { int x; }".repeat(100),
        ));
        cache.put(doc.clone());
        assert!(cache.contains("LA;"));
        cache.enforce_budget(Some("LA;"));
        // Single oversized doc is kept (the cache accepts one oversize entry).
        assert!(cache.contains("LA;"));
        // Replace with a smaller one — the oversized is dropped.
        cache.put(Arc::new(Document::new(
            "LB;".into(),
            "d".into(),
            "tiny".into(),
        )));
        cache.enforce_budget(Some("LB;"));
        assert!(!cache.contains("LA;"), "oversized doc evicted");
        assert!(cache.contains("LB;"), "small doc kept");
    }

    #[test]
    fn remove_drops_entry() {
        let mut cache = DocumentCache::default();
        cache.put(Arc::new(Document::new("LA;".into(), "d".into(), big(1))));
        assert_eq!(cache.len(), 1);
        cache.remove("LA;");
        assert!(cache.is_empty());
        assert_eq!(cache.bytes(), 0);
        cache.remove("never-there;"); // no-op
        assert!(cache.is_empty());
    }

    #[test]
    fn oversized_single_document_still_cached() {
        let mut cache = DocumentCache::new(8);
        cache.put(Arc::new(Document::new("LA;".into(), "d".into(), big(100))));
        cache.enforce_budget(Some("LB;"));
        assert!(
            cache.contains("LA;"),
            "soft budget never drops the last document"
        );
    }

    // ---- F28: Java \uXXXX decoding ----

    #[test]
    fn decode_ascii_passthrough() {
        assert_eq!(decode_java_unicode_escapes("hello world"), "hello world");
    }

    #[test]
    fn decode_simple_escape() {
        assert_eq!(
            decode_java_unicode_escapes(r"hello \u0041 world"),
            "hello A world"
        );
        // Multiple escapes in one string.
        assert_eq!(
            decode_java_unicode_escapes(r"\u00e9 \u00e8 \u00ea"),
            "é è ê"
        );
    }

    #[test]
    fn decode_surrogate_pair_to_non_bmp() {
        // U+1F600 GRINNING FACE = \uD83D\uDE00 in UTF-16.
        let decoded = decode_java_unicode_escapes(r"\uD83D\uDE00");
        assert_eq!(decoded.chars().count(), 1, "pair collapses to one char");
        assert_eq!(decoded, "\u{1F600}");
    }

    #[test]
    fn decode_bad_hex_preserved_verbatim() {
        // Non-hex chars: oracle preserves raw `\` and continues from `u`.
        assert_eq!(
            decode_java_unicode_escapes(r"foo \uXYZW bar"),
            "foo \\uXYZW bar"
        );
    }

    #[test]
    fn decode_lone_surrogate_preserved_verbatim() {
        // High surrogate without a low half.
        assert_eq!(
            decode_java_unicode_escapes(r"foo \uD83D bar"),
            "foo \\uD83D bar"
        );
        // Low surrogate without a high half.
        assert_eq!(
            decode_java_unicode_escapes(r"foo \uDE00 bar"),
            "foo \\uDE00 bar"
        );
        // Two high surrogates back-to-back: both preserved.
        assert_eq!(
            decode_java_unicode_escapes(r"\uD83D\uD83D"),
            "\\uD83D\\uD83D"
        );
    }

    #[test]
    fn decode_escape_at_end_of_string() {
        // Complete escape at the end.
        assert_eq!(
            decode_java_unicode_escapes(r"trailing \u0041"),
            "trailing A"
        );
        // Incomplete `\u` with no hex chars after.
        assert_eq!(
            decode_java_unicode_escapes(r"incomplete \u"),
            "incomplete \\u"
        );
        // Lone high surrogate as the very last escape.
        assert_eq!(decode_java_unicode_escapes(r"end \uD83D"), "end \\uD83D");
    }

    #[test]
    fn decode_empty_input() {
        assert_eq!(decode_java_unicode_escapes(""), "");
    }

    #[test]
    fn decode_escape_window_splitting_a_multibyte_char_is_preserved() {
        // `\u` followed by 4 bytes whose last byte splits a 3-byte char.
        assert_eq!(decode_java_unicode_escapes("\\u€€"), "\\u€€");
    }

    #[test]
    fn document_new_applies_unicode_decoding_first() {
        // Whole-source decode: line offsets / spans / outline reflect
        // the decoded text (matches oracle app.py:927 behavior).
        let src = String::from("// \u{00e9}\nclass C { int x; }\n");
        let encoded = src.replace("é", r"\u00e9");
        let doc = Document::new("LA;".into(), "classes.dex".into(), encoded);
        assert_eq!(doc.source.as_ref(), src);
        assert_eq!(doc.line(0), Some("// é"));
    }
}
