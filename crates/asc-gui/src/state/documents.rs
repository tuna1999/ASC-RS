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
}
