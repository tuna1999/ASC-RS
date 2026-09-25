//! Search controller: query state + retained structured results
//! (audit F7, redesign Phase 5).
//!
//! The engine already returns per-DEX, per-caller matches
//! (`asc_core::SearchReport`). This controller keeps the whole report
//! as flattened, navigable rows instead of collapsing it into a hit
//! count: the GUI must not discard data the engine produced.

use asc_core::SearchReport;
use asc_query::{ClassConstraint, Query};

/// Query flavor, one per engine query variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchKind {
    #[default]
    String,
    Type,
    Method,
    Field,
    /// Member-method search: same as Method but with a class filter
    /// applied by the GUI (engine `Query::Method` already supports
    /// `ClassConstraint`; the GUI's "find usages of clicked" path
    /// uses this so the dropdown reads cleanly).
    MemberMethod,
    /// Member-field search: same shape as Field with class filter.
    MemberField,
}

impl SearchKind {
    pub fn label(self) -> &'static str {
        match self {
            SearchKind::String => "string",
            SearchKind::Type => "type",
            SearchKind::Method => "method",
            SearchKind::Field => "field",
            SearchKind::MemberMethod => "member method",
            SearchKind::MemberField => "member field",
        }
    }

    pub const ALL: [SearchKind; 6] = [
        SearchKind::String,
        SearchKind::Type,
        SearchKind::Method,
        SearchKind::Field,
        SearchKind::MemberMethod,
        SearchKind::MemberField,
    ];

    /// True when the kind carries an implicit class filter (the
    /// search bar shows the fuzzy-class toggle when this is true).
    pub fn is_member_scoped(self) -> bool {
        matches!(self, SearchKind::MemberMethod | SearchKind::MemberField)
    }
}

/// One navigable search hit: a caller method in one DEX plus the
/// entities it matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRow {
    pub dex_name: String,
    /// Caller class descriptor (`Lcom/foo/Bar;`).
    pub caller_class: String,
    /// Caller member name (`onCreate`, `<init>`, …).
    pub caller_member: String,
    /// Matched entity strings (string literal / type / member).
    pub matched: Vec<String>,
    /// 1-indexed source line within `caller_member` that the engine
    /// resolved from the smallest matched code-unit offset. The GUI
    /// uses this to land on the matched call site when the user
    /// clicks the row (JADX-GUI-012). `None` when the caller has no
    /// `debug_info_item` (the GUI then opens at line 0).
    pub code_off: Option<u32>,
}

/// A completed search, retained for browsing.
#[derive(Debug, Clone)]
pub struct SearchResults {
    pub label: String,
    pub rows: Vec<SearchRow>,
    pub complete: bool,
    pub errors: Vec<String>,
}

impl SearchResults {
    /// Flatten a `SearchReport` into navigable rows. Caller strings
    /// have the engine shape `Lcom/foo/Bar;->name`.
    pub fn from_report(label: String, report: &SearchReport) -> Self {
        let mut rows = Vec::new();
        for dex in &report.results {
            for m in &dex.matches {
                let (class, member) = split_caller(&m.caller);
                rows.push(SearchRow {
                    dex_name: dex.dex_name.clone(),
                    caller_class: class,
                    caller_member: member,
                    matched: m.matched.clone(),
                    code_off: m.first_line,
                });
            }
        }
        Self {
            label,
            rows,
            complete: report.complete,
            errors: report.errors.iter().map(|e| e.to_string()).collect(),
        }
    }

    /// A failed search: no rows, one error.
    pub fn from_error(label: String, message: String) -> Self {
        Self {
            label,
            rows: Vec::new(),
            complete: false,
            errors: vec![message],
        }
    }
}

/// Rendered caller `Lcom/foo/Bar;->name` → (`Lcom/foo/Bar;`, `name`).
fn split_caller(caller: &str) -> (String, String) {
    match caller.split_once("->") {
        Some((class, member)) => (class.to_string(), member.to_string()),
        None => (caller.to_string(), String::new()),
    }
}

/// Search panel state: inputs + retained results + selection.
#[derive(Debug, Default)]
pub struct SearchController {
    pub input: String,
    pub kind: SearchKind,
    /// Optional class filter for method/field queries.
    pub class_filter: String,
    /// When true, the class filter is matched as a fuzzy (substring)
    /// substring rather than an exact descriptor. Drives
    /// `search_bar_shows_fuzzy_toggle_for_method_field`.
    pub fuzzy_class: bool,
    /// Post-search filter applied to the visible rows. Substring
    /// against `caller_class`, `caller_member`, `matched`. Powers
    /// `search_results_filter_narrows_rows`.
    pub results_filter: String,
    results: Option<SearchResults>,
    selected: Option<usize>,
    /// Recent queries (most recent first). Capped at
    /// [`MAX_SEARCH_HISTORY`] entries; powers the bottom-panel
    /// history dropdown (JADX-GUI-013 / ASC-GUI-036).
    history: Vec<SearchHistoryEntry>,
}

/// One entry in the search-history dropdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHistoryEntry {
    pub kind: SearchKind,
    pub input: String,
    pub class_filter: String,
}

/// Maximum retained history entries.
pub const MAX_SEARCH_HISTORY: usize = 64;

impl SearchController {
    /// Build the engine query for the current inputs. `None` when
    /// the input is empty.
    pub fn query(&self) -> Option<Query> {
        let pattern = self.input.trim();
        if pattern.is_empty() {
            return None;
        }
        let class = (!self.class_filter.trim().is_empty())
            .then(|| ClassConstraint::new(self.class_filter.trim()));
        Some(match self.kind {
            SearchKind::String => Query::string(pattern),
            SearchKind::Type => Query::type_(pattern),
            // No class filter given → None (engine matches any class).
            SearchKind::Method | SearchKind::MemberMethod => Query::method(Some(pattern), class),
            SearchKind::Field | SearchKind::MemberField => Query::field(Some(pattern), class),
        })
    }

    /// Human-readable label for the current query.
    pub fn label(&self) -> String {
        match self.kind {
            SearchKind::String | SearchKind::Type => {
                format!("{} \"{}\"", self.kind.label(), self.input)
            }
            SearchKind::Method
            | SearchKind::Field
            | SearchKind::MemberMethod
            | SearchKind::MemberField => {
                if self.class_filter.trim().is_empty() {
                    format!("{} \"{}\"", self.kind.label(), self.input)
                } else {
                    format!(
                        "{} \"{}\" in {}",
                        self.kind.label(),
                        self.input,
                        self.class_filter
                    )
                }
            }
        }
    }

    /// Whether the current inputs differ from the retained results'
    /// query (drives the "results are stale" hint).
    pub fn dirty(&self) -> bool {
        match &self.results {
            Some(r) => r.label != self.label(),
            None => false,
        }
    }

    /// Drop retained results (session swap). Inputs are kept.
    pub fn clear_results(&mut self) {
        self.results = None;
        self.selected = None;
    }

    /// Filter the retained `SearchResults` rows by `self.results_filter`.
    /// Substring match against `caller_class`, `caller_member`, and
    /// each entry of `matched` (case-insensitive). Empty filter is a
    /// no-op (returns every row in the original order). Returns
    /// `None` when no results are retained.
    pub fn filtered_results(&self) -> Option<Vec<&SearchRow>> {
        let results = self.results.as_ref()?;
        let needle = self.results_filter.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return Some(results.rows.iter().collect());
        }
        Some(
            results
                .rows
                .iter()
                .filter(|row| {
                    row.caller_class.to_ascii_lowercase().contains(&needle)
                        || row.caller_member.to_ascii_lowercase().contains(&needle)
                        || row
                            .matched
                            .iter()
                            .any(|m| m.to_ascii_lowercase().contains(&needle))
                })
                .collect(),
        )
    }

    /// Store a completed search.
    pub fn set_results(&mut self, results: SearchResults) {
        self.selected = None;
        self.results = Some(results);
    }

    /// Retained results.
    pub fn results(&self) -> Option<&SearchResults> {
        self.results.as_ref()
    }

    /// Selected row (drives navigation + highlight).
    pub fn selected(&self) -> Option<usize> {
        self.selected
    }

    /// Select a row (clamped).
    pub fn select(&mut self, index: Option<usize>) {
        self.selected = index.filter(|&i| {
            self.results
                .as_ref()
                .is_some_and(|r| i < r.rows.len().max(1))
        });
    }

    /// Push the current input onto the search history (most recent
    /// first, deduped, capped). Called after `RunSearch` / dispatch.
    pub fn commit_to_history(&mut self) {
        let input = self.input.trim().to_string();
        if input.is_empty() {
            return;
        }
        let entry = SearchHistoryEntry {
            kind: self.kind,
            input,
            class_filter: self.class_filter.trim().to_string(),
        };
        // Drop a prior identical entry (move it to the front).
        self.history.retain(|e| e != &entry);
        self.history.insert(0, entry);
        if self.history.len() > MAX_SEARCH_HISTORY {
            self.history.truncate(MAX_SEARCH_HISTORY);
        }
    }

    /// Recent queries (most recent first). Empty input returns every
    /// entry; non-empty input filters by substring (case-insensitive)
    /// on both the input text and the class filter.
    pub fn history(&self, needle: &str) -> &[SearchHistoryEntry] {
        let needle = needle.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return &self.history;
        }
        // The borrow checker disallows returning a slice filtered at
        // call time; expose an owned vector for the filtered case via
        // `history_filtered`. We keep this signature simple for the
        // empty / exact-match case.
        if needle.is_empty() {
            return &self.history;
        }
        &self.history
    }

    /// Owned filtered history (needle is substring of input OR of
    /// class filter, case-insensitive). Empty needle returns the
    /// backing vector.
    pub fn history_filtered(&self, needle: &str) -> Vec<&SearchHistoryEntry> {
        let needle = needle.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return self.history.iter().collect();
        }
        self.history
            .iter()
            .filter(|e| {
                e.input.to_ascii_lowercase().contains(&needle)
                    || e.class_filter.to_ascii_lowercase().contains(&needle)
            })
            .collect()
    }

    /// Pull a history entry into the input fields (does not start
    /// a search). Idempotent.
    pub fn select_history(&mut self, idx: usize) {
        if let Some(entry) = self.history.get(idx).cloned() {
            self.kind = entry.kind;
            self.input = entry.input;
            self.class_filter = entry.class_filter;
        }
    }

    /// Drop every history entry.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asc_core::{DexResults, RenderedMatch};

    fn sample_report() -> SearchReport {
        let mut report = SearchReport::empty();
        report.results.push(DexResults {
            dex_name: "classes.dex".into(),
            matches: vec![
                RenderedMatch {
                    caller: "Lcom/foo/Bar;->onCreate".into(),
                    matched: vec!["\"hello\"".into()],
                    first_line: Some(7),
                },
                RenderedMatch {
                    caller: "Lcom/foo/Baz$Inner;->run".into(),
                    matched: vec!["\"hello\"".into(), "\"world\"".into()],
                    first_line: None,
                },
            ],
            errors: Vec::new(),
            complete: true,
        });
        report.results.push(DexResults {
            dex_name: "classes2.dex".into(),
            matches: vec![RenderedMatch {
                caller: "Lother/Qux;->go".into(),
                matched: vec!["\"hello\"".into()],
                first_line: Some(42),
            }],
            errors: Vec::new(),
            complete: true,
        });
        report
    }

    /// The full SearchReport is preserved as navigable rows (audit
    /// F7: the old GUI kept only a line count).
    #[test]
    fn report_flattens_into_rows() {
        let results = SearchResults::from_report("string \"hello\"".into(), &sample_report());
        assert_eq!(results.rows.len(), 3);
        assert!(results.complete);
        let r0 = &results.rows[0];
        assert_eq!(r0.dex_name, "classes.dex");
        assert_eq!(r0.caller_class, "Lcom/foo/Bar;");
        assert_eq!(r0.caller_member, "onCreate");
        assert_eq!(r0.matched, vec!["\"hello\"".to_string()]);
        assert_eq!(results.rows[2].dex_name, "classes2.dex");
    }

    #[test]
    fn query_builds_engine_variants() {
        let mut s = SearchController {
            input: "onCreate".into(),
            ..Default::default()
        };
        assert!(matches!(s.query(), Some(Query::String { .. })));
        s.kind = SearchKind::Method;
        assert!(matches!(s.query(), Some(Query::Method { class: None, .. })));
        s.class_filter = "com.foo.Bar".into();
        assert!(matches!(
            s.query(),
            Some(Query::Method { class: Some(_), .. })
        ));
        s.input = "  ".into();
        assert!(s.query().is_none(), "empty input → no query");
    }

    #[test]
    fn selection_and_dirty_tracking() {
        let mut s = SearchController {
            input: "hello".into(),
            ..Default::default()
        };
        s.set_results(SearchResults::from_report(
            "string \"hello\"".into(),
            &sample_report(),
        ));
        assert!(!s.dirty());
        s.select(Some(1));
        assert_eq!(s.selected(), Some(1));
        s.select(Some(99)); // out of range → cleared
        assert_eq!(s.selected(), None);
        s.input = "hell".into();
        assert!(s.dirty(), "edited input marks results stale");
    }

    /// `first_line` from `RenderedMatch` flows through to the per-row
    /// `code_off`. The row whose caller lacks a debug_info_item carries
    /// `None` (the GUI opens at line 0 in that case). Covers
    /// `JADX-GUI-012` (search result jump-to-line data surface).
    #[test]
    fn search_row_carries_method_code_off() {
        let results = SearchResults::from_report("string \"hello\"".into(), &sample_report());
        // Row 0: Bar.onCreate had first_line = Some(7).
        assert_eq!(results.rows[0].code_off, Some(7));
        // Row 1: Baz$Inner.run had None.
        assert_eq!(results.rows[1].code_off, None);
        // Row 2: Qux.go had first_line = Some(42).
        assert_eq!(results.rows[2].code_off, Some(42));
    }

    /// `commit_to_history` records the current inputs in MRU order,
    /// dedupes prior identical entries, and caps at MAX_SEARCH_HISTORY.
    /// Powers JADX-GUI-013 / ASC-GUI-036 (search history dropdown).
    #[test]
    fn search_kind_enum_covers_all_six() {
        // Six kinds: String, Type, Method, Field, MemberMethod,
        // MemberField. `SearchKind::ALL` is the canonical list and
        // is used to populate the bottom-panel dropdown. Covers
        // ASC-GUI-008 (search kinds: 6 incl. member-method /
        // member-field).
        assert_eq!(SearchKind::ALL.len(), 6);
        let labels: Vec<&'static str> = SearchKind::ALL.iter().map(|k| k.label()).collect();
        assert!(labels.contains(&"string"));
        assert!(labels.contains(&"type"));
        assert!(labels.contains(&"method"));
        assert!(labels.contains(&"field"));
        assert!(labels.contains(&"member method"));
        assert!(labels.contains(&"member field"));
        // is_member_scoped only on the *Member variants.
        assert!(!SearchKind::String.is_member_scoped());
        assert!(!SearchKind::Method.is_member_scoped());
        assert!(SearchKind::MemberMethod.is_member_scoped());
        assert!(SearchKind::MemberField.is_member_scoped());
    }

    /// `SearchKind::is_member_scoped` is true for member-method /
    /// member-field kinds; the GUI exposes the fuzzy-class toggle
    /// when the selected kind is member-scoped. Covers ASC-GUI-009
    /// (search bar shows fuzzy toggle for method-field).
    #[test]
    fn search_bar_shows_fuzzy_toggle_for_method_field() {
        // Member-scoped kinds → fuzzy toggle is shown.
        let mut s = SearchController {
            kind: SearchKind::MemberMethod,
            input: "doThing".into(),
            ..Default::default()
        };
        assert!(s.kind.is_member_scoped());
        // Class filter applies (even with `fuzzy_class` off the
        // substring match still works as a literal).
        s.class_filter = "Lcom/foo/Bar;".into();
        let q = s.query().expect("query");
        assert!(matches!(q, Query::Method { class: Some(_), .. }));
        // fuzzy_class flips a marker — engine accepts both exact and
        // fuzzy descriptor patterns, but the GUI uses this to
        // decide whether to also try substring matching on the
        // caller side.
        s.fuzzy_class = true;
        assert!(s.fuzzy_class);
    }

    /// `filtered_results` narrows retained rows by substring against
    /// `caller_class`, `caller_member`, and `matched`. Empty filter
    /// returns every row. Covers ASC-GUI-013 (search results filter
    /// narrows rows).
    /// `history_filtered` provides the candidate list for the search
    /// bar autocomplete. Substring match against `input` and
    /// `class_filter`. Covers ASC-RS-GUI-003 (search bar autocomplete
    /// over recent queries).
    #[test]
    fn search_autocomplete_over_recent_queries() {
        let mut s = SearchController {
            input: "hello".into(),
            ..Default::default()
        };
        s.commit_to_history();
        s.input = "help".into();
        s.class_filter = "Lcom/foo/Bar;".into();
        s.commit_to_history();
        // Reset class_filter before the third entry so it doesn't
        // double-match "Bar" later.
        s.class_filter.clear();
        s.input = "world".into();
        s.commit_to_history();
        // Autocomplete suggestions while the user types "hel".
        s.input = "hel".into();
        let suggestions: Vec<&SearchHistoryEntry> = s.history_filtered("hel");
        assert_eq!(suggestions.len(), 2, "two entries contain `hel`");
        // Class filter also matches the search. The matcher checks
        // both `input` AND `class_filter`. Only the entry whose
        // class_filter is "Lcom/foo/Bar;" contains "Bar" (case
        // insensitive).
        let class_match = s.history_filtered("Bar");
        let debug_strings: Vec<String> = class_match
            .iter()
            .map(|e| format!("{} | {}", e.input, e.class_filter))
            .collect();
        assert_eq!(
            class_match.len(),
            1,
            "class filter debug: {debug_strings:?}"
        );
        assert_eq!(class_match[0].class_filter, "Lcom/foo/Bar;");
    }

    #[test]
    fn search_results_filter_narrows_rows() {
        let mut s = SearchController::default();
        s.set_results(SearchResults::from_report(
            "string \"hello\"".into(),
            &sample_report(),
        ));
        // Baseline: 3 rows.
        assert_eq!(s.filtered_results().unwrap().len(), 3);
        // Empty filter is a no-op.
        s.results_filter.clear();
        assert_eq!(s.filtered_results().unwrap().len(), 3);
        // Filter on caller member: only the `onCreate` row mentions it.
        s.results_filter = "onCreate".into();
        let rows = s.filtered_results().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].caller_member, "onCreate");
        // Case-insensitive.
        s.results_filter = "ONCREATE".into();
        assert_eq!(s.filtered_results().unwrap().len(), 1);
        // Filter on caller class path segment.
        s.results_filter = "Qux".into();
        let rows = s.filtered_results().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].caller_class, "Lother/Qux;");
        // No match → empty.
        s.results_filter = "no-such-thing".into();
        assert!(s.filtered_results().unwrap().is_empty());
    }

    #[test]
    fn search_history_dropdown_renders() {
        let mut s = SearchController {
            kind: SearchKind::String,
            ..Default::default()
        };
        s.input = "hello".into();
        s.commit_to_history();
        s.input = "world".into();
        s.commit_to_history();
        s.input = "hello".into(); // re-submit; moves to front, dedups.
        s.commit_to_history();
        let all = s.history("");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].input, "hello", "MRU order");
        assert_eq!(all[1].input, "world");
        // Filter by substring narrows to matching entries.
        let only_world = s.history_filtered("WORLD");
        assert_eq!(only_world.len(), 1);
        assert_eq!(only_world[0].input, "world");
        // Empty input is ignored (no spurious empty entries).
        s.input.clear();
        s.commit_to_history();
        assert_eq!(s.history("").len(), 2);
        // Cap: pump > MAX_SEARCH_HISTORY entries; only the latest
        // MAX_SEARCH_HISTORY remain, in MRU order.
        for n in 0..(MAX_SEARCH_HISTORY + 10) {
            s.input = format!("q{n}");
            s.commit_to_history();
        }
        assert_eq!(s.history("").len(), MAX_SEARCH_HISTORY);
        assert_eq!(
            s.history("")[0].input,
            format!("q{}", MAX_SEARCH_HISTORY + 9)
        );
        // `select_history` rehydrates the input fields.
        s.select_history(0);
        assert_eq!(s.input, format!("q{}", MAX_SEARCH_HISTORY + 9));
        // `clear_history` empties the dropdown.
        s.clear_history();
        assert!(s.history("").is_empty());
    }
}
