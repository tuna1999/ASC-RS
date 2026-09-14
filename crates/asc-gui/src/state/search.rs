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
}

impl SearchKind {
    pub fn label(self) -> &'static str {
        match self {
            SearchKind::String => "string",
            SearchKind::Type => "type",
            SearchKind::Method => "method",
            SearchKind::Field => "field",
        }
    }

    pub const ALL: [SearchKind; 4] = [
        SearchKind::String,
        SearchKind::Type,
        SearchKind::Method,
        SearchKind::Field,
    ];
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
    results: Option<SearchResults>,
    selected: Option<usize>,
}

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
            SearchKind::Method => Query::method(Some(pattern), class),
            SearchKind::Field => Query::field(Some(pattern), class),
        })
    }

    /// Human-readable label for the current query.
    pub fn label(&self) -> String {
        match self.kind {
            SearchKind::String | SearchKind::Type => {
                format!("{} \"{}\"", self.kind.label(), self.input)
            }
            SearchKind::Method | SearchKind::Field => {
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
                },
                RenderedMatch {
                    caller: "Lcom/foo/Baz$Inner;->run".into(),
                    matched: vec!["\"hello\"".into(), "\"world\"".into()],
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
}
