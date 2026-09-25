//! Location-based navigation history (audit F8, redesign Phase 4).
//!
//! A location is (document, optional line, origin) — enough to
//! represent a class opened from the tree, an outline jump, or a
//! search-match jump. Back/Forward restore the exact location,
//! including the scroll target line. History is append/truncate only:
//! closing a tab never rewrites it (a revisit re-decompiles on
//! demand).

/// Where a navigation came from (drives dedup + future UX hints).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavOrigin {
    /// Explorer tree click.
    Tree,
    /// Search-result selection.
    Search,
    /// Outline jump inside a document.
    Outline,
    /// Tab strip click.
    Tab,
    /// Back/Forward walk.
    History,
    /// Go-to-declaration (workflow D).
    Declaration,
}

/// One navigation target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationLocation {
    pub descriptor: String,
    /// 0-based line within the document (scroll target).
    pub line: Option<usize>,
    pub origin: NavOrigin,
}

/// Back/Forward history with a cursor.
#[derive(Debug, Default)]
pub struct NavigationHistory {
    entries: Vec<NavigationLocation>,
    cursor: usize,
}

impl NavigationHistory {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Current location.
    pub fn current(&self) -> Option<&NavigationLocation> {
        self.entries.get(self.cursor)
    }

    /// Cursor position (for status display).
    pub fn position(&self) -> (usize, usize) {
        (self.cursor, self.entries.len())
    }

    /// Record a visit. Truncates the forward tail; consecutive
    /// identical locations (same descriptor + line) collapse.
    pub fn push(&mut self, loc: NavigationLocation) {
        if let Some(current) = self.entries.get(self.cursor) {
            if current.descriptor == loc.descriptor && current.line == loc.line {
                // Same place: refresh origin in place, no new entry.
                self.entries[self.cursor].origin = loc.origin;
                return;
            }
        }
        self.entries.truncate(self.cursor + 1);
        self.entries.push(loc);
        self.cursor = self.entries.len() - 1;
    }

    /// Walk back. Returns the location to restore, if any.
    pub fn back(&mut self) -> Option<NavigationLocation> {
        if self.cursor == 0 {
            return None;
        }
        self.cursor -= 1;
        self.entries.get(self.cursor).cloned()
    }

    /// Walk forward. Returns the location to restore, if any.
    pub fn forward(&mut self) -> Option<NavigationLocation> {
        if self.cursor + 1 >= self.entries.len() {
            return None;
        }
        self.cursor += 1;
        self.entries.get(self.cursor).cloned()
    }

    /// Whether Back is available.
    pub fn can_back(&self) -> bool {
        self.cursor > 0
    }

    /// Whether Forward is available.
    pub fn can_forward(&self) -> bool {
        self.cursor + 1 < self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(desc: &str, line: Option<usize>) -> NavigationLocation {
        NavigationLocation {
            descriptor: desc.to_string(),
            line,
            origin: NavOrigin::Tree,
        }
    }

    /// Back/Forward across code locations → deterministic restore of
    /// document + line.
    #[test]
    fn back_forward_restores_locations() {
        let mut h = NavigationHistory::default();
        h.push(loc("LA;", None));
        h.push(loc("LB;", Some(3)));
        h.push(loc("LB;", Some(10))); // outline jump within same doc
        assert_eq!(h.position(), (2, 3));

        let b = h.back().expect("back to LB line 3");
        assert_eq!(b.line, Some(3));

        let b = h.back().expect("back to A");
        assert_eq!(b.descriptor, "LA;");
        assert_eq!(b.line, None);

        assert!(h.back().is_none(), "start of history");
        assert!(h.can_forward());

        let f = h.forward().expect("forward to LB:3");
        assert_eq!(f.descriptor, "LB;");
        assert_eq!(f.line, Some(3));
    }

    /// Pushing from the middle truncates the forward tail; identical
    /// consecutive locations collapse.
    #[test]
    fn push_truncates_and_collapses() {
        let mut h = NavigationHistory::default();
        h.push(loc("LA;", None));
        h.push(loc("LB;", None));
        h.back(); // cursor at LA;
        h.push(loc("LC;", None));
        assert_eq!(h.len(), 2, "forward tail truncated");
        assert!(!h.can_forward());

        h.push(loc("LC;", None)); // same location → collapse
        assert_eq!(h.len(), 2);
    }

    /// Closing a tab never rewrites history (unlike the old code,
    /// which `retain`-ed closed descriptors out of the history).
    #[test]
    fn history_is_not_rewritten_on_close() {
        let mut h = NavigationHistory::default();
        h.push(loc("LA;", None));
        h.push(loc("LB;", None));
        // (tab close happens elsewhere; history must be untouched)
        assert_eq!(h.len(), 2);
        assert!(h.back().is_some());
    }
}
