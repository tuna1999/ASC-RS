//! Tab state: lightweight metadata, separate from heavyweight
//! documents (audit F9, redesign Phase 4).
//!
//! Semantics:
//!
//! - Exactly one **Preview** tab exists at most. Single clicks in the
//!   Explorer / search results open (or replace) the preview tab.
//! - **Pinned** tabs are permanent until explicitly closed. Double
//!   click or Pin converts the current preview into a pinned tab.
//!   Opening 50 search results still leaves ≤ 1 preview tab.
//! - Tab metadata survives document-cache eviction: a tab whose
//!   document was dropped under memory pressure stays valid and can
//!   be re-decompiled on demand (ASC is fast and on-demand).
//! - Tabs are keyed by descriptor (unique within a session — the
//!   engine resolves the winning DEX).

/// Tab lifecycle kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabKind {
    /// Replaced by the next preview navigation; italic in the strip.
    Preview,
    /// Permanent until closed; pin glyph in the strip.
    Pinned,
}

/// Lightweight per-tab status. `Ready` means a document is (or was)
/// available; document eviction does **not** change tab state — the
/// shell re-issues the decompile on next activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TabStatus {
    /// Decompile task in flight.
    Loading,
    /// Document available (or previously loaded).
    Ready,
    /// Last decompile attempt failed; message shown in the strip.
    Failed(String),
}

/// One tab's metadata.
#[derive(Debug, Clone)]
pub struct Tab {
    pub descriptor: String,
    /// Winning DEX once known.
    pub dex_name: Option<String>,
    pub kind: TabKind,
    pub status: TabStatus,
}

/// Tab strip state controller.
#[derive(Debug, Default)]
pub struct TabController {
    tabs: Vec<Tab>,
    /// Descriptor of the visible tab.
    active: Option<String>,
}

impl TabController {
    /// All tabs in strip order (pinned in pin order, preview last).
    pub fn tabs(&self) -> &[Tab] {
        &self.tabs
    }

    /// Descriptor of the visible tab.
    pub fn active_descriptor(&self) -> Option<&str> {
        self.active.as_deref()
    }

    fn index_of(&self, descriptor: &str) -> Option<usize> {
        self.tabs.iter().position(|t| t.descriptor == descriptor)
    }

    /// Single-click semantics: open `descriptor` as the preview tab,
    /// replacing any existing preview. If the descriptor is already
    /// pinned (or already is the preview), just activate it.
    pub fn open_preview(&mut self, descriptor: &str) {
        if self.index_of(descriptor).is_some() {
            self.activate(descriptor);
            return;
        }
        // Replace the preview slot in place if it exists, else append.
        match self.tabs.iter_mut().find(|t| t.kind == TabKind::Preview) {
            Some(slot) => {
                slot.descriptor = descriptor.to_string();
                slot.dex_name = None;
                slot.status = TabStatus::Loading;
            }
            None => self.tabs.push(Tab {
                descriptor: descriptor.to_string(),
                dex_name: None,
                kind: TabKind::Preview,
                status: TabStatus::Loading,
            }),
        }
        self.activate(descriptor);
    }

    /// Drop every tab (session swap). Does not touch documents.
    pub fn clear(&mut self) {
        self.tabs.clear();
        self.active = None;
    }
}

impl TabController {
    /// Double-click / explicit-open semantics: a pinned tab.
    pub fn open_pinned(&mut self, descriptor: &str) {
        match self.index_of(descriptor) {
            Some(i) => {
                // Already present: promote to pinned if it was the
                // preview, then activate.
                self.tabs[i].kind = TabKind::Pinned;
                if self.tabs[i].status == TabStatus::Loading {
                    // keep loading status
                }
            }
            None => self.tabs.push(Tab {
                descriptor: descriptor.to_string(),
                dex_name: None,
                kind: TabKind::Pinned,
                status: TabStatus::Loading,
            }),
        }
        self.activate(descriptor);
    }

    /// Pin the current preview tab (or a specific one). No-op when
    /// nothing is open or the tab is already pinned.
    pub fn pin(&mut self, descriptor: Option<&str>) {
        let target = descriptor
            .map(str::to_string)
            .or_else(|| self.active.clone());
        if let Some(d) = target {
            if let Some(i) = self.index_of(&d) {
                self.tabs[i].kind = TabKind::Pinned;
            }
        }
    }

    /// Mark a tab's decompile as landed.
    pub fn set_ready(&mut self, descriptor: &str, dex_name: Option<String>) {
        if let Some(i) = self.index_of(descriptor) {
            self.tabs[i].status = TabStatus::Ready;
            if let Some(dex) = dex_name {
                self.tabs[i].dex_name = Some(dex);
            }
        }
    }

    /// Mark a tab's decompile as failed.
    pub fn set_failed(&mut self, descriptor: &str, message: String) {
        if let Some(i) = self.index_of(descriptor) {
            self.tabs[i].status = TabStatus::Failed(message);
        }
    }

    /// Activate a tab. No-op when absent.
    pub fn activate(&mut self, descriptor: &str) {
        if self.index_of(descriptor).is_some() {
            self.active = Some(descriptor.to_string());
        }
    }

    /// Close a tab explicitly. Activates the nearest neighbor when
    /// the visible tab closed. Returns the newly active descriptor.
    pub fn close(&mut self, descriptor: &str) -> Option<String> {
        let Some(pos) = self.index_of(descriptor) else {
            return self.active.clone();
        };
        self.tabs.remove(pos);
        if self.active.as_deref() == Some(descriptor) {
            self.active = self
                .tabs
                .get(pos.min(self.tabs.len().saturating_sub(1)))
                .map(|t| t.descriptor.clone());
        }
        self.active.clone()
    }

    /// Cycle to the next/previous tab (Ctrl+Tab / Ctrl+Shift+Tab).
    pub fn cycle(&mut self, forward: bool) {
        if self.tabs.is_empty() {
            return;
        }
        let current = self
            .active
            .as_deref()
            .and_then(|d| self.index_of(d))
            .unwrap_or(0);
        let next = if forward {
            (current + 1) % self.tabs.len()
        } else {
            current.wrapping_sub(1).min(self.tabs.len() - 1)
        };
        self.active = Some(self.tabs[next].descriptor.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// preview A, preview B → only B occupies the preview slot.
    #[test]
    fn preview_slot_is_single() {
        let mut tabs = TabController::default();
        tabs.open_preview("LA;");
        assert_eq!(tabs.tabs().len(), 1);
        assert_eq!(tabs.tabs()[0].descriptor, "LA;");
        assert_eq!(tabs.tabs()[0].kind, TabKind::Preview);
        tabs.open_preview("LB;");
        assert_eq!(tabs.tabs().len(), 1, "preview replaces, not stacks");
        assert_eq!(tabs.tabs()[0].descriptor, "LB;");
        assert_eq!(tabs.active_descriptor(), Some("LB;"));
    }

    /// preview A, pin A, preview B → A pinned + B preview.
    #[test]
    fn pin_converts_preview() {
        let mut tabs = TabController::default();
        tabs.open_preview("LA;");
        tabs.pin(None);
        tabs.open_preview("LB;");
        assert_eq!(tabs.tabs().len(), 2);
        assert_eq!(tabs.tabs()[0].descriptor, "LA;");
        assert_eq!(tabs.tabs()[0].kind, TabKind::Pinned);
        assert_eq!(tabs.tabs()[1].descriptor, "LB;");
        assert_eq!(tabs.tabs()[1].kind, TabKind::Preview);
        assert_eq!(tabs.active_descriptor(), Some("LB;"));
        // Re-previewing A activates the pinned tab (no duplicate).
        tabs.open_preview("LA;");
        assert_eq!(tabs.tabs().len(), 2);
        assert_eq!(tabs.active_descriptor(), Some("LA;"));
    }

    /// Metadata survives status changes; close activates neighbors.
    #[test]
    fn close_activates_neighbor() {
        let mut tabs = TabController::default();
        tabs.open_pinned("LA;");
        tabs.open_pinned("LB;");
        tabs.open_pinned("LC;");
        assert_eq!(tabs.active_descriptor(), Some("LC;"));
        assert_eq!(tabs.close("LC;").as_deref(), Some("LB;"));
        assert_eq!(tabs.close("LA;").as_deref(), Some("LB;"));
        assert_eq!(tabs.tabs().len(), 1);
    }

    /// Status transitions for loading → ready/failed.
    #[test]
    fn status_transitions() {
        let mut tabs = TabController::default();
        tabs.open_preview("LA;");
        assert_eq!(tabs.tabs()[0].status, TabStatus::Loading);
        tabs.set_ready("LA;", Some("classes.dex".into()));
        assert_eq!(tabs.tabs()[0].status, TabStatus::Ready);
        assert_eq!(tabs.tabs()[0].dex_name.as_deref(), Some("classes.dex"));
        tabs.set_failed("LA;", "boom".into());
        assert_eq!(tabs.tabs()[0].status, TabStatus::Failed("boom".into()));
    }

    /// Cycle wraps in both directions.
    #[test]
    fn cycle_wraps() {
        let mut tabs = TabController::default();
        tabs.open_pinned("LA;");
        tabs.open_pinned("LB;");
        assert_eq!(tabs.active_descriptor(), Some("LB;"));
        tabs.cycle(true);
        assert_eq!(tabs.active_descriptor(), Some("LA;"), "wraps to first");
        tabs.cycle(false);
        assert_eq!(tabs.active_descriptor(), Some("LB;"), "wraps to last");
    }

    /// Pinned tab metadata survives document-cache pressure (the
    /// document is a separate concern — see documents::DocumentCache).
    #[test]
    fn pinned_metadata_survives_document_eviction() {
        let mut tabs = TabController::default();
        tabs.open_preview("LA;");
        tabs.pin(None);
        tabs.set_ready("LA;", Some("classes2.dex".into()));
        // Simulate document-cache pressure: the cache drops the
        // heavyweight document (budget forces one of two out) while
        // the tab metadata above is a separate store.
        let mut docs = crate::state::documents::DocumentCache::new(256);
        docs.put(std::sync::Arc::new(crate::state::documents::Document::new(
            "LA;".into(),
            "classes2.dex".into(),
            "class A {}".repeat(64),
        )));
        docs.put(std::sync::Arc::new(crate::state::documents::Document::new(
            "LB;".into(),
            "classes2.dex".into(),
            "class B {}".repeat(4096),
        )));
        // Tiny budget: the LRU (LA;) is evicted, the active doc (LB)
        // survives.
        docs.enforce_budget(Some("LB;"));
        assert!(!docs.contains("LA;"), "document evicted under pressure");
        assert_eq!(tabs.tabs().len(), 1, "tab metadata remains valid");
        assert_eq!(tabs.tabs()[0].kind, TabKind::Pinned);
        assert_eq!(tabs.tabs()[0].descriptor, "LA;");
        assert_eq!(tabs.tabs()[0].status, TabStatus::Ready);
    }
}
