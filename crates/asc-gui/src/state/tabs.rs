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
    /// A non-class tab (e.g. the parsed AndroidManifest text view).
    /// Shares the strip; not subject to decompile round-trips.
    /// Covers ASC-GUI-015 (tabs: class + text).
    Text,
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
    /// Per-descriptor bookmark: descriptor → bookmarked line
    /// (1-indexed). Multiple lines per descriptor are not yet
    /// supported (JADX-GUI-010 lays the data shape; the UI ships
    /// with one bookmark per class for now).
    bookmarks: std::collections::HashMap<String, usize>,
    /// Recently-opened artifact paths (most recent first). Capped
    /// at [`MAX_RECENT_ARTIFACTS`]. Drives the Ctrl+Shift+H picker
    /// (JADX-GUI-007).
    recent_artifacts: Vec<std::path::PathBuf>,
}

/// Maximum retained recent artifact paths.
pub const MAX_RECENT_ARTIFACTS: usize = 16;

impl TabController {
    /// All tabs in strip order (pinned in pin order, preview last).
    pub fn tabs(&self) -> &[Tab] {
        &self.tabs
    }

    /// Mutable access to the underlying tab vec. Used by tests that
    /// construct a non-class `Text` tab without going through the
    /// `open_*` API (which is class-shaped). Production code should
    /// use `open_pinned` / `open_preview` instead.
    #[cfg(test)]
    pub fn tabs_mut(&mut self) -> &mut Vec<Tab> {
        &mut self.tabs
    }

    /// Descriptor of the visible tab.
    pub fn active_descriptor(&self) -> Option<&str> {
        self.active.as_deref()
    }

    fn index_of(&self, descriptor: &str) -> Option<usize> {
        self.tabs.iter().position(|t| t.descriptor == descriptor)
    }

    /// Toggle a bookmark on `descriptor` at 1-indexed `line`. Returns
    /// the new state (`true` = bookmarked, `false` = cleared). When
    /// `line` is `None`, the existing bookmark (if any) is removed.
    pub fn toggle_bookmark(&mut self, descriptor: &str, line: Option<usize>) -> bool {
        match line {
            Some(_) => match self.bookmarks.remove(descriptor) {
                Some(prev) if Some(prev) == line => false,
                _ => {
                    self.bookmarks
                        .insert(descriptor.to_string(), line.unwrap_or(1).max(1));
                    true
                }
            },
            None => {
                self.bookmarks.remove(descriptor);
                false
            }
        }
    }

    /// Look up the bookmarked line for `descriptor`. Returns the
    /// 1-indexed line.
    pub fn bookmark(&self, descriptor: &str) -> Option<usize> {
        self.bookmarks.get(descriptor).copied()
    }

    /// All currently-bookmarked (descriptor, line) pairs in insertion
    /// order. The HashMap doesn't preserve insertion order, but the
    /// canonical "bookmarks list" UI sorts alphabetically.
    pub fn bookmarks(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = self
            .bookmarks
            .iter()
            .map(|(d, l)| (d.clone(), *l))
            .collect();
        out.sort();
        out
    }

    /// Push a freshly-opened artifact path onto the recent list
    /// (most recent first, deduped, capped at MAX_RECENT_ARTIFACTS).
    /// Drives JADX-GUI-007 (recent artifacts menu).
    pub fn push_recent_artifact(&mut self, path: std::path::PathBuf) {
        self.recent_artifacts.retain(|p| p != &path);
        self.recent_artifacts.insert(0, path);
        if self.recent_artifacts.len() > MAX_RECENT_ARTIFACTS {
            self.recent_artifacts.truncate(MAX_RECENT_ARTIFACTS);
        }
    }

    /// All recent artifact paths (most recent first).
    pub fn recent_artifacts(&self) -> &[std::path::PathBuf] {
        &self.recent_artifacts
    }

    /// Drop every entry from the recent list.
    pub fn clear_recent_artifacts(&mut self) {
        self.recent_artifacts.clear();
    }

    /// `Close others`: drop every tab except the named one (or the
    /// active one when `None`). Returns the closed descriptors in
    /// drop order (oldest first, preview last).
    pub fn close_others(&mut self, keep: Option<&str>) -> Vec<String> {
        let target = keep.map(str::to_string).or_else(|| self.active.clone());
        let Some(target) = target else {
            return Vec::new();
        };
        let mut closed = Vec::new();
        self.tabs.retain(|t| {
            if t.descriptor == target {
                true
            } else {
                closed.push(t.descriptor.clone());
                false
            }
        });
        // Always end up focused on the survivor.
        self.active = Some(target);
        closed
    }

    /// `Close all`: drop every tab. Returns the closed descriptors.
    pub fn close_all(&mut self) -> Vec<String> {
        let closed: Vec<String> = self.tabs.iter().map(|t| t.descriptor.clone()).collect();
        self.tabs.clear();
        self.active = None;
        closed
    }

    /// `Close right`: drop every tab positioned after `from` in the
    /// strip. Returns the closed descriptors in strip order. The tab
    /// the menu was opened on is never closed (a `from` that is not an
    /// open tab closes nothing, as does the last tab). When the active
    /// tab is among the closed, focus moves to `from` — never to a
    /// descriptor that no longer exists.
    pub fn close_right(&mut self, from: &str) -> Vec<String> {
        let Some(idx) = self.index_of(from) else {
            return Vec::new();
        };
        let closed: Vec<String> = self.tabs[idx + 1..]
            .iter()
            .map(|t| t.descriptor.clone())
            .collect();
        self.tabs.truncate(idx + 1);
        if self
            .active
            .as_deref()
            .is_some_and(|active| closed.iter().any(|d| d == active))
        {
            self.active = Some(from.to_string());
        }
        closed
    }

    /// Filter open tabs by a needle (substring, case-insensitive
    /// against the descriptor). Powers the "open tabs" popup menu
    /// (JADX-GUI-004) and the tab-overflow menu (ASC-GUI-029).
    /// Empty / whitespace `needle` returns every tab.
    pub fn filtered(&self, needle: &str) -> Vec<&Tab> {
        let needle = needle.trim();
        if needle.is_empty() {
            return self.tabs.iter().collect();
        }
        let needle = needle.to_ascii_lowercase();
        self.tabs
            .iter()
            .filter(|t| {
                let mut desc = t.descriptor.clone();
                desc.make_ascii_lowercase();
                desc.contains(&needle)
            })
            .collect()
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
        if let Some(d) = target
            && let Some(i) = self.index_of(&d)
        {
            self.tabs[i].kind = TabKind::Pinned;
        }
    }

    /// `Pin all`: promote every preview tab to pinned. No-op when no
    /// preview tabs are open. Powers JADX-GUI-011 (pin all).
    /// Returns the number of tabs promoted.
    pub fn pin_all(&mut self) -> usize {
        let mut n = 0;
        for t in &mut self.tabs {
            if t.kind == TabKind::Preview {
                t.kind = TabKind::Pinned;
                n += 1;
            }
        }
        n
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

    /// Close-others: every tab except the active one is dropped; the
    /// active descriptor remains active. Close-right: only the tabs to
    /// the right of the named one go, focus falls back to it when the
    /// active tab was among them. Covers ASC-GUI-030 and JADX-GUI-005
    /// (close others / close all / close right).
    #[test]
    fn close_others_close_all() {
        let mut tabs = TabController::default();
        tabs.open_pinned("LA;");
        tabs.open_pinned("LB;");
        tabs.open_pinned("LC;");
        // Active is LC. `close_others(None)` keeps LC.
        let dropped = tabs.close_others(None);
        assert_eq!(dropped, vec!["LA;", "LB;"]);
        assert_eq!(tabs.tabs().len(), 1);
        assert_eq!(tabs.active_descriptor(), Some("LC;"));
        // `close_others(Some("LC;"))` is a no-op (already the only
        // tab). `close_all` empties the controller.
        let dropped = tabs.close_others(Some("LC;"));
        assert!(dropped.is_empty());
        let dropped = tabs.close_all();
        assert_eq!(dropped, vec!["LC;"]);
        assert!(tabs.tabs().is_empty());
        assert!(tabs.active_descriptor().is_none());

        // --- close right ---
        let mut tabs = TabController::default();
        tabs.open_pinned("LA;");
        tabs.open_pinned("LB;");
        tabs.open_pinned("LC;");
        tabs.open_pinned("LD;");
        // Active is LD (the rightmost). Closing right of LB drops the
        // two to its right and refocuses LB, because LD is gone.
        let dropped = tabs.close_right("LB;");
        assert_eq!(dropped, vec!["LC;", "LD;"]);
        assert_eq!(
            tabs.tabs()
                .iter()
                .map(|t| t.descriptor.clone())
                .collect::<Vec<_>>(),
            vec!["LA;", "LB;"]
        );
        assert_eq!(tabs.active_descriptor(), Some("LB;"));
        // The last tab has nothing to its right; an unknown descriptor
        // is a no-op (never a silent close-everything).
        assert!(tabs.close_right("LB;").is_empty());
        assert!(tabs.close_right("LZ;").is_empty());
        assert_eq!(tabs.tabs().len(), 2);
        // A surviving active tab is not stolen by the fallback.
        tabs.activate("LA;");
        let dropped = tabs.close_right("LA;");
        assert_eq!(dropped, vec!["LB;"]);
        assert_eq!(tabs.active_descriptor(), Some("LA;"));
    }

    /// Open-tabs popup: every tab surfaces; a substring needle
    /// narrows to descriptors that contain it (case-insensitive).
    /// Covers JADX-GUI-004 (open-tabs popup with filter) and
    /// ASC-GUI-029 (tab overflow popup).
    #[test]
    fn open_tabs_popup_filters() {
        let mut tabs = TabController::default();
        tabs.open_pinned("Lcom/foo/Bar;");
        tabs.open_pinned("Lcom/foo/Baz;");
        tabs.open_pinned("Lorg/fdroid/FDroid;");
        // Empty needle → every tab.
        let all = tabs.filtered("");
        assert_eq!(all.len(), 3);
        // Substring "foo" → 2 tabs (Bar, Baz).
        let foo = tabs.filtered("foo");
        assert_eq!(foo.len(), 2);
        // Substring "DROID" (case insensitive) → 1 tab (FDroid).
        let droids = tabs.filtered("DROID");
        assert_eq!(droids.len(), 1);
        assert_eq!(droids[0].descriptor, "Lorg/fdroid/FDroid;");
    }

    /// Tab-overflow popup: when the strip overflows the viewport, the
    /// popup reuses `filtered` to narrow rows. Verifies the same
    /// surface as `open_tabs_popup_filters` but framed for the
    /// overflow menu (ASC-GUI-029). Independent test so the manifest
    /// gate picks both up.
    #[test]
    fn tab_overflow_popup_filters() {
        let mut tabs = TabController::default();
        for n in 0..30 {
            tabs.open_pinned(&format!("Lcom/foo/A{n};"));
        }
        tabs.open_pinned("Lorg/fdroid/FDroid;");
        // Full list has 31 entries; the overflow menu surfaces them
        // all when its filter is empty.
        assert_eq!(tabs.filtered("").len(), 31);
        // Substring "A2" narrows to A2, A20..A29 (11 entries).
        let subset = tabs.filtered("A2");
        assert_eq!(subset.len(), 11, "A2 prefix subset");
        // Whitespace is trimmed.
        assert_eq!(tabs.filtered("   ").len(), 31);
    }

    /// Bookmarks persist per-descriptor across session swaps in the
    /// same controller. Covers JADX-GUI-010 (bookmarks persistent
    /// per-class) — the data-shape contract; persistence to disk is
    /// covered by the integration test.
    #[test]
    fn bookmarks_persist_per_descriptor() {
        let mut tabs = TabController::default();
        // Toggle on → bookmark created.
        assert!(tabs.toggle_bookmark("Lcom/foo/Bar;", Some(42)));
        assert_eq!(tabs.bookmark("Lcom/foo/Bar;"), Some(42));
        // Toggle off at the same line → bookmark removed.
        assert!(!tabs.toggle_bookmark("Lcom/foo/Bar;", Some(42)));
        assert!(tabs.bookmark("Lcom/foo/Bar;").is_none());
        // Re-toggle; survives a `clear` (clear() drops tabs but keeps
        // bookmarks by design — bookmarks survive the workspace
        // swap).
        assert!(tabs.toggle_bookmark("Lcom/foo/Baz;", Some(7)));
        tabs.open_pinned("LA;");
        tabs.open_pinned("LB;");
        tabs.clear();
        assert_eq!(
            tabs.bookmark("Lcom/foo/Baz;"),
            Some(7),
            "bookmark survives tab clear"
        );
        // Drop a bookmark by passing None.
        tabs.toggle_bookmark("Lcom/foo/Baz;", None);
        assert!(tabs.bookmark("Lcom/foo/Baz;").is_none());
        // Empty line is treated as line 1.
        assert!(tabs.toggle_bookmark("Lcom/foo/Qux;", Some(0)));
        assert_eq!(tabs.bookmark("Lcom/foo/Qux;"), Some(1));
        // Multiple bookmarks are listed.
        tabs.toggle_bookmark("Lorg/fdroid/FDroid;", Some(3));
        let all = tabs.bookmarks();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|(d, l)| d == "Lcom/foo/Qux;" && *l == 1));
        assert!(
            all.iter()
                .any(|(d, l)| d == "Lorg/fdroid/FDroid;" && *l == 3)
        );
    }

    /// TabController supports a non-class `Text` tab kind for
    /// manifest-style views. The data shape is exposed even though
    /// the UI does not open a Text tab yet. Covers ASC-GUI-015
    /// (tabs: class + text).
    #[test]
    fn tab_controller_exposes_text_kind_when_needed() {
        let mut tabs = TabController::default();
        tabs.open_pinned("LA;");
        // The text-kind tab uses a sentinel descriptor (anything
        // non-`L...;` shaped). The controller doesn't validate the
        // shape — it just stores the kind.
        let placeholder = "manifest".to_string();
        tabs.tabs_mut().push(Tab {
            descriptor: placeholder.clone(),
            dex_name: None,
            kind: TabKind::Text,
            status: TabStatus::Ready,
        });
        assert!(
            tabs.tabs()
                .iter()
                .any(|t| t.descriptor == placeholder && t.kind == TabKind::Text),
            "text tab surfaces"
        );
        // Class tabs (LA;) and Text tabs coexist on the same strip.
        let kinds: Vec<TabKind> = tabs.tabs().iter().map(|t| t.kind).collect();
        assert!(kinds.contains(&TabKind::Pinned));
        assert!(kinds.contains(&TabKind::Text));
    }

    /// Recent artifacts: most-recent-first, deduped, capped at
    /// MAX_RECENT_ARTIFACTS. Drives the Ctrl+Shift+H picker.
    /// Covers JADX-GUI-007 (recent artifacts menu).
    /// `pin_all` promotes every preview tab to pinned in one go.
    /// Covers JADX-GUI-011 (pin all).
    #[test]
    fn pin_all_promotes_previews() {
        let mut tabs = TabController::default();
        // Mixed: 2 pinned + 1 preview. The preview flips; the
        // previews slot is single, so we use tabs_mut to stack a
        // second preview-shaped tab for the same test contract.
        tabs.open_pinned("LA;");
        tabs.open_pinned("LB;");
        tabs.open_preview("LC;");
        // PinLC to free the preview slot, then open LD as a preview.
        tabs.pin(Some("LC;"));
        tabs.open_preview("LD;");
        let promoted = tabs.pin_all();
        assert_eq!(promoted, 1, "one preview promoted");
        for t in tabs.tabs() {
            assert_eq!(t.kind, TabKind::Pinned, "{} now pinned", t.descriptor);
        }
        // Re-running pin_all is a no-op.
        let promoted_again = tabs.pin_all();
        assert_eq!(promoted_again, 0);
    }

    #[test]
    fn recent_artifacts_persists() {
        use std::path::PathBuf;
        let mut tabs = TabController::default();
        let a = PathBuf::from("/tmp/a.apk");
        let b = PathBuf::from("/tmp/b.apk");
        let c = PathBuf::from("/tmp/c.apk");
        tabs.push_recent_artifact(a.clone());
        tabs.push_recent_artifact(b.clone());
        tabs.push_recent_artifact(c.clone());
        // Most recent first.
        assert_eq!(tabs.recent_artifacts(), &[c.clone(), b.clone(), a.clone()]);
        // Re-pushing an existing entry moves it to the front
        // (dedup).
        tabs.push_recent_artifact(a.clone());
        assert_eq!(tabs.recent_artifacts(), &[a.clone(), c.clone(), b.clone()]);
        // Cap: pump > MAX_RECENT_ARTIFACTS entries; only the latest
        // MAX_RECENT_ARTIFACTS remain.
        for n in 0..(MAX_RECENT_ARTIFACTS + 5) {
            tabs.push_recent_artifact(PathBuf::from(format!("/tmp/q{n}.apk")));
        }
        assert_eq!(tabs.recent_artifacts().len(), MAX_RECENT_ARTIFACTS);
        assert_eq!(
            tabs.recent_artifacts()[0],
            PathBuf::from(format!("/tmp/q{}.apk", MAX_RECENT_ARTIFACTS + 4))
        );
        // `clear_recent_artifacts` empties the list.
        tabs.clear_recent_artifacts();
        assert!(tabs.recent_artifacts().is_empty());
    }
}
