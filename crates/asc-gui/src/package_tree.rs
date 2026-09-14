//! Nested package tree for the left panel (jadx-style "Source" tree).
//!
//! Maps Dalvik descriptors (`Lcom/foo/Bar$Baz;`) onto a tree of
//! package nodes (`com`, `foo`) with class leaves (`Bar`, inner
//! classes nested one level deeper: `Bar ▸ Baz`). The tree is built
//! once per session and re-rendered every frame, so building is
//! allocation-frugal: one `Vec<TreeNode>` arena, children referenced
//! by index.
//!
//! Filtering (`filter_classes`) returns a flat, sorted list of
//! matching descriptors — the tree view switches to this flat list
//! while the filter box is non-empty (same UX as jadx's class search).

use std::collections::BTreeMap;

use crate::session::ClassEntry;

/// Index into the `nodes` arena of a [`PackageTree`].
type NodeIdx = usize;

/// One node in the tree arena.
#[derive(Debug)]
pub struct TreeNode {
    /// Display label (`com`, `material`, `ClockFaceView`, `Default`).
    pub label: String,
    /// Full path for this node (`com.google`, `…ClockFaceView$Default`).
    pub path: String,
    /// Sorted child nodes (packages and nested classes).
    pub children: BTreeMap<String, NodeIdx>,
    /// Leaf classes directly under this node (index into `entries`).
    pub class_leaves: Vec<usize>,
    /// True when this node is a class (vs a package).
    pub is_class: bool,
}

/// Arena-based package tree over a class list.
#[derive(Debug)]
pub struct PackageTree {
    nodes: Vec<TreeNode>,
    /// The class list the tree was built from (leaf indices point here).
    entries: Vec<ClassEntry>,
}

impl PackageTree {
    /// Build a tree from `entries` (the session's `all_classes()` list).
    pub fn build(entries: Vec<ClassEntry>) -> Self {
        let mut tree = Self {
            nodes: vec![TreeNode {
                label: String::new(),
                path: String::new(),
                children: BTreeMap::new(),
                class_leaves: Vec::new(),
                is_class: false,
            }],
            entries,
        };
        for idx in 0..tree.entries.len() {
            let desc_full = tree.entries[idx].descriptor.clone();
            let desc = desc_full.trim_start_matches('L');
            let desc = desc.strip_suffix(';').unwrap_or(desc);
            // Package segments up to the last '/', then `$`-split for
            // inner classes: `pkg/Outer$Inner` ends up as leaf
            // `Inner` under class node `Outer` under the package.
            let (pkg, class_path) = match desc.rfind('/') {
                Some(pos) => (&desc[..pos], &desc[pos + 1..]),
                None => ("", desc),
            };
            let mut node = 0usize;
            for seg in pkg.split('/').filter(|s| !s.is_empty()) {
                node = tree.child(node, seg, false);
            }
            for seg in class_path.split('$').filter(|s| !s.is_empty()) {
                node = tree.child(node, seg, true);
            }
            // The full descriptor is a leaf on its innermost node.
            tree.nodes[node].class_leaves.push(idx);
        }
        tree
    }

    /// Look up (or create) a child node of `parent`.
    fn child(&mut self, parent: NodeIdx, label: &str, is_class: bool) -> NodeIdx {
        if let Some(&existing) = self.nodes[parent].children.get(label) {
            return existing;
        }
        // Separator: `$` when the parent is a class (inner class),
        // `.` when the parent is a package.
        let path = if self.nodes[parent].path.is_empty() {
            label.to_string()
        } else if self.nodes[parent].is_class {
            format!("{}${label}", self.nodes[parent].path)
        } else {
            format!("{}.{}", self.nodes[parent].path, label)
        };
        let idx = self.nodes.len();
        self.nodes.push(TreeNode {
            label: label.to_string(),
            path,
            children: BTreeMap::new(),
            class_leaves: Vec::new(),
            is_class,
        });
        self.nodes[parent].children.insert(label.to_string(), idx);
        idx
    }

    /// Root node index (always 0).
    pub fn root(&self) -> NodeIdx {
        0
    }

    /// Node accessor for rendering.
    pub fn node(&self, idx: NodeIdx) -> &TreeNode {
        &self.nodes[idx]
    }

    /// Class entry behind a leaf index.
    pub fn entry(&self, leaf: usize) -> &ClassEntry {
        &self.entries[leaf]
    }

    /// Total class count in the tree.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the tree holds no classes.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Case-insensitive substring filter over descriptors. Returns
    /// matching leaf indices sorted by descriptor (the entries list is
    /// already sorted, so a stable filter keeps it sorted).
    pub fn filter(&self, needle: &str) -> Vec<usize> {
        let needle = needle.to_ascii_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.descriptor.to_ascii_lowercase().contains(&needle))
            .map(|(i, _)| i)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(desc: &str) -> ClassEntry {
        ClassEntry {
            descriptor: desc.to_string(),
            dex_name: "classes.dex".to_string(),
        }
    }

    #[test]
    fn builds_nested_packages_and_inner_classes() {
        let tree = PackageTree::build(vec![
            entry("Lcom/google/material/ClockFaceView;"),
            entry("Lcom/google/material/ClockFaceView$Hand;"),
            entry("Landroid/support/INotificationSideChannel$Default;"),
            entry("LFoo;"),
        ]);
        // Root: 2 packages (com, android) + 1 default-package class node.
        let root = tree.node(tree.root());
        assert_eq!(root.children.len(), 3, "com, android, Foo");
        assert!(root.class_leaves.is_empty(), "no leaf directly on root");
        let foo = root.children["Foo"];
        assert_eq!(tree.node(foo).class_leaves.len(), 1, "Foo owns its entry");

        let com = root.children["com"];
        let google = tree.node(com).children["google"];
        let material = tree.node(google).children["material"];
        let m = tree.node(material);
        assert_eq!(m.children.len(), 1, "ClockFaceView");
        let cfv = tree.node(m.children["ClockFaceView"]);
        assert_eq!(cfv.children.len(), 1, "Hand");
        assert_eq!(cfv.path, "com.google.material.ClockFaceView");
        assert_eq!(cfv.class_leaves.len(), 1, "ClockFaceView owns its entry");
        let hand = tree.node(cfv.children["Hand"]);
        assert_eq!(hand.path, "com.google.material.ClockFaceView$Hand");
        assert_eq!(hand.class_leaves.len(), 1, "Hand owns its entry");

        // android.support -> INotificationSideChannel -> Default
        let android = root.children["android"];
        let support = tree.node(android).children["support"];
        let inot = tree.node(support).children["INotificationSideChannel"];
        let default_idx = tree.node(inot).children["Default"];
        assert_eq!(tree.node(default_idx).label, "Default");
    }

    #[test]
    fn filter_matches_case_insensitive() {
        let tree = PackageTree::build(vec![
            entry("Lcom/Aaa/One;"),
            entry("Lcom/bbb/clockface;"),
            entry("LClock;"),
        ]);
        let hits = tree.filter("CLOCK");
        assert_eq!(hits.len(), 2);
        assert_eq!(tree.entry(hits[0]).descriptor, "Lcom/bbb/clockface;");
        assert_eq!(tree.entry(hits[1]).descriptor, "LClock;");
        assert!(tree.filter("zzz").is_empty());
    }

    #[test]
    fn len_counts_entries_not_nodes() {
        let tree = PackageTree::build(vec![entry("La/B;"), entry("La/C$D;")]);
        assert_eq!(tree.len(), 2);
        assert!(!tree.is_empty());
    }
}
