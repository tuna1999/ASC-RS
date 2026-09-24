# ASC-RS GUI autoresearch notes

Baseline established for the GUI-as-workbench goal. Companion to
`docs/gui-feature-matrix.md` (the matrix is the data; this doc is the
narrative).

## 1. Major architectural findings

The current `asc-gui` already implements the **task/document/
controller** model that `gui-redesign-plan.md` targeted, in roughly
2 000 lines of `app.rs`, ~1 300 lines of `state/`, ~2 000 lines of
`ui/`, plus the `task.rs` plumbing. The design pillars are intact:

- **Lazy/on-demand APK and DEX processing.** Artifact open runs as a
  background task; class enumeration is built per-DEX on demand;
  decompile is issued per click; document cache is byte-budgeted
  (32 MiB soft cap).
- **Bounded memory.** `DocumentCache::enforce_budget` evicts LRU
  documents but keeps tab metadata alive; eviction never steals the
  active document.
- **No global xref/index database.** Nothing in `asc-gui` calls into
  `asc_rebuild` or `asc_decompile` directly; the boundary is
  `asc_core::{run_findrefs, run_getclass}` only (verified: `grep -r
  'use asc_rebuild\|use asc_decompile' crates/asc-gui` returns no
  results).
- **Task identity + generation gate.** `TaskManager::poll` stamps
  every result with `stale = discarded || generation != current`,
  and the single `apply_task` match arms apply the result. The F1
  bug from `gui-audit.md` is closed; `late_result_cannot_steal_newer_activation`
  is green headless.
- **State/controllers split.** `state/{documents,tabs,navigation,search}.rs`
  are pure (only `Document` holds the heavyweight source). `ui/*`
  modules read state and queue `Command` data; the `Command` enum is
  the single dispatcher entry point (`app.rs::dispatch`).
- **No async runtime.** Only `std::thread::spawn` + `std::sync::mpsc`
  in `task.rs`; `cargo` confirms zero `tokio` / `async-std` deps.
- **Design tokens.** `design::Tokens { DARK, LIGHT }` is the single
  source of truth; `apply()` re-styles the egui context on theme
  switch. The `grep` for raw `Color32::from_rgb` outside
  `crates/asc-gui/src/design.rs` returns only the token definitions.

The `gui-audit.md` findings F1–F11 are all closed by the redesign
phases 1–8 (see commit log on `master`). The remaining `gui-audit.md`
risks (init cost at ~80 ms on fdroid) are not blocking the
workbench-target baseline.

## 2. ASC parity gaps

Sorted by feature weight (P0 = 8) and ease of fix:

### P0 (parity with frozen oracle ASC GUI)

| ID | Gap | Why it matters | Estimated effort |
|---|---|---|---|
| ASC-GUI-008 | Search kinds: 4 vs oracle's 6 (missing member-method, member-field) | Oracle exposes `method` and `field` as standalone search kinds (full-string match) | small — extend `SearchKind` enum + draw + wire `Query::method/field` |
| ASC-GUI-009 | Fuzzy-class checkbox missing | Oracle lets users opt into substring match for member ref kinds | small — one checkbox + plumbing |
| ASC-GUI-013 | No post-search filter on result rows | Oracle filters visible rows by free-text after search | small — `bottom_panel::draw_result_rows` accepts an additional filter param |
| ASC-GUI-015 | Text-tab kind for `AndroidManifest.xml` | Oracle has a separate `kind="text"` EditorTab | small — extend `TabKind` + add text-tab path through `TabController` |
| ASC-GUI-025 | No dedicated Settings dialog | Oracle has `SettingsDialog` with theme combo | small — new `Command::OpenSettings` + egui modal |
| ASC-GUI-028 | Middle-click close on tab | Oracle binds `<Button-2>` | small — `ui::editor::draw_tab_strip` add middle-click handler |
| ASC-GUI-029 | Tab overflow popup | Oracle has `more` button + filtered listbox | medium — popup with `egui` + filterable list |
| ASC-GUI-030 | Close others / close all | Oracle right-click context | small — extend `TabController` |
| ASC-GUI-035 | Per-DEX load progress text | Oracle streams progress; we batch | medium — small `WorkspaceSession::open` callback API per AGENTS.md §18 |
| ASC-GUI-036 | Search history dropdown | Oracle persists recent queries | small — surface `WorkspaceSession::findrefs_history` |

### P1 (jadx-inspired RE workflows)

Top 5 by impact:

| ID | Feature | Backend | Effort |
|---|---|---|---|
| JADX-GUI-003 | Go to declaration | needs `asc_query::resolve_declaration` (single pass) | small engine + UI surface |
| JADX-GUI-002 | Find usages at method level | `Query::method(class, name)` already exists | UI only |
| JADX-GUI-008 | Outline filter | none | small UI |
| JADX-GUI-004/005 | Open-tabs popup + close others/all | none | medium UI |
| JADX-GUI-006/015 | Copy descriptor / FQN | none | tiny |

### P2 (engine-extending, small)

| ID | Feature | Engine delta |
|---|---|---|
| ASC-RS-GUI-001 | Callgraph one-hop | `Query::outgoing_from_method` (one pass over the method's `insns_exact`) |
| ASC-RS-GUI-006 | Strings used by class | `asc_query::class_strings` (per-class walk of method bodies) |

### P3 (BLOCKED — large backend)

| ID | Feature | Reason |
|---|---|---|
| ASC-RS-GUI-101 | Smali viewer | requires a smali writer on top of `RefWalker` |
| ASC-RS-GUI-102 | Bytecode viewer | requires opcode-aware formatter |
| ASC-RS-GUI-103 | Resources browsing | requires a resource decoder (no engine work exists) |
| ASC-RS-GUI-104 | CFG | forbidden by AGENTS.md philosophy (global preprocessing) |
| ASC-RS-GUI-105 | Transitive call graph | same — would need a global xref |
| ASC-RS-GUI-106 | Debugger | static-only project |
| ASC-RS-GUI-107 | Cross-class rename | requires full Java semantic analysis |
| ASC-RS-GUI-108 | Comment persistence across reloads | per AGENTS.md F26: intentionally scratchpad |
| ASC-RS-GUI-109 | Live streaming findrefs | requires engine callback API; AGENTS.md §18 documents the policy |
| ASC-RS-GUI-110 | Layout persistence via file | egui `persistence` feature already covers it |

## 3. JADX candidate features (evaluated)

JADX is a richer workbench than ASC's frozen oracle. After auditing the
public JADX UI surface (MainWindow, NavigationTree, TabsController,
SearchDialog, search providers, codearea, ClassCodeContentPanel,
SmaliArea, usage/reference navigation, bookmarks, comments, settings,
resources browsing, keyboard shortcuts, context menus, preview/pinned
tabs), the following workflows translate cleanly to ASC-RS without
violating its architecture:

- **Open-tabs popup with filter** (JADX-GUI-004) — egui has the
  primitive (`egui::Window` + filtered list).
- **Bookmarks per descriptor** (JADX-GUI-010) — egui persistence
  covers storage.
- **Settings dialog** (JADX-GUI-009) — already partly implemented via
  the View menu.
- **Quick-switch tabs (Ctrl+1..9)** (JADX-GUI-014) — pure dispatch.
- **Outline filter** (JADX-GUI-008) — pure UI.

The following JADX features are **explicitly NOT_APPLICABLE** for
ASC-RS:

- Smali / bytecode views (`RefWalker` exists but no smali writer).
- Resources browsing (no engine).
- Comments persistence (per AGENTS.md F26).
- Debugger (out of scope).

## 4. Performance concerns

Measurements on the same machine as the audit (12th-gen i7-12700T):

| Cost | Worst corpus (fdroid) | Notes |
|---|---|---|
| `WorkspaceSession::open` | 0.6 ms | mmap + per-DEX entry listing |
| `all_classes()` first call | 63 ms | linear in class count |
| `PackageTree::build` | 14 ms | once per artifact |
| Manifest parse | 1.9 ms | once per artifact |
| `run_getclass` (one click) | 67 ms | end-to-end |
| `run_findrefs` (one query) | 105 ms | end-to-end |
| `Document::new` (tokenize + outline) | off-thread, ~0 ms UI cost | spans + outline built on worker |
| Per-frame source clones | 0 (post-redesign) | `Arc<Document>` only |
| Per-frame filter cache | cached per needle | `PackageTree::filter_cache` |
| Tab activation tokenize | 0 (post-redesign) | already done at decompile time |

Headroom for new features:

- The render path is **already** zero-copy for documents; new features
  must respect the `Arc<Document>` discipline and read metadata only.
- Tokenize + outline run **once per document**; new inspector panes
  that derive from them must read `Document::outline` and `Document::spans`
  rather than re-tokenizing.
- Search and decompile are off-thread; new features that need engine
  work must follow the `TaskManager::submit` pattern (no inline
  blocking calls on the UI thread).

## 5. Recommended implementation order

The first autoresearch campaign should target features in this order,
optimising for (weight × ease) ÷ blast radius:

1. **ASC-GUI-008 + 009** (search kinds + fuzzy checkbox): weight 8+8,
   backend already there, ~80 lines.
2. **ASC-GUI-013** (post-search filter): weight 8, ~40 lines.
3. **ASC-GUI-029 + 030** (tab overflow + close others/all): weight 8+8,
   pure UI state.
4. **ASC-GUI-036** (search history dropdown): weight 8, surface existing
   `WorkspaceSession::findrefs_history`.
5. **ASC-GUI-015** (text tab for manifest): weight 8, small `TabKind`
   variant.
6. **ASC-GUI-025** (settings dialog): weight 8, ~60 lines.
7. **JADX-GUI-002** (find usages at method level): weight 5, surface
   existing `Query::method`.
8. **JADX-GUI-008** (outline filter): weight 5, ~30 lines.
9. **JADX-GUI-006 / 015** (copy descriptor/FQN): weight 5+5, trivial.

These nine features clear **84 weight points** and lift the baseline
score by an estimated ~30 percentage points, with no engine work.

The next tier needs small engine additions (each documented per
AGENTS.md §18 in a separate proposal):

- JADX-GUI-003 (Go to declaration) — `asc_query::resolve_declaration`.
- ASC-RS-GUI-001 (callgraph one-hop) — `asc_query::outgoing_from_method`.
- ASC-RS-GUI-006 (strings used by class) — `asc_query::class_strings`.

The remaining P1/P2 features are either already complete or BLOCKED.

## 6. Exact command to start the next autoresearch campaign

After the baseline lands, the next campaign runs:

```bash
cd E:/Dev/ASC-RS
bash autoresearch.sh
```

To match CI (no corpus, no selfcheck):

```bash
cd E:/Dev/ASC-RS
ASC_RS_FAST=1 bash autoresearch.sh
```

A single command runs every gate, emits every METRIC line, and exits
non-zero on any gate failure. CI consumes the METRIC lines via
`grep '^METRIC ' autoresearch.out`.

## 7. What NOT to do

These moves would inflate the score without delivering real parity
and are forbidden by the freezing policy:

- Reweighting priorities or feature weights.
- Deleting failing acceptance tests.
- Silently widening an acceptance to make a feature PASS.
- Marking a feature COMPLETE without its acceptance test passing.
- Marking a BLOCKED feature as COMPLETE.
- Touching the frozen oracle / corpus / golden fixtures.

## 8. References

- `AGENTS.md` — repository guidelines + verification gates.
- `docs/gui-audit.md` — Phase 0 audit; F1–F11 all closed.
- `docs/gui-architecture.md` — module ownership target.
- `docs/gui-redesign-plan.md` — phased migration; all phases landed.
- `docs/design-language.md` — workbench design tokens.
- `reference/asc/src/asc_client/gui/{app,widgets,runtime,settings,source_edit,text_utils,theme}.py`
  — frozen oracle ASC GUI source.
- `docs/gui-feature-matrix.md` — feature matrix + scoring formula.
- `tests/gui_features/feature_manifest.json` — machine-readable manifest.
- `tests/gui_features/score.py` — deterministic scoring.
- `autoresearch.sh` — gate harness + METRIC emitter.