# GUI Architecture — ASC-RS workbench target

Companion to `gui-audit.md` (findings F1–F11). This document defines the
module ownership the refactor converges to. Philosophy: *query the
artifact, preserve the context* — on-demand engine work, deterministic
state, responsive before pretty.

## 1. Module layout (smallest clean ownership)

```text
crates/asc-gui/src/
  app.rs            eframe shell: owns Workspace, pumps tasks, delegates rendering
  design.rs         design tokens + theme application (see design-language.md)
  task.rs           TaskId / SessionGeneration / TaskManager / TaskEnvelope
  session.rs        APK handle + per-DEX class cache (tab storage REMOVED)
  package_tree.rs   arena tree + cached filter
  highlight.rs      tokenizer + outline (unchanged engine)
  selfcheck.rs      headless smoke (unchanged)
  state/
    mod.rs          re-exports + WorkspaceState (session-level view state)
    documents.rs    DocumentId / Document / DocumentCache
    tabs.rs         Tab / TabKind (Preview|Pinned) / TabController
    navigation.rs   NavigationLocation / NavigationHistory
    search.rs       SearchController (query state + retained SearchReport)
  ui/
    mod.rs          workspace layout composition
    explorer.rs     left panel (tree / filter / flat results)
    editor.rs       tab strip + code view + view mode (Java/Metadata)
    inspector.rs    right panel (symbol/DEX/references/metadata)
    bottom_panel.rs Search Results | References | Problems | Tasks
    status_bar.rs   one-line status + counters
    palette.rs      command palette + quick-open (Phase 8)
```

`app.rs` shrinks to: construct `Workspace`, dispatch `Command`s, pump
`TaskManager`, call `ui::draw_workspace`. No engine calls, no string
business logic.

## 2. Task system (fixes F1 F2 F3 F10)

```rust
pub struct TaskId(u64);              // unique per app process
pub struct SessionGeneration(u64);   // bumped on every open/reload

pub enum TaskKind { DecompileClass, FindRefs, LoadClassList }

pub struct TaskEnvelope<T> {
    pub task_id: TaskId,
    pub generation: SessionGeneration,
    pub payload: T,
}
```

- `TaskManager::spawn(kind, input, ctx)` stamps `{task_id, generation}`
  at spawn time and returns the receiver. One channel per task is kept
  (mpsc), but the manager polls them by identity, not by slot.
- `TaskManager::poll(&mut self) -> Vec<(TaskId, TaskOutcome)>` drains
  ready results only; UI applies them via a match on `task_id`.
- Staleness rule (single choke point): a result whose `generation` ≠
  current is dropped **before** it reaches any state. Old workers may
  physically finish; their results never mutate newer state. This
  replaces F2's ownership accident with an explicit check.
- Activation intent (fixes F1): intent is carried **on the task**, not in
  a shared slot. `state.tabs` records `pending: Option<TaskId>` — set to
  the *latest* DecompileClass task; only the result of exactly that task
  activates a tab. A failing older task can no longer clear it.
- Supersede/cancel (fixes F3): starting a new FindRefs marks the previous
  one superseded (result dropped on arrival). Cooperative cancel is a
  cancellation flag checked between DEX entries; threads finish their
  current entry and exit (never blocks the UI, never kills mid-parse).
- Bound: at most one live FindRefs and a small bounded set of
  DecompileClass tasks (deduped by target — clicking an in-flight class
  again is a no-op).

## 3. Documents and tabs (fixes F4 F5 F9)

```rust
pub struct DocumentId(u64);                       // stable, monotonic
pub struct Document {
    pub id: DocumentId,
    pub descriptor: String,                       // Lcom/foo/Bar;
    pub dex_name: String,
    pub source: Arc<str>,                         // shared, immutable
    pub line_offsets: Arc<[u32]>,                 // line index for O(1) line slice
    pub spans: Vec<Vec<Span>>,                    // computed once, off UI thread
    pub outline: Vec<OutlineEntry>,               // computed once, off UI thread
}
```

- `DocumentCache` (state/documents.rs) owns `HashMap<DocumentId, Arc<Document>>`
  plus a byte-budgeted eviction order (soft cap in MiB). Eviction drops
  the `Document` (heavy) while `Tab` metadata (light) stays valid; a
  pinned tab whose document was evicted shows a "reload" affordance that
  re-issues the decompile task. Tab identity NEVER keys on heap contents.
- Tab metadata (`state/tabs.rs`):

```rust
pub struct Tab {
    pub id: TabId,
    pub doc_id: Option<DocumentId>,   // None = loading (task in flight) or evicted
    pub descriptor: String,
    pub dex_name: Option<String>,
    pub kind: TabKind,                // Preview | Pinned
    pub status: TabStatus,            // Loading | Ready | Error(String)
}
```

- Exactly one Preview slot: single-click in Explorer/Search **replaces**
  the preview tab's content; double-click / Pin converts to Pinned
  (opening 50 search results still leaves ≤ 1 preview tab). Pinned tabs
  are never silently evicted; close is explicit.
- Tokenize/outline runs once per document, on the worker thread inside
  the DecompileClass task (fixes F5: no sync tokenization on activation,
  no recompute on tab switches). `Arc<str>` + `line_offsets` let the
  render path slice lines without cloning (fixes F4).

## 4. Navigation (fixes F8)

```rust
pub struct NavigationLocation {
    pub descriptor: String,        // resolves to DocumentId when open
    pub line: Option<usize>,       // 0-based line within the document
    pub origin: NavOrigin,         // Tree | Search | Outline | Symbol | Tab
}
```

History is a `Vec<NavigationLocation>` + cursor, append-and-truncate on
new visits from a *different* origin location, never rewritten on tab
close (closed tabs re-decompile on revisit — ASC is fast and on-demand).
Back/Forward restores document + line (scroll target), deterministically.

Smali listings are navigation locations like any other document:
`ShowSmali` / `ShowSmaliMethod` route through `navigate_to` on both a
cache hit and a cache miss, so the first open is recorded in the history
(Back returns to the class, Forward to the listing), the disasm job stays
deduplicated, and a `#smali` view key never reaches the engine as a class
descriptor (GUI-hardening audit F1/F2).

### Click-derived state (GUI-hardening audit F1)

`symbol_sel` and `last_click` are captured from **one document version**:
the document key it was clicked in, the token, and byte / line offsets
into that source. Consumers read them through `AscApp::active_symbol_sel`
/ `AscApp::clicked_line` / `clicked_member`, which refuse a value whose
document key is not the one on screen — a document switch must never let
class A's descriptor, token or line number drive an action in class B
(dispatch, bookmark or line comment). A source-replacing edit drops the
selection (its offsets are invalid); a line jump inside the same document
keeps it. A click in a `#smali` listing resolves its owning class through
`class_of_tab_key`, never the view key. `comment_target` carries its
document key for the same reason: the bar applies only to the document it
was armed for.

## 5. Search (fixes F7)

`SearchController` retains the full `SearchReport`:

```rust
pub struct SearchResults {
    pub label: String,               // `string "onCreate"`
    pub rows: Vec<SearchRow>,        // flattened, per RenderedMatch
    pub complete: bool,
    pub errors: Vec<SearchError>,    // Problems view
}
pub struct SearchRow {
    pub dex_name: String,
    pub caller_class: String,        // parsed from RenderedMatch.caller
    pub caller_member: String,
    pub matched: Vec<String>,        // entities (string literal / type / member)
}
```

Selecting a row → navigate to `caller_class` (preview tab) with the
search row pinned in the References/Results bottom view. The bottom panel
tabs are: **Search Results** (last query), **References** (selection-derived
context), **Problems** (SearchError list + engine failures), **Tasks**
(live task table: kind, target, state, duration). All lists render through
`show_rows` virtualization.

Streaming (per-DEX batches) is deferred: the completed-report model is
correct and fast (105 ms worst corpus). If added later, it is a small
`asc-core` callback-API addition documented per repo policy §18 — not an
engine redesign.

## 6. Event flow (steady state)

```text
user input ──▶ ui/*.rs draw fns emit Commands (pure data)
Commands ──▶ app.rs dispatch ──▶ TaskManager.spawn / state mutation
worker thread ──▶ TaskEnvelope{task_id, generation, payload}
app.rs pump ──▶ generation check ──▶ state apply (tabs/search/nav)
state ──▶ next frame renders (read-only borrow)
```

Rules: draw functions never mutate engine-derived state, never allocate
per-frame copies of documents (metadata only), never call asc-core
directly.

## 7. Session / init (spec §11)

- `AscApp` constructs instantly with an empty workspace; the APK open is
  itself a task (kind `LoadClassList`) posting per-DEX class batches.
- Window paints immediately with "loading" state; Explorer fills as DEX
  batches land (each batch appended to the tree; `PackageTree::extend`).
- Manifest parse stays on the worker (it is one small entry; measured
  0.2–1.9 ms but off-thread anyway).
- No global preprocessing beyond class enumeration (already ASC's
  cheapest op: pure `class_def` walk, no decompile, no xrefs, no index).

## 8. Testability

`state/*` and `task.rs` are pure/headless (no egui types beyond `Context`
for repaint requests). Every audit §8 regression scenario is a unit test
against controllers + a fake task pump — no native window needed
(`egui::Context::default()`, same as existing app.rs tests). UI modules
are thin enough that behavioral tests live below them.
