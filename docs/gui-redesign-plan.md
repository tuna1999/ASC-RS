# GUI Redesign Plan — phased migration

Execution order and acceptance criteria for the refactor defined in
`gui-architecture.md`. Risk-first: state determinism before layout,
layout before polish. Repository stays green at every phase boundary
(`cargo fmt --check`, `clippy --workspace --all-targets --all-features`,
`test --workspace`, `asc-gui --selfcheck corpus/apk/workload.apk`).

## Phase 0 — audit + baseline (this commit)

Deliverables: `gui-audit.md`, `gui-architecture.md`, `design-language.md`,
this plan, `examples/gui_bench.rs` baseline harness.
Numbers: audit §2. Exit: docs merged, baseline recorded.

## Phase 1 — deterministic task identity

- `task.rs`: `TaskId`, `SessionGeneration`, `TaskKind`, `TaskEnvelope`,
  `TaskManager` (spawn stamped envelopes, identity-based poll,
  generation gate, supersede for findrefs, dedup of in-flight
  decompiles, bounded concurrency).
- Rewire `app.rs`: `pending_findrefs`/`pending_getclass`/`want_active`
  removed; activation intent keyed by `TaskId`.
- Fix F1 (failure of stale request can't clear newer intent), F2
  (generation gate replaces receiver-drop accident), F3 (supersede).
- Tests: audit §8 scenarios 1, 2, 3, 6.
- Acceptance: all four scenarios deterministic; existing tests green;
  gui_bench shows no regression on worker-op timings.

## Phase 2 — document cache / render-path costs

- `state/documents.rs`: `DocumentId`, `Document { source: Arc<str>,
  line_offsets, spans, outline }`; spans/outline computed on worker
  inside the decompile task.
- `session.rs` loses tab storage (`open_tab/open_tabs/close_tab`,
  MAX_OPEN_TABS) — class cache stays.
- Render path reads `Arc<Document>` by id; no per-frame source clones;
  status counts from metadata; tree filter cached (lowercased keys,
  recompute on filter-text change only, not per frame).
- Tests: audit §8 scenario 7 (eviction keeps tab metadata).
- Acceptance: `open_tabs()`-style snapshot cost eliminated (0 source
  copies per frame); activation does no tokenize work; gui_bench
  per-frame clones → ~0.

## Phase 3 — state/controllers split

- `state/` modules own all mutation; `app.rs` becomes shell +
  dispatch. UI draw fns take `&mut` controllers but contain no engine
  calls and no cross-controller logic.
- Commands introduced as data enum (groundwork for Phase 8 shortcuts).
- Acceptance: `app.rs` < ~300 lines; no engine imports in `ui/*`.

## Phase 4 — tabs + navigation

- `state/tabs.rs`: Preview/Pinned/Loading/Error semantics, single
  preview slot, pin conversion, explicit close; never evict pinned.
- `state/navigation.rs`: `NavigationLocation {descriptor, line, origin}`,
  non-destructive history, Back/Forward restore location + scroll.
- UI: single click = preview, double-click/pin = pinned; outline jumps
  and search jumps push locations with lines.
- Tests: audit §8 scenarios 4, 5, 8.
- Acceptance: all three scenarios green headless.

## Phase 5 — search workspace

- `state/search.rs`: retain full `SearchReport`; flattened
  `SearchRow`s (dex, caller class/member, matched entities).
- `ui/bottom_panel.rs`: Search Results | References | Problems | Tasks,
  virtualized, selectable rows → navigation.
- Findrefs input moves to toolbar search field + bottom panel.
- Acceptance: select result → preview at caller class; result list
  stays visible; Problems lists SearchErrors; Tasks lists live tasks.

## Phase 6 — workspace layout

- `ui/mod.rs` composes menubar / toolbar / activity bar / Explorer /
  Editor / Inspector / Bottom / Status per design-language §2.
- Panels resizable + collapsible (persisted via egui memory in Phase 8).
- Acceptance: editor owns remaining space; each panel toggles;
  layout survives resize.

## Phase 7 — design tokens

- `design.rs` tokens + theme application; all scattered colors/sizes
  replaced; syntax colors relocated into tokens.
- Acceptance: no raw `Color32`/size literals outside `design.rs`
  (grep-enforced in review); visual check on corpus APK.

## Phase 8 — commands, palette, persistence

- Command enum complete (Open, Reload, Back, Forward, QuickOpen,
  GlobalSearch, FindRefs, FindInDocument, CloseTab, PinTab, NextTab,
  PrevTab, Toggle{Explorer,Inspector,BottomPanel}, CancelTask).
- Shortcuts: Ctrl+O, Ctrl+P, Ctrl+Shift+F, Ctrl+F, Alt+←/→, Ctrl+W,
  Ctrl+Tab, Ctrl+Shift+P, Esc (cancel task / close palette).
- Command palette + quick open (fuzzy over class list, virtualized).
- Persist panel visibility/size via egui memory (native eframe
  persistence); no new files written by the GUI.
- Acceptance: every command reachable from palette + shortcut;
  shortcut table matches design-language.

## Deferred (documented, not scheduled)

- Streaming findrefs (needs small core callback API; per §18 requires
  documented justification before touching asc-core).
- Smali/Bytecode/CFG editor representations (only when engine-backed).
- Split-view sync (Java | Smali).

## Risk register

| risk | mitigation |
|---|---|
| eframe repaint loop stalls on busy poll | keep `request_repaint_after` cadence; poll is non-blocking try_recv |
| worker thread panics poison state | engine is panic-free by invariant; worker catches nothing, process abort acceptable? No — wrap job in `catch_unwind` at task boundary, convert to TaskOutcome::Failed |
| Arc<str> churn vs plain String | measurement-driven (audit §2); Arc chosen only where shares exist (tabs ↔ documents ↔ editor) |
| losing selfcheck parity | selfcheck path untouched by phases 1–8 (engine-only calls) |
