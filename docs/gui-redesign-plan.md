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
| worker thread panics poison state | wrap job in `catch_unwind` at task boundary, convert to `TaskOutcome::Failed` (done) |
| Arc<str> churn vs plain String | measurement-driven (audit §2); Arc chosen only where shares exist (tabs ↔ documents ↔ editor) |
| losing selfcheck parity | selfcheck path untouched by phases 1–8 (engine-only calls) |

---

## Execution record (2026-09-15)

All phases landed on `master` (one commit per phase; the Phase 3–8
state/UI work landed as one coherent cutover after Phase 1/2 proved
the task/document model).

| gate | result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --all-features` | 0 warnings |
| `cargo test --workspace` | 244+ tests green (43 in asc-gui, incl. all audit §8 scenarios + a headless full-render smoke driving every panel through `egui::Context::run`) |
| `asc-gui --selfcheck corpus/apk/workload.apk` | exit 0 |
| native launch smoke | process alive ≥8 s with corpus artifact loaded |

### Measured outcomes (same machine, `examples/gui_bench`, release)

| metric | before | after |
|---|---|---|
| per-frame source copies (8×512 KiB docs) | 1.0–1.9 ms + 4 MiB alloc, ≥2×/frame | **0** (one `Arc` clone; get+slice ≈ 0.06–0.12 ms) |
| tab activation | 4–7 ms tokenize + 1–2 ms outline on UI thread | **0** (spans/outline built on worker) |
| window interactive | after full class enumeration (9–80 ms corpus; linear in classes) | **immediately** (artifact opens as `LoadArtifact` task; tree lands ≤1 frame later) |
| explorer filter | O(N·L) scan every frame | cached per needle |
| findrefs | single-slot, no cancel/supersede | supersede + Esc cancel; discard-on-arrival |
| search results | hit count only | full per-DEX/per-caller rows, clickable |
| GUI overhead on engine ops | — | none (getclass 10.7–67 ms, findrefs 27–95 ms ≈ engine-only) |

### Scenario tests (audit §8, all green headless)

1. A/B late ordering → latest preview stays active (`late_result_cannot_steal_newer_activation`)
2. A fails, B succeeds → B active (`older_failure_does_not_clear_newer_intent`)
3. old-generation result after reload → ignored (`old_generation_result_ignored`, `generation_bump_marks_old_results_stale`)
4. preview A, preview B → single preview slot (`preview_slot_is_single`)
5. preview A, pin A, preview B → pinned + preview (`pin_converts_preview`, `preview_pin_preview_flow`)
6. cancelled/superseded search A, late → discarded (`superseded_findrefs_discarded_on_arrival`, `cancelled_task_result_discarded`)
7. pinned tab under cache pressure → metadata intact (`pinned_metadata_survives_document_eviction`)
8. Back/Forward restore document + line (`back_forward_restores_locations`, `navigation_restores_locations`)

### Notes / deliberate deviations

- **Persistence**: enabled via eframe's `persistence` feature — panel
  sizes, collapse state and window geometry persist through egui
  memory (native eframe storage); no custom config files.
- **Streaming search**: deferred per §10 (completed-report model
  retained; worst-corpus query ≈ 95 ms).
- **Per-DEX incremental explorer fill**: single `LoadArtifact` batch
  instead (enumeration is 3–63 ms total on corpus; the window is
  interactive before it starts, which is the actual §11 requirement).
- **References inspector view**: shows the retained search summary;
  per-symbol engine-driven findrefs is a search-with-class-filter run
  (no second engine path was invented).

### Polish round 2 (2026-09-15, driven by rendered screenshots)

Visual review via `egui_kittest` + wgpu software rasterization
(`visual_shots` test, `ASC_GUI_SHOTS=1` — renders the real workspace
to PNG, no GPU/window needed) surfaced and fixed:

| finding | fix |
|---|---|
| palette invisible (`Window::fixed_size([w, 0])` pinned interior height to 0 — Ctrl+P showed nothing) | `min_width/max_width`, content-sized height; full keyboard nav (▲▼/Enter/Esc), selected-row highlight, footer hints |
| bottom search-bar Enter only ran an *empty* query (inverted condition) | corrected |
| `Command::FindReferences` existed but no UI queued it | Analysis menu + palette entry: engine `Query::type_` on the active descriptor → REFERENCES bottom tab (new `TaskKind::FindRefsClass`, own supersede lane) |
| `Document.outline` computed on the worker but never rendered | STRUCTURE section in the inspector: fields dimmed, methods bright, click jumps to line |
| design §2 activity bar missing | 36px far-left strip: ▤ Explorer / 🔍 Search / ☰ Tasks, accent when active |
| glyph coverage unknown | `glyph_probe` test rasterizes candidates: `⌕ ✓ ⧉ ⋮ …` are tofu in egui default fonts; `🔍 ✔ ▤ ☰ ≡ ⚙ ▲▼ ▸▾ ⌘ ⚠ ●` render — UI now uses only covered glyphs |
| tab strip: dead code, boxed close button, status glyph after the close button, no active indicator | accent underline on the active tab, status glyph inside the tab, hover-only ×, no separators |
| editor empty state = one weak line in a void | structured quick-start (title + Ctrl+O/P/Shift+F/1-2-3 rows) |
| search rows overflowed on long literals | 96-char ellipsis + pointing-hand cursor |
| status bar `0 MiB` for small docs | human B/KiB/MiB |
| find current-match vs other matches indistinguishable | current match = stronger tint + accent border; other matches lighter |

Verification: 8 reference screenshots regenerated and inspected, all
gates green (fmt, clippy 0, workspace tests, selfcheck, native launch
smoke ≥8 s). Screenshot harness is permanent: `ASC_GUI_SHOTS=1 cargo
test -p asc-gui --lib visual_shots`.

### Jadx-style tree icons (2026-09-15)

Explorer rows now carry raster icons instead of text glyphs:

- **Packages**: amber folder (open/closed variants swap with the
  expanded state), 15 px, after the ▸/▾ chevron.
- **Classes**: source-file document with a colored kind badge —
  class `C` (accent blue), interface `I` (info), enum `E` (warning),
  annotation `@` (olive). Kind comes free from
  `class_def.access_flags` during enumeration (`ClassKind`), no new
  engine work.
- Assets: 32×32 RGBA blobs (`assets/ic_*.rgba`), generated by
  PowerShell System.Drawing, embedded via `include_bytes!`, uploaded
  once as `TextureHandle`s (`icons.rs`). No font-coverage exposure —
  the whole class of tofu bugs this round fixed does not apply to
  raster icons.

