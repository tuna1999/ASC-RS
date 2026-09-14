# GUI Audit — ASC-RS `asc-gui` (Phase 0)

Date: 2026-09-14 · branch `master` @ `ab5f060` · audited files:
`crates/asc-gui/src/{app,session,worker,package_tree,highlight,selfcheck,lib,main}.rs`,
`crates/asc-gui/tests/integration.rs`, consumers in `asc-core`.

All measurements: `cargo run --release -p asc-gui --example gui_bench`
(harness committed with this audit), 12th-gen i7-12700T, corpus APKs.

## 1. Current architecture map

```text
main.rs                    binary: --selfcheck | GUI mode
  └─ WorkspaceSession::open(path)          sync, before any window
  └─ eframe::run_native(AscApp::new)       sync init inside app-creator closure

app.rs  AscApp (1049 lines, 20 fields)     ALL state + ALL rendering
  ├─ session: WorkspaceSession             APK + per-DEX class cache + TAB STORAGE
  ├─ tree: PackageTree                     built once per session
  ├─ manifest / tree_filter / expanded
  ├─ query_input / query_kind / pending_findrefs: Option<Receiver>
  ├─ pending_getclass: Vec<Receiver>       anonymous receivers
  ├─ want_active: Option<String>           single-slot activation intent
  ├─ selected_class / active_tab / active_spans / active_outline
  ├─ nav_history: Vec<String> / nav_pos    descriptor-only
  └─ status / last_error / show_outline / show_findrefs / show_errors

worker.rs  spawn_job(Job) -> Receiver<JobResult>   thread-per-job, fire-and-forget
session.rs WorkspaceSession                           open_tab/open_tabs/close_tab (LRU-8)
package_tree.rs  arena tree + per-frame filter
highlight.rs     line tokenizer + outline heuristic
selfcheck.rs     headless engine smoke (kept as-is)
```

Frame flow (`AscApp::update`, app.rs:764-909): `poll_workers` → menubar →
toolbar (shortcuts inline) → bottom findrefs → statusbar → right outline →
left tree → central tabs+code.

## 2. Baseline measurements (release)

| cost | workload (6 220 cls) | aurora (9 930) | fdroid (13 394) |
|---|---|---|---|
| `WorkspaceSession::open` | 0.1 ms | 0.6 ms | 0.6 ms |
| `all_classes()` first call | 3.2 ms | 39.0 ms | 63.3 ms |
| `PackageTree::build` | 5.5 ms | 7.1 ms | 14.0 ms |
| manifest parse | 0.2 ms | 0.6 ms | 1.9 ms |
| **`AscApp::new` total (pre-first-frame)** | **~9 ms** | **~47 ms** | **~80 ms** |
| `run_getclass` (one click) | 11.2 ms | 36.5 ms | 67.0 ms |
| `run_findrefs` (one query) | 28.7 ms | 60.9 ms | 105.6 ms |
| `open_tabs()` snapshot, 8×512 KiB tabs | 1.0 ms | 1.4 ms | 1.0 ms |
| same, `.len()` (status-bar call) | 1.4 ms | 1.9 ms | 1.3 ms |
| tokenize 512 KiB doc (UI thread) | 4.2 ms | 7.0 ms | 4.7 ms |
| outline 512 KiB doc (UI thread) | 1.8 ms | 1.1 ms | 2.1 ms |
| `tree.filter("e")` per frame | 0.5 ms | 0.6 ms | 1.6 ms |

Corpus APKs are small (≤ 13.4 k classes). Init cost is linear in class
count and dominated by per-DEX inflate + `class_def` walk
(`session.rs:196-204` → `classes_for_dex` → `build_class_list`). A
100 k-class multidex APK projects to ≈ 600 ms of pre-window stall on this
machine; the *pattern* (block first paint on global enumeration) is the
defect, not the current corpus numbers.

## 3. Confirmed instability findings (root causes)

### F1 — `want_active` is a single slot cleared by the wrong request
`app.rs:357-369`. `want_active: Option<String>` holds the descriptor of
the *latest* click. In the `Err` branch of the getclass poll (line 366)
**any** failure sets `self.want_active = None` — including a failure for a
request that is *not* the one `want_active` refers to.

Broken sequence (deterministic, same session):

```text
tab X open (active_tab = Some(X))
click A → want_active = A, job A spawned
click B → want_active = B, job B spawned
job A fails → want_active = None      ← clears B's intent
job B succeeds → want_active ≠ B and active_tab.is_some()
              → B's tab is stored but NEVER activated (silent)
```

Violates the required invariant "click A, click B, A fails, B succeeds →
B active". Also line 358 `|| self.active_tab.is_none()` activates the
first *completing* job when no tab is open — a transient wrong-tab flash
when A (stale click) finishes before B.

### F2 — anonymous receivers; staleness handled by accident
`worker.rs:57-65` spawns one detached `std::thread` per job returning a
bare `Receiver`. Nothing carries identity (no task id, no session
generation). On Open/Reload, `load_session` (`app.rs:158-160`) replaces
the whole app struct — old receivers drop, the channel disconnects, and
late worker sends fail silently. That is *currently* the only reason an
old-APK result cannot corrupt a new session: an ownership accident, not a
design. Same-session ordering bugs (F1) are unaffected by it.

### F3 — findrefs is single-slot with no cancellation
`app.rs:172-174`: `start_findrefs` refuses while `pending_findrefs` is
`Some`. A slow query on a big APK blocks all further queries until it
finishes; there is no cancel and no way for a new query to supersede an
old one (required scenario "cancel search A, start search B, A returns
late → A cannot replace B" is currently impossible *and* untestable).

### F4 — per-frame full-source cloning
`session.rs:242-244` `open_tabs()` clones every `SourceTab` **including
`source: String`**. Call sites per frame:
- `draw_code_area` (app.rs:489) — full snapshot
- toolbar status (app.rs:849) — `open_tabs().len()` (clones everything for a count)
- `tab_by_descriptor` (app.rs:254-259) — another full single-tab clone on every activation

Measured 1.0–1.9 ms and a 4 MiB allocation per call at 8×512 KiB tabs,
≥ 2 calls per frame ≈ 25 % of a 60 fps frame budget spent copying, with
matching allocator churn. Cost grows linearly with open-tab count and
class size.

### F5 — synchronous tokenize/outline on the UI thread
`activate` (app.rs:232-251) tokenizes the entire source and rebuilds the
outline on every activation — including plain tab switches. Measured
4–7 ms + 1–2 ms per 512 KiB document. Spans/outline are recomputed even
when re-activating a previously visited tab (they are stored only for the
*active* tab, `active_spans`/`active_outline`).

### F6 — filter + tree walk re-run every frame
- `package_tree.rs:135-143` `filter()` allocates a lowercased copy of
  every descriptor per call; called every frame while the filter box is
  non-empty (app.rs:412). 0.5–1.6 ms at 13 k classes — plus allocation
  churn that grows with the class list.
- `draw_tree_node` (app.rs:431-444) clones `label`, `path`, and the first
  leaf descriptor `String` per visible node per frame, and collects
  children into a fresh `Vec<usize>` per node per frame.

### F7 — search results are discarded
`app.rs:294-311` reduces `SearchReport` to
`{line_count, complete, error_count, errors}`. `SearchReport.results[*].
matches[*]` (`asc-core/src/report.rs:34-60`: `RenderedMatch {caller,
matched: Vec<String>}`) — structured per-DEX, per-caller data the engine
already produced — is dropped. The user gets "N caller lines" and nothing
to click. This is a pure GUI-side data loss, not an engine gap.

### F8 — navigation is descriptor-only and destructively edited
`nav_history: Vec<String>` (app.rs:75-77). No line/symbol location (outline
jumps and future search-match jumps cannot participate). `close_tab`
(app.rs:272-273) `retain`s the descriptor out of history, silently
re-indexing Back/Forward targets.

### F9 — tab "semantics" are an LRU cache with identity collisions
`session.rs:206-253`. Tabs are keyed `dex_name::descriptor` but closed by
bare `descriptor` (line 248-253) — multidex shadow classes collide.
Eviction at `MAX_OPEN_TABS = 8` is silent and *not* LRU-correct:
activating an existing tab (app.rs:213-214) never refreshes `opened_at`,
so the most-recently-viewed tab can be evicted first. No preview/pinned
distinction; opening N search results would evict everything.

### F10 — thread-per-job fan-out
Every click spawns an outer thread; each getclass job additionally spawns
its own 8-thread `WorkerPool` (`asc-core/src/pipeline.rs:173-180`,
`GetClassOptions::default()`). N rapid clicks ≈ N×(1+min(8, dex_count))
threads. Bounded in practice by click rate; unbounded in principle.

### F11 — design constants scattered
Raw `Color32`s at app.rs:655-663, 871-880, highlight.rs:244-254; magic
sizes 13.0/12.5/26.0/240.0/220.0 throughout; shortcut checks inline in
the toolbar draw (app.rs:824-835). No token layer exists.

## 4. Performance hazards ranked

1. F4 per-frame source cloning — largest measurable per-frame cost, grows with usage.
2. F5 sync tokenize on activation — visible stall per click/switch on large classes.
3. §2 init stall — linear pre-window block; wrong shape even where currently small.
4. F6 per-frame filter + node clones — O(N) every frame while filtering.
5. F10 thread fan-out — modest today, principled bound needed.

## 5. State/concurrency hazards ranked

1. F1 want_active race (concrete user-visible bug).
2. F2 anonymous receivers — correctness by accident; blocks identity-based cancel/stale-drop.
3. F3 single-slot findrefs — no supersede/cancel.
4. F9 tab identity collisions + wrong eviction order.
5. F8 destructive history rewrite.

## 6. Code worth preserving

- `package_tree.rs` — arena design, `$`-nested inner classes; keep (add cached filter + lowercased keys).
- `highlight.rs` — line-local tokenizer + outline heuristic; pure, tested; keep (relocate colors to tokens).
- `show_rows` virtualized code view + `spans_to_job` LayoutJob assembly (app.rs:569-592, 721-755) — pattern is right; costs are in what feeds it.
- `session.rs` per-DEX lazy class cache (`class_cache`, BEHAVIOR.md §36 license) — keep; move tab storage out.
- `selfcheck.rs` + `tests/integration.rs` — untouched, must stay green.
- poll cadence `request_repaint_after(50ms)` + `try_recv` — keep.

## 7. Code requiring refactor

- `app.rs` `AscApp` — god object; split state from rendering (see `gui-architecture.md`).
- `worker.rs` — replace with identity-stamped task manager (Phase 1).
- `session.rs` tab block (`open_tab`/`open_tabs`/`close_tab`, lines 206-253) — replaced by TabController + DocumentCache.
- `FindRefsView` (app.rs:116-123) — replaced by SearchController retaining `SearchReport`.

## 8. Tests required before refactor

Existing (keep green): app.rs tests (getclass queue, activate-without-job,
history walk, spans coverage), tests/integration.rs (selfcheck, class
listing, history cap).

New regression tests (Phase 1+, headless via `egui::Context::default()`):

1. click A, click B, B first, A late → B stays active.
2. click A (fails), click B (succeeds) → B activates (fails today: F1).
3. old-APK job completes after reload → result ignored by generation.
4. preview A, preview B → only B in preview slot.
5. preview A, pin A, preview B → A pinned + B preview.
6. cancel search A, start search B, A lands late → A discarded.
7. document-cache pressure evicts pinned tab's document, not its metadata.
8. Back/Forward restores location (document + line) deterministically.

## 9. Benchmark protocol (acceptance targets)

Run `gui_bench` before and after each phase touching init/render paths.
Claims of improvement must cite these numbers on the same machine:
time-to-interactive (init block), per-frame clone cost (→ 0 after Phase 2),
activation tokenize stall (→ off critical path or amortized), filter cost
(cached), search overhead added by GUI (envelope/identity cost ≈ 0).
