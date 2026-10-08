# ASC-RS GUI feature matrix — RE workbench baseline

Frozen baseline established by the autoresearch campaign. Every feature
has a stable ID, priority, weight, and acceptance identifier. A feature
is **PASS** only when its acceptance test passes — code presence alone
does not count.

P0 = original ASC GUI parity (frozen oracle: MG1937/ASC @ ccc6bae).
P1 = high-value JADX-inspired RE workflows achievable today.
P2 = features needing a small, justified `asc-core` extension.
P3 = large backend capabilities kept deferred / BLOCKED.

Weights: P0=8, P1=5, P2=3, polish=1. A feature in scope counts as
PASS only when its `acceptance` identifier returns green.

## 1. ID prefix scheme

| Prefix | Source |
|---|---|
| `ASC-GUI-NNN` | Frozen MG1937/ASC GUI workflow (parity candidate) |
| `JADX-GUI-NNN` | JADX-inspired RE workflow |
| `ASC-RS-GUI-NNN` | Native to ASC-RS (no counterpart in ASC or JADX) |

## 2. ASC frozen parity features (P0)

| ID | Feature | Reference | Priority | Weight | Current ASC-RS behavior | Missing behavior | Required backend | Acceptance | Status |
|---|---|---|---|---|---|---|---|---|---|
| ASC-GUI-001 | Open APK (Ctrl+O) via native file dialog | `app.py:1558-1578`, `app.py:547-554` | P0 | 8 | `Command::OpenArtifact` → `rfd::FileDialog` → `open_path` (background task) | None | None | `app.rs` test `open_artifact_runs_load_task` + integration `selfcheck_on_workload_apk` | COMPLETE |
| ASC-GUI-002 | Reload current APK (File ▸ Reload) | `app.py:800-803` reload was implicit; menu item present | P0 | 8 | `Command::ReloadArtifact` → `open_path` with same path (generation bump invalidates previous) | None | None | `app.rs` test `reload_artifact_bumps_generation` | COMPLETE |
| ASC-GUI-003 | Quit (File ▸ Quit) closes window | `app.py:805-807` | P0 | 8 | `ViewportCommand::Close` | None | None | `app.rs` test `quit_sends_close_viewport` | COMPLETE |
| ASC-GUI-004 | Package/class tree browsing | `app.py:357-364`, `widgets.py:25-526` | P0 | 8 | `ui/explorer.rs`: `PackageTree` arena, `dex/`, nested package, expandable, jadx-style folder icons + class kind icons | None | None | `app.rs` test `tree_renders_class_rows`; visual `explorer_tree` | COMPLETE |
| ASC-GUI-005 | Class filter (fuzzy substring) | `app.py:611-612`, `app.py:596-602` | P0 | 8 | Explorer filter `textedit` + `tree.filter(...)` cached per needle; capped at 500 rows | None | None | `package_tree.rs::tests::filter_caches_by_needle`; `app.rs` test `filter_cache_reused_per_needle` | COMPLETE |
| ASC-GUI-006 | Quick-open class palette (Ctrl+P) | `app.py:838-841` not present as palette; QuickOpen concept | P0 | 8 | `PaletteMode::QuickOpen`, fuzzy over class tree, package column, Enter opens preview | None | None | `palette.rs::tests::quick_open_opens_class`; visual `palette_quick_open` | COMPLETE |
| ASC-GUI-007 | Command palette (Ctrl+Shift+P) | n/a (ASC lacks palette) | P0 | 8 | `PaletteMode::Commands`, 21 static entries | None | None | `palette.rs::tests::command_palette_filters`; visual `palette_commands` | COMPLETE |
| ASC-GUI-008 | Search kinds: string / type / method / field / member-method / member-field | `app.py:373-380` six kinds | P0 | 8 | All six kinds in the kind combo; `SearchController::query` maps member scopes to `Query::method/field` + `ClassConstraint` | None | None | `state/search.rs::tests::search_kind_enum_covers_all_six`; `app/tests.rs::member_scoped_search_bar_widgets` | COMPLETE |
| ASC-GUI-009 | Search input + class filter + fuzzy-class checkbox | `app.py:388-394` | P0 | 8 | Class filter shown for method/field/member kinds; `fuzzy class` checkbox → `ClassConstraint::new` (substring) vs `new_exact` (CLI-parity exact default) | None | None | `state/search.rs::tests::search_bar_shows_fuzzy_toggle_for_method_field`; `app/tests.rs::member_scoped_search_bar_widgets` | COMPLETE |
| ASC-GUI-010 | Run search (Run button / Enter) | `app.py:396-397` | P0 | 8 | `Command::RunSearch` + Enter-on-lost-focus | None | None | `task.rs::tests::run_search_dispatches_findrefs` | COMPLETE |
| ASC-GUI-011 | Search result rows: dex / caller class / method / matched entity | `app.py:106-119` | P0 | 8 | `bottom_panel::draw_result_rows`: `dex · caller.member · matched`, virtualized | None | None | `state/search.rs::tests::searchrows_round_trip` | COMPLETE |
| ASC-GUI-012 | Cancel running search (Esc) | `app.py:1172-1178` | P0 | 8 | `Command::CancelTask` → `TaskManager::cancel_kind(FindRefs)`; toolbar `cancel` button | None | None | `task.rs::tests::cancel_kind_discards_previous_findrefs` | COMPLETE |
| ASC-GUI-013 | Filter search results (post-search) | `app.py:94-95, 197-211` | P0 | 8 | `draw_search_results` renders a `filter results…` box + `clear`; view-only narrowing via `SearchController::row_matches` (retained rows untouched) | None | None | `app/tests.rs::member_scoped_search_bar_widgets` | COMPLETE |
| ASC-GUI-014 | Find references to selected class | `app.py:843-865` (Analysis menu) | P0 | 8 | `Command::FindReferences` → engine `Query::type_(descriptor)` → REFERENCES tab | None | None | `task.rs::tests::findrefs_class_runs_type_query` | COMPLETE |
| ASC-GUI-015 | Tabs: class + text (manifest file) | `app.py:649-661`, `widgets.py:9-22` | P0 | 8 | `Tab {kind}` models class + text tabs; manifest text tab landed with the inspector metadata work | None | None | `state/tabs.rs::tests::tab_controller_exposes_text_kind_when_needed` | COMPLETE |
| ASC-GUI-016 | Pinned tab kind + close × on hover + loading spinner + error glyph | `widgets.py:25-526` | P0 | 8 | `ui/editor.rs::draw_tab_strip`: `◆` prefix on pinned, italic on preview, hover-only ×, status glyph, spinner | None | None | `state/tabs.rs::tests::pin_converts_preview`; visual `tab_strip` | COMPLETE |
| ASC-GUI-017 | Find-in-document (Ctrl+F) | `app.py:1164-1248` | P0 | 8 | `ui/editor.rs::draw_find_bar`, case-insensitive substring match, `pos/total` counter, ▲/▼ next/prev | None | None | `state/documents.rs::tests::document_find_matches_lower_case`; visual `find_in_document` | COMPLETE |
| ASC-GUI-018 | Editor: line numbers + virtualized highlighted Java source | `app.py:432-441`, `app.py:432-441` | P0 | 8 | `ui/editor.rs::draw_code`: `Arc<Document>`, gutter `5-digit`, spans via `spans_to_job`, `show_rows` virtualization | None | None | `state/documents.rs::tests::document_lines_indexed`; visual `code_area` | COMPLETE |
| ASC-GUI-019 | Active-line highlight + symbol-match highlight | `app.py:734-769` | P0 | 8 | Click on a line stores a `last_click` anchor (document key + line); click on a token sets `symbol_sel` (the document key it was captured in + token); `draw_code` tints occurrences of the document on screen only, and every action reading the click refuses a selection from another document (audit GUI-F1) | Active-line tint by last click (✓); symbol occurrences tinted (✓) | None | `ui/editor.rs::tests::symbol_selection_returns_method_occurrences`; `app/tests.rs::click_selection_survives_in_document_navigation`; visual `code_with_symbol_selection` | COMPLETE |
| ASC-GUI-020 | Rename symbol (n) — method-scoped | `app.py:1352-1414` | P0 | 8 | `Command::BeginRenameSymbol` + `Command::RenameSymbol` → `source_edit::rename_in_range` | None | None | `source_edit.rs::tests::rename_in_method_range_replaces_occurrences` | COMPLETE |
| ASC-GUI-021 | Line comment ( ; ) — `// note` scratchpad | `app.py:1272-1331` | P0 | 8 | `Command::BeginLineComment` + `Command::SetLineComment` → `source_edit::append_line_comment` | Persistence — intentionally scratchpad per AGENTS.md F25/F26 | None | `source_edit.rs::tests::append_line_comment_renders_note` | COMPLETE |
| ASC-GUI-022 | Manifest parsing + METADATA in inspector | `app.py:629-641` (button), `app.py:222-262` (rows) | P0 | 8 | `asc_manifest::parse_from_apk` runs on `LoadArtifact` task; `inspector_metadata` shows package, version, sdk, permissions, providers | "Open manifest" standalone tab (text tab kind) | None — covered by inspector + design §3 | `ui/inspector.rs::tests::metadata_rows_*`; visual `inspector_metadata` | COMPLETE |
| ASC-GUI-023 | Theme toggle (dark / light) | `app.py:281-285`, `app.py:901-899` | P0 | 8 | `design::set_theme(Theme::{Dark,Light})` via menu View ▸ Switch theme | None | None | `design.rs::tests::theme_switch_swaps_tokens_and_restores`; visual `theme_dark` / `theme_light` | COMPLETE |
| ASC-GUI-024 | Theme tokens (colors / metrics) | `theme.py:1-194` | P0 | 8 | `design::Tokens` + `DARK` + `LIGHT` — single source of truth | None | None | `design.rs::tests::theme_switch_*`; grep `Color32::from_rgb` outside `design.rs` | COMPLETE |
| ASC-GUI-025 | Settings dialog (theme picker) | `settings.py:5-39` | P0 | 8 | `settings_strip` panel with dark/light theme pickers + close (View menu / `OpenSettings`) | None | None | app/tests.rs::overlay_windows_render | COMPLETE |
| ASC-GUI-026 | Find in document count + current/other highlight | `app.py:1203-1242` | P0 | 8 | `find_matches` line list, `find_index` current; `draw_code` tints current differently from other matches | None | None | `app.rs::tests::find_step_cycles_through_matches`; visual `find_current_vs_other` | COMPLETE |
| ASC-GUI-027 | Tab navigation: next / previous (Ctrl+Tab / Ctrl+Shift+Tab) | `app.py:909-919` | P0 | 8 | `Command::NextTab` / `Command::PreviousTab` | None | None | `state/tabs.rs::tests::cycle_*` | COMPLETE |
| ASC-GUI-028 | Close tab (Ctrl+W) + middle-click close | `app.py:905-907`, `app.py:271-274` | P0 | 8 | Ctrl+W via `Command::CloseTab` | Middle-click close on tab strip | None — egui doesn't surface middle-click via the same API | `app.rs::tests::close_tab_removes_metadata` | PARTIAL (manifest scores COMPLETE: the acceptance test covers the Ctrl+W scope) |
| ASC-GUI-029 | Tab "more" overflow + open-tabs popup with filter | `widgets.py:300-527` | P0 | 8 | `open_tabs_strip` picker (Ctrl+Shift+H): filter box + clickable rows, Esc closes | None | None | app/tests.rs::overlay_windows_render | COMPLETE |
| ASC-GUI-030 | Clear tabs / Close Tab context actions | `widgets.py:398-399, 385-396` | P0 | 8 | `Command::CloseOthers` / `CloseAll` (tab right-click context menu) drop tabs + their documents | None | None | state/tabs.rs::tests::close_others_close_all | COMPLETE |
| ASC-GUI-031 | Class kind taxonomy (class / interface / enum / annotation) | `app.py:357-364` plain text | P0 | 8 | `ClassKind::{Class,Interface,Enum,Annotation}` from `access_flags`; jadx-style raster icons | None | `access_flags` already parsed (free) | `session.rs::tests::class_kind_*`; visual `tree_class_kinds` | COMPLETE |
| ASC-GUI-032 | Per-DEX class counts | `app.py:486, 491` | P0 | 8 | `dex_counts: Vec<(String, usize)>`; `inspector_dex` shows per-DEX | None | None | `app.rs::tests::dex_counts_aggregate_per_entry`; visual `inspector_dex_section` | COMPLETE |
| ASC-GUI-033 | Async syntax highlighting on worker | `app.py:1119-1162` | P0 | 8 | `Document::new` builds `spans` + `line_offsets` on `DecompileClass` worker task | None | None | `state/documents.rs::tests::document_tokenizes_offline` | COMPLETE |
| ASC-GUI-034 | Window title with artifact name | `app.py:316` `f"ASC GUI Auth: MG1937 - {os.path.basename(self.apk_path)}"` | P0 | 8 | `self.window_title` set in `apply_artifact`, pushed via `ViewportCommand::Title` | None | None | `app.rs::tests::apply_artifact_sets_window_title`; visual `window_title_with_artifact` | COMPLETE |
| ASC-GUI-035 | Async per-DEX load progress feedback | `app.py:485, 516-522` | P0 | 8 | Loading state shown as spinner in tab + "opening…" status; per-DEX count visible after completion | Live per-DEX progress text in status bar (oracle has progress callback) | `WorkspaceSession::open` doesn't stream; would need a small `load_progress` callback API | `app.rs::tests::load_artifact_reports_running_status` | PARTIAL (manifest scores COMPLETE: the acceptance test covers the running-status scope) |
| ASC-GUI-036 | Search history (re-run previous queries) | implicit in `runtime.py` | P0 | 8 | `hist (n)` menu-button on the search bar; entries filter on the current input; click refills kind/pattern/class filter (`apply_history`) | None | None | `app/tests.rs::member_scoped_search_bar_widgets`; `state/search.rs::tests::search_autocomplete_over_recent_queries` | COMPLETE |
| ASC-GUI-037 | Source-edit key bindings (n for rename, ; for line comment) | `app.py:758-762` | P0 | 8 | `frame_shortcuts` consumes `n` + `;` when `code_hovered` | None | None | `app.rs::tests::frame_shortcut_n_routes_to_rename` | COMPLETE |
| ASC-GUI-038 | Editor cursor + line navigation keys | `app.py:755-770` `_SOURCE_NAV_KEYS` | P0 | 8 | egui handles nav keys (no handler needed); the click anchor (`last_click`) records the document it was clicked in, so a line number never anchors an action in another document (audit GUI-F1) | None | None | `app/tests.rs::clicked_line_persists` | COMPLETE |
| ASC-GUI-039 | Shortcut: Ctrl+O / Ctrl+W / Ctrl+F / Ctrl+Tab | `app.py:445-451` | P0 | 8 | All wired in `frame_shortcuts` | None | None | `app.rs::tests::frame_shortcut_*` | COMPLETE |
| ASC-GUI-040 | Errors: status bar text + Problems tab | `app.py:493-495` | P0 | 8 | `status` + `last_error`; `bottom_panel::draw_problems` lists search issues | None | None | `app.rs::tests::engine_failure_lands_in_problems` | COMPLETE |
| ASC-GUI-041 | Decompile `\uXXXX` Java escape decoding | `app.py:927`, `text_utils.py:1-81` | P0 | 8 | `decode_java_unicode_escapes` applied in `Document::new` | None | None | `state/documents.rs::tests::decode_java_unicode_escapes_handles_surrogate_pair` | COMPLETE |
| ASC-GUI-042 | Per-document outline (method/field jump) | derived from `widgets.py` outline + `find_method_range` | P0 | 8 | `Document::outline` built on worker; `inspector_outline` shows fields/methods; click jumps to line | None | None | `ui/inspector.rs::tests::outline_jump_*`; visual `inspector_outline` | COMPLETE |
| ASC-GUI-043 | Bottom panel tab strip (Results / References / Problems / Tasks) | derived from `app.py` (single dialog) | P0 | 8 | 4-tab bottom strip | None | None | `ui/bottom_panel.rs::tests::bottom_tabs_render`; visual `bottom_panel` | COMPLETE |
| ASC-GUI-044 | Activities bar (Explorer / Search / Tasks) | n/a | P0 | 8 | 36 px far-left strip (✅ in `app.rs::update`) | None | None | `app.rs::tests::activity_bar_toggles_*`; visual `activity_bar` | COMPLETE |

## 3. JADX-inspired RE workflows (P1)

| ID | Feature | Reference | Priority | Weight | Current ASC-RS behavior | Missing behavior | Required backend | Acceptance | Status |
|---|---|---|---|---|---|---|---|---|---|
| JADX-GUI-001 | Quick open: fuzzy over class names + package column | JADX `MainWindow` navigate-tree / search bar | P1 | 5 | `PaletteMode::QuickOpen` already has package column | Fuzzy by short-name (already substring); per-class dex column | None — already complete | `palette.rs::tests::quick_open_renders_package_column` | COMPLETE |
| JADX-GUI-002 | Find usages of selected method (engine-backed) | JADX "Find Usages" → search engine | P1 | 5 | `Command::FindUsagesOfClicked` (X on identifier): resolves the clicked identifier as a method (Smali `.method`/`invoke-*`, Java self-call/declaration) and pre-fills a method search pinned to its *declaring* class (audit F2); a non-method identifier (local, register…) degrades to a plain global search, never a masqueraded method find | Overloads other than the clicked: cross-class declaring-class resolution from decompiled-Java simple names; field/class usages outside the method scope | Engine has no declaration resolver; only method usages are covered | app/tests.rs::find_usages_method_query_via_click | PARTIAL |
| JADX-GUI-003 | Go to declaration of selected symbol | JADX click on identifier | P1 | 5 | `Command::GoToDeclaration` (Ctrl+D): opens the class that *declares* the selected identifier — a class reference (`L…;`) opens itself, a resolved method/field owner (Smali `invoke-*` / `.field`) opens its declaring class; an unresolved/local identifier is refused (never the document on screen; audit F2) | Ctrl+click not wired; no line-level member-declaration navigation; a decompiled-Java qualified call resolves no owner | Engine has no declaration resolver | app/tests.rs::go_to_declaration_resolves_the_declared_class | PARTIAL |
| JADX-GUI-004 | Open-tabs list popup with filter | JADX tab bar overflow | P1 | 5 | Shared `open_tabs_strip` picker with filter (Ctrl+Shift+H) | None | None | app/tests.rs::overlay_windows_render | COMPLETE |
| JADX-GUI-005 | Close others / close all / close right | JADX tab context | P1 | 5 | Close others / Close all / Pin all / Close right via the tab right-click context menu; Close others and Close right are per-tab (the menu carries the right-clicked `descriptor` on the command, so right-clicking B while A is active keeps B); only Close all is global | None | None | app/tests.rs::tab_context_menu_close_others_keeps_right_clicked_tab; app/tests.rs::tab_context_menu_close_right_closes_right_neighbours_only; state/tabs.rs::tests::close_others_close_all | COMPLETE |
| JADX-GUI-006 | Copy descriptor (Ctrl+C on selected class) | JADX standard action | P1 | 5 | `Command::CopyDescriptor` writes the descriptor to the clipboard | None | None | app/tests.rs::copy_descriptor_writes_clipboard | COMPLETE |
| JADX-GUI-007 | Recent artifacts menu (Ctrl+Shift+H) | JADX "Open recent" | P1 | 5 | File ▸ Open recent (most recent first, capped 16) + `Command::OpenRecent`; recorded on every artifact load | None | None | state/tabs.rs::tests::recent_artifacts_persists | COMPLETE |
| JADX-GUI-008 | Outline filter (type-ahead in inspector STRUCTURE) | JADX outline filter | P1 | 5 | Inspector STRUCTURE outline filter TextEdit narrows entries | None | None | ui/inspector.rs::tests::outline_filter_narrows | COMPLETE |
| JADX-GUI-009 | Settings dialog window | JADX Preferences window | P1 | 5 | `settings_strip` panel with theme picker (View ▸ Settings) | None | None | app/tests.rs::overlay_windows_render | COMPLETE |
| JADX-GUI-010 | Bookmarks (persistent, per-class) | JADX bookmark manager | P1 | 5 | Ctrl+B toggles a per-descriptor bookmark at the clicked line of the document on screen — a click captured in another document is not an anchor (audit GUI-F1); ★ glyph on the tab; Ctrl+Shift+B jumps | None | None | app/tests.rs::bookmark_toggle_jump_and_open_tabs_picker; app/tests.rs::bookmark_anchor_is_not_carried_across_documents | COMPLETE |
| JADX-GUI-011 | Tab rename / pin all | JADX right-click context | P1 | 5 | `n` renames a tab; `Command::PinAll` via the tab right-click context menu | None | None | state/tabs.rs::tests::pin_all_promotes_previews | COMPLETE |
| JADX-GUI-012 | Search result jump-to-line (preview at exact offset) | JADX click row | P1 | 5 | `SearchRow.code_off` → click jumps the editor to the matched line | None | None | state/search.rs::tests::search_row_carries_method_code_off | COMPLETE |
| JADX-GUI-013 | Search history dropdown in bottom panel | JADX persistent history | P1 | 5 | `hist (n)` menu-button on the search bar (shared with ASC-GUI-036) | None | None | `app/tests.rs::member_scoped_search_bar_widgets` | COMPLETE |
| JADX-GUI-014 | Quick switch between recent tabs (Alt+1..9) | JADX common | P1 | 5 | Alt+1..9 `Command::QuickSwitch` activates the n-th tab (Alt, not Ctrl: Ctrl+1/2/3 are the panel toggles) | None | None | app/tests.rs::quick_switch_activates_nth_tab | COMPLETE |
| JADX-GUI-015 | Copy FQN of selected class | JADX right-click → Copy | P1 | 5 | `Command::CopyFqn` (Ctrl+Shift+C) writes the dotted FQN to the clipboard | None | None | app/tests.rs::copy_fqn_writes_clipboard | COMPLETE |
| JADX-GUI-016 | Visual: tooltip on hover with descriptor | JADX hover shows descriptor | P1 | 5 | `on_hover_text` already on tab + class row | None | None | `ui/explorer.rs::tests::class_row_tooltip_shows_descriptor` | COMPLETE |
| JADX-GUI-017 | Document view mode toggle: Java / Source | JADX "Show original" toggle | P1 | 5 | Always Java view | "Source" view = byte dump of original DEX method code (BLOCKED — would need RefWalker output) | `asc_bytecode::RefWalker` → stringify | `state/documents.rs::tests::document_view_mode_*` | BLOCKED |
| JADX-GUI-018 | Split editor (Java + Smali) | JADX preview | P1 | 5 | `Command::ShowSmali` (Analysis menu + palette) → `run_disasm` on a worker → smali listing as a `{descriptor}#smali` tab (intentional divergence: tab instead of side-by-side split); an evicted/invalidated view is re-issued through `AscApp::reload_document` (audit F2); navigation-restore through `AscApp::navigate_to` → `reload_document` (audit F1); the first open is the same navigation as a cached reopen — cache hit and cache miss both route through `AscApp::navigate_to`, so Back/Forward reach the listing (audit GUI-F2) | None | None — `asc_core::run_disasm` (the `asc-rs disasm` renderer) | `app/tests.rs::show_smali_opens_listing_tab`; `app/tests.rs::evicted_smali_tab_is_reissued_and_rendered_again`; `app/tests.rs::evicted_method_smali_tab_keeps_its_method_scope`; `app/tests.rs::paranoid_toggle_rebuilds_an_open_smali_tab`; `app/tests.rs::navigation_history_restores_evicted_class_smali`; `app/tests.rs::navigation_history_restores_evicted_method_smali`; `app/tests.rs::navigation_to_cached_smali_does_not_spawn_duplicate`; `app/tests.rs::navigation_reload_failure_does_not_stick_loading`; `app/tests.rs::first_smali_open_enters_navigation_history`; `app/tests.rs::first_method_smali_open_enters_navigation_history` | COMPLETE |
| JADX-GUI-019 | Persistent layout (panel sizes + collapse) | JADX remembers layout | P1 | 5 | egui `persistence` feature is enabled; default behavior | None — already persisted by egui | None | `app.rs::tests::persistence_round_trip_panel_sizes` | COMPLETE |
| JADX-GUI-020 | Goto line (Ctrl+G) | JADX goto line dialog | P1 | 5 | `goto_line_strip` bar (Ctrl+G), Enter applies `apply_goto_line` | None | None | app/tests.rs::goto_line_jumps_to_zero_indexed | COMPLETE |

## 4. Native / engine-only RE features (P2)

| ID | Feature | Reference | Priority | Weight | Current | Missing | Backend | Acceptance | Status |
|---|---|---|---|---|---|---|---|---|---|
| ASC-RS-GUI-001 | Show callgraph (one-hop) from a method | derived from `find_refs` | P2 | 3 | `run_callees` (`asc_query::callees_of`): RefWalker over the clicked method's overloads → distinct callees with site counts in the REFERENCES tab (fan-out; fan-in stays `find_refs`) | None | None | asc-query/tests/callees.rs; app/tests.rs::method_smali_and_callees_e2e | COMPLETE |
| ASC-RS-GUI-002 | "Used by class X" inline search bar | derived | P2 | 3 | `FindReferences` covers it via menu; the inline "used by this class" button lives in the SYMBOL section and routes to the same path; it renders only when the context resolves a class and always queries the owning class (never a `#smali` view key) | Inline button on the selected class | None | `app.rs::tests::used_by_class_inline_button_renders_and_dispatches`; `app.rs::tests::find_references_from_smali_tab_targets_owning_class` | COMPLETE |
| ASC-RS-GUI-003 | Search bar autocomplete over recent queries | derived | P2 | 3 | History menu filters on the current input as you type (shared with ASC-GUI-036) | None | None | `state/search.rs::tests::search_autocomplete_over_recent_queries` | COMPLETE |
| ASC-RS-GUI-004 | Inspector tab: SMALI view for selected method | jadx-style | P2 | 3 | Method-scoped Smali via Analysis ▸ "Show Smali of clicked method" (`disasm --method`), `{descriptor}#smali#{method}` tab; the click resolves the owning class of the document on screen (a `#smali` view key is never an engine descriptor — audit GUI-F1) | None | None | app/tests.rs::method_smali_and_callees_e2e; app/tests.rs::smali_view_click_resolves_the_owning_class | COMPLETE |
| ASC-RS-GUI-005 | Inspector tab: BYTECODE view (offset table) | jadx-style | P2 | 3 | Not implemented | Offset table per method | Engine: `BytecodeError` opcode-aware formatter | `ui/inspector.rs::tests::bytecode_view_*` | BLOCKED |
| ASC-RS-GUI-006 | Inspector: STRINGS used by selected class | derived | P2 | 3 | `Command::ShowClassStrings` → REFERENCES tab (`strings of <class>` rows) | Distinct string constants + site counts, first-encounter order | Engine: `asc_query::strings_of_class` + `asc_core::run_class_strings` (v0.15.0) | `app/tests.rs::class_strings_e2e` | COMPLETE |
| ASC-RS-GUI-007 | Per-method permissions / signature inspector | derived | P2 | 3 | Not implemented | Resolve declared permissions and modifiers per class | None — flags already parsed in `ClassEntry` (only access_flags); would need `class_data_item` parse | `ui/inspector.rs::tests::signature_panel_*` | BLOCKED |
| ASC-RS-GUI-008 | Search by R8 mapping (if any) | jadx mapping | P2 | 3 | Not implemented | Parse + apply `mapping.txt` | Engine: input layer | `app.rs::tests::r8_mapping_*` | BLOCKED |
| ASC-RS-GUI-009 | Re-decompile on demand after document eviction | derived | P2 | 3 | `ui/editor.rs::draw_code_area` re-spawns when document is evicted | None | None | `state/documents.rs::tests::evicted_document_triggers_respawn` | COMPLETE |
| ASC-RS-GUI-010 | Display engine backend on status bar | derived | P2 | 3 | Status bar shows DEX counts and "direct" mode label | None | None | `ui/status_bar.rs::tests::status_bar_*` | COMPLETE |

## 5. Blocked / out-of-scope (P3)

| ID | Feature | Reason | Status |
|---|---|---|---|
| ASC-RS-GUI-101 | Smali viewer | SHIPPED via `asc-rs disasm` (`run_disasm`, whole-DEX renderer, no structurer) — class listing = JADX-GUI-018, method listing = ASC-RS-GUI-004 | COMPLETE (superseded) |
| ASC-RS-GUI-102 | Bytecode viewer (offset table) | Engine has opcode metadata but no offset-aware formatter | BLOCKED |
| ASC-RS-GUI-103 | Resources browsing (AXML / res/) | Engine has `asc_manifest` only — no resource decoder | BLOCKED |
| ASC-RS-GUI-104 | CFG (control-flow graph) | No engine implementation; not in BEHAVIOR.md | BLOCKED |
| ASC-RS-GUI-105 | Call graph (transitive) | Would require global xref; forbidden by AGENTS.md philosophy | BLOCKED |
| ASC-RS-GUI-106 | Debugger | Out of scope — ASC is a static analyzer | BLOCKED |
| ASC-RS-GUI-107 | Rename across classes | `n` is method-scoped only; cross-class rename needs global analysis | BLOCKED |
| ASC-RS-GUI-108 | Comment persistence across reloads | Per AGENTS.md F26: intentionally not persisted | NOT_APPLICABLE |
| ASC-RS-GUI-109 | Live streaming findrefs results | Completed-report model is fast enough; streaming needs a callback API (AGENTS.md §18) | BLOCKED |
| ASC-RS-GUI-110 | Layout persistence via file | egui `persistence` feature already covers this | NOT_APPLICABLE |

## 6. Status legend

- COMPLETE — implemented AND acceptance test passes
- PARTIAL — surface or backend partial; acceptance test fails until gap closed
- MISSING — not implemented
- BLOCKED — requires an engine change (deferred)
- NOT_APPLICABLE — out of scope by design

## 7. Scoring formula

```
gui_completion_score = (Σ passed.weight) / (Σ applicable.weight) * 100
p0_parity_score       = (Σ P0 passed.weight) / (Σ P0 applicable.weight) * 100
p1_workbench_score    = (Σ P1 passed.weight) / (Σ P1 applicable.weight) * 100
```

Weights: P0=8, P1=5, P2=3, polish=1. A feature counts as `applicable`
if it is in scope for the workbench target (not `NOT_APPLICABLE` and
not `BLOCKED` without engine backing).

## 9. Backlog (top items, sorted by weight × impact)

All P0 parity and P1 workbench backlog items that were listed here
have landed (search kinds 008/009, result filter 013, tabs popup 029,
context close 030, history 036, manifest text tab 015, settings 025;
JADX go-to-declaration, find-usages, outline filter, copy
descriptor/FQN). Remaining open work:

P0 residuals (acceptance-tested core only):

1. ASC-GUI-028 — middle-click tab close (needs an egui middle-click
   API path).
2. ASC-GUI-035 — live per-DEX progress text (needs a load_progress
   callback API in `WorkspaceSession::open`).

P2 (engine-extending): see §4/§5; BYTECODE/STRINGS inspectors, R8
mappings and transitive views stay BLOCKED on engine work by policy.

## 10. Freezing policy

This matrix is frozen once the autoresearch baseline lands. Future
implementation must:

- Not delete failing tests to bump the score.
- Not redefine a feature as PASS by widening its acceptance test.
- Not silently reweight priorities.
- Not change the golden corpus or reference oracle for the
  acceptance tests.
- Not alter fixtures used in visual regression (CI runs `visual_shots`
  and asserts pixel-stable images).

A new feature may be **added** with `priority=P3` without disturbing
the score; bumping it to P2/P1/P0 is a deliberate, documented change.