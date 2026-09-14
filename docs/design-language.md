# ASC Instant Workbench — design language

Visual system for `asc-gui`. Goals: **speed, precision, low overhead,
technical density, analysis context**. Explicitly not: cyberpunk, gaming
launcher, web SaaS, terminal cosplay. Native, compact, dark-first.

## 1. Tokens (`design.rs`)

Single source of truth. All rendering code references semantic tokens;
raw `Color32`/f32 literals in `ui/*` are prohibited outside `design.rs`.

```rust
pub struct Tokens { /* all values below as fields */ }
```

### Palette (dark, reference values)

| token | value | use |
|---|---|---|
| `app_bg` | `#0F1115` | window background |
| `panel_bg` | `#14171D` | side/bottom panel background |
| `surface` | `#191D24` | cards, inputs, tab strip |
| `hover` | `#202631` | hover fill |
| `border` | `#2A313C` | separators, panel edges |
| `text` | `#E6EAF0` | primary text |
| `text_secondary` | `#9099A7` | hints, counts, meta |
| `text_disabled` | `#5C6674` | unavailable actions |
| `accent` | `#4C8DFF` | selection, focus, active tab underline |
| `success` | `#3FB950` | complete, ready |
| `warning` | `#D29922` | incomplete, warnings |
| `error` | `#F85149` | failures, destructive |
| `info` | `#58A6FF` | informational badges |

Syntax colors (kept from the audit as semantic tokens, tuned to the
palette): keyword/modifier `#CC8844`, type `#A9B7C6`, annotation
`#BBB529`, string `##6AA75E` → `#7CBF6B`, number `#2AA198`, comment
`#6E7681`, plain `#C8CEDA`.

### Metrics

| token | value |
|---|---|
| `row_tree` | 20.0 px |
| `row_list` | 20.0 px |
| `tab_height` | 26.0 px |
| `toolbar_height` | 30.0 px |
| `status_height` | 24.0 px |
| `menubar_height` | 22.0 px |
| `code_size` | 13.0 px monospace |
| `ui_size` | 13.0 px |
| `small_size` | 11.5 px |
| `panel_padding` | 8.0 px |
| `spacing` | 4.0 / 8.0 px (tight / normal) |
| `explorer_default` | 260 px |
| `inspector_default` | 240 px |
| `bottom_default` | 180 px |

## 2. Layout

```text
┌─────────────────────────────────────────────────────────────────┐
│ menubar: File Navigate Search View Analysis Help                │
├────┬────────────────────────────────────────────────────────────┤
│ tb │ ◀ ▶   search artifact…                          ⌘P          │  toolbar
├────┼────────────────┬────────────────────────┬──────────────────┤
│ E  │ EXPLORER       │ tabs …                 │ INSPECTOR        │
│ R  │ filter…        ├────────────────────────┤ Symbol            │
│ B  │ ▾ classes.dex  │                        │ DEX               │
│ R  │   ▾ com/…      │  Java source           │ References        │
│    │     Foo        │  (virtualized)         │ Metadata          │
├────┴────────────────┴────────────────────────┴──────────────────┤
│ SEARCH RESULTS │ REFERENCES │ PROBLEMS │ TASKS        (resizable)│
├─────────────────────────────────────────────────────────────────┤
│ ● Ready │ 2 DEX │ 13 394 classes │ direct │ decompiling Foo…    │
└─────────────────────────────────────────────────────────────────┘
```

- Activity bar (far left, ~36 px): Explorer / Search / Tasks toggles —
  icon buttons, accent when active.
- Editor gets all remaining space; Inspector and Bottom are collapsible
  and resizable; Explorer collapsible.
- Status bar: state dot (`success`/`warning`/`error`/`accent`-busy) +
  DEX/class counts + engine mode ("ASC Direct") + transient operation.

## 3. Components

- **Tree row**: 20 px, monospace 12.5 px; package glyph `▸/▾` (secondary
  until hover); class leaf diamond; selected row = `accent` tinted
  background + `text`; hover = `hover` fill. Nested classes under class
  nodes, `$` path shown dimmed.
- **Tab**: 26 px; label = short class name, monospace; preview tabs
  italic with "preview" tint; pinned tabs carry a pin glyph; active tab =
  `surface` + 2 px `accent` underline; close `×` on hover; loading =
  inline spinner; error = `error`-tinted label with tooltip.
- **Editor gutter**: 5-digit line numbers, `text_disabled`, right-aligned,
  non-selectable; the active navigation target line gets `accent` tint.
- **Search row**: `dex · CallerClass.member · matched entity` — matched
  entity in `accent`; row hover = `hover`; selected row keeps result list
  visible (never auto-hides the bottom panel).
- **Badges**: counts (`12 hits`) `text_secondary`; completeness ✓
  `success` / ⚠ `warning`; task states: queued `text_secondary`, running
  `accent` + elapsed, done `success`, failed `error`, stale/cancelled
  `text_disabled`.
- **Inspector sections** (collapsible groups): Symbol (selection),
  DEX (winning dex + dex of current doc), References (of selected
  symbol — engine-backed only), Metadata (manifest facts).

## 4. Interaction states

- Busy: spinner in issuing surface + status dot `accent`; never a modal,
  never a frozen panel (other panels stay interactive).
- Empty: each panel has a one-line `text_secondary` hint ("open an APK to
  begin", "run a search to see results").
- Stale (superseded/generation-mismatch): results simply never appear;
  Tasks view may show them greyed as "discarded".
- Errors: inline in Problems + status bar; never a dialog.

## 5. Non-goals

No glow/neon, no rounded card grids, no emoji icons beyond existing
glyph conventions, no per-widget theming escapes, no animation beyond
spinners. egui default fonts; sizing via tokens only.
