# Reference Behavior — what the Python oracle emits

This is the contract `asc-rs` must reproduce. Every behavior described below
was read directly from the source at
`reference/asc/` @ commit `ccc6bae7704f5c5ef1a7271e27314837079621fb`. Line
numbers refer to that tree.

Source-of-truth files:

- CLI entry:         `reference/asc/main.py`
- APK / dex IO:      `reference/asc/src/asc_client/apk_handler.py`
- Androguard bridge: `reference/asc/src/asc_client/asc_handler.py`
- DEX 041 splitter:  `reference/asc/src/asc_client/dex_container.py`
- Findrefs:          `reference/asc/src/asc_core/findrefs/{findrefs_manager,scan/code_item_scan}.py`
- Locators:          `reference/asc/src/asc_core/findrefs/locator/*.py`
- Extraction:        `reference/asc/src/asc_core/core/dex/dex_manager.py`

## 1. CLI surface (captured from `main.py`)

### `getclass <apk> <class> [-o out] [--threads N] [--debug]`

```
python main.py getclass APP.apk Lcom/poc/Main; -o Main.java
python main.py getclass APP.apk com.poc.Main --threads 16
```

`<class>` accepts either:

- Dalvik descriptor form `Lcom/poc/Main;` — passed through unchanged.
- Java dotted form `com.poc.Main` — normalized to `Lcom/poc/Main;` by
  `_format_class_name` (`main.py:10-20`). The normalization is:
  - Replace `.` with `/`.
  - If the result does not start with `L`, prepend `L`.
  - If it does not end with `;`, append `;`.
  - Empty string after normalization raises `ValueError("Class name cannot be empty")`.

`--threads` / `--thread` defaults to **8**. `--debug` prints profiling lines
prefixed with `[DEBUG]` to stdout (after the decompiled source for getclass).

### `findrefs <apk> string <value> [-o out] [--threads N] [--debug]`

```
python main.py findrefs APP.apk string onCreate -o refs.txt
```

`<value>` is the fuzzy pattern; the search is fuzzy substring (subject to the
regex caveat below).

### `findrefs <apk> type <value> [-o out] [--threads N] [--debug]`

```
python main.py findrefs APP.apk type com.poc.Main
python main.py findrefs APP.apk type Landroid/content/Intent;
```

`<value>` is the fuzzy type pattern. The locator runs it through
`StringLocator.locate`, so matching is by substring of the **descriptor**
string (the entry stored in `string_ids` that the type_id table points at).
The descriptor includes the surrounding `L…;` for class types.

### `findrefs <apk> method [name] [--class X [--fuzzy-class]] [-o out]`

```
python main.py findrefs APP.apk method onCreate
python main.py findrefs APP.apk method onCreate --class com.poc.Main
python main.py findrefs APP.apk method onCreate --class com.poc.Main --fuzzy-class
```

Either `name` or `--class` must be supplied
(`_build_member_find`, `main.py:33-43`). If neither is present the CLI exits
non-zero with `Error: method query needs at least one of class or method name`.

### `findrefs <apk> field [name] [--class X [--fuzzy-class]] [-o out]`

Same shape as `method`, just for fields. `--class` is exact unless
`--fuzzy-class` is given.

## 2. Per-DEX findrefs line format

`asc_handler.AscHandler.findrefs` (`asc_handler.py:80-129`) produces lines of
the form:

```
{dex_name} | {caller.fullname}->{caller.name} | matched=({matched})
```

Where:

- `dex_name` is the entry name taken from the ZIP central directory
  (e.g. `classes.dex`, `classes2.dex`). For DEX 041 containers the
  Python code emits `classes.dex!classes{idx+1}.dex`
  (`dex_container.iter_logical_dex_buffers`, `dex_container.py:142-149`).
- `{caller.fullname}` is `Lcom/foo/Bar;` (Dalvik descriptor form).
- `{caller.name}` is the bare method name (no signature).
- `{matched}` is a `;`-joined list of the matched entity names:
  - `string` → the raw string contents (Python `str(dex.strings[idx])`).
  - `type`   → the descriptor `dex.types[idx].descriptor`.
  - `method` → `f"{method.cls.fullname}->{method.name}"`.
  - `field`  → `f"{field.cls.fullname}->{field.name}"`.
- Caller methods are emitted in **sorted method-id order** (`sorted(grouped)`
  in `asc_handler.py:121`), regardless of the offset where the match was
  found inside the caller body.
- Matched-entity ids inside one caller line are de-duplicated and
  emitted in sorted id order (`sorted(grouped[mid])`).
- A caller line is emitted **once per caller**, even if the same caller
  has multiple hits (a caller method with three string refs to the same
  target produces a single line with one entry inside `matched=()`).
- Lines are joined with `\n` and a trailing `\n` is appended per DEX
  that yields at least one hit (`main.py:101-104`). DEXes with no hits
  emit no lines for that subparser at all (`main.py:99-100`).

The `_format_method` helper used for the caller side is
`{method.cls.fullname}->{method.name}` (`asc_handler.py:65-67`) — note this is
identical to the matched-name format used for `method` and `field`, so
`matched=(...)` and the caller-side descriptor have the same shape when the
find type is `method` or `field`.

### Worked examples (copied from real runs of the oracle against `corpus/dex/classes.dex`)

```
classes.dex | Lcom/example/MainActivity;->onCreate | matched=(Landroid/os/Bundle;)
classes.dex | Lcom/example/MainActivity;->onResume | matched=(Landroidx/lifecycle/Lifecycle;)
classes.dex | Lcom/example/MainActivity;->onResume | matched=(Landroidx/lifecycle/DefaultLifecycleObserver;)
classes.dex | Lcom/example/net/HttpClient;->get | matched=(https://)
classes.dex | Lcom/example/net/HttpClient;->get | matched=(Authorization)
classes.dex | Lcom/example/net/HttpClient;->post | matched=(https://)
classes.dex | Lcom/example/net/HttpClient;->post | matched=(Authorization)
```

(See `tests/fixtures/golden/cases.json` and the corresponding
`golden/findrefs_*.txt` files for the exact captured output.)

## 3. Matching semantics per find-type

All four findrefs queries share the same two-stage pipeline:

1. **Locate** — produce a set of target indices for the entity the user asked
   about (`find_ref` in `findrefs_manager.py:83-110`).
2. **Scan** — walk every code item, look at opcodes that take an index of that
   kind, and emit a per-method line for each **caller method** containing at
   least one such index reference (`code_item_scan.py:264-271`).

Locators are built once per DEX (lazily, on first use for that kind).

### 3.1 `string` — always fuzzy substring

`_match_string_offset` (`string_locator.py:47-63`) does the following:

```python
pattern = re.compile(string)        # NB: not re.escape — see caveat
for match in pattern.finditer(submem):  # submem = string_data region
    offset = strdata_start + match.end()
    offset = mm.find(b'\x00', offset, strdata_end)
    yield offset + 1
```

Each match becomes the offset of the `\x00` terminator; the loc index is
`stridx_map[offset] - 1`. So:

- The query is matched against the **decoded string-data region** (after the
  MUTF-8 length prefix). For most inputs (ASCII, dotted names) this is
  equivalent to byte-substring matching.
- **The Python code uses `re.compile` without `re.escape`.** A user-supplied
  pattern like `https://` or `Lcom/foo` works as substring. A pattern like
  `.*` would match across terminators — in practice that does not happen
  because `match.end()` is bounded by the next `\x00` lookup, but the regex
  itself is *not* a literal substring search. The test corpus therefore uses
  queries that have no regex metacharacters.
- The mapping goes through `stridx_map: { string_data_off -> string_idx }`,
  which is built by walking the `string_ids` array in order and recording each
  descriptor's data offset (`string_locator.py:33-44`). An end sentinel is
  inserted at `strdata_end + 1` mapped to `string_ids_size`, so the final
  string can still be located even though its terminator byte is the one that
  ends the data region. This means an "extra" match at the very end is
  decoded as `string_ids_size` and then truncated to `string_ids_size - 1`
  (`string_locator.py:71-72`).

### 3.2 `type` — descriptor substring through `StringLocator`

`TypeLocator.locate` (`type_locator.py:34-47`) reuses
`StringLocator.locate(type_str)` to find the candidate `str_idx`s, then
looks those up in `type_maps: { str_idx -> { type_idx, ... } }`.

- The match is therefore on the **string_id entries that the type_id table
  points at**, i.e. on the descriptor text (`L…;` for class types, `[I`,
  `[Ljava/lang/String;`, etc. for arrays/primitives).
- A query of `Intent` matches every class whose descriptor contains
  `Intent` as a substring (so both `Lcom/x/IntentHandler;` and
  `Lcom/y/MyIntent;` show up, plus the `Intent` class itself).
- A query of `Landroid/content/Intent;` matches *exactly* the descriptor for
  that class (assuming the descriptor is present), plus any other descriptor
  that happens to literally contain that string (none in practice).

### 3.3 `method` — name substring + class constraint

`MethodLocator.locate` (`method_locator.py:86-146`) takes
`{"class": [clz_or_None, precise_bool], "method": name_or_None}`. The
`precise_bool` comes from `_normalize_class_query` and the `--fuzzy-class`
flag (`main.py:23-30`):

- **No `--class`**: only `method` is consulted. `str_locator.locate(method)`
  is run as a string query, intersected with `method_maps: { name_str_idx ->
  { method_idx, ... } }`. The string query goes through `re.compile`, same
  caveat as for `string`.
- **`--class X` without `--fuzzy-class`**: the class value is normalized to
  Dalvik descriptor form (`Lcom/foo/Bar;`). The locator then performs a
  **binary search of the type_ids table** for an exact descriptor match
  (`_find_type_idx_precisely`, `method_locator.py:44-61`). If the class is
  not in the DEX, the locator returns the empty set and no lines are emitted
  for this DEX.
  - If `method` is also given, the locator takes the intersection of that
    class's `clz_maps[type_idx]` method set with the method-name matches
    found by `str_locator.locate(method)` (then filtered by the
    `_match_clz_mids` substring check `method.name.find(method) != -1`,
    `method_locator.py:72-78`).
- **`--class X --fuzzy-class`**: the class value is **kept as-is** (dotted
  form allowed), passed through `TypeLocator.locate(clz)` (substring match
  against descriptors), and then intersected with the `method` matches
  derived through `str_locator.locate(method)`.

In all branches: `clz is None` AND `method is None` returns the empty set,
which makes `find_ref` return `[]` with no scan.

### 3.4 `field` — same shape as `method`

`FieldLocator.locate` mirrors `MethodLocator.locate` exactly
(`field_locator.py:87-147`):

- No class: only `field` substring (via str_locator).
- `--class X` precise: binary-search type_ids for `X`; if `field` is also
  given, intersect with str_locator-derived field-name matches, then filter
  with `_match_clz_fids` (`field.name.find(field) != -1`).
- `--class X --fuzzy-class`: substring on descriptor via `TypeLocator`.

### 3.5 Code-item scan — opcode → index → caller

`_IDX_GROUPS` in `code_item_scan.py:115-134` enumerates the opcode groups
that consume each index kind:

- string: `0x1a` (21c), `0x1b` (31c, jumbo)
- type: `0x1c 0x1f 0x20 0x22 0x23 0x24 0x25`
- field: `0x52..0x5f` (instance) and `0x60..0x6d` (static)
- method: `0x6e..0x72`, `0x74..0x78`, `0xfa`, `0xfb`
- (call_site / method_handle / proto are deliberately **not scanned** — see
  the comment at `code_item_scan.py:262-263`.)

The reference implementation uses two optimization paths for the scan:

1. A `re`-based path (`_build_scan_pattern` + `pattern.finditer`) used when
   the opcode class has fewer than 2 opcodes (`_DENSE_OPCODE_COUNT == 2`).
2. A `bytes.translate` + `int.from_bytes` mask path
   (`_scan_code_item_dense`) used otherwise. The mask is computed over the
   full code region: it AND-masks the opcode byte against the high index
   byte to short-circuit the per-survivor check.

The prefilter only matters for performance; both paths converge on
"check the full index at offset+2 against the candidate id set". The
matching rule is **exact index equality**, not substring or range.

After offsets are found, `insn_locator.locate(offsets)` maps each offset to
the containing method id(s) — one insn offset can land in multiple methods
(`insn_locator.py:169-204`). The reference output then groups by caller
method id, de-duplicates, and emits a single line per caller.

## 4. `getclass` pipeline

`_handle_getclass` (`main.py:56-84`) runs three stages in sequence:

1. **Class → DEX lookup** via `ApkHandler.get_class_dex`
   (`apk_handler.py:361-415`):
   - Open the APK as `mmap`.
   - Parse the central directory for entries whose name ends in `.dex`
     (`_parse_cd_dex_entries`, `apk_handler.py:139-208`).
   - Sort entries by `local_header_off` ascending.
   - Submit each entry to a `ThreadPoolExecutor` (capacity capped at
     `min(entries, max(6, min(threads, 12)))`).
   - Each worker inflates the entry with `zlib.decompressobj` /
     `_inflate_deflate_chunks` (`apk_handler.py:245-287`) and runs
     `_inflate_and_hit` (`apk_handler.py:311-343`) which:
     - Returns early if the magic is not `dex\n0..\x00` or the buffer is
       shorter than 0x70.
     - Locates the type_idx of the requested descriptor via
       `_find_type_idx` (linear scan of `type_ids` table,
       `apk_handler.py:69-104`).
     - Returns `(True, name, data)` if `_class_defs_contains_type_idx`
       confirms the class is defined here, `(False, name, data)` otherwise.
   - As soon as one worker reports a hit, the orchestrator sets a stop
     event, cancels in-flight futures, and returns `(name, data)`.
2. **DEX reconstruction** via `DexManager.extract_and_rebuild`
   (`dex_manager.py:51-103`):
   - Re-parse the DEX with `tinydex.DEX.parse`.
   - Run `DvmInterpreter` over every method's bytecode to collect all
     string/type/field/method indices the class touches.
   - Hollow out only those records (`DexHollower.hollow`).
   - Remap indices into a contiguous renumbered table (`DexIndexMapper`).
   - Rebuild a minimal DEX with the required class + dependencies
     (`DexBuilder.build`).
   - The resulting `bytearray` is held **only in memory**; `getclass` never
     writes it to disk.
3. **Decompile** via `decompile_dex_bytes` (`decompiler.py:268-285`):
   - Load the minimal DEX with `androguard.core.dex.DEX(bytes(dex_bytes))`.
   - Build a `FakeAnalysis(d)` to skip androguard's slow cross-reference
     initialization (`decompiler.py:255-266`).
   - Call `androguard.decompiler.decompile.DvClass(target_class, dx).process()`.
   - `get_source()` is patched to prepend any per-method annotations
     (`decompiler.py:219-227`).
   - The decompiled Java source is returned as a single `str`.

The CLI:

- Always prints the decompiled source to stdout
  (`print(source_code)` at `main.py:84`).
- If `-o/--output` is given, also writes the source to that file (and
  ensures a trailing `\n` if missing) **before** printing
  (`main.py:79-84`).
- With `--debug`, prints `[DEBUG] Hit DEX: <name>`,
  `[DEBUG] APK Scan Time: <us> us`, `[DEBUG] Total Execution Time: <us> us`,
  and a `-----…` separator **after** the source on stdout
  (`main.py:73-77`).
- If the class is not found in any DEX, `_handle_getclass` raises
  `ValueError("Class {dalvik_class} not found in APK.")`, which the
  top-level handler catches and prints as `Error: <msg>` on stderr, exit 1.

### Androguard interaction

`asc_handler.py` never calls androguard directly; the dependency is hidden
behind `decompiler.py`, which:

- Stubs out a fixed set of heavy modules before importing androguard so
  startup cost drops from >3s to ~1s
  (`_STUBBED_MODULES` list at `decompiler.py:23-67`, install loop at 80-81).
- Patches `androguard.core.dex.HeaderItem.__init__` to swallow
  `AttributeError` on the `cm` argument (legacy androguard API quirk).
- Wraps several androguard helpers with `functools.lru_cache`
  (`decompiler.py:106-126`) and monkey-patches
  `decompile.DvClass.__init__`, `process_method`, and
  `DvMethod.get_source` to inject annotations.

`asc-rs` should match the *output*: decompiled Java source for the single
target class. We do not need to reproduce androguard's exact source layout
byte-for-byte; we need to reproduce the level of detail and structure
(declarations, method signatures with access flags, statements in
Dalvik-disassembly-derived control order). See
`tests/fixtures/golden/getclass_*.java` for the captured text.

## 5. DEX entry discovery + ordering

Central-directory discovery (`apk_handler.py:139-208`):

1. Locate the End-Of-Central-Directory signature (`PK\x05\x06`) by
   `mm.rfind` over the last `65536 + 22` bytes
   (`_find_eocd`, `apk_handler.py:134-136`).
2. Read `eocd_offset_total = u16 @ +10` and walk the central directory
   from `eocd_off - cd_size` to `eocd_off`.
3. For each entry, check the magic `PK\x01\x02`, the version made by/needed
   to extract, the compression method, the local header offset, and the
   entry name. An entry is included iff:
   - It is not a directory.
   - Its name ends in `.dex` (case-sensitive ASCII compare, `_DEX_SUFFIX`).
4. The entry record is `(name, uncomp_size, comp_size, local_header_off,
   comp_method)`.

Before the per-entry dispatch:

- `for_each_findrefs` and `get_class_dex` both `entries.sort(key=lambda x:
  x[2])` (`x[2]` is `local_header_off`). That guarantees ascending offset
  order regardless of insertion order in the central directory.
- `for_each_findrefs` also closes the mmap before submitting to the
  process pool; workers re-open the APK on demand (see
  `_get_worker_apk_mm` at `apk_handler.py:229-242`).
- Entries that are stored uncompressed (comp_method == 0) are still
  processed through `_inflate_dex` (`apk_handler.py:266-287`) — they take
  the no-decompress fast path inside that helper.

The `findrefs` orchestrator uses `ProcessPoolExecutor` (not threads) so that
heavy `tinydex` parsing does not stall on the GIL. The `getclass` path uses
`ThreadPoolExecutor` because the inflate step dominates and is I/O / zlib
bound.

## 6. DEX 041 container handling (`dex041_logical_offsets`)

A DEX 041 file is a single APK entry whose first 8 bytes are the
`"dex\n041\x00"` magic. The reference implementation recognizes it as a
"container" holding N logical DEX files back-to-back
(`dex_container.py:10-26`):

```python
DEX041_MAGIC = b"dex\n041\x00"
offsets = []
off = 0
while off + 0x70 <= len(data) and data[off:off+8] == DEX041_MAGIC:
    file_size = u32_at(data, off + 0x20)
    if file_size < 0x70 or off + file_size > len(data):
        break
    offsets.append(off)
    off += file_size
return offsets or [0]
```

So the layout is: magic at `off`, header at `[off..off+0x70]`, total size at
`+0x20`, the next logical DEX starts at `off + file_size`, and so on.

For each non-first logical header (`header_off > 0`), `iter_logical_dex_buffers`
calls `normalize_dex041_logical` (`dex_container.py:71-79`), which copies the
header bytes `[header_off..header_off+header_size]` to position 0 of a fresh
buffer and leaves the rest of the original data unchanged. The header's
physical offsets (string_ids_off, type_ids_off, etc.) are still valid because
they were already relative to the *start of that logical DEX*, not the start
of the container — that is the contract d8 produces.

The reference implementation also exposes a more aggressive
`_patch_u32` / `_patch_class_data_code_offsets` / `_patch_code_item_debug_offsets`
path (`dex_container.py:29-139`) that subtracts `header_off` from every
physical offset. In practice `findrefs_manager.find_ref` and
`decompile_dex_bytes` are happy with the simpler header-copy normalization,
and the offset-subtraction helpers are only invoked if some downstream
consumer needs them. We do not see them in any default code path.

`asc-rs` note: **we will NOT port the offset-subtraction patch**. The
header-copy normalization (or its Rust equivalent: "treat each logical DEX
header as the start of a parse, ignoring bytes before it") is sufficient.
The patch helpers are an oracle-only behavior that exists to handle a
legacy consumer that assumes physical file offsets start at 0; we have no
such consumer in `asc-rs`.

## 7. Error / not-found behavior

- Class not in any DEX (`getclass`):
  - `ApkHandler.get_class_dex` returns `None`.
  - `_handle_getclass` raises `ValueError("Class {dalvik_class} not found in APK.")`.
  - Top-level `main()` catches all `Exception`, prints
    `Error: {e}` to **stderr**, and exits with status 1
    (`main.py:179-184`).
  - With `--debug`, the traceback is appended after the error line.
- findrefs query with neither name nor class (method/field):
  - `_build_member_find` raises `ValueError(f"{key} query needs at least
    one of class or {key} name")`.
  - Top-level handler prints `Error: <msg>` to stderr, exits 1.
- findrefs with no matches anywhere:
  - No lines are emitted on stdout. No error. Exit 0. (The CLI does not
    signal "no matches" explicitly — the caller has to count lines.)
- findrefs with a class that exists only in some DEXes:
  - For each DEX that lacks the class, that DEX produces no lines.
  - The output is **interleaved by DEX in offset order**; `for_each_findrefs`
    yields per DEX as soon as a worker finishes, so the order is
    "whatever finished first" rather than strictly ascending. The order
    inside one DEX, however, is stable (sorted caller method id, sorted
    matched entity ids — see §2).
- Malformed APK / no `.dex` entries / no central directory:
  - `_parse_cd_dex_entries` returns an empty list.
  - `for_each_findrefs` is a no-op (no output, exit 0).
  - `get_class_dex` returns `None`; getclass raises the not-found error.
- Bad class name (`""` or only separators):
  - `_format_class_name` raises `ValueError("Class name cannot be empty")`
    before any DEX is opened.

## 8. What asc-rs must reproduce (summary checklist)

- [ ] The `dex_name | caller.fullname->caller.name | matched=(...)`
      line format, sorted caller ids, de-duplicated matched ids per
      caller, sorted matched ids.
- [ ] DEX entries in ascending central-directory offset order, emitted
      via a per-DEX stream (yield-as-finished is fine).
- [ ] Substring matching for `string`, `type`, `field.name`, `method.name`.
      (Documented as fuzzy; the regex-compile path is a hidden quirk of
      the oracle that affects patterns containing metacharacters — the
      corpus avoids that.)
- [ ] `method`/`field` `--class` resolution: precise = binary-search of
      type_ids for exact descriptor `L…;`; fuzzy = substring via
      `TypeLocator`.
- [ ] `getclass` produces a single decompiled source body (Java-ish,
      method signatures with access flags and parameter types,
      statements) on stdout, optionally also written to `-o`.
- [ ] Not-found: stderr `Error: …`, exit 1.
- [ ] DEX 041 container: header-copy normalization, not the
      offset-subtraction patch.
