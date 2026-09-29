---
name: apk-analysis
description: Use when analyzing an Android APK/DEX: finding who calls a method/field/string/type, locating a class, listing classes, or extracting class source, with the asc-rs CLI (ASC-RS).
---

# Using asc-rs (APK analysis CLI)

Binary: `asc-rs` (Windows: `asc-rs.exe`) — a standalone prebuilt executable, no JVM/Python/Rust toolchain needed. If `asc-rs` is not on PATH, locate the shipped binary in the environment rather than building anything. Lazy, on-demand; no preprocessing. Run `asc-rs <cmd> --help` for flags.

## Commands

```
asc-rs findrefs <apk> string <substr>            # callers of a string-pool match
asc-rs findrefs <apk> type   <substr>            # callers referencing a type descriptor
asc-rs findrefs <apk> method [name] [--class C [--fuzzy-class]]
asc-rs findrefs <apk> field  [name] [--class C [--fuzzy-class]]
asc-rs getclass <apk> <Lpkg/Cls; | pkg.Cls>      # decompile ONE class
asc-rs listclass <apk> [-o FILE]                 # all class descriptors, DEX order
```
Shared flags (any position): `-o FILE`, `--threads N` (default 8), `--debug` (timings to stderr), `--format text|json` (findrefs only), `--paranoid` (decode Paranoid/LSParanoid strings; off by default).

## Choosing the command

| Goal | Use |
|---|---|
| Who uses URL / key / log text | `findrefs string` |
| Who calls API X (e.g. `getSystemService`) | `findrefs method X` |
| Who calls anything on class C | `findrefs method --class C` (no name) |
| Who touches a field | `findrefs field` |
| Who references a type (e.g. `Ljava/lang/StringBuilder;`) | `findrefs type` |
| Class name unknown | `listclass`, filter output, then `getclass` |
| Read a class's shape | `getclass` |

## Output

- findrefs text: `dex | Lcaller/Class;->method | matched=(a; b)`, one line per caller method. `matched` for long regex strings can be huge; use `-o` and search the file, don't print raw.
- findrefs `--format json`: `{complete, matched_method_count, line_count, results:[{dex_name, complete, matches:[{caller, matched:[...]}]}]}`. Prefer json for post-processing.
- `--class` accepts `Lpkg/C;` or dotted. Exact by default; `--fuzzy-class` = substring.
- `getclass` prints decompiled Java (droidsaw backend): `// Source: X.java`, package, fields, and method bodies. Decompiled bodies can be imperfect; cross-check critical logic with `findrefs`.
- Exit codes: `0` ok, `1` class not found (`getclass`), `2` engine error. `findrefs` with zero hits prints nothing and exits `0`; check for empty output, not exit code.
- `--paranoid`: use when `getclass` shows `long v = -123…L; X.y(v)` pairs (a static `(J)String` call) or `findrefs string` misses text you know exists. `getclass` then shows the decoded literals; `findrefs string` also matches decoded values. Only ids that are a `const-wide` in the same basic block get decoded; other calls stay as-is. The output is rewritten bytecode, not the original. Say so when you quote it.

## Workflow

1. `listclass <apk>` → file, then filter for candidates (obfuscated APKs: search by package/pattern).
2. `findrefs` with the narrowest predicate (`--class` + name beats name alone). Matching is substring: short names (`get`, `http`) flood results.
3. `getclass` on interesting callers/classes.
4. Redirect big output: `-o out.txt` (findrefs appends; `listclass` overwrites).

## Pitfalls

- On Windows, piping to `head` prints a harmless "pipe has been ended" panic; use `-o` and read the file.
- Constructors/static init are `<init>` / `<clinit>`.
- Multidex is automatic (`classes*.dex` numeric order); `dex_name` says which.
- No Smali, CFG, or call-graph output exists. Say the tool can't provide it; never fabricate.
- Smoke-test on any small APK you have; verify the binary runs with `asc-rs --help` before relying on it.
