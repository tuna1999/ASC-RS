---
name: apk-analysis
description: Use when analyzing an Android APK/DEX (including packed or malicious samples): finding who calls a method/field/string/type, locating a class, listing classes, extracting class source, or dumping the manifest, with the asc-rs CLI (ASC-RS).
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
asc-rs manifest <apk> [-o FILE]                  # package, version, SDKs, permissions, components
asc-rs inspect <apk|dex> [-o FILE]               # entry inventory, DEX coverage/checksums, packer signals, manifest-vs-DEX check
asc-rs native  <apk|dex> [-o FILE]               # lib/ + assets/*.so ELF inventory, DEX native methods, JNI export name match
```
Input: an APK/ZIP **or a bare `.dex`** (DEX 035..041; e.g. a runtime-dumped DEX). A bare DEX is one virtual entry named after the file; `manifest` on it exits `2` ("requires an APK"); an unparseable or CDEX/ODEX/VDEX file exits `2` with a clear error instead of empty output.
Shared flags (any position): `-o FILE`, `--threads N` (default 8), `--debug` (timings to stderr), `--format text|json` (findrefs, getclass, listclass, manifest), `--paranoid` (decode Paranoid/LSParanoid strings; off by default).

## Choosing the command

| Goal | Use |
|---|---|
| Who uses URL / key / log text | `findrefs string` |
| Who calls API X (e.g. `getSystemService`) | `findrefs method X` |
| Who calls anything on class C | `findrefs method --class C` (no name) |
| Who touches a field | `findrefs field` |
| Who references a type (e.g. `Ljava/lang/StringBuilder;`) | `findrefs type` |
| Class name unknown | `listclass`, filter output, then `getclass` |
| Package, permissions, exported components, receivers | `manifest` |
| Is this sample packed / is there hidden payload? | `inspect` |
| Which native libs/methods exist, which `Java_*` exports match? | `native` |
| Read a class's shape | `getclass` |

## Output

- findrefs text: `dex | Lcaller/Class;->method | matched=(a; b)`, one line per caller method. `matched` for long regex strings can be huge; use `-o` and search the file, don't print raw.
- findrefs `--format json`: `{complete, matched_method_count, line_count, results:[{dex_name, complete, matches:[{caller, matched:[...]}]}]}`. Prefer json for post-processing.
- `--class` accepts `Lpkg/C;` or dotted. Exact by default; `--fuzzy-class` = substring.
- `getclass` prints decompiled Java (droidsaw backend): `// Source: X.java`, package, fields, and method bodies. Decompiled bodies can be imperfect; cross-check critical logic with `findrefs`.
- Exit codes: `0` ok, `1` class not found (`getclass`), `2` engine error. `findrefs` with zero hits prints nothing and exits `0`; check for empty output, not exit code.
- `--format json` for the other commands: `listclass` → `{total, per_dex:[{dex_name,count}], classes:[...]}`; `getclass` → `{dex_name, class_def_off, source}`; `manifest` → the full structured manifest (`package`, `permissions`, `activities`, `services`, `receivers`, `providers`; absent values are `null`). Errors stay on stderr with the usual exit code (no JSON error body).
- `manifest` text: `package:`, `version:`, `sdk:`, then `permissions`, `activities`, `services`, `receivers`, `providers` sections; components carry `[exported]` and `action …` lines. It tolerates the manifest tampering Android itself ignores (zeroed root chunk type, garbage string-pool slots, garbage chunks after `</manifest>`), so it works on samples that break strict parsers. Exit `2` = the manifest really is unparseable (or absent).
- `--paranoid`: use when `getclass` shows `long v = -123…L; X.y(v)` pairs (a static `(J)String` call) or `findrefs string` misses text you know exists. `getclass` then shows the decoded literals; `findrefs string` also matches decoded values. Only ids that are a `const-wide` in the same basic block get decoded; other calls stay as-is. The output is rewritten bytecode, not the original. Say so when you quote it.

## Workflow

1. Malware/unknown sample: start with `manifest` (permissions + exported components/receivers are your first IOCs), then `listclass <apk>` → file, then filter for candidates (obfuscated APKs: search by package/pattern).
2. `findrefs` with the narrowest predicate (`--class` + name beats name alone). Matching is substring: short names (`get`, `http`) flood results.
3. `getclass` on interesting callers/classes.
4. Redirect big output: `-o out.txt` (findrefs appends; `listclass` and `manifest` overwrite and print nothing to stdout).

## Native libraries (`native`)

Scans `lib/**.so` and `assets/**.so` (in memory, never written to disk; 64 MiB cap each) and every native method (`ACC_NATIVE`) in both direct and virtual lists of all DEX (including DEX-041 members). Methods are joined to libs by JNI symbol name (short and long form). A match is a *candidate* link, not proof. `unbound` = no `Java_*` export of that name: dynamic registration (`RegisterNatives`) is possible but NOT detected or resolved. `abi_dir` is reported next to `e_machine` and can disagree (`MISMATCH`). Symbol table comes from section headers, else `PT_DYNAMIC`; `symbol_source: none` or `[INCOMPLETE]` means exports are unknown, not zero. Split APKs (`config.*.apk`) carry libs but no DEX: pair them with the base APK by hand. Both `--format json` and text list every native method.

## Packed APKs

`asc-rs inspect` automates the checks below. `packer: virbox` needs >= 2 independent Virbox signals (stub class `Lv<hex>/l<hex>;`, `assets/l<hex>_{a32,a64,x86,x64}.so` family, the string "Virbox"). Other packers are NOT identified (no rule verified yet): `packer: none identified` does not mean unpacked. "tail bytes" = bytes past what the DEX map declares; it is only reported when the map gives an exact extent (`coverage unknown` otherwise, and never read as 0) and is an appended-payload *candidate*, not proof. Entropy is from a <=1 MiB prefix and unverified. `--format json` gives the full per-entry inventory; text lists only dex/elf/zip entries.

Suspect a packer when `listclass` returns only a few classes but `classes.dex` is large (MBs), and manifest components (e.g. `…LoginActivity`) are missing from `listclass`. The real DEX is encrypted and appended to or hidden beside a stub; no static tool (asc-rs or jadx) can see it.
- Virbox signs: stub classes `Lv<hex>/l<hex>;` (+ `$inner`), the string `"Virbox"` (`findrefs string Virbox`), native methods `I<hex>_00…05`, `assets/l<hex>_{a32,a64,x86,x64}.so`.
- Report only the stub + manifest as analysed; say the payload was not. Next step: runtime dump (BlackDex / frida-dexdump), then run asc-rs on the dumped DEX (zip it as `classes.dex` in an APK).

## asc-rs vs jadx class counts

`listclass` lists only classes defined in `classes*.dex` (what ART loads). jadx also shows nodes for components declared in the manifest (even when no DEX defines them) and for embedded Java class files (e.g. `DebugProbesKt.bin`, magic `CAFEBABE` → `kotlin.coroutines.jvm.internal`). jadx showing more is expected, not an asc-rs bug. Use `manifest` to see declared-but-absent components.

## Pitfalls

- On Windows, piping to `head` prints a harmless "pipe has been ended" panic; use `-o` and read the file.
- On Windows, paths with non-ASCII characters (e.g. Vietnamese file names) can make captured stdout come back empty. Use `-o FILE` and read the file (set `PYTHONIOENCODING=utf-8` if a Python helper prints).
- Constructors/static init are `<init>` / `<clinit>`.
- Multidex is automatic (`classes*.dex` numeric order); `dex_name` says which.
- No Smali, CFG, or call-graph output exists. Say the tool can't provide it; never fabricate.
- Smoke-test on any small APK you have; verify the binary runs with `asc-rs --help` before relying on it.
