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
asc-rs disasm <apk> <Lpkg/Cls; | pkg.Cls> [--method NAME]   # Smali-syntax listing of ONE class (bytecode, not Java)
asc-rs listclass <apk> [-o FILE]                 # all class descriptors, DEX order
asc-rs manifest <apk> [-o FILE]                  # full manifest: package, split markers, application attrs + meta-data, permissions (maxSdk), uses-features, queries, components with deep-link data/aliases
asc-rs inspect <apk|dex> [-o FILE]               # entry inventory, DEX coverage/checksums, packer signals, manifest-vs-DEX check
asc-rs native  <apk|dex> [-o FILE]               # lib/ + assets/*.so ELF inventory, DEX native methods, JNI export name match
asc-rs cert    <apk> [-o FILE]                   # signing certs: JAR v1 + APK Signature Scheme v2/v3 (display only, NOT verified)
asc-rs resources <apk> [--id 0x7f020000 | --strings PAT] [--limit N] [-o FILE]   # resources.arsc inventory / lookup / search
```
Input: an APK/ZIP **or a bare `.dex`** (DEX 035..041; e.g. a runtime-dumped DEX). A bare DEX is one virtual entry named after the file; `manifest`, `cert` and `resources` on it exit `2` ("requires an APK"); an unparseable or CDEX/ODEX/VDEX file exits `2` with a clear error instead of empty output.
Shared flags (any position): `-o FILE`, `--threads N` (default 8), `--debug` (timings to stderr), `--format text|json` (all commands), `--paranoid` (decode Paranoid/LSParanoid strings; off by default), `--decode-xor` (decode const-array XOR strings; off by default).

## Choosing the command

| Goal | Use |
|---|---|
| Who uses URL / key / log text | `findrefs string` |
| Who calls API X (e.g. `getSystemService`) | `findrefs method X` |
| Who calls anything on class C | `findrefs method --class C` (no name) |
| Who touches a field | `findrefs field` |
| Who references a type (e.g. `Ljava/lang/StringBuilder;`) | `findrefs type` |
| Class name unknown | `listclass`, filter output, then `getclass` |
| Package, permissions, exported components (declared vs inferred), receivers, deep links (`scheme/host/pathPrefix`), meta-data, split markers | `manifest` |
| Is this sample packed / is there hidden payload? | `inspect` |
| Which native libs/methods exist, which `Java_*` exports match? | `native` |
| Who signed this APK / do two samples share a signer? | `cert` |
| Resource names/values, lure text in `resources.arsc`, ID lookup | `resources` |
| Read a class's shape | `getclass` |
| Decompiled Java looks wrong (`getclass` warning) or you need exact bytecode/operands | `disasm` |

## Output

- findrefs text: `dex | Lcaller/Class;->method | matched=(a; b)`, one line per caller method. `matched` for long regex strings can be huge; use `-o` and search the file, don't print raw.
- findrefs `--format json`: `{complete, matched_method_count, line_count, results:[{dex_name, complete, matches:[{caller, matched:[...]}]}]}`. Prefer json for post-processing.
- `--class` accepts `Lpkg/C;` or dotted. Exact by default; `--fuzzy-class` = substring.
- `getclass` prints decompiled Java (droidsaw backend): `// Source: X.java`, package, fields, and method bodies. Decompiled bodies can be imperfect; cross-check critical logic with `findrefs`.
- `getclass` stderr `warning: decompiled Java may be incorrect: N local(s) read but never assigned: v2_3, …` = the droidsaw structurer dropped a phi (name heuristic, stdout/JSON unchanged, exit code unchanged). It does NOT detect the twin defect of a loop body emitted twice, so no warning is not proof the Java is right.
- `disasm` prints Smali-syntax (first line is a `#` note): `.class/.super/.implements`, `.field`, `.method … .end method` with `.registers`, instructions, `:addr_<hex>` labels, `.catch/.catchall`, and `.packed-switch/.sparse-switch/.array-data` blocks at the method end (switch case targets are relative to the switch instruction, as the DEX spec says). Not emitted: annotations, static initial values, debug info (`.line/.local/.param`). Registers are always `vN` (no `pN`), labels are `:addr_<hex>` — dialect differences from baksmali, not byte-identical. It does NOT go through the Java structurer, so it lacks the missing-assignment/duplicated-loop defects. `--method NAME` = exact name, every overload, fields omitted. It refuses instead of guessing: a method with an unknown opcode, bad payload, out-of-range pool reference or branch into the middle of an instruction fails the whole command with `Lcls;->name: code_item at 0x… pc N: reason` (exit 2). Exit `1` = class or method not found. Evidence: a 2,014-class sample of five corpus DEX (663k instructions) has 0 mnemonic and 0 try/catch mismatches vs androguard and 4 formatting-only operand reports; `tests/differential/run_disasm_diff.py` still exits 1 on ~15 methods it attributes to oracle/runner payload-tail handling (2 spot-checked as fine, the rest not individually reviewed). `invoke-custom`, `invoke-polymorphic`, `const-method-handle/type` are covered only by synthetic DEX (none in the corpus); no baksmali was available for byte comparison.
- Exit codes: `0` ok, `1` class not found / invalid input, `2` engine error. `findrefs` with zero hits prints nothing and exits `0` — but if any `classes*.dex` entry failed to scan, `findrefs` prints every hit it did find, warns per failing DEX on stderr and exits `2` (JSON keeps `complete:false` + `errors`). Check stdout *and* exit code, not just one.
- A `classes*.dex` entry whose bytes are **not a DEX** (bad magic — encrypted/scratch/packed payload) is a different case: it is skipped, not failed. `findrefs` still exits `0` and JSON keeps `complete:true`, but the skip is listed in `errors` and printed as `warning: … is not a DEX` on stderr. `listclass` skips it too, and that one is silent (no errors field, no warning). `getclass` treats the class as simply not found (exit `1`) even when the APK contains other, real DEX files. So `complete:true` + exit 0 does **not** prove the whole APK was decoded — use `asc-rs inspect` to check every DEX's `class_count` / `coverage_note`, and read stderr.
- `--format json` for the other commands: `listclass` → `{total, per_dex:[{dex_name,count}], classes:[...]}`; `getclass` → `{dex_name, class_def_off, source}`; `manifest` → the full structured manifest (`package`, `split`/`splitTypes`/…, `application` incl. `meta_data` and security booleans, `permissions` (with `max_sdk`), `uses_features`, `queries`, `activities`/`services`/`receivers` with `intent_filters[].{actions,categories,data,auto_verify,priority}` + `meta_data`, `activity_aliases`, `providers`; absent values are `null`). Backward compatible: pre-existing keys kept; `exported` is now the *effective* value (declared, else Android's filter/target-SDK inference) and `exported_explicit` carries what the manifest actually declared. Errors stay on stderr with the usual exit code (no JSON error body).
- `manifest` text: `package:`, `version:`, `sdk:`, optional `split:` line, `application:` block (declared values; `(default)` marks platform defaults, e.g. `allowBackup=true(default)`), `permissions`, `uses-features`, `queries`, then `activities`, `services`, `receivers`, `activity-alias`, `providers`. Components carry `[exported=true]`/`[exported=false]` when declared and `[exported=true(auto)]` when inferred from filters — `(auto)` is Android's inference, not a declaration. Filters print `action`/`category`/`data scheme=… host=… pathPrefix=…` lines plus `(autoVerify=… priority=…)` flags; multiple `<data>` elements stay separate (Android ORs them). `meta-data:` lines print `name = value` / `resource=@0x…`. It tolerates the manifest tampering Android itself ignores (zeroed root chunk type, garbage string-pool slots, garbage chunks after `</manifest>`), and non-Android namespaces (`tools:`, `dist:`) never alias android: attributes. Exit `2` = the manifest really is unparseable (or absent).
- `--paranoid`: use when `getclass` shows `long v = -123…L; X.y(v)` pairs (a static `(J)String` call) or `findrefs string` misses text you know exists. `getclass` then shows the decoded literals; `findrefs string` also matches decoded values. Only ids that are a `const-wide` in the same basic block get decoded; other calls stay as-is. The output is rewritten bytecode, not the original. Say so when you quote it.

- `--decode-xor`: use when strings in the sample are hidden as `byte[] a = {8, 7, …}; X.i(a)` (a static `([B)String` decoder that XORs every element with a literal key) — common in packer stubs (verified on a Virbox sample). `findrefs string` also matches decoded values; `getclass` replaces provable calls with the decoded literal (the array-building code stays as dead code). Only sites proven on **every** path are patched: the key must be a literal, all elements constant (`const`+`aput-byte` chains or `fill-array-data`), the bytes valid UTF-8, and no alias of the array read after the call (the decoder mutates in place). Unprovable sites stay as-is — absence of a decode is not evidence of a hidden string. Like `--paranoid`, the output is rewritten bytecode, not the original.

## Workflow

1. Malware/unknown sample: start with `manifest` (permissions + exported components/receivers are your first IOCs), then `listclass <apk>` → file, then filter for candidates (obfuscated APKs: search by package/pattern).
2. `findrefs` with the narrowest predicate (`--class` + name beats name alone). Matching is substring: short names (`get`, `http`) flood results.
3. `getclass` on interesting callers/classes.
4. Redirect big output: `-o out.txt` (findrefs appends; `listclass`, `manifest`, `inspect`, `native` and `cert` overwrite and print nothing to stdout).

## Signing certificates (`cert`)

Lists JAR v1 (`META-INF/*.RSA|DSA|EC`) and APK Signature Scheme v2/v3/v3.1 signers with SHA-256/SHA-1 fingerprints, subject/issuer/serial/validity, algorithm IDs (full `u32`) and the v3 SDK range. **Nothing is verified**: no signature, digest, chain or trust check, so a fingerprint identifies a certificate, not the integrity or authorship of the APK (`verification: not_performed` in text and JSON). Roles: `signer` is the first v2/v3 certificate or the v1 certificate matching the SignerInfo issuer+serial; the rest are `chain`, or `unmatched` if the v1 signer cannot be identified. Scheme equality is stated only when SHA-256 sets match; differences are shown (not an error). Unknown signing-block pair IDs are listed verbatim. `subject == issuer` is shown but never claimed as self-signed. Subjects print in encoded order (openssl `-nameopt RFC2253` prints reversed). `no signing material found` does not mean unsigned/valid. Malformed signing data prints the partial report and exits `2`, as does a raw `.dex` or unreadable input; ZIP64 archives report the signing block as `unsupported` (scheme status `unknown`).

## Resource table (`resources`)

Reads `resources.arsc`: without filters it prints packages, entry/config counts and per-type counts. `--id 0x7f020000` lists every config variant of that ID (ID = package<<24 | (type+typeIdOffset)<<16 | entry index; the key-string index is a different field). `--strings PAT` is a case-sensitive substring over key names (`matched=key`) and string values (`matched=value`, including bag items); `--limit N` (default 100) caps printed hits, `matches:` still shows the total. `TYPE_STRING` values come from the table's global pool; references print as raw `@0x…` IDs (system `0x01…` included, never resolved). A `res/…` value is the path the table claims, not proof the file is a valid resource. Config text is `default` or locale/dpi/vNN plus `raw=<hex>`. No `resources.arsc` entry: text says so, exit `0`. Undecodable string slots read as empty and are noted in `diagnostic:` lines; a malformed chunk is skipped (the walk never guesses the next chunk), the report says `INCOMPLETE` and the exit code is `2`. Raw DEX or an unparseable table exits `2`. Values are display strings and not aapt2-equivalent; compact/sparse/offset16 layouts follow AOSP but are only synthetic-tested (the corpus has dense layouts, package `0x7f`).

## Native libraries (`native`)

Scans `lib/**.so` and `assets/**.so` (in memory, never written to disk; 64 MiB cap each) and every native method (`ACC_NATIVE`) in both direct and virtual lists of all DEX (including DEX-041 members). Methods are joined to libs by JNI symbol name (short and long form). A match is a *candidate* link, not proof. `unbound` = no `Java_*` export of that name: dynamic registration (`RegisterNatives`) is possible but NOT detected or resolved. `abi_dir` is reported next to `e_machine` and can disagree (`MISMATCH`). Symbol table comes from section headers, else `PT_DYNAMIC`; `symbol_source: none` or `[INCOMPLETE]` means exports are unknown, not zero. Split APKs (`config.*.apk`) carry libs but no DEX: pair them with the base APK by hand. Both `--format json` and text list every native method.

## Packed APKs

`asc-rs inspect` automates the checks below. `packer: virbox` needs >= 2 independent Virbox signals (stub class `Lv<hex>/l<hex>;`, `assets/l<hex>_{a32,a64,x86,x64}.so` family, the string "Virbox"). Other packers are NOT identified (no rule verified yet): `packer: none identified` does not mean unpacked. "tail bytes" = bytes past what the DEX map declares; it is only reported when the map gives an exact extent (`coverage unknown` otherwise, and never read as 0) and is an appended-payload *candidate*, not proof. Entropy is from a <=1 MiB prefix and unverified. `--format json` gives the full per-entry inventory; text lists only dex/elf/zip entries.

`inspect` memory: it reads every `classes*.dex` byte (checksum, SHA-1, Virbox string scan) plus up to 1 MiB of each entry for entropy. On STORED APKs those are mmap page touches, so its peak working set grows with DEX size (measured ~83 MiB on a 76.6 MiB APK with 53 MiB of STORED DEX) while private memory stays ~8-10 MiB (`read_bytes = 0`; clean file-backed pages, reclaimable). Other commands touch far less (`cert`/`manifest`/`resources` ~5-15 MiB on the same file). Do not read a large working set as a leak.

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
- A process-wide 2 GiB budget caps DEX bytes held by concurrent `getclass`/`disasm`/`findrefs` scans. An APK large enough to hit it fails with `memory budget exceeded` (exit `2`; `findrefs` records it per DEX and still exits `2` with partial output) — that means the input is pathological for this machine, not that the tool is broken.
- No Smali, CFG, or call-graph output exists. Say the tool can't provide it; never fabricate.
- Smoke-test on any small APK you have; verify the binary runs with `asc-rs --help` before relying on it.
