# Disasm oracle — normalization rules

`dump_androguard_disasm.py` is the androguard side of the F5 `asc-rs disasm` differential.
It does **not** depend on the Rust binary, so both listings come from independent decoders.

    reference\venv\Scripts\python.exe tests\differential\dump_androguard_disasm.py \
        corpus\dex\aurora_classes.dex --class "LA/F$a;"   # listing on stdout (--stats = histogram on stderr)

Record: `<method descriptor>\t<code unit offset>\t<mnemonic>\t<operands>`, no header.
Descriptor is `Lcls;->name(params)ret`. Offset is 4 lowercase hex digits, no `0x`, measured
into `insns` in **16-bit code units** (DEX instruction index), so it steps by instruction
size (`0000,0001,0002,0004`). Operands are comma+space separated, empty when none; tabs,
newlines and backslashes inside an operand are escaped, so a record is always one line.
Operands: register `vN` (wide pair glued `v0v1`) · literal signed decimal `-2147483648` ·
string `"this$0"` · type raw · proto `(J)B` · field `LA/A;->b:I` (smali colon form) ·
method `Lz4/c;-><init>(Lx4/d;)V` · branch `@+014c` (hex, branch-**relative**) ·
`callsite[CALL_SITE_ITEM#N]` · `handle[METHOD_HANDLE_ITEM#N]` · `payload[ident=0xNNNN,size=N]`
· unresolvable refs by raw table index · anything that fails: `<unresolved:ExcType:msg>`,
never a guess.
Registers are `vN`, never `pN` (no parameter mapping, so `v`/`p` is not a diff surface).
Wide pairs are written `vNvN+1` only where real: the implicit pair of `move-wide`,
`iget-wide`, `const-wide*`, `move-result-object`, …, or the lowest argument register of an
`invoke-*` whose callee's **first parameter** is `J`/`D`. Order is deterministic: classes
by descriptor, methods by `(class, name, ret, params)`.

## Known androguard 4.1.3 gaps

* **No payload expansion and no `.catch`.** Payload pseudo-instructions keep only
  `ident`/`size` (not the branch's AA register, never the payload data); `get_tries()`/
  `get_handlers()` exist but the listing never prints them, so switch-case and `.catch`
  lines cannot be diffed.
* **`CALL_SITE_ITEM`/`METHOD_HANDLE_ITEM` are never parsed**, so `invoke-custom[/range]`
  and `const-method-handle` are unresolvable. `const-method-type` *is* resolvable.
* **`get_operands()` is raw and correct; `get_output()` is not, and is not used.** Wrong
  for `45cc`/`4rcc` (prints raw table indices; their `get_operands()` is a bare `pass`
  raising `TypeError` without an `idx` arg — the oracle resolves method+proto itself), and
  for `const-method-handle` (mis-tagged `Kind.METH`) / `const-method-type` (tagged
  `Kind.PROTO`, not a `Kind` member, so `get_kind()` returns `None`).
* **Opcode 0xFF is shared by `const-wide` and `const-method-type`** and the linear sweep
  rejects any op whose low byte is `0x00`/`0xFF` unless it is a known payload id, so
  `const-method-type` with non-zero AA dies as `Unknown Instruction`.
* **One bad opcode truncates the rest of the method**; the oracle emits
  `# ERROR <method> at code unit 0x…` on stderr, bumps `code_errors`, continues.
* **Corpus gap:** the five `corpus/dex/*.dex` contain no `invoke-custom`,
  `invoke-polymorphic`, `const-method-handle` or `const-method-type`; those paths were
  verified separately by splicing the opcodes into a copy of `aurora_classes2.dex`.
