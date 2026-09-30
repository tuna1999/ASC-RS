#!/usr/bin/env python3
"""Operand-level disassembly oracle built on androguard 4.1.3.

Independent of the asc-rs Rust binary -- it needs only a `.dex` file and the
`androguard` package -- so its listing can be diffed 1:1 against the parallel
normalized listing produced by `asc-rs disasm`.

    reference\\venv\\Scripts\\python.exe tests\\differential\\dump_androguard_disasm.py \\
        corpus\\dex\\aurora_classes.dex --class "LA/F$a;" > aurora_AFa.smali.txt
    reference\\venv\\Scripts\\python.exe tests\\differential\\dump_androguard_disasm.py \\
        corpus\\dex\\aurora_classes.dex --stats

Output is one tab-separated line per instruction, no header:

    <method descriptor>\\t<code unit offset>\\t<mnemonic>\\t<operands>

* method descriptor: `Lcls;->name(params)ret`
* code unit offset: 4 hex digits, no `0x`; offset into the `insns` blob in
  16-bit code units (i.e. the DEX "instruction index")
* operands: normalized, see `README_disasm_oracle.md`; empty when none

Operands come from androguard's `Instruction.get_operands()`, which is raw and
correct for every format it implements. Three exceptions are resolved by the
oracle itself because the pinned androguard renderer is wrong or cannot resolve
the reference at all:

* 45cc / 4rcc  -> `get_operands()` takes no `idx` (it is a bare `pass`) and
  `get_output()` prints raw table indices for the method/proto pair
* 0xFE const-method-handle -> androguard tags it `Kind.METH` and would print it
  as a method ref
* 0xFF const-method-type -> androguard tags it `Kind.PROTO`, which is not a
  member of the `Kind` enum, so the dispatch in `get_kind()` falls through to
  `None`

Output is streamed: instructions are written to stdout as they are decoded, no
DEX-sized listing is ever held in memory. Classes and methods are visited in
sorted order, so the listing is deterministic and byte-stable across runs.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter

# androguard logs the whole parse through loguru at DEBUG; drop the handler
# before any DEX is constructed so stdout stays a pure listing.
try:
    from loguru import logger as _logger

    _logger.remove()
except Exception:  # pragma: no cover - androguard always ships loguru
    pass

from androguard.core.dex import DEX  # noqa: E402
from androguard.core.dex.dex_types import Kind, Operand  # noqa: E402

# androguard decodes payload pseudo-instructions into these classes; they are
# not real instructions and have no get_operands().
PAYLOAD_CLASSES = ("PackedSwitch", "SparseSwitch", "FillArrayData")

# androguard names one Python class per instruction format: Instruction35c,
# Instruction3rc, Instruction4rcc, Instruction22cs, ...
_FORMAT_RE = re.compile(r"^Instruction(\d+)([A-Za-z]*)$")

# Mnemonics whose first register operand is the low half of a wide pair: the
# high half is implicit (A/AA, and the source of 11x/12x/22x/32x), so we print
# `vAvB`.
WIDE_FIRST_REG = frozenset(
    """
    move-wide move-wide/16 move-wide/from16 move-object move-object/16
    move-object/from16 move-result-wide move-result-wide/16
    move-result-object move-result-object/16 move-exception
    iget-wide iget-wide/16 iget-object iget-object/16
    iput-wide iput-wide/16 iput-object iput-object/16
    const-wide const-wide/16 const-wide/32 const-wide/high16
    const-wide/high16/16 const-wide/jumbo
    """.split()
)

# invoke-* mnemonics: their argument registers have no per-operand type, so the
# width of the lowest one is resolved from the callee descriptor (see
# first_arg_wide) instead of being guessed from the register number.
INVOKES = frozenset(
    """
    invoke-virtual invoke-super invoke-direct invoke-static invoke-interface
    invoke-polymorphic invoke-custom
    invoke-virtual/range invoke-super/range invoke-direct/range
    invoke-static/range invoke-interface/range invoke-polymorphic/range
    invoke-custom/range
    """.split()
)


def esc(text: str) -> str:
    """Escape a resolved string so a record never holds a tab or a newline."""
    return (
        text.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def format_of(insn) -> str:
    """Normalized DEX format id of `insn` (35c, 3rc, 31t, ...)."""
    name = type(insn).__name__
    if name in PAYLOAD_CLASSES:
        return "00x"
    # Instruction35c / Instruction3rc / Instruction4rcc / Instruction22cs ...
    m = _FORMAT_RE.match(name)
    return m.group(1) + m.group(2).lower() if m else "???"


def registers_of(insn, fmt: str) -> list[int]:
    """Register list of a multi-register (35c/45cc/3rc/4rcc/52c/5rc) format."""
    if fmt in ("35c", "45cc"):
        return [insn.C, insn.D, insn.E, insn.F, insn.G][: insn.A]
    if fmt in ("3rc", "3rmi", "3rms", "4rcc", "5rc"):
        return list(range(insn.CCCC, insn.NNNN + 1))
    if fmt == "52c":
        return [insn.AAAA, insn.BBBB]
    return []


def render_reg(insn, fmt: str, name: str, reg: int, first_wide: bool = False) -> str:
    """`vN`, or `vNvN+1` when `reg` starts a wide pair.

    `first_wide` is only meaningful for invoke-* : the lowest argument register
    of a call is wide exactly when the callee's *first* parameter is J or D, so
    the caller resolves it from the method descriptor and passes it down.
    """
    wide = False
    if reg < 256:
        if name in INVOKES:
            regs = registers_of(insn, fmt)
            wide = first_wide and bool(regs) and reg == regs[0]
        elif name in WIDE_FIRST_REG:
            wide = reg % 2 == 0
    return f"v{reg}v{reg + 1}" if wide else f"v{reg}"


def ref(d: DEX, kind: int, value: int) -> str:
    """Resolve a reference operand into its normalized, space-free spelling."""
    if kind == Kind.STRING:
        return '"' + esc(d.CM.get_string(value)) + '"'
    if kind == Kind.TYPE:
        return d.CM.get_type(value)
    if kind == Kind.METH:
        m = d.CM.get_method_ref(value)
        return f"{m.get_class_name()}->{m.get_name()}{m.get_real_descriptor()}"
    if kind == Kind.FIELD:
        f = d.CM.get_field_ref(value)
        return f"{f.get_class_name()}->{f.get_name()}:{f.get_type()}"
    if kind == Kind.PROTO:
        p = d.CM.get_proto(value)
        return f"{''.join(p[0].split())}{p[1]}"
    raise ValueError(f"unhandled reference kind {kind}")


def first_arg_wide(d: DEX, insn) -> bool:
    """True when the lowest argument register of an invoke-* is a wide pair.

    The callee's parameters are laid out in the argument registers from the
    lowest one up, so the lowest register holds the *first* parameter and is wide
    exactly when that parameter is `J` or `D`.
    """
    try:
        proto = d.CM.get_method_ref(insn.BBBB).get_proto()[0]
    except Exception:  # noqa: BLE001 - unknown ref, do not guess a width
        return False
    params = proto.replace(" ", "").strip("()").split(";")
    params = [p for p in params if p]
    return bool(params) and params[0] in ("J", "D")


def render(d: DEX, insn) -> str:
    """Normalized operand list of `insn` (comma separated, no brackets)."""
    name = insn.get_name()
    fmt = format_of(insn)

    if type(insn).__name__ in PAYLOAD_CLASSES:
        # androguard does not expand payload directives (it does not even keep
        # the AA register the directive branches on): only the payload header is
        # available, so only the header is reported.
        return f"payload[ident=0x{insn.ident:04x},size={insn.size}]"
    if fmt in ("45cc", "4rcc"):
        regs = registers_of(insn, fmt)
        wide = first_arg_wide(d, insn)
        return ", ".join(
            [render_reg(insn, fmt, name, r, wide) for r in regs]
            + [ref(d, Kind.METH, insn.BBBB), ref(d, Kind.PROTO, insn.HHHH)]
        )
    if name == "const-method-handle":
        # androguard mislabels this as Kind.METH; METHOD_HANDLE_ITEM is not
        # parsed by androguard 4.1.3 at all, so report the table index.
        return f"handle[METHOD_HANDLE_ITEM#{insn.BBBB}]"
    if name == "const-method-type":
        # androguard tags this Kind.PROTO, which is not a member of the Kind
        # enum, so get_kind() falls through to None. PROTO_ID_ITEM *is* parsed,
        # so the prototype is resolvable.
        return ref(d, Kind.PROTO, insn.BBBB)

    try:
        operands = insn.get_operands()
    except TypeError:  # 45cc/4rcc (handled above) or a future gap
        raise ValueError("get_operands() unsupported for this format") from None

    wide = first_arg_wide(d, insn) if name in INVOKES else False
    parts: list[str] = []
    for op in operands:
        tag = op[0]
        if tag == Operand.REGISTER:
            parts.append(render_reg(insn, fmt, name, op[1], wide))
        elif tag == Operand.LITERAL:
            parts.append(str(op[1]))
        elif tag == Operand.OFFSET:
            # signed: androguard stores the 16-bit branch offset with the
            # instruction's sign, so a backward branch is negative
            parts.append(f"@{op[1]:+05x}")
        elif tag & Operand.KIND:
            kind = tag - Operand.KIND
            if kind == Kind.CALL_SITE:
                # CALL_SITE_ITEM is not parsed by androguard 4.1.3
                parts.append(f"callsite[CALL_SITE_ITEM#{op[1]}]")
            elif kind == Kind.METH_PROTO:
                parts.append(f"methproto[METHOD_ID_ITEM#{op[1]}]")
            else:
                parts.append(ref(d, kind, op[1]))
        else:
            parts.append(f"raw:{op[1]}")
    return ", ".join(parts)


def method_descriptor(m) -> str:
    d = m.get_descriptor()
    return f"{m.get_class_name()}->{m.get_name()}{''.join(d.split())}"


def method_key(m):
    d = m.get_descriptor()
    return (
        m.get_class_name(),
        m.get_name(),
        d[d.rfind(")") + 1 :],
        d[d.find("(") + 1 : d.rfind(")")],
    )


class _Sink:
    """Swallow the listing when only --stats was requested."""

    def write(self, _s: str) -> None:
        pass


def dump(d: DEX, class_filter: str | None, out, stats: Counter) -> None:
    classes = sorted(d.get_classes(), key=lambda c: c.get_name())
    if class_filter is not None:
        classes = [c for c in classes if c.get_name() == class_filter]
        if not classes:
            raise SystemExit(f"class not found: {class_filter}")

    for cls in classes:
        for m in sorted(cls.get_methods(), key=method_key):
            code = m.get_code()
            if code is None:
                continue
            desc = method_descriptor(m)
            stats["methods"] += 1
            idx = 0
            try:
                for insn in code.get_bc().get_instructions():
                    name = insn.get_name()
                    stats["mn:" + name] += 1
                    try:
                        operands = render(d, insn)
                    except Exception as exc:  # noqa: BLE001 - report, never guess
                        stats["render_errors"] += 1
                        operands = f"<unresolved:{type(exc).__name__}:{esc(str(exc))}>"
                    stats["instructions"] += 1
                    out.write(f"{desc}\t{idx:04x}\t{name}\t{operands}\n")
                    idx += insn.get_length() // 2
            except Exception as exc:  # noqa: BLE001 - malformed code unit
                stats["code_errors"] += 1
                sys.stderr.write(
                    f"# ERROR {desc} at code unit 0x{idx:04x}: "
                    f"{type(exc).__name__}: {exc}\n"
                )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Dump a normalized DEX instruction listing (androguard oracle)."
    )
    ap.add_argument("dex", type=str, help="path to a .dex file")
    ap.add_argument(
        "--class",
        dest="class_filter",
        default=None,
        metavar="DESCRIPTOR",
        help='only dump this class, e.g. "LA/F$a;"',
    )
    ap.add_argument(
        "--stats",
        action="store_true",
        help="write the mnemonic histogram to stderr instead of a listing",
    )
    args = ap.parse_args(argv)

    with open(args.dex, "rb") as fh:
        d = DEX(fh.read(), using_api=34)

    stats: Counter = Counter()
    dump(d, args.class_filter, _Sink() if args.stats else sys.stdout, stats)
    for k in sorted(stats):
        print(f"{k}\t{stats[k]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
