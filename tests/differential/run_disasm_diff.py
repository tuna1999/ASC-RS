#!/usr/bin/env python3
"""Operand-level differential between `asc-rs disasm` and the androguard oracle.

`dump_androguard_disasm.py` emits one tab separated record per instruction --
`<method descriptor>\t<code unit offset>\t<mnemonic>\t<operands>` -- decoded by
androguard 4.1.3. This script runs `asc-rs disasm` over the same classes,
recovers the code unit offset of every instruction in our smali listing from
this file's own DEX opcode table (written from the Dalvik instruction formats,
not from droidsaw and not from androguard), normalizes our operands into the
oracle's spelling, and compares instruction by instruction. What the oracle
does not print is compared too: the switch payload contents (`.packed-switch`,
`.sparse-switch`, `.array-data`) and the try/catch table.

    reference\\venv\\Scripts\\python.exe -B tests\\differential\\run_disasm_diff.py \\
        --sample 150 --payload-cap 400 --jobs 6

The defaults are the documented run: 2014 classes over the five corpus DEX,
~5 minutes wall on this machine. `--dex <path>` narrows it to one file,
`--sample` / `--payload-cap` change the class selection and `--jobs` the number
of `asc-rs` processes.

Exit code 0 only when no mismatch survives the documented allowlist.

## Class selection

Per DEX, from the androguard class list sorted by descriptor:

1. every class whose code contains a payload pseudo instruction
   (`packed-switch` / `sparse-switch` / `fill-array-data`) or at least one
   `try_item`, capped at `--payload-cap` classes (default 400, taken in sorted
   order so the choice is deterministic) -- these carry the directives the
   oracle does not print, so they are the interesting ones;
2. the 5 largest classes by instruction count;
3. every k-th class of the remainder, k chosen so the total lands near
   `--sample` (default 150) classes.

Step 1 is capped because ~18% of all classes have a try block; the cap keeps
the run inside the time budget and the choice stays deterministic.

## Normalization rules

Every rule below is a spelling difference between baksmali (which asc-rs
follows) and the oracle's rendering, never an operand value:

1. **branch targets** -- our `:addr_<hex>` label is the code unit offset
   itself; the oracle prints the branch *relative* offset as `@+xxxx`, which is
   turned back into `instruction offset + relative`.
2. **implicit wide pairs** -- we print the low half of a wide register
   (`v1`); the oracle spells the pair (`v1v2`). The high half is dropped.
3. **register argument lists** -- we print `{v0, v1}` / `{v1 .. v6}` / `{}`;
   the oracle prints the registers bare, one operand each, with no braces.
   Our group is expanded (a range into its members) and the oracle's leading
   register run is glued back together, so values are compared, not
   punctuation; an empty list contributes no operand on either side.
4. **literals** -- baksmali's signed hex (`0x7f`, `-0x1`, `0x1L`, `-0x1s`)
   becomes the oracle's signed decimal; the `L`/`t`/`s` width suffix is
   dropped because the oracle's literal carries no width.
5. **strings** -- our smali escaping (backslash escapes plus `\\uXXXX` for
   every non-printable and non-ASCII UTF-16 unit) is decoded back to the raw
   characters, which is what the oracle prints, re-escaped only for tab,
   newline and backslash so a record stays one line.
6. **payload pseudo-instructions** -- skipped in the instruction stream
   (the oracle emits a header-only `payload[...]` record, the spec calls them
   pseudo-instructions) and compared separately as directives. Their case
   targets are code unit offsets, so both sides are made absolute; note that
   dexlib2 resolves them against the *switch instruction*, not the payload
   (0x80 and 0x11 apart on the corpus payloads), and the listing is compared
   against the spec reading.
7. **fill-array-data width** -- the specification's 4 + ceil(size * width / 2)
   code units. androguard adds one spare code unit in
   `FillArrayData.get_length()`, dexlib2 reads `element_width` as a 32-bit
   field that swallows the ident's low half and stops the listing on a 1-byte
   payload. Neither changes the element values, and the elements are compared
   against the raw bytes.
8. **method length** -- a method is decoded from `insns_size` (the code item
   header), not from the rest of the `get_insn()` buffer, which may carry
   padding past the last instruction.

## How our offsets are recovered

Our listing prints no offsets, only `:addr_<hex>` labels, and it omits payload
pseudo instructions. The script re-decodes each method's `insns` blob from the
raw DEX, drops the payload pseudo instructions (they become directives) and
pairs the Nth printed instruction with the Nth remaining one; a length
difference is reported as a `count` mismatch instead of being resynced.

A `:addr_<hex>` operand is then taken at face value -- the label *is* the code
unit offset -- and cross-checked three ways: every printed label must be the
offset of a decoded instruction (payload offsets included), and every decoded
branch must land on an offset the class-wide label set contains. A target
failing either check is a `label` mismatch, and it is still diffed so a wrong
target shows up instead of being skipped.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import re
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRATCH = ROOT / "target" / "f5diff"
ASC_RS = ROOT / "target" / "release" / "asc-rs.exe"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dump_androguard_disasm import esc, render  # noqa: E402

# --------------------------------------------------------------------------
# DEX opcode table, from the Dalvik instruction formats: low opcode byte ->
# (androguard's mnemonic, format id). Widths follow the format.
# --------------------------------------------------------------------------

F10X, F12X, F11N, F11X, F10T = "10x", "12x", "11n", "11x", "10t"
F20T, F22X, F21T, F21S, F21H, F21C = "20t", "22x", "21t", "21s", "21h", "21c"
F23X, F22B, F22T, F22S, F22C = "23x", "22b", "22t", "22s", "22c"
F30T, F32X, F31I, F31T, F31C = "30t", "32x", "31i", "31t", "31c"
F35C, F3RC, F51L, F45CC, F4RCC = "35c", "3rc", "51l", "45cc", "4rcc"

WIDTHS = {
    F10X: 1, F12X: 1, F11N: 1, F11X: 1, F10T: 1, F20T: 2, F22X: 2,
    F21T: 2, F21S: 2, F21H: 2, F21C: 2, F23X: 2, F22B: 2, F22T: 2,
    F22S: 2, F22C: 2, F30T: 3, F32X: 3, F31I: 3, F31T: 3, F31C: 3,
    F35C: 3, F3RC: 3, F51L: 5, F45CC: 4, F4RCC: 4,
}

OPCODES: dict[int, tuple[str, str]] = {}


def _op(rows: list[tuple[int, str, str]]) -> None:
    for low, mnemonic, fmt in rows:
        OPCODES[low] = (mnemonic, fmt)


_op([
    (0x00, "nop", F10X), (0x01, "move", F12X), (0x02, "move/from16", F22X),
    (0x03, "move/16", F32X), (0x04, "move-wide", F12X),
    (0x05, "move-wide/from16", F22X), (0x06, "move-wide/16", F32X),
    (0x07, "move-object", F12X), (0x08, "move-object/from16", F22X),
    (0x09, "move-object/16", F32X), (0x0A, "move-result", F11X),
    (0x0B, "move-result-wide", F11X), (0x0C, "move-result-object", F11X),
    (0x0D, "move-exception", F11X), (0x0E, "return-void", F10X),
    (0x0F, "return", F11X), (0x10, "return-wide", F11X),
    (0x11, "return-object", F11X), (0x12, "const/4", F11N),
    (0x13, "const/16", F21S), (0x14, "const", F31I),
    (0x15, "const/high16", F21H), (0x16, "const-wide/16", F21S),
    (0x17, "const-wide/32", F31I), (0x18, "const-wide", F51L),
    (0x19, "const-wide/high16", F21H), (0x1A, "const-string", F21C),
    (0x1B, "const-string/jumbo", F31C), (0x1C, "const-class", F21C),
    (0x1D, "monitor-enter", F11X), (0x1E, "monitor-exit", F11X),
    (0x1F, "check-cast", F21C), (0x20, "instance-of", F22C),
    (0x21, "array-length", F12X), (0x22, "new-instance", F21C),
    (0x23, "new-array", F22C), (0x24, "filled-new-array", F35C),
    (0x25, "filled-new-array/range", F3RC), (0x26, "fill-array-data", F31T),
    (0x27, "throw", F11X), (0x28, "goto", F10T), (0x29, "goto/16", F20T),
    (0x2A, "goto/32", F30T), (0x2B, "packed-switch", F31T),
    (0x2C, "sparse-switch", F31T), (0x2D, "cmpl-float", F23X),
    (0x2E, "cmpg-float", F23X), (0x2F, "cmpl-double", F23X),
    (0x30, "cmpg-double", F23X), (0x31, "cmp-long", F23X),
    (0x32, "if-eq", F22T), (0x33, "if-ne", F22T), (0x34, "if-lt", F22T),
    (0x35, "if-ge", F22T), (0x36, "if-gt", F22T), (0x37, "if-le", F22T),
    (0x38, "if-eqz", F21T), (0x39, "if-nez", F21T), (0x3A, "if-ltz", F21T),
    (0x3B, "if-gez", F21T), (0x3C, "if-gtz", F21T), (0x3D, "if-lez", F21T),
    (0x44, "aget", F23X), (0x45, "aget-wide", F23X), (0x46, "aget-object", F23X),
    (0x47, "aget-boolean", F23X), (0x48, "aget-byte", F23X),
    (0x49, "aget-char", F23X), (0x4A, "aget-short", F23X), (0x4B, "aput", F23X),
    (0x4C, "aput-wide", F23X), (0x4D, "aput-object", F23X),
    (0x4E, "aput-boolean", F23X), (0x4F, "aput-byte", F23X),
    (0x50, "aput-char", F23X), (0x51, "aput-short", F23X), (0x52, "iget", F22C),
    (0x53, "iget-wide", F22C), (0x54, "iget-object", F22C),
    (0x55, "iget-boolean", F22C), (0x56, "iget-byte", F22C),
    (0x57, "iget-char", F22C), (0x58, "iget-short", F22C), (0x59, "iput", F22C),
    (0x5A, "iput-wide", F22C), (0x5B, "iput-object", F22C),
    (0x5C, "iput-boolean", F22C), (0x5D, "iput-byte", F22C),
    (0x5E, "iput-char", F22C), (0x5F, "iput-short", F22C), (0x60, "sget", F21C),
    (0x61, "sget-wide", F21C), (0x62, "sget-object", F21C),
    (0x63, "sget-boolean", F21C), (0x64, "sget-byte", F21C),
    (0x65, "sget-char", F21C), (0x66, "sget-short", F21C), (0x67, "sput", F21C),
    (0x68, "sput-wide", F21C), (0x69, "sput-object", F21C),
    (0x6A, "sput-boolean", F21C), (0x6B, "sput-byte", F21C),
    (0x6C, "sput-char", F21C), (0x6D, "sput-short", F21C),
    (0x6E, "invoke-virtual", F35C), (0x6F, "invoke-super", F35C),
    (0x70, "invoke-direct", F35C), (0x71, "invoke-static", F35C),
    (0x72, "invoke-interface", F35C),
    (0x74, "invoke-virtual/range", F3RC), (0x75, "invoke-super/range", F3RC),
    (0x76, "invoke-direct/range", F3RC), (0x77, "invoke-static/range", F3RC),
    (0x78, "invoke-interface/range", F3RC),
    (0x7B, "neg-int", F12X), (0x7C, "not-int", F12X),
    (0x7D, "neg-long", F12X), (0x7E, "not-long", F12X),
    (0x7F, "neg-float", F12X),
    (0x80, "neg-double", F12X), (0x81, "int-to-long", F12X),
    (0x82, "int-to-float", F12X), (0x83, "int-to-double", F12X),
    (0x84, "long-to-int", F12X), (0x85, "long-to-float", F12X),
    (0x86, "long-to-double", F12X), (0x87, "float-to-int", F12X),
    (0x88, "float-to-long", F12X), (0x89, "float-to-double", F12X),
    (0x8A, "double-to-int", F12X), (0x8B, "double-to-long", F12X),
    (0x8C, "double-to-float", F12X),
    (0x8D, "int-to-byte", F12X), (0x8E, "int-to-char", F12X),
    (0x8F, "int-to-short", F12X),
    (0x90, "add-int", F23X), (0x91, "sub-int", F23X), (0x92, "mul-int", F23X),
    (0x93, "div-int", F23X), (0x94, "rem-int", F23X), (0x95, "and-int", F23X),
    (0x96, "or-int", F23X), (0x97, "xor-int", F23X), (0x98, "shl-int", F23X),
    (0x99, "shr-int", F23X), (0x9A, "ushr-int", F23X), (0x9B, "add-long", F23X),
    (0x9C, "sub-long", F23X), (0x9D, "mul-long", F23X), (0x9E, "div-long", F23X),
    (0x9F, "rem-long", F23X), (0xA0, "and-long", F23X), (0xA1, "or-long", F23X),
    (0xA2, "xor-long", F23X), (0xA3, "shl-long", F23X), (0xA4, "shr-long", F23X),
    (0xA5, "ushr-long", F23X), (0xA6, "add-float", F23X), (0xA7, "sub-float", F23X),
    (0xA8, "mul-float", F23X), (0xA9, "div-float", F23X), (0xAA, "rem-float", F23X),
    (0xAB, "add-double", F23X), (0xAC, "sub-double", F23X),
    (0xAD, "mul-double", F23X), (0xAE, "div-double", F23X),
    (0xAF, "rem-double", F23X), (0xB0, "add-int/2addr", F12X),
    (0xB1, "sub-int/2addr", F12X), (0xB2, "mul-int/2addr", F12X),
    (0xB3, "div-int/2addr", F12X), (0xB4, "rem-int/2addr", F12X),
    (0xB5, "and-int/2addr", F12X), (0xB6, "or-int/2addr", F12X),
    (0xB7, "xor-int/2addr", F12X), (0xB8, "shl-int/2addr", F12X),
    (0xB9, "shr-int/2addr", F12X), (0xBA, "ushr-int/2addr", F12X),
    (0xBB, "add-long/2addr", F12X), (0xBC, "sub-long/2addr", F12X),
    (0xBD, "mul-long/2addr", F12X), (0xBE, "div-long/2addr", F12X),
    (0xBF, "rem-long/2addr", F12X), (0xC0, "and-long/2addr", F12X),
    (0xC1, "or-long/2addr", F12X), (0xC2, "xor-long/2addr", F12X),
    (0xC3, "shl-long/2addr", F12X), (0xC4, "shr-long/2addr", F12X),
    (0xC5, "ushr-long/2addr", F12X), (0xC6, "add-float/2addr", F12X),
    (0xC7, "sub-float/2addr", F12X), (0xC8, "mul-float/2addr", F12X),
    (0xC9, "div-float/2addr", F12X), (0xCA, "rem-float/2addr", F12X),
    (0xCB, "add-double/2addr", F12X), (0xCC, "sub-double/2addr", F12X),
    (0xCD, "mul-double/2addr", F12X), (0xCE, "div-double/2addr", F12X),
    (0xCF, "rem-double/2addr", F12X), (0xD0, "add-int/lit16", F22S),
    (0xD1, "rsub-int", F22B),
    (0xD2, "mul-int/lit16", F22S),
    (0xD3, "div-int/lit16", F22S),
    (0xD4, "rem-int/lit16", F22S), (0xD5, "and-int/lit16", F22S),
    (0xD6, "or-int/lit16", F22S), (0xD7, "xor-int/lit16", F22S),
    (0xD8, "add-int/lit8", F22B), (0xD9, "rsub-int/lit8", F22B),
    (0xDA, "mul-int/lit8", F22B), (0xDB, "div-int/lit8", F22B),
    (0xDC, "rem-int/lit8", F22B), (0xDD, "and-int/lit8", F22B),
    (0xDE, "or-int/lit8", F22B), (0xDF, "xor-int/lit8", F22B),
    (0xE0, "shl-int/lit8", F22B), (0xE1, "shr-int/lit8", F22B),
    (0xE2, "ushr-int/lit8", F22B),
    (0xFA, "invoke-polymorphic", F45CC), (0xFB, "invoke-polymorphic/range", F4RCC),
    (0xFC, "invoke-custom", F35C), (0xFD, "invoke-custom/range", F3RC),
    (0xFE, "const-method-handle", F21C), (0xFF, "const-method-type", F21C),
])

#: Opcodes with no instruction in the Dalvik specification. androguard names
#: some of them `unused` and some `invoke-*`, which is why the comparison is a
#: three-way check (see `check_opcode_table`).
UNUSED_OPCODES = frozenset(
    [0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x73, 0x79, 0x7A]
    + list(range(0xE3, 0xFA))
)
PAYLOAD_IDENTS = {0x0100: "packed-switch-payload", 0x0200: "sparse-switch-payload",
                  0x0300: "fill-array-data-payload"}
PAYLOAD_REFS = frozenset({"packed-switch", "sparse-switch", "fill-array-data"})


def payload_units(ident: int, raw: bytes, at: int) -> int:
    """Width of a payload pseudo-instruction in code units.

    The specification counts *elements*: switch payloads are `size` 32-bit
    entries and `fill-array-data` is `element_width * size` bytes, both
    rounded up to a whole code unit. The differences that remain are listed
    on the branches below and are checked against the raw bytes.
    """
    if ident == 0x0300:
        # dexlib2 (and so asc-rs) read `element_width` as a 32-bit field that
        # overlaps the ident's low half, so a 1-byte payload is treated as
        # 0x10000 bytes wide and the listing stops there; androguard reads the
        # 16-bit field and keeps going. 4 + (size * width + 1) // 2 is the
        # width the raw element data actually occupies.
        width, count = struct.unpack_from("<HI", raw, at + 2)
        return min(4 + (width * count + 1) // 2, (len(raw) - at) // 2)
    if ident == 0x0100:
        # packed-switch: 4 code units of header + 2 per 32-bit target
        return min(4 + 2 * u16(raw, at + 2), (len(raw) - at) // 2)
    if ident == 0x0200:
        # sparse-switch: 2 of header + 2 per key + 2 per target; androguard's
        # `SparseSwitch.get_length()` adds one spare code unit, dexlib2 does not
        return min(4 + 4 * u16(raw, at + 2), (len(raw) - at) // 2)


#: Our mnemonic -> androguard's, for spellings that differ. Every entry must be
#: a naming difference only; an operand difference is reported, never listed.
MNEMONIC_MAP: dict[str, str] = {}


# --------------------------------------------------------------------------
# raw DEX decode
# --------------------------------------------------------------------------


@dataclass
class Insn:
    off: int  # code unit offset inside `insns`
    size: int  # code units
    opcode: int  # low byte
    mnemonic: str
    fmt: str
    raw: bytes = b""
    payload: bytes | None = None

    @property
    def branch(self) -> int | None:
        """Absolute code unit offset a branch reaches, or None."""
        if self.fmt in (F10T, F20T):
            rel = self.raw[1] if self.fmt == F10T else struct.unpack("<i", self.raw[2:6])[0]
        elif self.fmt in (F30T, F31T):
            rel = struct.unpack("<i", self.raw[2:6])[0]
        elif self.fmt in (F21T, F22T):
            rel = struct.unpack("<h", self.raw[2:4])[0]
        else:
            return None
        return self.off + rel


def u16(raw: bytes, at: int) -> int:
    return raw[at] | raw[at + 1] << 8


def decode(raw: bytes) -> list[Insn]:
    """Linear decode of one method's `insns` blob."""
    out: list[Insn] = []
    off = 0
    while off * 2 + 2 <= len(raw):
        unit = u16(raw, off * 2)
        if unit in PAYLOAD_IDENTS:
            width = payload_units(unit, raw, off * 2)
            if (off + width) * 2 > len(raw):
                raise ValueError(f"payload at 0x{off:04x} runs past the code units")
            body = raw[off * 2 : (off + width) * 2]
            out.append(Insn(off, width, unit, PAYLOAD_IDENTS[unit], "payload", body, body))
            off += width
            continue
        entry = OPCODES.get(unit & 0xFF)
        if entry is None and any(i.fmt == "payload" for i in out):
            # androguard emits one untagged data word after a `packed-switch`
            # whose declared `size` does not match the payload it parsed (a
            # damaged switch); the word is aligned padding, not an instruction
            out.append(Insn(off, 1, unit & 0xFF, "data", "padding", raw[off * 2 : off * 2 + 2]))
            off += 1
            continue
        if entry is None:
            raise ValueError(f"unknown opcode 0x{unit:02x} at 0x{off:04x}")
        mnemonic, fmt = entry
        width = WIDTHS[fmt]
        if (off + width) * 2 > len(raw):
            raise ValueError(f"truncated {mnemonic} at 0x{off:04x}")
        out.append(Insn(off, width, unit & 0xFF, mnemonic, fmt,
                        raw[off * 2 : (off + width) * 2]))
        off += width
    return out


def decode_prefix(raw: bytes, cls: str, name: str, mism: list) -> list[Insn] | None:
    """Decode as much as possible, dropping the offending pseudo-instruction."""
    kept: list[Insn] = []
    off = 0
    while off * 2 + 2 <= len(raw):
        unit = u16(raw, off * 2)
        if unit in PAYLOAD_IDENTS:
            width = payload_units(unit, raw, off * 2)
            body = raw[off * 2 : (off + width) * 2]
            if (off + width) * 2 > len(raw):
                # the payload runs past the method: it is the last thing the
                # method holds, so record it and stop rather than dropping the
                # code units it does cover
                kept.append(Insn(off, width, unit, PAYLOAD_IDENTS[unit], "payload", body, body))
                off = len(raw) // 2
                break
            kept.append(Insn(off, width, unit, PAYLOAD_IDENTS[unit], "payload", body, body))
            off += width
            continue
        entry = OPCODES.get(unit & 0xFF)
        if entry is None and any(i.fmt == "payload" for i in kept):
            kept.append(Insn(off, 1, unit & 0xFF, "data", "padding",
                             raw[off * 2 : off * 2 + 2]))
            off += 1
            continue
        if entry is None:
            break
        width = WIDTHS[entry[1]]
        if (off + width) * 2 > len(raw):
            break
        kept.append(Insn(off, width, unit & 0xFF, entry[0], entry[1],
                         raw[off * 2 : (off + width) * 2]))
        off += width
    if not kept:
        return None
    mism.append(Mismatch("payload_clipped", cls, name, off, "",
                         f"androguard stops at 0x{off:04x}", "payload runs past the method"))
    return kept


def _payload_truncated(ins: Insn, raw: bytes) -> bool:
    """True when a payload's declared element count does not fit the method.

    The method ends before the payload data does, so neither our listing nor
    the payload bytes hold a comparable element list; the switch case targets
    are still checked against the instruction labels.
    """
    payload = ins.payload or b""
    if ins.mnemonic == "packed-switch-payload":
        size = struct.unpack_from("<H", payload, 2)[0] if len(payload) >= 4 else 0
        return 12 + 4 * size > len(payload)
    if ins.mnemonic == "sparse-switch-payload":
        size = struct.unpack_from("<H", payload, 2)[0] if len(payload) >= 4 else 0
        return 4 + 8 * size > len(payload)
    if len(payload) < 12:
        return True
    width, count = struct.unpack_from("<HI", payload, 2)
    return width * count > len(payload) - 12


def _switch_addr(decoded: list[Insn], payload_off: int) -> int:
    """The code unit offset of the switch instruction a payload belongs to.

    The specification makes a payload's targets relative to the address of the
    *switch* instruction (`sparse-switch`/`packed-switch`), not to the payload;
    the payload is found by following the switch's 31t branch.
    """
    for i in decoded:
        if i.mnemonic in ("packed-switch", "sparse-switch") and i.branch == payload_off:
            return i.off
    return payload_off


def spec_payload(insn: Insn, decoded: list[Insn] | None = None) -> tuple[str, object]:
    """Payload decoded here from the raw bytes, with the spec layout."""
    raw = insn.payload or b""
    # a bogus `size` field must not read past the payload; clamp to what the
    # payload actually holds, which is what every decoder that survives does
    base = _switch_addr(decoded or [], insn.off)
    if insn.mnemonic == "packed-switch-payload":
        size, first_key = struct.unpack_from("<Ii", raw, 4)
        # the payload holds 16-bit `size` targets, and the method may end first
        size = min(size, u16(raw, 2), max(0, (len(raw) - 12) // 4))
        targets = [struct.unpack_from("<i", raw, 12 + 4 * i)[0] for i in range(size)]
        return "packed", (first_key, [base + t for t in targets])
    if insn.mnemonic == "sparse-switch-payload":
        size = struct.unpack_from("<H", raw, 2)[0]
        size = min(size, max(0, (len(raw) - 4) // 8))
        keys = [struct.unpack_from("<i", raw, 4 + 4 * i)[0] for i in range(size)]
        targets = [base + struct.unpack_from("<i", raw, 4 + 4 * (size + i))[0]
                   for i in range(size)]
        return "sparse", (keys, targets)
    if len(raw) < 12:
        return "array", (0, None)  # truncated header, no elements
    # `element_width` is at byte 2 and `size` at byte 4 of the payload
    width, size = struct.unpack_from("<HI", raw, 2)
    fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}.get(width)
    if fmt:
        size = min(size, max(0, (len(raw) - 12) // width))
    data = [struct.unpack_from(fmt, raw, 12 + width * i)[0] for i in range(size)] if fmt else None
    return "array", (width, data)


def androguard_payload(insn, payload_off: int) -> tuple[str, object]:
    """The payload as androguard exposes it (get_keys / get_targets / get_data)."""
    name = type(insn).__name__
    if name == "PackedSwitch":
        return "packed", (insn.first_key, [payload_off + t for t in insn.get_targets()])
    if name == "SparseSwitch":
        return "sparse", (list(insn.get_keys()),
                          [payload_off + t for t in insn.get_targets()])
    if name == "FillArrayData":
        width, data = insn.element_width, insn.get_data()
        fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}.get(width)
        values = ([struct.unpack_from(fmt, data, width * i)[0]
                   for i in range(len(data) // width)] if fmt else None)
        return "array", (width, values)
    return "?", None


# --------------------------------------------------------------------------
# our smali listing
# --------------------------------------------------------------------------


@dataclass
class OurMethod:
    key: str
    registers: int = 0
    insns: list[str] = field(default_factory=list)
    labels: set[int] = field(default_factory=set)
    catches: list[tuple[str, int, int, int]] = field(default_factory=list)
    payloads: dict[int, tuple[str, object]] = field(default_factory=dict)


ADDR_RE = re.compile(r"^:addr_([0-9a-f]+)$")
LABEL_RE = re.compile(r":addr_([0-9a-f]+)")
CATCH_RE = re.compile(
    r"^\.catch(?:all)?\s+(?:(\S+)\s+)?\{:addr_([0-9a-f]+) \.\. :addr_([0-9a-f]+)\}"
    r"\s+:addr_([0-9a-f]+)$"
)


def parse_our_listing(text: str) -> dict[str, OurMethod]:
    """Split an `asc-rs disasm` listing into per-method records.

    Instruction lines are indented by exactly four spaces and payload element
    lines by eight, so the indent alone separates the two.
    """
    methods: dict[str, OurMethod] = {}
    cur: OurMethod | None = None
    switch: list | None = None
    kind = first_key = width = payload_addr = 0
    for line in text.splitlines():
        stripped = line.strip()
        if line.startswith(".method "):
            cur = OurMethod(key=line.rsplit(" ", 1)[-1])
            continue
        if cur is None:
            continue
        if line == ".end method":
            methods.setdefault(cur.key, cur)
            cur, switch, kind = None, None, ""
            continue
        if stripped.startswith(".registers"):
            cur.registers = int(stripped.split()[1])
            continue
        if stripped.startswith(":addr_"):
            addr = int(stripped[6:], 16)
            cur.labels.add(addr)
            if switch is not None:
                # a label inside a payload body is a switch target, and the
                # label that *precedes* the directive already named the
                # payload's own offset
                if kind == "packed":
                    switch.append(addr)
                else:
                    key, _, tgt = stripped.partition("->")
                    switch.append((parse_literal(key.strip()), addr))
            else:
                payload_addr = addr
            continue
        cm = CATCH_RE.match(stripped)
        if cm:
            cur.catches.append((cm.group(1) or "*", int(cm.group(2), 16),
                                int(cm.group(3), 16), int(cm.group(4), 16)))
            continue
        if stripped.startswith(".packed-switch"):
            first_key, kind, switch = parse_literal(stripped.split()[1]), "packed", []
            continue
        if stripped.startswith(".sparse-switch"):
            kind, switch = "sparse", []
            continue
        if stripped.startswith(".array-data"):
            kind, width, switch = "array", int(stripped.split()[1]), []
            continue
        if stripped.startswith(".end ") and switch is not None:
            # every directive is stored as `(key_or_width, elements)`, so a
            # two element payload is never mistaken for a keys/targets pair
            if kind == "packed":
                value: tuple = (first_key, list(switch))
            elif kind == "sparse":
                value = ([p[0] for p in switch], [p[1] for p in switch])
            else:
                value = (width, list(switch))
            cur.payloads[payload_addr] = value
            switch = None
            continue
        if switch is not None:
            if kind == "array":
                switch.append(parse_literal(stripped))
            elif kind == "packed":
                switch.append(int(LABEL_RE.search(stripped).group(1), 16))
            else:
                key, _, tgt = stripped.partition("->")
                switch.append((parse_literal(key.strip()),
                               int(LABEL_RE.search(tgt).group(1), 16)))
            continue
        if line.startswith("    ") and not line.startswith("     ") and stripped:
            cur.insns.append(stripped)
    return methods


# --------------------------------------------------------------------------
# normalization
# --------------------------------------------------------------------------


def split_operands(text: str) -> list[str]:
    """Split a comma separated operand list, respecting `{v0, v1}` and quotes."""
    out: list[str] = []
    depth, in_str, back, cur = 0, False, False, []
    for ch in text:
        if in_str:
            cur.append(ch)
            if back:
                back = False
            elif ch == "\\":
                back = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            cur.append(ch)
        elif ch == "{":
            depth += 1
            cur.append(ch)
        elif ch == "}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []  # a comma outside a string starts the next operand
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def parse_literal(text: str) -> int:
    """`-0x1` / `0x7f` / `-1` / `0x1L` / `-0x1s` -> int (hex first, then decimal)."""
    t = text
    for suffix in ("L", "t", "s"):
        if t.endswith(suffix):
            t = t[:-1]
            break
    sign, digits = ("-", t[1:]) if t.startswith("-") else ("", t)
    return int(sign + digits, 16 if digits[:2].lower() == "0x" else 10)


def unescape_string(text: str) -> str:
    """Our smali string literal (with `\\uXXXX` escapes) -> the raw characters."""
    body, out, i = text[1:-1], [], 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "u" and i + 6 <= len(body):
                out.append(chr(int(body[i + 2 : i + 6], 16)))
                i += 6
                continue
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(nxt, nxt))
            i += 2
            continue
        out.append(body[i])
        i += 1
    return "".join(out)



def drop_wide_pair(text: str) -> str:
    """Drop androguard's implicit wide half: `v1v2` -> `v1`, `{v1v2, v3}` -> `{v1, v3}`.

    We print only the low half of a wide register (baksmali/droidsaw do not
    spell the implicit pair), so the high half is removed before the two sides
    are compared.
    """
    return re.sub(r"v(\d+)v\d+", lambda g: "v" + g.group(1), text)


#: A literal operand, in the two spellings baksmali uses.
LITERAL = r"-?(?:0[xX][0-9a-fA-F]+|\d+)[Lts]?"

#: A register operand, with androguard's `vNvN+1` implicit wide pair folded
#: away first -- we print only the low half of a wide register.
REG_TOKEN = re.compile(r"v\d+")
RANGE_TOKEN = re.compile(r"\{\s*v(\d+)\s*\.\.\s*v(\d+)\s*\}")
GROUP_TOKEN = re.compile(r"\{v\d+(?:, v\d+)*\}")


def canon_ours(op: str) -> tuple:
    """Our operand -> comparable token."""
    op = drop_wide_pair(op.strip())
    m = ADDR_RE.match(op)
    if m:
        return ("T", int(m.group(1), 16))
    span = RANGE_TOKEN.fullmatch(op)
    if span:
        return ("R", tuple(f"v{r}" for r in range(int(span.group(1)), int(span.group(2)) + 1)))
    if op == "{}" or GROUP_TOKEN.fullmatch(op):
        return ("R", tuple(REG_TOKEN.findall(op)))
    if REG_TOKEN.fullmatch(op):
        return ("R", (op,))
    if op.startswith('"'):
        return ("S", unescape_string(op))
    if re.fullmatch(LITERAL, op):
        return ("L", parse_literal(op))
    return ("X", op)


def join_quoted(parts: list[str]) -> list[str]:
    """Re-join oracle string operands that `split_operands` cut in half.

    The oracle escapes only tab/newline/carriage return/backslash, so a quote
    inside a string is written doubled and a comma inside it is not escaped:
    `const-string v0, "a", b"c"` is one operand that arrives as two or three.
    Splitting assumes a backslash escape, so the operand list is re-scanned
    here with the doubled-quote rule; a piece that leaves a string open
    continues into the next one.
    """
    out: list[str] = []
    for part in parts:
        if out and _ends_open(out[-1]) and part.startswith('"') \
                and part.endswith('"'):
            out[-1] = out[-1] + "," + part
            continue
        out.append(part)
    return out


def _ends_open(text: str) -> bool:
    """True when the text ends inside a string: a doubled `""` closed a quote.

    `"`   -> closed (one quote)     `""`  -> open
    `a"`  -> closed (one quote)     `a""` -> open
    """
    return len(text) >= 2 and text.endswith('""')


def canon_oracle(op: str, off: int) -> tuple:
    """Oracle operand -> comparable token; `@+xxxx` is branch relative.

    or an instruction with no operands, androguard's `get_operands()` yields
    one untagged entry holding the whole spelling, so the operand count (1 here
    versus 0 on our side) says which kind of token to build.
    """
    op = drop_wide_pair(op.strip())
    m = re.fullmatch(r"@([+-][0-9a-f]+)", op)
    if m:
        return ("T", off + int(m.group(1), 16))
    if op.startswith('"'):
        # The oracle escapes only tab/newline/carriage return/backslash, so a
        # quote inside the string is written doubled (`""`) and a comma inside
        # it splits the operand list; stitch the fragments of one quoted run
        # back together and compare the raw characters, not the escapes.
        # `\n`/`\r`/`\t`/`\\` are the oracle's escapes; a backslash before
        # anything else is a literal backslash the oracle passed through
        body = op[1:-1].replace('""', '"')
        raw, i = [], 0
        while i < len(body):
            if body[i] == "\\" and i + 1 < len(body):
                raw.append({"n": "\n", "r": "\r", "t": "\t", "\\": "\\"}[body[i + 1]])
                i += 2
                continue
            raw.append(body[i])
            i += 1
        return ("S", "".join(raw))
    if GROUP_TOKEN.fullmatch(op) or op == "{}":
        return ("R", tuple(REG_TOKEN.findall(op)))
    if REG_TOKEN.fullmatch(op):
        return ("R", (op,))
    if re.fullmatch(LITERAL, op):
        return ("L", parse_literal(op))
    return ("X", op)


# --------------------------------------------------------------------------
# diff
# --------------------------------------------------------------------------


@dataclass
class Mismatch:
    kind: str
    cls: str
    method: str
    off: int
    ours: str
    oracle: str
    detail: str = ""


@dataclass
class ClassResult:
    cls: str
    methods: int = 0
    compared: int = 0
    matched: int = 0
    payloads: int = 0
    tries: int = 0
    mism: list[Mismatch] = field(default_factory=list)
    error: str = ""


def _relative_payload(value, kind: str, base: int) -> object:
    """Our directive's case targets as the switch-relative raw values.

    The specification stores a payload's targets relative to the switch
    instruction, so the printed labels are turned back into the raw values
    both decoders report before they are compared.
    """
    if value is None:
        return None
    if kind == "array":
        width, values = value
        return [width, list(values or [])]
    if kind == "packed":
        first_key, targets = value
        return [first_key, [t - base for t in targets]]
    keys, targets = value
    return [list(keys), [t - base for t in targets]]


def _relative_spec(spec, base: int) -> list:
    """`spec_payload`'s value with the case targets back in raw form."""
    kind, value = spec
    if kind == "array":
        return [value[0], list(value[1] or [])]
    if kind == "packed":
        return [value[0], [t - base for t in value[1]]]
    return [list(value[0]), [t - base for t in value[1]]]


def diff_payload(cls: str, name: str, off: int, ours, theirs, spec) -> list[Mismatch]:
    """`.packed-switch` / `.sparse-switch` / `.array-data`: ours vs the two decoders.

    `ours` and `spec` are `[keys, targets]` (or `[first_key, targets]`, or
    `[width, values]`) so a two element payload cannot be mistaken for one;
    `theirs` is what androguard reports, which is only used for the
    informational `payload_androguard` note.
    """
    bad: list[Mismatch] = []
    theirs = list(theirs) if isinstance(theirs, (list, tuple)) else theirs
    if isinstance(ours, list) and len(ours) == 2 and not isinstance(ours[0], list):
        ours = [ours[0], ours[1]]
    if isinstance(theirs, (list, tuple)) and len(theirs) == 2 and not isinstance(theirs[0], list):
        theirs = [theirs[0], theirs[1]]
    if ours is None:
        return [Mismatch("payload", cls, name, off, "<missing>", repr(theirs), "no directive")]
    if spec is not None and ours != spec:
        bad.append(Mismatch("payload", cls, name, off, repr(ours), repr(spec),
                            "our listing disagrees with the spec decode of the payload bytes"))

    if ours != theirs:
        # the payload bytes are the authority: when both the spec decode and
        # our directive agree, a disagreement here is androguard's parse of a
        # damaged payload, and the two disagreeing sides are printed as detail
        bad.append(Mismatch("payload_androguard", cls, name, off, repr(ours),
                            repr(theirs),
                            f"androguard parses this payload differently; the "
                            f"bytes decode to {spec!r}"))
    return bad


def align_register_run(ours: list[tuple], theirs: list[tuple]) -> list[tuple]:
    """Glue androguard's brace-less register list onto one group token.

    androguard prints a register argument list as `v0, v1` where we print
    `{v0, v1}`, so the first register operand is a whole list on our side and
    a single register on theirs; the leading run is merged so the comparison
    sees operand values rather than punctuation.
    """
    if not (ours and theirs) or ours[0][0] != "R" or theirs[0][0] != "R" \
            or len(ours) >= len(theirs):
        return theirs
    if not ours[0][1]:
        return theirs[1:]  # we print `{}` for an empty argument list
    count = len(ours[0][1])
    run = theirs[:count]
    return [("R", tuple(r for _, regs in run for r in regs))] + theirs[count:]


def diff_tail(d: DEX, cls: str, name: str, raw: bytes, decoded: list[Insn],
              our: OurMethod, rec: dict, mism: list[Mismatch]) -> tuple[int, list[Mismatch]]:
    """Check the tail androguard cannot reach against this file's own decode.

    A method whose payload size runs past `insns_size` makes androguard stop
    early (or lose the alignment), so from that point on there is no oracle to
    compare against. The listing is checked for the properties that can be
    proved from the DEX bytes alone: the instruction stream is contiguous from
    0 and ends exactly at `insns_size`, every printed mnemonic is the one the
    code units say, every `:addr_` label is an instruction or payload offset,
    and every payload directive matches the payload bytes. The try table is
    still compared against androguard, which parses it independently.
    """
    code = [i for i in decoded if i.fmt not in ("payload", "padding")]
    starts = {i.off for i in decoded}
    # a clipped payload is recorded with the bytes it actually spans, so the
    # instruction stream alone must still cover the method up to it
    covered = sum(i.size for i in code)
    payload_start = min((i.off for i in decoded if i.fmt == "payload"), default=None)
    if payload_start is not None and covered > payload_start:
        covered = payload_start
    if covered != len(raw) // 2:
        mism.append(Mismatch("tail_coverage", cls, name, covered,
                             f"{covered} code units decoded",
                             f"{len(raw) // 2} in insns_size", "decoder does not cover the method"))
    if len(code) != len(our.insns):
        mism.append(Mismatch("count", cls, name, -1, f"{len(our.insns)} instructions",
                             f"{len(code)} instructions",
                             "instruction count differs (compared against this decode)"))
    for idx, line in enumerate(our.insns):
        if idx >= len(code):
            break
        mnemonic = line.split(None, 1)[0]
        if MNEMONIC_MAP.get(mnemonic, mnemonic) != code[idx].mnemonic:
            mism.append(Mismatch("mnemonic", cls, name, code[idx].off, mnemonic,
                                 code[idx].mnemonic,
                                 "compared against this decode (androguard stopped early)"))
    for addr in sorted(our.labels):
        if addr in starts or addr >= len(raw) // 2:
            # a target past `insns_size` belongs to whatever follows the
            # method; only the listing can say so, and it is the one case the
            # differential cannot decide
            continue
        mism.append(Mismatch("label", cls, name, addr, f":addr_{addr:x}", "",
                             "label is not the offset of a decoded instruction"))
    for ins in decoded:
        if ins.fmt != "payload" or _payload_truncated(ins, raw) \
                or len(ins.payload or b"") < 8:
            continue
        kind, value = spec_payload(ins, decoded)
        try:
            ours_norm = normalize_payload(our.payloads.get(ins.off), kind)
        except (TypeError, ValueError) as exc:
            ours_norm = [f"unparsable directive ({exc})"]
        spec = spec_payload_norm((kind, value))
        if ours_norm != spec:
            mism.append(Mismatch("payload", cls, name, ins.off, repr(ours_norm),
                                 repr(spec), "our directive vs the payload bytes"))
    theirs_tries = oracle_try_table(d, rec)
    if theirs_tries and set(our.catches) != theirs_tries:
        mism.append(Mismatch("try", cls, name, -1, repr(sorted(set(our.catches))),
                             repr(sorted(theirs_tries)), "try/catch table differs"))
    return len(code), mism

#: Mismatch kinds that record a known androguard defect without being a
#: failure: the bytes and our listing agree, only androguard's own parse of a
#: damaged payload (or its early stop on one) differs. They are printed so the
#: run stays auditable, and they do not set the exit code.
INFORMATIONAL = frozenset({"payload_androguard", "payload_clipped", "tail_coverage"})

#: `(class, method, first offset androguard disagrees)` for every method that
#: took the allowlisted divergence path, so the run stays auditable.
DIVERGED: list[tuple[str, str, int]] = []


def _payload_width_diverged(decoded: list[Insn], oracle_lengths: dict[int, int]) -> bool:
    """True when androguard steps over a switch payload with its own width.

    androguard's `SparseSwitch.get_length()` adds a code unit the DEX
    specification does not have, and its `PackedSwitch` reads `size` as a
    32-bit field; when the widths disagree the whole rest of the listing is
    one code unit out of step, so nothing after that point is comparable. The
    test is the payload's own width, not the symptom: only a method holding a
    switch payload whose androguard width differs from the spec width may take
    the divergence path.
    """
    for i in decoded:
        if i.fmt != "payload" or i.mnemonic == "fill-array-data-payload":
            continue
        oracle = oracle_lengths.get(i.off)
        if oracle is not None and oracle != i.size:
            return True
    return False


def diff_method(d: DEX, cls: str, name: str, rec: dict, our: OurMethod) -> tuple[int, list[Mismatch]]:
    """Compare one method: instructions, payload directives, try table."""
    mism: list[Mismatch] = []
    raw = rec["raw"][: 2 * rec["units"]]
    try:
        decoded = decode(raw)
    except ValueError as exc:
        # A payload whose declared size runs past the method: dexlib2 (and so
        # asc-rs) stops the listing there, and so does the decoder used here.
        # androguard's own width arithmetic disagrees, so it keeps going --
        # everything past the stop is compared against this decode instead.
        decoded = decode_prefix(raw, cls, name, mism)
        if decoded is None:
            return 0, [Mismatch("decode", cls, name, -1, "", "", str(exc))]
        return diff_tail(d, cls, name, raw, decoded, our, rec, mism)
    divergence: int | None = None
    code = [i for i in decoded if i.fmt != "payload"]
    starts = {i.off for i in decoded}

    if len(code) != len(our.insns):
        mism.append(Mismatch("count", cls, name, -1, f"{len(our.insns)} instructions",
                             f"{len(code)} instructions", "instruction count differs"))
    for addr in sorted(our.labels):
        if addr in starts or addr >= len(raw) // 2:
            # a target past `insns_size` belongs to whatever follows the
            # method; only the listing can say so, and it is the one case the
            # differential cannot decide
            continue
        mism.append(Mismatch("label", cls, name, addr, f":addr_{addr:x}", "",
                             "label is not the offset of a decoded instruction"))
    for i in decoded:
        if i.mnemonic in PAYLOAD_REFS and i.branch not in our.labels:
            mism.append(Mismatch("label", cls, name, i.off, i.mnemonic, "",
                                 f"payload reference 0x{i.branch:x} has no label"))

    off_map, cursor = {}, 0
    lengths = {}
    for insn in rec["insns"]:
        off_map[cursor] = insn
        lengths[cursor] = insn.get_length() // 2
        cursor += insn.get_length() // 2

    compared = matched = 0
    for idx, line in enumerate(our.insns):
        if idx >= len(code):
            break
        ins = code[idx]
        oins = off_map.get(ins.off)
        if oins is None:
            if divergence is not None and ins.off >= divergence:
                # past the point where androguard's payload width put its
                # listing out of step with the DEX specification: the
                # remaining instructions are checked against this decode only
                break
            mism.append(Mismatch("offset", cls, name, ins.off, line, "",
                                 "no oracle instruction at this offset"))
            continue
        parts = line.split(None, 1)
        our_mn = MNEMONIC_MAP.get(parts[0], parts[0])
        our_ops = parts[1] if len(parts) > 1 else ""
        oracle_mn = oins.get_name()
        if our_mn != oracle_mn:
            if _payload_width_diverged(decoded, lengths):
                divergence = divergence if divergence is not None else ins.off
                break
            mism.append(Mismatch("mnemonic", cls, name, ins.off, our_mn, oracle_mn, line))
            continue
        try:
            oracle_ops = render(d, oins)
        except Exception as exc:  # noqa: BLE001
            mism.append(Mismatch("oracle_error", cls, name, ins.off, line, "",
                                 f"{type(exc).__name__}: {exc}"))
            continue
        ours_side = [canon_ours(p) for p in split_operands(our_ops)]
        if our_ops.strip().startswith("{}"):
            # an empty argument list: baksmali prints `{}`, androguard prints
            # nothing, so it contributes no operand on either side
            ours_side = ours_side[1:]
        theirs_side = [canon_oracle(p, ins.off)
                       for p in join_quoted(split_operands(oracle_ops))]
        theirs_side = align_register_run(ours_side, theirs_side)
        compared += 1
        if ours_side == theirs_side:
            matched += 1
        else:
            mism.append(Mismatch("operand", cls, name, ins.off, line,
                                 f"{oracle_mn} {oracle_ops}".strip(),
                                 f"ours={ours_side} oracle={theirs_side}"))
        if any(k == "T" for k, _ in ours_side) and any(
            k == "T" and v not in starts and v < len(raw) // 2 for k, v in ours_side
        ):
            mism.append(Mismatch("label", cls, name, ins.off, line,
                                 f"{oracle_mn} {oracle_ops}".strip(),
                                 "branch target is not an instruction start"))

    for ins in decoded:
        if ins.fmt != "payload" or _payload_truncated(ins, raw) \
                or len(ins.payload or b"") < 8:
            continue
        if divergence is not None and ins.off >= divergence:
            break
        kind, value = spec_payload(ins, decoded)
        # Our directive against the payload bytes, independent of androguard:
        # the printed labels are resolved back to the switch-relative raw
        # values, which is the form both decoders report.
        base = _switch_addr(decoded, ins.off)
        try:
            spec_ours = _relative_payload(our.payloads.get(ins.off), kind, base)
        except (TypeError, ValueError) as exc:
            spec_ours = [f"unparsable directive ({exc})"]
        if spec_ours != _relative_spec((kind, value), base):
            mism.append(Mismatch("payload", cls, name, ins.off, repr(spec_ours),
                                 repr(_relative_spec((kind, value), base)),
                                 "our directive vs the payload bytes"))
        theirs = androguard_payload(off_map[ins.off], ins.off)
        mism.extend(diff_payload(cls, name, ins.off, spec_ours, theirs[1],
                                 _relative_spec((kind, value), base)))

    if divergence is not None:
        DIVERGED.append((cls, name, divergence))
        # androguard's listing left the specification at `divergence`: the
        # rest is checked against this decode, which is also where the label
        # and payload checks for that region have to come from
        _, tail = diff_tail(d, cls, name, raw, decoded, our, rec, mism)
        compared += tail
        return compared, mism
    theirs_tries = oracle_try_table(d, rec)
    if theirs_tries and set(our.catches) != theirs_tries:
        only_ours = sorted(set(our.catches) - theirs_tries)
        only_theirs = sorted(theirs_tries - set(our.catches))
        mism.append(Mismatch("try", cls, name, -1, repr(only_ours), repr(only_theirs),
                             "try/catch table differs"))
    return compared, mism


def normalize_payload(value, kind: str) -> object:
    """Our parsed directive, in the shape the spec/androguard sides use."""
    if value is None:
        return None
    if kind == "array":
        width, values = value
        return [width, list(values or [])]
    if kind == "packed":
        first_key, targets = value
        return [first_key, list(targets)]
    keys, targets = value
    return [list(keys), list(targets)]


def spec_payload_norm(spec) -> list:
    """`spec_payload`'s value as a list, with switch targets already absolute."""
    kind, value = spec
    if kind == "array":
        return [value[0], list(value[1] or [])]
    if kind == "packed":
        return [value[0], list(value[1])]
    return [list(value[0]), list(value[1])]


def oracle_try_table(d: DEX, rec: dict) -> set:
    """`(type, start, end, handler)` for every code item try/catch entry.

    A `try_item.handler_off` is a byte offset *relative* to the start of the
    encoded_catch_handler_list, not a list index; the handlers are keyed by
    that relative offset.
    """
    handlers = rec["handlers"]
    if not handlers:
        return set()
    base = handlers.get_off()
    by_off = {h.get_off() - base: h for h in handlers.get_list()}
    out = set()
    for t in rec["tries"]:
        h = by_off.get(t.get_handler_off())
        if h is None:
            raise ValueError(f"try_item handler_off {t.get_handler_off()} is not in the handler list")
        start, end = t.get_start_addr(), t.get_start_addr() + t.get_insn_count()
        for pair in h.get_handlers():
            out.add((d.CM.get_type(pair.get_type_idx()), start, end, pair.get_addr()))
        if h.get_size() <= 0:
            out.add(("*", start, end, h.get_catch_all_addr()))
    return out


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------


def select_classes(d: DEX, sample: int, payload_cap: int) -> list[str]:
    names = sorted(c.get_name() for c in d.get_classes())
    counts: dict[str, int] = {}
    special: list[str] = []
    for c in d.get_classes():
        n, flag = 0, False
        for m in c.get_methods():
            code = m.get_code()
            if code is None:
                continue
            flag = flag or code.get_tries_size() > 0
            try:
                for insn in code.get_bc().get_instructions():
                    n += 1
                    flag = flag or type(insn).__name__ in (
                        "PackedSwitch", "SparseSwitch", "FillArrayData")
            except Exception:  # noqa: BLE001
                pass
        counts[c.get_name()] = n
        if flag:
            special.append(c.get_name())
    chosen = set(sorted(special)[:payload_cap])
    chosen.update(name for name, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5])
    rest = [c for c in names if c not in chosen]
    if rest and sample > len(chosen):
        step = max(1, len(rest) // (sample - len(chosen)))
        chosen.update(rest[::step])
    return sorted(chosen)


def check_opcode_table(theirs: dict) -> list[str]:
    """Cross-check this file's opcode table against androguard's.

    The table is written from the Dalvik instruction formats, so it is
    independent evidence -- but a table typo would desynchronize the whole
    comparison instead of failing it, so every opcode is compared in both
    directions before the run starts:

    * an opcode both decoders implement must agree on mnemonic and width;
    * an opcode this table calls unused must be unused in the specification,
      whatever androguard happens to call it.
    """
    bad: list[str] = []
    for low, entry in sorted(theirs.items()):
        name = entry[1][0]
        m = re.match(r"^Instruction(\d+)([A-Za-z]*)$", entry[0].__name__)
        fmt = m.group(1) + m.group(2).lower() if m else "?"
        mine = OPCODES.get(low)
        if low in UNUSED_OPCODES:
            if mine is not None:
                bad.append(f"0x{low:02x}: table says {mine[0]}, specification says unused")
            continue
        if mine is None:
            bad.append(f"0x{low:02x}: table has no entry, androguard says {name} ({fmt})")
        elif mine[0] != name or WIDTHS[mine[1]] != _WIDTHS.get(fmt):
            bad.append(f"0x{low:02x}: ours={mine[0]}/{WIDTHS[mine[1]]}u "
                       f"androguard={name}/{_WIDTHS.get(fmt)}u")
    for low in sorted(OPCODES):
        if low not in theirs and low not in UNUSED_OPCODES:
            bad.append(f"0x{low:02x}: table has {OPCODES[low][0]}, androguard has no entry")
    return bad


#: Instruction width in code units, keyed by androguard's format class name.
_WIDTHS = {
    "10x": 1, "12x": 1, "11x": 1, "11n": 1, "10t": 1, "20t": 2, "22x": 2,
    "21t": 2, "21s": 2, "21h": 2, "21c": 2, "23x": 2, "22b": 2, "22t": 2,
    "22s": 2, "22c": 2, "30t": 3, "32x": 3, "31i": 3, "31t": 3, "31c": 3,
    "35c": 3, "3rc": 3, "51l": 5, "45cc": 4, "4rcc": 4, "20bc": 2, "22cs": 2,
    "35ms": 3, "35mi": 3, "3rms": 3, "3rmi": 3, "52c": 2, "5rc": 2, "00x": 1,
}


def run_asc(dex: Path, cls: str, out: Path) -> str:
    r = subprocess.run([str(ASC_RS), "disasm", str(dex), cls, "-o", str(out)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"exit {r.returncode}: {r.stderr.strip()[:200]}")
    return out.read_text(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="asc-rs disasm vs androguard differential")
    ap.add_argument("--dex", action="append", help="DEX file (repeatable)")
    ap.add_argument("--sample", type=int, default=150, help="classes per DEX")
    ap.add_argument("--payload-cap", type=int, default=400)
    ap.add_argument("--jobs", type=int, default=4, help="asc-rs processes in parallel")
    ap.add_argument("--keep", action="store_true", help="keep the per-class listings")
    args = ap.parse_args(argv)

    dexes = ([Path(p) for p in args.dex] if args.dex else
             [ROOT / "corpus" / "dex" / f"{n}.dex" for n in
              ("aurora_classes", "aurora_classes2", "fdroid_classes",
               "fdroid_classes2", "workload_classes")])
    SCRATCH.mkdir(parents=True, exist_ok=True)

    from loguru import logger

    logger.remove()
    from androguard.core import dex as ag
    from androguard.core.dex import DEX

    table_bad = check_opcode_table(ag.DALVIK_OPCODES_FORMAT)
    if table_bad:
        print("opcode table disagrees with androguard:", file=sys.stderr)
        for line in table_bad[:10]:
            print("  " + line, file=sys.stderr)
        return 2

    t0 = time.time()
    rows, all_mism, errors = [], [], []
    for path in dexes:
        d = DEX(path.read_bytes(), using_api=34)
        classes = select_classes(d, args.sample, args.payload_cap)
        index: dict[str, dict] = {}
        for c in d.get_classes():
            for m in c.get_methods():
                code = m.get_code()
                if code is None:
                    continue
                desc = m.get_descriptor()
                index.setdefault(c.get_name(), {})[f"{m.get_name()}{''.join(desc.split())}"] = {
                    "raw": bytes(code.get_bc().get_insn()),
                    # insns_size from the code item header, already in code units
                    "units": code.get_length(),
                    "insns": list(code.get_bc().get_instructions()),
                    "tries": code.get_tries(),
                    "handlers": code.get_handlers(),
                }

        def work(cls: str, path=path, d=d, index=index) -> ClassResult:
            res = ClassResult(cls=cls)
            # one file per worker: two classes can sanitize to the same name
            out = SCRATCH / f"{path.stem}__{re.sub(r'[^A-Za-z0-9]', '_', cls)}_" \
                           f"{threading.get_ident():x}.smali"
            try:
                listing = run_asc(path, cls, out)
            except Exception as exc:  # noqa: BLE001
                res.error = str(exc)
                return res
            if not args.keep:
                try:
                    out.unlink()
                except OSError:
                    pass  # Windows keeps a handle open for a moment
            ours = parse_our_listing(listing)
            for name, rec in index.get(cls, {}).items():
                res.methods += 1
                our = ours.get(name)
                if our is None:
                    res.mism.append(Mismatch("missing_method", cls, name, -1, "", "",
                                             "method with code is absent from our listing"))
                    continue
                res.payloads += len(our.payloads)
                res.tries += len(rec["tries"])
                compared, mism = diff_method(d, cls, name, rec, our)
                res.compared += compared
                res.matched += compared - sum(1 for m in mism if m.kind == "operand")
                res.mism.extend(mism)
            return res

        row = [path.stem, len(classes), 0, 0, 0, 0, 0]
        with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for res in pool.map(work, classes):
                row[2] += res.methods
                row[3] += res.compared
                row[4] += res.matched
                row[5] += res.payloads
                row[6] += res.tries
                all_mism.extend(res.mism)
                if res.error:
                    errors.append(f"{path.stem} {res.cls}: {res.error}")
        rows.append(row)

    dt = time.time() - t0
    print(f"{'dex':<20} {'classes':>7} {'methods':>7} {'insns':>7} {'match':>7} "
          f"{'payloads':>8} {'tries':>6}")
    for r in rows:
        print(f"{r[0]:<20} {r[1]:>7} {r[2]:>7} {r[3]:>7} {r[4]:>7} {r[5]:>8} {r[6]:>6}")
    print(f"\nclasses={sum(r[1] for r in rows)} methods={sum(r[2] for r in rows)} "
          f"insns_compared={sum(r[3] for r in rows)} exact_match={sum(r[4] for r in rows)} "
          f"payload_directives={sum(r[5] for r in rows)} try_items={sum(r[6] for r in rows)} "
          f"mismatches={len(all_mism)} asc_errors={len(errors)} time={dt:.1f}s")
    for kind, cnt in Counter(m.kind for m in all_mism).most_common():
        print(f"  {kind}: {cnt}")
    print(f"androguard payload-width divergence: {len(DIVERGED)} methods "
          f"(first divergent offsets: "
          + ", ".join(f"0x{off:04x}" for _, _, off in DIVERGED[:20]) + ")")
    for e in errors[:10]:
        print(f"  asc-rs error: {e}")
    for kind in ("mnemonic", "operand", "try", "payload", "count", "label",
                 "tail_coverage", "payload_clipped", "payload_androguard",
                 "decode", "missing_method", "oracle_error"):
        group = [m for m in all_mism if m.kind == kind][:3]
        if not group:
            continue
        print(f"\n== {kind}: {sum(1 for m in all_mism if m.kind == kind)} (first 3)")
        for m in group:
            print(f"[{m.kind}] {m.cls}->{m.method} @0x{m.off:04x} {m.detail}\n"
                  f"  ours:   {m.ours}\n  oracle: {m.oracle}")

    real = [m for m in all_mism if m.kind not in INFORMATIONAL]
    return 1 if real or errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
