#!/usr/bin/env python3
"""asc-rs disasm debug directives vs androguard's debug_info parser.

androguard decodes every debug_info_item into DBGBytecode records; this
script runs the DEX debug state machine over those records and checks that
`asc-rs disasm` prints the same `.line`/`.local`/`.end local`/
`.restart local`/`.prologue`/`.epilogue` directives, in the same order, each
in front of the same instruction. It also checks `.param` names. Run with
the oracle interpreter (`reference/venv`); exit 1 on any mismatch.
"""
from __future__ import annotations

import argparse
import io
import random
import subprocess
import sys
from pathlib import Path

from androguard.core.dex import DEX, DebugInfoItem
from loguru import logger

logger.remove()

ROOT = Path(__file__).resolve().parents[2]
PAYLOADS = {"PackedSwitch", "SparseSwitch", "FillArrayData"}


def unquote(s: str | None) -> str:
    return "null" if s is None else '"' + s + '"'


def oracle_events(cm, raw: bytes, code) -> tuple[list[tuple[int, str]], list]:
    # CodeItem.get_debug() is broken in androguard 4.1.3 (seeks the DEX
    # object), so parse the item through androguard's own DebugInfoItem.
    if code.debug_info_off == 0:
        return [], []
    buff = io.BytesIO(raw)
    buff.seek(code.debug_info_off)
    dbg = DebugInfoItem(buff, cm)
    line = dbg.get_line_start()
    addr = 0
    out: list[tuple[int, str]] = []
    locals_: dict[int, str] = {}
    s = lambda i: None if i == -1 else cm.get_string(i)  # noqa: E731
    t = lambda i: None if i == -1 else cm.get_type(i)  # noqa: E731
    for b in dbg.get_bytecodes():
        op, f = b.get_op_value(), [v for v, _ in b.format]
        if op == 0x00:
            break
        if op == 0x01:
            addr += f[0]
        elif op == 0x02:
            line += f[0]
        elif op in (0x03, 0x04):
            desc = f"{unquote(s(f[1]))}:{t(f[2]) or 'V'}"
            if op == 0x04 and f[3] != -1:
                desc += f", {unquote(s(f[3]))}"
            out.append((addr, f".local v{f[0]}, {desc}"))
            locals_[f[0]] = desc
        elif op in (0x05, 0x06):
            what = ".end local" if op == 0x05 else ".restart local"
            note = f"    # {locals_[f[0]]}" if f[0] in locals_ else ""
            out.append((addr, f"{what} v{f[0]}{note}"))
        elif op == 0x07:
            out.append((addr, ".prologue"))
        elif op == 0x08:
            out.append((addr, ".epilogue"))
        elif op == 0x09:
            out.append((addr, f".source {unquote(s(f[0]))}"))
        else:
            adj = op - 0x0A
            line += -4 + adj % 15
            addr += adj // 15
            out.append((addr, f".line {line}"))
    out.sort(key=lambda e: e[0])
    names = [None if i == -1 else cm.get_string(i) for i in dbg.get_parameter_names()]
    return out, names


def placed(events, code) -> list[tuple[int, str]]:
    """(index of the instruction the directive precedes, text)."""
    addrs, a = [], 0
    for ins in code.get_bc().get_instructions():
        if type(ins).__name__ not in PAYLOADS:
            addrs.append(a)
        a += ins.get_length() // 2
    res, i = [], 0
    for at, text in events:
        while i < len(addrs) and addrs[i] < at:
            i += 1
        res.append((i, text))
    return res


def ours(listing: str) -> dict[str, tuple[list[tuple[int, str]], list[str]]]:
    methods, cur, n, ev, params = {}, None, 0, [], []
    in_ann = False
    for line in listing.splitlines():
        st = line.strip()
        if line.startswith(".method "):
            cur, n, ev, params = line.rsplit(" ", 1)[-1], 0, [], []
            continue
        if cur is None:
            continue
        if line == ".end method":
            methods.setdefault(cur, (ev, params))
            cur = None
            continue
        if in_ann:
            in_ann = st != ".end annotation"
            continue
        if not line.startswith("    ") or line.startswith("        "):
            continue
        if st.startswith(".annotation "):
            in_ann = True
        elif st.startswith(".param "):
            params.append(st)
        elif st.startswith((".line ", ".local ", ".end local", ".restart local",
                            ".prologue", ".epilogue", ".source ")):
            ev.append((n, st))
        elif st and not st.startswith((".", ":", "#")):
            n += 1
    return methods


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dex", action="append", type=Path)
    ap.add_argument("--sample", type=int, default=300, help="classes per DEX")
    ap.add_argument("--binary", type=Path, default=ROOT / "target/release/asc-rs.exe")
    a = ap.parse_args()
    dexes = a.dex or sorted((ROOT / "corpus/dex").glob("*.dex"))
    rnd = random.Random(7)
    checked = bad = 0
    kinds: dict[str, int] = {}
    for path in dexes:
        raw = path.read_bytes()
        d = DEX(raw, using_api=34)
        classes = [c for c in d.get_classes() if c.get_methods()]
        for c in rnd.sample(classes, min(a.sample, len(classes))):
            r = subprocess.run([str(a.binary), "disasm", str(path), c.get_name()],
                               capture_output=True, text=True, encoding="utf-8")
            if r.returncode != 0:
                continue  # instruction-level refusals are run_disasm_diff's job
            got = ours(r.stdout)
            for m in c.get_methods():
                code = m.get_code()
                if code is None:
                    continue
                key = m.get_name() + m.get_descriptor().replace(" ", "")
                if key not in got:
                    continue
                ev, names = oracle_events(d.CM, raw, code)
                want = placed(ev, code)
                have, params = got[key]
                named = [p for p in params if '"' in p]
                checked += 1
                for _, text in want:
                    k = text.split(' v')[0].split(' ')[0]
                    kinds[k] = kinds.get(k, 0) + 1
                kinds['.param'] = kinds.get('.param', 0) + len(named)
                exp_named = sum(1 for x in names if x is not None)
                if have != want or len(named) != exp_named:
                    bad += 1
                    if bad <= 5:
                        print(f"MISMATCH {c.get_name()}->{key}")
                        for x, y in zip(have, want):
                            if x != y:
                                print(f"  ours:   {x}\n  oracle: {y}")
                                break
                        else:
                            print(f"  ours {len(have)} directives, oracle {len(want)};"
                                  f" .param names ours {len(named)} oracle {exp_named}")
    print(f"methods_checked={checked} mismatches={bad} directives={kinds}")
    return 1 if bad or not checked else 0


if __name__ == "__main__":
    sys.exit(main())
