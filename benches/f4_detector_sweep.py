"""F4 detector sweep: false positives, silent read-before-assign, loop-body copies.

Measures the `unbound_locals` warning (asc-decompile `diagnose`) against the
whole decompiled text, which is *not* the detector itself — every verdict is
derived independently from the listing.

Sampling rule (fixed, so the numbers in
docs/research/malware-triage-roadmap.md `### (h)` can be re-derived):
five DEX under `corpus/dex`, `--per-dex 120` classes each taken with a fixed
stride `len(classes) // per_dex`, in listing order. `getclass` runs on the DEX
file, the warning is read from stderr, the body from stdout.

Modes
  --mode fp     classify every reported name; a report is a false positive when
                the first occurrence is a declaration or an assignment
  --mode fn     names read before any write in the same method that the
                detector stays silent about
  --mode defect count classes whose body repeats an adjacent statement window
                (SSA names normalised) — the shape `duplicated_catch_bodies`
                cannot see

Exit 0 always: this is a report, not a gate.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "target/release/asc-rs.exe"
LOCAL = re.compile(r"\bv(\d+)_(\d+)\b")
SSA = re.compile(r"\bv\d+_\d+\b")
WARN = re.compile(r"(\d+) local\(s\) read but never assigned: (.*)$")
DECL = re.compile(r"^\s*(?:final\s+)?[A-Za-z_$][\w.$<>\[\]]*\s+([a-z_$][\w$]*\w*)\s*[;=\[,]")
FOR_EACH = re.compile(r"\bfor\s*\([^;)]*$")
PRIMITIVES = frozenset("int long byte boolean char short float double void".split())


def plausible_type(token: str) -> bool:
    """A declaration's type is a primitive, capitalised, or qualified name —
    `isSupported = v0_4;` is a field assignment, not a declaration."""
    last = token.rsplit(".", 1)[-1].rstrip("[]")
    return token in PRIMITIVES or (last[:1].isupper() and last[:1].isalpha()) or "." in token


def classes(dex: Path) -> list[str]:
    out = subprocess.run(
        [str(EXE), "listclass", str(dex), "--format", "json"],
        capture_output=True, text=True,
    ).stdout
    return re.findall(r'"(L[^"]+;)"', out)


def decompile(dex: Path, cls: str) -> tuple[str, str]:
    r = subprocess.run([str(EXE), "getclass", str(dex), cls], capture_output=True, text=True)
    return r.stdout, r.stderr


METHOD_START = re.compile(r"^ {4}(?![} ])\S.*\{$", re.M)


def method_start(src: str, at: int) -> int:
    """Start of the enclosing method body, so names stay per method like the
    detector's own scope (`v0_15` in another method is not this one)."""
    last = 0
    for m in METHOD_START.finditer(src, 0, at):
        last = m.start()
    return last


def first_read(src: str, name: str, occurrence: int, floor: int = 0) -> int | None:
    pos = floor - 1
    for _ in range(occurrence + 1):
        pos = src.find(name, pos + 1)
        if pos < 0:
            return None
    return pos


def classify(src: str, name: str) -> tuple[str, int]:
    """`declaration` / `assignment` (false positive) or `read` (true positive).

    The detector binds per method, so a name is only a false positive when its
    *first* occurrence inside every method that uses it is a bind — `v1_5`
    declared in one method and read in another is still a real report.
    """
    first_in_block: dict[int, int] = {}
    pos = -1
    while True:
        pos = src.find(name, pos + 1)
        if pos < 0:
            break
        first_in_block.setdefault(method_start(src, pos), pos)
    verdict, at = "read", -1
    for block, pos in first_in_block.items():
        kind = _one(src, name, pos)
        if kind == "read":
            return "read", pos
        verdict, at = kind, pos
    return verdict, at


def _one(src: str, name: str, pos: int) -> str:
    line_start = src.rfind("\n", 0, pos) + 1
    line_end = src.find("\n", pos)
    line = src[line_start : line_end if line_end >= 0 else len(src)]
    head = line.split()[0] if line.split() else ""
    decl = DECL.match(line)
    if decl and decl.group(1) == name and pos - line_start > 0 and plausible_type(head):
        return "declaration"
    if FOR_EACH.search(src[max(0, pos - 60) : pos]):
        return "declaration"
    tail = src[pos + len(name) :].lstrip()
    if not tail.startswith("==") and (
        tail.startswith("=") or tail.startswith(("++", "--")) or re.match(r"[+\-*/%&|^]=", tail)
    ):
        return "assignment"
    return "read"


def writes_in_method_all(src: str, name: str) -> bool:
    """True when every method using `name` writes it somewhere."""
    blocks: dict[int, list[int]] = {}
    pos = -1
    while True:
        pos = src.find(name, pos + 1)
        if pos < 0:
            break
        blocks.setdefault(method_start(src, pos), []).append(pos)
    return all(
        re.search(rf"\b{re.escape(name)}\s*=(?!=)", src[b[0] :]) for b in blocks.values()
    )


def duplicated_windows(text: str, width: int = 3) -> int:
    stmts = [
        SSA.sub("v", line.strip())
        for line in text.splitlines()
        if line.strip().endswith(";") or line.strip().startswith(("while", "if", "for"))
    ]
    return sum(
        1
        for i in range(len(stmts) - 2 * width + 1)
        if stmts[i : i + width] == stmts[i + width : i + 2 * width]
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=["fp", "fn", "defect", "all"], default="all")
    ap.add_argument("--per-dex", type=int, default=120)
    args = ap.parse_args()

    fp = fn = defect = scanned = 0
    examples: list[dict] = []
    for dex in sorted((ROOT / "corpus/dex").glob("*.dex")):
        names = classes(dex)
        stride = max(1, len(names) // args.per_dex)
        for cls in names[::stride][: args.per_dex]:
            scanned += 1
            src, err = decompile(dex, cls)
            if args.mode in ("defect", "all") and duplicated_windows(src):
                defect += 1
                if len(examples) < 5:
                    examples.append({"class": cls, "dex": dex.name, "kind": "loop_copy"})
            m = WARN.search(err)
            if m:
                for name in (n.strip() for n in m.group(2).split(",")):
                    verdict, pos = classify(src, name)
                    if verdict != "read":  # noqa: F841 - pos feeds the example
                        fp += 1
                        if len(examples) < 5:
                            examples.append(
                                {"class": cls, "name": name, "kind": verdict, "at": pos}
                            )
                continue
            if args.mode in ("fn", "all"):
                # Silent class: count every name the detector missed that is
                # read before any write in its own method.
                for name in {f"v{a}_{b}" for a, b in LOCAL.findall(src)}:
                    if classify(src, name)[0] == "read" and not writes_in_method_all(
                        src, name
                    ):
                        fn += 1
    print(
        json.dumps(
            {"classes_scanned": scanned, "false_positives": fp, "silent_read_before_write": fn,
             "classes_with_a_repeated_window": defect, "examples": examples},
            indent=1,
        )
    )


if __name__ == "__main__":
    main()
