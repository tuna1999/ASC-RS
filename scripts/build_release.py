"""Build a byte-reproducible source ZIP for an ASC-RS release.

Port of reference/asc/scripts/build_release.py to the Rust workspace layout.
Deterministic: fixed ZipInfo timestamps, fixed external_attr, sorted paths,
DEFLATED. Re-running produces a byte-identical archive.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Source-tree roots the oracle-style release needs to build from source.
# Mirror what the oracle packed (main.py/requirements.txt/src/docs/etc.) but
# adapted to the Rust workspace. `git ls-files` of these paths gives the set.
PACKED = [
    "Cargo.toml",
    "Cargo.lock",
    "LICENSE",
    "NOTICE",
    "README.md",
    ".gitignore",
    "crates",
    "tests",
    "benches",
    "fuzz",
    "docs",
    "seeds",
    "skills",
]

# Members every source release MUST contain (legal + agent skill docs).
# Checked before packing so a forgotten file fails the build loudly.
REQUIRED_MEMBERS = [
    "LICENSE",
    "NOTICE",
    "README.md",
    "Cargo.toml",
    "Cargo.lock",
    "skills/apk-analysis/SKILL.md",
    "crates/asc-core/src/pipeline.rs",
]

_SEMVER = re.compile(
    r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-(?:alpha|beta|rc)\.[1-9]\d*)?"
)


def _validate(version: str) -> None:
    if not _SEMVER.fullmatch(version):
        raise ValueError(
            "expected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N "
            "(also alpha/beta)"
        )


def _list_files() -> list[str]:
    raw = subprocess.check_output(
        ["git", "ls-files", "-z", "--", *PACKED],
        cwd=ROOT,
    ).decode("utf-8", "replace")
    return sorted(p for p in raw.split("\0") if p)


def build(version: str, output: Path) -> Path:
    _validate(version)
    paths = _list_files()
    if not paths:
        raise RuntimeError("git ls-files returned no paths; refusing to build empty release")
    missing = [m for m in REQUIRED_MEMBERS if m not in set(paths)]
    if missing:
        raise RuntimeError(
            "release is missing required members: " + ", ".join(sorted(missing))
        )

    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"ASC-RS-{version}-source.zip"

    # Fixed 1980-01-01 00:00:00 — ZipInfo's date_time is local-naive, but the
    # bytes don't change run-to-run on the same machine. Using a stable value
    # is what makes the archive byte-reproducible.
    fixed_dt = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in paths:
            info = zipfile.ZipInfo(f"ASC-RS-{version}/{path}", fixed_dt)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3  # Unix (constant bytes)
            data = (ROOT / path).read_bytes()
            zf.writestr(info, data)

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text(
        f"{digest}  {archive.name}\n", encoding="ascii"
    )
    return archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="Release tag, e.g. v0.1.1 or v0.2.0-rc.1")
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()
    try:
        archive = build(args.version, args.output)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    print(f"{digest}  {archive}")
    print(f"wrote {archive} and {args.output / 'SHA256SUMS'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
