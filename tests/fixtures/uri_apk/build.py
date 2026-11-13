#!/usr/bin/env python3
"""Build tests/fixtures/uri_apk/uri_groups.apk from tests/fixtures/uri_match_cases.json.

One `<activity>` per case (`.c_<case_id>`), each carrying the case's filter, so the
real AXML path (aapt2 output -> asc-manifest decoder -> evaluator) is exercised
instead of the JSON model. Writes `cases.txt` (`case_id<TAB>uri<TAB>flag_on<TAB>
source_expected`) next to the APK as the test's expectation table.

Needs aapt2 + an API 35 android.jar (neither ships with the repo):

  export AAPT2=/path/to/aapt2.exe ANDROID_JAR=/path/to/platforms/android-35/android.jar
  python tests/fixtures/uri_apk/build.py

Regenerate and commit the APK only when uri_match_cases.json changes. Rebuilds
are byte-identical with the pinned aapt2 (build 16666295, md5 701c72b77837cd8acecc87aa4433cdfc).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE.parent / "uri_match_cases.json"
OUT_APK = HERE / "uri_groups.apk"
OUT_TABLE = HERE / "cases.txt"
# Unsigned tools (aapt2) cannot create files outside target/ on this Windows box
# (mechanism unconfirmed; unsigned binaries of any language reproduce it), so
# link into the build dir and copy with this (signed) python.
BUILD_DIR = HERE.parents[2] / "target" / "uri_apk_build"

DATA_ATTR = {"scheme": "scheme", "host": "host", "port": "port", "path": "path",
             "mime_type": "mimeType", "path_prefix": "pathPrefix", "path_pattern": "pathPattern",
             "path_advanced_pattern": "pathAdvancedPattern"}
PART_ATTR = {"path": "path", "fragment": "fragment", "query": "query"}
KIND_SUFFIX = {"exact": "", "prefix": "Prefix", "suffix": "Suffix",
               "pattern": "Pattern", "advanced": "AdvancedPattern"}


def esc(v: str) -> str:
    # aapt2 treats `\\` as an escape inside attribute values, so a value that must
    # keep a literal backslash has to be written doubled.
    return (str(v).replace("\\", "\\\\").replace("&", "&amp;")
            .replace("<", "&lt;").replace('"', "&quot;"))


def data_element(d: dict, indent: str) -> str:
    attrs = "".join(
        f' android:{DATA_ATTR[k]}="{esc(d[k])}"' for k in d if k in DATA_ATTR
    )
    return f"{indent}<data{attrs}/>"


def group_element(g: dict, indent: str) -> str:
    out = [f'{indent}<uri-relative-filter-group android:allow="{str(g["allow"]).lower()}">']
    for d in g["data"]:
        attrs = "".join(
            f' android:{PART_ATTR[p["part"]]}{KIND_SUFFIX[p["kind"]]}="{esc(p["value"])}"'
            for p in d["parts"]
        )
        out.append(f"{indent}  <data{attrs}/>")
    out.append(f"{indent}</uri-relative-filter-group>")
    return "\n".join(out)


def main() -> int:
    aapt2 = os.environ.get("AAPT2")
    jar = os.environ.get("ANDROID_JAR")
    if not aapt2 or not jar:
        sys.exit("set AAPT2 and ANDROID_JAR (API 35 platform android.jar)")
    cases = json.loads(CASES.read_text(encoding="utf-8"))["cases"]
    acts = []
    for c in cases:
        f = c["filter"]
        lines = [f'    <activity android:name=".c_{c["case_id"]}" android:exported="true">',
                 "      <intent-filter>",
                 '        <action android:name="android.intent.action.VIEW"/>']
        lines += [data_element(d, "        ") for d in f["data"]]
        # <group android:name> mime groups: the framework parses the element
        # (IntentFilter.parseIntentFilter) but no aapt2 build still accepts it,
        # so a case that declares mime_groups makes this build fail loudly.
        lines += [f'        <group android:name="{esc(n)}"/>' for n in f.get("mime_groups", [])]
        lines += [group_element(g, "        ") for g in f.get("groups", [])]
        lines += ["      </intent-filter>", "    </activity>"]
        acts.append("\n".join(lines))
    xml = "\n".join([
        '<?xml version="1.0" encoding="utf-8"?>',
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"',
        '          package="asc.rs.urifixture">',
        "  <application>",
        *acts,
        "  </application>",
        "</manifest>",
        "",
    ])
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=BUILD_DIR) as td:
        man = Path(td) / "AndroidManifest.xml"
        man.write_text(xml, encoding="utf-8")
        built = Path(td) / "uri_groups.apk"
        subprocess.run([aapt2, "link", "-o", str(built), "--manifest", str(man),
                        "-I", jar, "--min-sdk-version", "35",
                        "--target-sdk-version", "35"],
                       check=True)
        shutil.copyfile(built, OUT_APK)
    OUT_TABLE.write_text("".join(
        f'{c["case_id"]}\t{c["uri"]}\t{int(c["flag_on"])}\t{c["source_expected"]}\n'
        for c in cases), encoding="utf-8")
    print(f"wrote {OUT_APK.name} ({OUT_APK.stat().st_size} B) and {OUT_TABLE.name} "
          f"with {len(cases)} case(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
