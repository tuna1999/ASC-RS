#!/usr/bin/env python3
"""Warm-runner helper invoked by ``benches/benchmark.py``.

Runs the oracle N times inside a long-lived Python process so the
import-and-init cost is amortised. Emits ``RUN_TIME=<seconds>`` on stdout
once per iteration.

Usage::

    python benches/_warm_runner.py <N> -- <oracle_argv...>

The oracle argv starts after the ``--``. The harness always passes
``--`` so the split is unambiguous.
"""

import sys
import time

if __name__ != "__main__":
    sys.exit(0)

if len(sys.argv) < 4 or sys.argv[2] != "--":
    sys.stderr.write(
        "warm_runner usage: _warm_runner.py <N> -- <oracle_argv...>\n"
    )
    sys.exit(2)

try:
    n = int(sys.argv[1])
except ValueError:
    sys.stderr.write(f"bad N: {sys.argv[1]!r}\n")
    sys.exit(2)

oracle_argv = sys.argv[3:]

# Import oracle machinery once.
from src.asc_client.apk_handler import ApkHandler
from src.asc_client.asc_handler import AscHandler

# Re-route stdout to a buffer while we invoke the oracle so the harness
# can read RUN_TIME= lines back.
import io

for i in range(n):
    sink = io.StringIO()
    real_stdout = sys.stdout
    sys.stdout = sink
    t0 = time.perf_counter()
    try:
        if oracle_argv[0] == "findrefs":
            handler = ApkHandler(oracle_argv[1])
            ft = oracle_argv[2]
            val = oracle_argv[3] if len(oracle_argv) > 3 else None
            if ft == "string":
                query = {"string": val}
            elif ft == "type":
                query = {"type": val}
            elif ft == "method":
                query = {"method": {"class": None, "method": val}}
            elif ft == "field":
                query = {"field": {"class": None, "field": val}}
            else:
                sys.stderr.write(f"unknown find type: {ft}\n")
                sys.exit(3)
            for _dex_name, lines in handler.for_each_findrefs(ft, query):
                if not lines:
                    continue
                sink.write("\n".join(lines) + "\n")
        elif oracle_argv[0] == "getclass":
            handler = ApkHandler(oracle_argv[1])
            cls = oracle_argv[2]
            hit = handler.get_class_dex(cls)
            if hit is None:
                sys.stderr.write(f"Class {cls} not found\n")
                sys.exit(1)
            _name, dex_buf = hit
            asc = AscHandler()
            sink.write(asc.getclass(dex_buf, cls))
        else:
            sys.stderr.write(f"unknown subcommand: {oracle_argv[0]}\n")
            sys.exit(3)
    finally:
        sys.stdout = real_stdout
    elapsed = time.perf_counter() - t0
    real_stdout.write(f"RUN_TIME={elapsed:.6f}\n")
    real_stdout.flush()