"""python -m patcher.bench [--release DIR] [--tests]

Runs patcher.propose (real CLI) on the three real fixtures with the current PATCHER_MODEL
and prints seconds per fix and whether the diff applied (and, with --tests, whether
victim/tests pass on the patched copy).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

from . import claude_cli
from .checks import REPO, check_diff, patched_copy
from .core import propose


def _applies(release: str, diff: str) -> bool:
    if not diff.strip():
        return False
    root, errs = patched_copy(release, [diff])
    shutil.rmtree(root, ignore_errors=True)
    return not errs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m patcher.bench")
    ap.add_argument("--release", default=os.path.join(REPO, "runtime", "releases", "t0"))
    ap.add_argument("--tests", action="store_true", help="also run victim/tests on each patched copy")
    a = ap.parse_args(argv)
    if not os.path.isdir(os.path.join(a.release, "victim")):
        a.release = REPO
    sys.path.insert(0, os.path.join(REPO, "patcher", "tests", "fixtures"))
    from incidents import all_incidents

    os.environ.pop("PATCHER_FORCE_FALLBACK", None)
    print(f"model={claude_cli.model()} timeout={claude_cli.timeout_s():.0f}s release={a.release}")
    rows = []
    for oracle, inc in all_incidents().items():
        t0 = time.monotonic()
        out = propose(a.release, inc, [], 1)
        secs = time.monotonic() - t0
        chk = check_diff(a.release, out["diff"]) if a.tests else None
        applied = chk["applies"] if chk else _applies(a.release, out["diff"])
        line = (f"{inc['vuln_class']:<10} {inc['method']} {inc['route']:<28} {secs:6.1f}s  source={out['source']:<8} "
                f"applied={'yes' if applied else 'no'}")
        if chk is not None:
            line += f"  tests={'ok' if chk['tests_ok'] else 'FAIL'}"
        print(line, flush=True)
        rows.append((secs, applied, out["source"]))
    n_ok = sum(1 for _, ok, src in rows if ok and src == "llm")
    print(f"total {sum(r[0] for r in rows):.1f}s  mean {sum(r[0] for r in rows) / len(rows):.1f}s/fix  "
          f"llm diffs applied {n_ok}/{len(rows)}")
    return 0 if n_ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
