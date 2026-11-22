"""Local checks of a proposed diff (used by patcher's own tests and the bench; the
authoritative gates live in pipeline/). Runs on throw-away copies only."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def touched_paths(diff: str) -> list[str]:
    out = []
    for m in re.finditer(r"^diff --git a/(\S+) b/(\S+)$", diff, flags=re.M):
        for p in m.groups():
            if p not in out:
                out.append(p)
    return out


def patched_copy(release_dir: str, diffs: list[str]) -> tuple[str, list[str]]:
    """Copy release_dir/victim + immune_contracts to a temp root and git-apply the diffs.
    -> (root, errors). Caller removes root."""
    root = tempfile.mkdtemp(prefix="patcher-check-")
    shutil.copytree(os.path.join(release_dir, "victim"), os.path.join(root, "victim"), symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(os.path.join(REPO, "immune_contracts"), os.path.join(root, "immune_contracts"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    with open(os.path.join(root, "pytest.ini"), "w") as f:
        f.write("[pytest]\n")
    errors = []
    for d in diffs:
        r = subprocess.run(["git", "apply", "--whitespace=nowarn", "-"], cwd=root,
                           input=d.encode("utf-8"),  # bytes: a text pipe would CRLF-ify on Windows
                           capture_output=True)
        if r.returncode != 0:
            errors.append(r.stderr.strip())
    return root, errors


def run_victim_tests(root: str, timeout: float = 300) -> tuple[bool, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "APP_DB", "APP_STATIC", "APP_SECRET")}
    env["PYTHONPATH"] = root
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "victim/tests"],
                       cwd=root, env=env, capture_output=True, text=True, timeout=timeout)
    lines = [l for l in r.stdout.strip().splitlines() if l.strip()]
    return r.returncode == 0, (lines[-1] if lines else r.stderr[-300:])


def replay(root: str, requests: list[dict], timeout: float = 300) -> list[dict]:
    """Send requests through shadow.harness running the `victim` in `root`."""
    import json
    work = tempfile.mkdtemp(prefix="patcher-probe-")
    try:
        env = {k: v for k, v in os.environ.items() if k not in ("APP_DB", "APP_STATIC", "APP_SECRET", "MARKERS_PATH")}
        env["PYTHONPATH"] = root + os.pathsep + REPO
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        r = subprocess.run([sys.executable, "-m", "patcher._harness_probe", work], cwd=root, env=env,
                           input=json.dumps({"requests": requests}), capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            raise RuntimeError(r.stderr[-2000:])
        return json.loads(r.stdout)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def check_diff(release_dir: str, diff: str) -> dict:
    """{"applies", "only_app", "tests_ok", "tests_line", "paths", "error"}"""
    paths = touched_paths(diff)
    res = {"paths": paths, "applies": False, "only_app": bool(paths) and all(p.startswith("victim/app/") for p in paths),
           "tests_ok": False, "tests_line": "", "error": ""}
    if not diff.strip():
        res["error"] = "empty diff"
        return res
    root, errors = patched_copy(release_dir, [diff])
    try:
        if errors:
            res["error"] = errors[0][:500]
            return res
        res["applies"] = True
        res["tests_ok"], res["tests_line"] = run_victim_tests(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return res
