"""Unified diffs: parse the file list, apply to a temp copy of a release."""
from __future__ import annotations

import difflib
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field


class DiffError(Exception):
    pass


@dataclass
class FileChange:
    old: str | None          # path relative to the release dir, None for /dev/null
    new: str | None
    added: int = 0
    removed: int = 0
    flags: list = field(default_factory=list)   # binary, mode, rename, ...

    @property
    def path(self) -> str:
        return self.new or self.old or ""


def _strip(p: str, level: int) -> str | None:
    p = p.split("\t")[0].strip()
    if p == "/dev/null":
        return None
    if p.startswith('"') and p.endswith('"'):
        p = p[1:-1]
    parts = p.split("/")
    return "/".join(parts[level:]) if level else p


def strip_level(diff: str) -> int:
    olds = re.findall(r"^--- (\S+)", diff, re.M)
    news = re.findall(r"^\+\+\+ (\S+)", diff, re.M)
    paths = [p for p in olds + news if p != "/dev/null"]
    if paths and all(p.startswith(("a/", "b/")) for p in paths):
        return 1
    return 0


def parse(diff: str) -> list:
    if not isinstance(diff, str) or not diff.strip():
        raise DiffError("empty diff")
    level = strip_level(diff)
    files: list = []
    cur = None
    pending = []
    lines = diff.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        i += 1
        if line.startswith("diff --git "):
            if pending:
                files.append(FileChange(None, None, flags=pending))
            pending, cur = [], None
            continue
        if cur is None and line.startswith(("old mode", "new mode", "deleted file mode", "new file mode",
                                            "similarity index", "rename from", "rename to", "copy from", "copy to")):
            pending.append("-".join(line.split(" ")[:2]))
            continue
        if line.startswith("Binary files") or line.startswith("GIT binary patch"):
            files.append(FileChange(None, None, flags=pending + ["binary"]))
            pending, cur = [], None
            continue
        if line.startswith("--- ") and nxt.startswith("+++ "):
            cur = FileChange(_strip(line[4:], level), _strip(nxt[4:], level), flags=pending)
            pending = []
            files.append(cur)
            i += 1
            continue
        if cur is not None:
            if line.startswith("+"):
                cur.added += 1
            elif line.startswith("-"):
                cur.removed += 1
    if pending:
        files.append(FileChange(None, None, flags=pending))
    if not files:
        raise DiffError("no file headers (---/+++) found")
    return files


def copy_release(release_dir: str, dest_parent: str | None = None) -> str:
    """Copy <release>/victim into a fresh temp dir; returns the new release dir."""
    work = tempfile.mkdtemp(prefix="pipeline-rel-", dir=dest_parent)
    shutil.copytree(os.path.join(release_dir, "victim"), os.path.join(work, "victim"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"), symlinks=True)
    return work


def _digest(release_dir: str, paths: list) -> dict:
    out = {}
    for p in paths:
        try:
            with open(os.path.join(release_dir, p), "rb") as f:
                out[p] = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            out[p] = None
    return out


def apply(diff: str, release_dir: str, timeout: float = 30) -> None:
    """Apply in place with `git apply`. Raises DiffError.

    git must never discover an enclosing repository (a release copy may live inside the project tree):
    with `diff --git` patches it would resolve paths against that repo's root and silently skip them.
    So GIT_CEILING_DIRECTORIES/GIT_DIR isolate it, and afterwards every file named by the diff must
    actually have changed. Hunk counts are trusted first; `--recount` is the fallback."""
    level = strip_level(diff)
    if not diff.endswith("\n"):
        diff += "\n"
    release_dir = os.path.realpath(release_dir)
    targets = sorted({c.path for c in parse(diff) if c.path})
    before = _digest(release_dir, targets)
    env = dict(os.environ, GIT_CEILING_DIRECTORIES=os.path.dirname(release_dir),
               GIT_DIR=os.path.join(release_dir, ".no-such-git-dir"), GIT_CONFIG_NOSYSTEM="1")
    env.pop("GIT_WORK_TREE", None)
    err = ""
    for extra in ([], ["--recount"]):
        args = ["git", "apply", "-p%d" % level, "--whitespace=nowarn"] + extra
        chk = subprocess.run(args + ["--check", "-"], input=diff.encode(), cwd=release_dir, capture_output=True,
                             timeout=timeout, env=env)
        if chk.returncode != 0:
            err = err or chk.stderr.decode("utf-8", "replace").strip()[-600:]
            continue
        p = subprocess.run(args + ["-"], input=diff.encode(), cwd=release_dir, capture_output=True, timeout=timeout,
                           env=env)
        if p.returncode != 0:
            raise DiffError("diff does not apply: " + p.stderr.decode("utf-8", "replace").strip()[-600:])
        after = _digest(release_dir, targets)
        same = [t for t in targets if before[t] == after[t]]
        if same:
            raise DiffError("diff applied without changing %s" % ", ".join(same))
        return
    raise DiffError("diff does not apply: " + err)


def make(release_dir: str, edits: dict) -> str:
    """Unified diff (a/ b/ prefixes) from {relpath: new_text} against release_dir."""
    out = []
    for rel in sorted(edits):
        try:
            with open(os.path.join(release_dir, rel)) as f:
                old = f.read()
        except FileNotFoundError:
            old = None
        new = edits[rel]
        a = old.splitlines(keepends=True) if old is not None else []
        b = new.splitlines(keepends=True) if new is not None else []
        out += difflib.unified_diff(a, b, "a/" + rel if old is not None else "/dev/null",
                                    "b/" + rel if new is not None else "/dev/null")
    text = "".join(l if l.endswith("\n") else l + "\n\\ No newline at end of file\n" for l in out)
    return text
