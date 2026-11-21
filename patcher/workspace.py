"""Throw-away copies of `release_dir/victim` with a private git baseline.

The git directory lives NEXT TO the work tree (not inside it), so the model's
file tools never see `.git` and cannot tamper with the baseline.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

_SKIP_DIRS = {"__pycache__", ".pytest_cache", ".git"}


class Workspace:
    """tmp/work/victim  (copy)   tmp/git  (baseline repo)."""

    def __init__(self, release_dir: str, prefix: str = "patcher-"):
        self.release_dir = os.path.realpath(release_dir)
        src = os.path.join(self.release_dir, "victim")
        if not os.path.isdir(src):
            raise FileNotFoundError(f"{src} is not a directory")
        self.tmp = tempfile.mkdtemp(prefix=prefix)
        self.work = os.path.join(self.tmp, "work")
        self.gitdir = os.path.join(self.tmp, "git")
        os.makedirs(self.work)
        self.skipped: list[str] = []
        self._copy(src, os.path.join(self.work, "victim"))
        self.git("init", "-q", "--template=")
        self.git("add", "-A")
        self.git("commit", "-q", "--no-verify", "-m", "baseline")

    # -- copy: regular files and directories only; symlinks are never followed
    def _copy(self, src: str, dst: str) -> None:
        os.makedirs(dst)
        for entry in sorted(os.scandir(src), key=lambda e: e.name):
            s, d = entry.path, os.path.join(dst, entry.name)
            rel = os.path.relpath(s, self.release_dir)
            if entry.is_symlink():
                self.skipped.append(rel)
            elif entry.is_dir(follow_symlinks=False):
                if entry.name not in _SKIP_DIRS:
                    self._copy(s, d)
            elif entry.is_file(follow_symlinks=False):
                if not entry.name.endswith(".pyc"):
                    shutil.copy2(s, d, follow_symlinks=False)
            else:
                self.skipped.append(rel)

    def git(self, *args: str, check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
        cmd = ["git", "--git-dir", self.gitdir, "--work-tree", self.work,
               "-c", "user.name=patcher", "-c", "user.email=patcher@localhost",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
               "-c", "core.quotepath=off", *args]
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        return subprocess.run(cmd, cwd=self.work, check=check, capture_output=True, text=True, input=input, env=env)

    def diff(self) -> str:
        """Unified diff of the work tree against the baseline, new files included."""
        self.git("add", "-A")
        return self.git("diff", "--cached", "--no-color", "--no-ext-diff", "--no-renames", "--binary").stdout

    def apply(self, diff: str) -> tuple[bool, str]:
        """git apply `diff` to the work tree. Returns (ok, message)."""
        if not diff.strip():
            return False, "empty diff"
        r = self.git("apply", "--whitespace=nowarn", "-", check=False, input=diff)
        if r.returncode == 0:
            return True, ""
        r2 = self.git("apply", "--whitespace=nowarn", "--recount", "-C1", "-", check=False, input=diff)
        if r2.returncode == 0:
            return True, "applied with reduced context"
        return False, (r.stderr or r2.stderr).strip()

    def is_applied(self, diff: str) -> bool:
        return self.git("apply", "--reverse", "--check", "-", check=False, input=diff).returncode == 0

    def close(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
