"""Throw-away copies of a release (its `app.release_paths`) with a private git baseline.

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
    """tmp/work/<release paths>  (copy)   tmp/git  (baseline repo)."""

    def __init__(self, release_dir: str, prefix: str = "patcher-", paths: list[str] | None = None):
        self.release_dir = os.path.realpath(release_dir)
        if paths is None:
            from immune import config as icfg
            paths = icfg.current().app.release_paths
        self.paths = list(paths)
        missing = [p for p in self.paths if not os.path.lexists(os.path.join(self.release_dir, p))]
        if missing or not self.paths:
            raise FileNotFoundError(f"{self.release_dir} lacks {missing or 'release paths'}")
        self.tmp = tempfile.mkdtemp(prefix=prefix)
        self.work = os.path.join(self.tmp, "work")
        self.gitdir = os.path.join(self.tmp, "git")
        os.makedirs(self.work)
        self.skipped: list[str] = []
        for p in self.paths:
            src, dst = os.path.join(self.release_dir, p), os.path.join(self.work, p)
            if os.path.islink(src):
                self.skipped.append(p)
            elif os.path.isdir(src):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                self._copy(src, dst)
            elif os.path.isfile(src):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst, follow_symlinks=False)
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
               "-c", "core.quotepath=off",
               # The pipeline is LF-canonical; a host with core.autocrlf=true would
               # otherwise rewrite the work tree on checkout-like operations.
               "-c", "core.autocrlf=false", "-c", "core.eol=lf", *args]
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        if input is None:
            return subprocess.run(cmd, cwd=self.work, check=check, capture_output=True, text=True, env=env)
        # stdin in bytes: a text-mode pipe would translate LF to CRLF on Windows
        # and every LF patch would stop applying.
        raw = subprocess.run(cmd, cwd=self.work, check=check, capture_output=True,
                             input=input.encode("utf-8"), env=env)
        return subprocess.CompletedProcess(raw.args, raw.returncode,
                                           raw.stdout.decode("utf-8", "replace"),
                                           raw.stderr.decode("utf-8", "replace"))

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
