"""RepoTarget (docs/plan-construccion.md §9c): where fixes become pull requests.

  local     a git repo under the runtime dir (<runtime>/repo), no GitHub. PRs are JSON records
            in <repo>/.git/immune/prs/. Development and tests.
  scratch   } the `gh` CLI against env GITHUB_REPO (owner/name). The repo must contain the project's
  official  } app.release_paths at its root and the tag repo.t0_tag. Branch protection is not required.

Flow per incident: ensure_base() -> open_change() after the policy gate -> report() per gate ->
merge() when green (or abandon()) -> materialise(sha) -> comment() with timings -> revert() on rollback.
Branches: run/<run>/base (created from tag repo.t0_tag), run/<run>/fix-<incident>; label run-<run>.
What a release holds (and what is committed / extracted) is `app.release_paths` of .immune/config.yaml.
"""
from __future__ import annotations

import base64
import io
import json
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass, field

from . import diffs

log = logging.getLogger("pipeline.repo")


def _project():
    from immune import config as icfg
    return icfg.current()


def _paths(paths):
    return list(paths) if paths is not None else list(_project().app.release_paths)


def _tag(tag):
    return tag or _project().repo.t0_tag


class RepoError(Exception):
    pass


@dataclass
class Change:
    incident: str
    branch: str
    url: str
    number: int
    head: str = ""
    attempt: int = 0
    statuses: dict = field(default_factory=dict)

    def to_dict(self):
        return dict(self.__dict__)


def base_branch(run: str) -> str:
    return "run/%s/base" % run


def fix_branch(run: str, incident: str) -> str:
    return "run/%s/fix-%s" % (run, incident)


def safe_extract(tf: tarfile.TarFile, dest: str, strip: int = 0, prefix=None) -> int:
    """Extract regular files/dirs under the release paths (`prefix`: list or str, default app.release_paths)
    only; refuse links and escaping paths. -> files written."""
    prefixes = [prefix] if isinstance(prefix, str) else _paths(prefix)
    prefixes = [p.rstrip("/") + "/" for p in prefixes]
    n = 0
    for m in tf.getmembers():
        parts = m.name.split("/")[strip:]
        name = "/".join(p for p in parts if p not in ("", "."))
        if not name or not any((name + "/").startswith(p) for p in prefixes):
            continue
        if name.startswith("/") or ".." in name.split("/") or m.issym() or m.islnk() or m.isdev():
            raise RepoError("unsafe archive member %r" % m.name)
        target = os.path.join(dest, name)
        if m.isdir():
            os.makedirs(target, exist_ok=True)
            continue
        if not m.isfile():
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with tf.extractfile(m) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)
        n += 1
    return n


def _complete(dest: str, paths) -> bool:
    return bool(paths) and all(os.path.exists(os.path.join(dest, p)) for p in paths)


def _install(tmp: str, dest: str, paths=None) -> None:
    if _complete(dest, _paths(paths)):
        shutil.rmtree(tmp, ignore_errors=True)
        return
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.replace(tmp, dest)


# ====================================================================== local
class LocalRepo:
    kind = "local"

    def __init__(self, path: str, run: str, t0_release_dir: str, timeout: float = 60, paths=None, t0_tag=None):
        self.path, self.run, self.t0, self.timeout = path, run, t0_release_dir, timeout
        self.paths, self.t0_tag = _paths(paths), _tag(t0_tag)
        self.prs_dir = os.path.join(path, ".git", "immune", "prs")

    def git(self, *args, input=None, check=True) -> str:
        cmd = ["git", "-C", self.path, "-c", "user.name=immune-pipeline", "-c", "user.email=pipeline@immune.invalid",
               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args]
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
        p = subprocess.run(cmd, input=input, capture_output=True, timeout=self.timeout, env=env)
        if check and p.returncode != 0:
            raise RepoError("git %s: %s" % (" ".join(args[:3]), p.stderr.decode("utf-8", "replace").strip()[-500:]))
        return p.stdout.decode("utf-8", "replace").strip()

    def _has_ref(self, ref: str) -> bool:
        return subprocess.run(["git", "-C", self.path, "rev-parse", "--verify", "--quiet", ref],
                              capture_output=True, timeout=self.timeout).returncode == 0

    def ensure_base(self) -> str:
        if not os.path.isdir(os.path.join(self.path, ".git")):
            os.makedirs(self.path, exist_ok=True)
            self.git("init", "-q", "-b", "main")
            for p in self.paths:
                src, dst = os.path.join(self.t0, p), os.path.join(self.path, p)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
                elif os.path.isfile(src):
                    os.makedirs(os.path.dirname(dst) or self.path, exist_ok=True)
                    shutil.copy2(src, dst)
            with open(os.path.join(self.path, ".gitignore"), "w") as f:
                f.write("__pycache__/\n*.pyc\n.pytest_cache/\n")
            self.git("add", "-A")
            self.git("commit", "-q", "-m", "t0")
            self.git("tag", self.t0_tag)
        if not self._has_ref("refs/tags/" + self.t0_tag):
            raise RepoError("local repo has no tag %s" % self.t0_tag)
        base = base_branch(self.run)
        if not self._has_ref("refs/heads/" + base):
            self.git("branch", base, self.t0_tag)
        os.makedirs(self.prs_dir, exist_ok=True)
        return self.git("rev-parse", base)

    def _pr_path(self, number: int) -> str:
        return os.path.join(self.prs_dir, "%d.json" % number)

    def _save_pr(self, rec: dict) -> None:
        with open(self._pr_path(rec["number"]) + ".tmp", "w") as f:
            json.dump(rec, f, indent=1)
        os.replace(self._pr_path(rec["number"]) + ".tmp", self._pr_path(rec["number"]))

    def _load_pr(self, number: int) -> dict:
        with open(self._pr_path(number)) as f:
            return json.load(f)

    def _find_pr(self, branch: str):
        for fn in sorted(os.listdir(self.prs_dir)):
            if fn.endswith(".json"):
                rec = json.load(open(os.path.join(self.prs_dir, fn)))
                if rec["head"] == branch and rec["state"] == "open":
                    return rec
        return None

    def open_change(self, incident: str, attempt: int, diff: str, patched_dir: str, title: str, body: str) -> Change:
        base = base_branch(self.run)
        br = fix_branch(self.run, incident)
        wt = tempfile.mkdtemp(prefix="pipeline-wt-")
        try:
            self.git("worktree", "add", "-q", "-f", "--detach", wt, base)
            try:
                diffs.apply(diff, wt)
            except diffs.DiffError as e:
                raise RepoError("diff does not apply on %s: %s" % (base, e))
            g = LocalRepo(wt, self.run, self.t0, self.timeout, self.paths, self.t0_tag)
            g.git("add", "-A", "--", *self.paths)
            g.git("commit", "-q", "-m", "%s (attempt %d)\n\n%s" % (title, attempt, incident))
            head = g.git("rev-parse", "HEAD")
        finally:
            self.git("worktree", "remove", "--force", wt, check=False)
            shutil.rmtree(wt, ignore_errors=True)
        self.git("branch", "-f", br, head)
        rec = self._find_pr(br)
        if rec is None:
            number = len([f for f in os.listdir(self.prs_dir) if f.endswith(".json")]) + 1
            rec = {"number": number, "title": title, "body": body, "base": base, "head": br, "state": "open",
                   "label": "run-%s" % self.run, "commits": [], "statuses": {}, "comments": [], "created": time.time()}
        rec["commits"].append(head)
        rec["statuses"].setdefault(head, {})
        self._save_pr(rec)
        url = "file://%s#pr-%d" % (self._pr_path(rec["number"]), rec["number"])
        return Change(incident, br, url, rec["number"], head, attempt)

    def report(self, change: Change, gate: str, ok: bool, detail: str) -> None:
        rec = self._load_pr(change.number)
        rec["statuses"].setdefault(change.head, {})["immune/" + gate] = {
            "state": "success" if ok else "failure", "description": detail[:140], "detail": detail, "ts": time.time()}
        self._save_pr(rec)
        change.statuses[gate] = ok

    def merge(self, change: Change) -> str:
        base = base_branch(self.run)
        wt = tempfile.mkdtemp(prefix="pipeline-wt-")
        try:
            self.git("worktree", "add", "-q", "-f", wt, base)
            g = LocalRepo(wt, self.run, self.t0, self.timeout, self.paths, self.t0_tag)
            g.git("merge", "--no-ff", "-q", "-m", "Merge PR #%d from %s" % (change.number, change.branch), change.head)
            sha = g.git("rev-parse", "HEAD")
        finally:
            self.git("worktree", "remove", "--force", wt, check=False)
            shutil.rmtree(wt, ignore_errors=True)
        rec = self._load_pr(change.number)
        rec.update(state="merged", merge_sha=sha, merged=time.time())
        self._save_pr(rec)
        return sha

    def materialise(self, sha: str, dest: str) -> str:
        if _complete(dest, self.paths):
            return dest
        raw = subprocess.run(["git", "-C", self.path, "archive", "--format=tar", sha, "--", *self.paths],
                             capture_output=True, timeout=self.timeout)
        if raw.returncode != 0:
            raise RepoError("git archive failed: %s" % raw.stderr.decode()[-300:])
        tmp = tempfile.mkdtemp(prefix=".rel-", dir=os.path.dirname(dest) if os.path.isdir(os.path.dirname(dest)) else None)
        with tarfile.open(fileobj=io.BytesIO(raw.stdout)) as tf:
            safe_extract(tf, tmp, prefix=self.paths)
        _install(tmp, dest, self.paths)
        return dest

    def comment(self, change: Change, text: str) -> None:
        rec = self._load_pr(change.number)
        rec["comments"].append({"ts": time.time(), "body": text})
        self._save_pr(rec)

    def abandon(self, change: Change, reason: str) -> None:
        rec = self._load_pr(change.number)
        rec["comments"].append({"ts": time.time(), "body": reason})
        rec["state"] = "closed"
        self._save_pr(rec)

    def revert(self, change: Change, sha: str, reason: str) -> str:
        base = base_branch(self.run)
        wt = tempfile.mkdtemp(prefix="pipeline-wt-")
        try:
            self.git("worktree", "add", "-q", "-f", wt, base)
            g = LocalRepo(wt, self.run, self.t0, self.timeout, self.paths, self.t0_tag)
            g.git("revert", "--no-edit", "-m", "1", sha)
            new = g.git("rev-parse", "HEAD")
        finally:
            self.git("worktree", "remove", "--force", wt, check=False)
            shutil.rmtree(wt, ignore_errors=True)
        self.comment(change, "Reverted on %s: %s" % (base, reason))
        return new


# ====================================================================== GitHub (gh CLI)
class GhError(RepoError):
    pass


def run_gh(args: list, input: bytes | None = None, timeout: float = 60) -> bytes:
    """Run `gh` with a timeout; returns stdout bytes, raises GhError. Replaced in tests."""
    try:
        p = subprocess.run(["gh", *args], input=input, capture_output=True, timeout=timeout,
                           env=dict(os.environ, GH_PROMPT_DISABLED="1", NO_COLOR="1"))
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GhError("gh %s: %s" % (" ".join(args[:3]), e))
    if p.returncode != 0:
        raise GhError("gh %s: %s" % (" ".join(args[:3]), p.stderr.decode("utf-8", "replace").strip()[-400:]))
    return p.stdout


class GitHubRepo:
    """scratch/official targets. All git objects are created through the REST API (`gh api`), no clone."""

    def __init__(self, repo: str, run: str, kind: str = "scratch", gh=run_gh, timeout: float = 60, paths=None,
                 t0_tag=None):
        if not repo or "/" not in repo:
            raise RepoError("GITHUB_REPO must be owner/name (got %r)" % repo)
        self.repo, self.run, self.kind, self.gh, self.timeout = repo, run, kind, gh, timeout
        self.paths, self.t0_tag = _paths(paths), _tag(t0_tag)

    def api(self, path: str, method: str = "GET", body: dict | None = None) -> dict:
        args = ["api", "-X", method, "repos/%s/%s" % (self.repo, path.lstrip("/")), "-H", "Accept: application/vnd.github+json"]
        data = None
        if body is not None:
            args += ["--input", "-"]
            data = json.dumps(body).encode()
        out = self.gh(args, input=data, timeout=self.timeout)
        return json.loads(out.decode() or "{}") if out.strip() else {}

    def _ref_sha(self, ref: str) -> str | None:
        try:
            r = self.api("git/ref/" + ref)
        except GhError as e:
            if "404" in str(e) or "Not Found" in str(e):
                return None
            raise
        obj = r.get("object") or {}
        if obj.get("type") == "tag":   # annotated tag -> commit
            obj = (self.api("git/tags/" + obj["sha"]).get("object") or {})
        return obj.get("sha")

    def ensure_base(self) -> str:
        base = base_branch(self.run)
        sha = self._ref_sha("heads/" + base)
        if sha:
            return sha
        t0 = self._ref_sha("tags/" + self.t0_tag)
        if not t0:
            raise RepoError("%s has no tag %s" % (self.repo, self.t0_tag))
        self.api("git/refs", "POST", {"ref": "refs/heads/" + base, "sha": t0})
        try:
            self.gh(["label", "create", "run-%s" % self.run, "--repo", self.repo, "--force",
                     "--description", "immune pipeline run %s" % self.run], timeout=self.timeout)
        except GhError as e:
            log.warning("label: %s", e)
        return t0

    def open_change(self, incident: str, attempt: int, diff: str, patched_dir: str, title: str, body: str) -> Change:
        base = base_branch(self.run)
        br = fix_branch(self.run, incident)
        base_sha = self._ref_sha("heads/" + base)
        if not base_sha:
            raise RepoError("base branch %s missing" % base)
        base_tree = self.api("git/commits/" + base_sha)["tree"]["sha"]
        entries = []
        for ch in diffs.parse(diff):
            p = ch.new
            with open(os.path.join(patched_dir, p), "rb") as f:
                content = f.read()
            blob = self.api("git/blobs", "POST", {"content": base64.b64encode(content).decode(), "encoding": "base64"})
            entries.append({"path": p, "mode": "100644", "type": "blob", "sha": blob["sha"]})
        tree = self.api("git/trees", "POST", {"base_tree": base_tree, "tree": entries})
        commit = self.api("git/commits", "POST", {"message": "%s (attempt %d)\n\n%s" % (title, attempt, incident),
                                                  "tree": tree["sha"], "parents": [base_sha]})
        head = commit["sha"]
        if self._ref_sha("heads/" + br):
            self.api("git/refs/heads/" + br, "PATCH", {"sha": head, "force": True})
        else:
            self.api("git/refs", "POST", {"ref": "refs/heads/" + br, "sha": head})
        prs = json.loads(self.gh(["pr", "list", "--repo", self.repo, "--head", br, "--state", "open",
                                  "--json", "number,url"], timeout=self.timeout).decode() or "[]")
        if prs:
            number, url = prs[0]["number"], prs[0]["url"]
        else:
            out = self.gh(["pr", "create", "--repo", self.repo, "--base", base, "--head", br, "--title", title,
                           "--body-file", "-", "--label", "run-%s" % self.run], input=body.encode(),
                          timeout=self.timeout).decode().strip()
            url = out.splitlines()[-1].strip()
            number = int(url.rstrip("/").rsplit("/", 1)[-1])
        return Change(incident, br, url, number, head, attempt)

    def report(self, change: Change, gate: str, ok: bool, detail: str) -> None:
        self.api("statuses/" + change.head, "POST", {"state": "success" if ok else "failure",
                                                    "context": "immune/" + gate, "description": detail[:139]})
        change.statuses[gate] = ok

    def merge(self, change: Change) -> str:
        self.gh(["pr", "merge", str(change.number), "--repo", self.repo, "--merge", "--match-head-commit", change.head],
                timeout=self.timeout)
        info = json.loads(self.gh(["pr", "view", str(change.number), "--repo", self.repo, "--json", "mergeCommit,state"],
                                  timeout=self.timeout).decode())
        sha = (info.get("mergeCommit") or {}).get("oid")
        if not sha:
            raise RepoError("PR #%d merged but no merge commit reported (%s)" % (change.number, info.get("state")))
        return sha

    def materialise(self, sha: str, dest: str) -> str:
        if _complete(dest, self.paths):
            return dest
        raw = self.gh(["api", "repos/%s/tarball/%s" % (self.repo, sha)], timeout=max(self.timeout, 120))
        tmp = tempfile.mkdtemp(prefix=".rel-", dir=os.path.dirname(dest) if os.path.isdir(os.path.dirname(dest)) else None)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
            if not safe_extract(tf, tmp, strip=1, prefix=self.paths):
                raise RepoError("tarball of %s has none of %s" % (sha, ", ".join(self.paths)))
        _install(tmp, dest, self.paths)
        return dest

    def comment(self, change: Change, text: str) -> None:
        self.gh(["pr", "comment", str(change.number), "--repo", self.repo, "--body-file", "-"], input=text.encode(),
                timeout=self.timeout)

    def abandon(self, change: Change, reason: str) -> None:
        self.gh(["pr", "close", str(change.number), "--repo", self.repo, "--comment", reason[:6000]], timeout=self.timeout)

    def revert(self, change: Change, sha: str, reason: str) -> str:
        base = base_branch(self.run)
        merge = self.api("git/commits/" + sha)
        parent = merge["parents"][0]["sha"]
        tree = self.api("git/commits/" + parent)["tree"]["sha"]
        head = self._ref_sha("heads/" + base)
        c = self.api("git/commits", "POST", {"message": "Revert %s: %s" % (sha[:12], reason[:200]), "tree": tree,
                                             "parents": [head]})
        self.api("git/refs/heads/" + base, "PATCH", {"sha": c["sha"], "force": False})
        self.comment(change, "Reverted on `%s`: %s" % (base, reason))
        return c["sha"]


def make_target(cfg, gh=run_gh):
    kind = cfg.repo_target
    app = cfg.project
    if kind == "local":
        return LocalRepo(os.environ.get("REPO_TARGET_DIR") or os.path.join(cfg.runtime_dir, "repo"), cfg.run_id,
                         cfg.release_dir("t0"), paths=app.app.release_paths, t0_tag=app.repo.t0_tag)
    if kind in ("scratch", "official"):
        return GitHubRepo(cfg.github_repo, cfg.run_id, kind, gh=gh, paths=app.app.release_paths, t0_tag=app.repo.t0_tag)
    raise RepoError("REPO_TARGET must be local|scratch|official (got %r)" % kind)
