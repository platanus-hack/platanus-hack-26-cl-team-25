"""RepoTarget: local git repo (real git) and the GitHub target against a mocked `gh` (never calls GitHub)."""
import base64
import hashlib
import io
import json
import os
import tarfile

import pytest

from pipeline import diffs, fixes, repo
from pipeline.config import Config


def _patched(t0, d):
    w = diffs.copy_release(t0, os.path.dirname(t0))
    diffs.apply(d, w)
    return w


def test_local_repo_flow(tmp_path, t0):
    r = repo.LocalRepo(str(tmp_path / "repo"), "r1", t0)
    r.ensure_base()
    r.ensure_base()                                   # idempotent
    d = fixes.build_diff(t0, fixes.TRAV_GOOD)
    ch = r.open_change("inc-1", 1, d, _patched(t0, d), "fix(traversal)", "body")
    assert ch.branch == "run/r1/fix-inc-1" and ch.number == 1
    for g in ("policy", "properties"):
        r.report(ch, g, True, g + " ok")
    sha = r.merge(ch)
    dest = r.materialise(sha, str(tmp_path / "releases" / sha[:12]))
    assert "commonpath" in open(os.path.join(dest, "victim/app/files.py")).read()
    pr = json.load(open(os.path.join(r.prs_dir, "1.json")))
    assert pr["state"] == "merged" and set(pr["statuses"][ch.head]) == {"immune/policy", "immune/properties"}
    assert r.git("rev-parse", "run/r1/base") == sha
    assert r.git("rev-parse", "victim-t0") != sha
    new = r.revert(ch, sha, "rolled back")
    assert "commonpath" not in r.git("show", "%s:victim/app/files.py" % new)


class FakeGh:
    """Just enough of the GitHub REST API + `gh pr` for GitHubRepo."""

    def __init__(self, t0):
        self.calls, self.objects, self.refs, self.prs, self.statuses, self.comments = [], {}, {}, {}, {}, []
        files = {}
        for d, _ds, fs in os.walk(os.path.join(t0, "victim")):
            for f in fs:
                if "__pycache__" in d:
                    continue
                p = os.path.relpath(os.path.join(d, f), t0)
                files[p] = open(os.path.join(d, f), "rb").read()
        tree = self._tree(files)
        self.refs["tags/victim-t0"] = self._commit(tree, [], "t0")

    def _put(self, obj):
        sha = hashlib.sha1(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()
        self.objects[sha] = obj
        return sha

    def _tree(self, files):
        return self._put({"type": "tree", "files": files})

    def _commit(self, tree, parents, msg):
        return self._put({"type": "commit", "tree": tree, "parents": parents, "message": msg})

    def files_at(self, sha):
        return self.objects[self.objects[sha]["tree"]]["files"]

    def __call__(self, args, input=None, timeout=60):
        self.calls.append(args)
        if args[0] == "api" and args[1] == "-X":
            method, path = args[2], args[3].split("/", 3)[3]
            body = json.loads(input) if input else None
            return json.dumps(self.api(method, path, body)).encode()
        if args[0] == "api" and "/tarball/" in args[1]:
            sha = args[1].rsplit("/", 1)[1]
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                for p, content in self.files_at(sha).items():
                    ti = tarfile.TarInfo("owner-repo-%s/%s" % (sha[:7], p))
                    ti.size = len(content)
                    tf.addfile(ti, io.BytesIO(content))
            return buf.getvalue()
        if args[:2] == ["label", "create"]:
            return b""
        if args[:2] == ["pr", "list"]:
            head = args[args.index("--head") + 1]
            return json.dumps([{"number": n, "url": pr["url"]} for n, pr in self.prs.items()
                               if pr["head"] == head and pr["state"] == "open"]).encode()
        if args[:2] == ["pr", "create"]:
            n = len(self.prs) + 1
            self.prs[n] = {"head": args[args.index("--head") + 1], "base": args[args.index("--base") + 1],
                           "title": args[args.index("--title") + 1], "body": input.decode(), "state": "open",
                           "url": "https://github.com/o/r/pull/%d" % n, "labels": [args[args.index("--label") + 1]]}
            return ("Creating pull request\n%s\n" % self.prs[n]["url"]).encode()
        if args[:2] == ["pr", "merge"]:
            pr = self.prs[int(args[2])]
            head = self.refs["heads/" + pr["head"]]
            assert args[args.index("--match-head-commit") + 1] == head
            base = self.refs["heads/" + pr["base"]]
            m = self._commit(self.objects[head]["tree"], [base, head], "merge")
            self.refs["heads/" + pr["base"]] = m
            pr.update(state="MERGED", merge=m)
            return b""
        if args[:2] == ["pr", "view"]:
            pr = self.prs[int(args[2])]
            return json.dumps({"state": pr["state"], "mergeCommit": {"oid": pr.get("merge")}}).encode()
        if args[:2] == ["pr", "comment"]:
            self.comments.append((int(args[2]), input.decode()))
            return b""
        if args[:2] == ["pr", "close"]:
            self.prs[int(args[2])]["state"] = "closed"
            return b""
        raise AssertionError("unexpected gh call %r" % args)

    def api(self, method, path, body):
        if method == "GET" and path.startswith("git/ref/"):
            ref = path[len("git/ref/"):]
            if ref not in self.refs:
                raise repo.GhError("gh api: HTTP 404: Not Found")
            return {"object": {"type": "commit", "sha": self.refs[ref]}}
        if method == "POST" and path == "git/refs":
            self.refs[body["ref"][5:]] = body["sha"]
            return {}
        if method == "PATCH" and path.startswith("git/refs/"):
            self.refs[path[len("git/refs/"):]] = body["sha"]
            return {}
        if method == "GET" and path.startswith("git/commits/"):
            c = self.objects[path.rsplit("/", 1)[1]]
            return {"tree": {"sha": c["tree"]}, "parents": [{"sha": p} for p in c["parents"]]}
        if method == "POST" and path == "git/blobs":
            return {"sha": self._put({"type": "blob", "content": base64.b64decode(body["content"])})}
        if method == "POST" and path == "git/trees":
            files = dict(self.objects[body["base_tree"]]["files"])
            for e in body["tree"]:
                files[e["path"]] = self.objects[e["sha"]]["content"]
            return {"sha": self._tree(files)}
        if method == "POST" and path == "git/commits":
            return {"sha": self._commit(body["tree"], body["parents"], body["message"])}
        if method == "POST" and path.startswith("statuses/"):
            self.statuses.setdefault(path.split("/", 1)[1], []).append(body)
            return {}
        raise AssertionError("unexpected api %s %s" % (method, path))


def test_github_target_with_mocked_gh(tmp_path, t0, monkeypatch):
    gh = FakeGh(t0)
    monkeypatch.setenv("REPO_TARGET", "scratch")
    monkeypatch.setenv("GITHUB_REPO", "o/r")
    monkeypatch.setenv("RUN_ID", "r7")
    cfg = Config.from_env()
    r = repo.make_target(cfg, gh=gh)
    assert isinstance(r, repo.GitHubRepo) and r.kind == "scratch"
    base = r.ensure_base()
    assert gh.refs["heads/run/r7/base"] == gh.refs["tags/victim-t0"] == base
    d = fixes.build_diff(t0, fixes.SQLI_GOOD)
    body = "evidence: ````\nGET /api/products?q=' OR 1=1\n````"
    ch = r.open_change("inc-0001", 1, d, _patched(t0, d), "fix(sqli): GET /api/products", body)
    assert ch.url == "https://github.com/o/r/pull/1" and ch.branch == "run/r7/fix-inc-0001"
    pr = gh.prs[1]
    assert pr["base"] == "run/r7/base" and pr["labels"] == ["run-r7"] and "OR 1=1" in pr["body"]
    assert b"LIKE ? OR category" in gh.files_at(gh.refs["heads/run/r7/fix-inc-0001"])["victim/app/products.py"]
    for g in ("policy", "properties", "poc", "tests", "legit"):
        r.report(ch, g, True, "%s ok" % g)
    assert [s["context"] for s in gh.statuses[ch.head]] == ["immune/policy", "immune/properties", "immune/poc",
                                                           "immune/tests", "immune/legit"]
    # a second attempt force-updates the same branch and reuses the PR
    ch2 = r.open_change("inc-0001", 2, d, _patched(t0, d), "fix(sqli): GET /api/products", body)
    assert ch2.number == 1 and len(gh.prs) == 1
    sha = r.merge(ch2)
    assert gh.refs["heads/run/r7/base"] == sha
    dest = r.materialise(sha, str(tmp_path / "releases" / sha[:12]))
    assert "LIKE ? OR category" in open(os.path.join(dest, "victim/app/products.py")).read()
    r.comment(ch2, "| step | seconds |")
    assert gh.comments == [(1, "| step | seconds |")]
    r.revert(ch2, sha, "rolled back")
    assert b"LIKE ? OR category" not in gh.files_at(gh.refs["heads/run/r7/base"])["victim/app/products.py"]
    assert all(c[0] in ("api", "label", "pr") for c in gh.calls)


def test_github_requires_repo_and_tag(t0):
    with pytest.raises(repo.RepoError):
        repo.GitHubRepo("", "r", gh=lambda *a, **k: b"")
    gh = FakeGh(t0)
    gh.refs.clear()
    with pytest.raises(repo.RepoError):
        repo.GitHubRepo("o/r", "r", gh=gh).ensure_base()


def test_safe_extract_refuses_links(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("x/victim/evil")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/passwd"
        tf.addfile(ti)
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tf, pytest.raises(repo.RepoError):
        repo.safe_extract(tf, str(tmp_path), strip=1)


def test_orchestrator_falls_back_to_local_when_github_fails(tmp_path, t0):
    from pipeline.orchestrator import Pipeline

    class Broken(repo.GitHubRepo):
        def open_change(self, *a, **k):
            raise repo.GhError("gh: HTTP 502")
    p = Pipeline.__new__(Pipeline)
    p.repo = Broken("o/r", "r", gh=lambda *a, **k: b"")
    p.local_fallback = lambda: repo.LocalRepo(str(tmp_path / "repo"), "r", t0)
    p.bus = type("B", (), {"publish": lambda *a, **k: None})()
    inc = {"incident": "inc-1", "vuln_class": "sqli", "method": "GET", "route": "/api/products",
           "param": {"in": "query", "name": "q"}, "sink": {"file": "f", "line": 1}, "evidence": {"request": {}, "events": []},
           "evidence_rid": "x", "log": []}
    p._pr_body = lambda inc: "body"
    d = fixes.build_diff(t0, fixes.SQLI_GOOD)
    ch = p._open_change(inc, 1, d, _patched(t0, d), None)
    assert ch.url.startswith("file://") and isinstance(p.repo, repo.LocalRepo)
