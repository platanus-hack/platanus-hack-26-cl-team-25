"""Judge for `app.runtime: generic` (any language): the gates' runner interface backed by ephemeral clone triples.

The in-process harness cannot run a Node/Go/... app, so every runner job of `pipeline.gates.Validator`
(`harness`, `plain`, `replay`, `pytest`) runs against a throw-away triple on its own `--internal` network:

  <prefix>-judge-<pid>-<n>-db    postgres:16-alpine loaded from the shadow dump (template `seed`)
  <prefix>-judge-<pid>-<n>       the t0 app image with the release under test mounted read-only at
                                 app.workdir (source overlay: interpreted languages only, see README)
  <prefix>-judge-<pid>-<n>-obs   the observer (immune-sidecar:1, SIDECAR_JUDGE=1), --cap-add SYS_PTRACE only

Requests go from the host to the observer (host -> container IP on the internal network; nothing in
the triple can reach anything else). Each response carries `x-imm-trace` (judge mode only): the oracle
events, executed statements with their bound parameters, successful file opens, marker owners. Job
results have the same shape as `pipeline/runner_entry.py`, so `gates.py`, `properties.py` and
`verify.py` work unchanged. `tests` runs `tests.command` in the app image with DATABASE_URL pointing
at a fresh copy of the seed (database `tests`).

`GenericPolicy` replaces the Python-AST policy gate for non-Python sources (see `check_generic`).
"""
from __future__ import annotations

import base64
import hashlib
import itertools
import json
import logging
import math
import os
import re
import secrets
import subprocess
import threading
import time

import httpx

from immune_contracts import wire

from . import diffs, policy
from .gates import Validator
from .runner import RunnerError

log = logging.getLogger("pipeline.generic")
SIDECAR_IMAGE = "immune-sidecar:1"
PG_IMAGE = "postgres:16-alpine"


def _docker(*args, check=True, timeout=120):
    p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RunnerError("docker %s: %s" % (" ".join(args[:2]), (p.stderr or p.stdout).strip()[-600:]))
    return p


def _ip(name: str, net: str) -> str:
    return _docker("inspect", "-f", '{{(index .NetworkSettings.Networks "%s").IPAddress}}' % net, name).stdout.strip()


class Triple:
    """One ephemeral app + Postgres + observer for one release directory."""

    def __init__(self, runner: "JudgeRunner", release_dir: str):
        self.r = runner
        self.release_dir = os.path.realpath(release_dir)
        self.base = "%s-%d-%d" % (runner.prefix, os.getpid(), next(runner.seq))
        self.net, self.db, self.app, self.obs = self.base + "-net", self.base + "-db", self.base, self.base + "-obs"
        self.su_pw, self.app_pw = secrets.token_hex(10), secrets.token_hex(10)
        self.url = None
        self.timing = {}

    def labels(self):
        return ["--label", "immune.project=%s" % self.r.project.name, "--label", "immune.component=judge"]

    def common(self):
        return ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256"]

    def up(self):
        from fleet.generic import sidecar_config
        f, proj = self.r.facts, self.r.project
        t0 = time.time()
        # a patched copy lives in a mkdtemp (0700) dir; the app runs as its image's (unprivileged) user
        st = os.stat(self.release_dir)
        if not st.st_mode & 0o005:
            os.chmod(self.release_dir, (st.st_mode | 0o055) & 0o7777)
        _docker("network", "create", "--internal", *self.labels(), self.net)
        pginit = os.path.join(proj.shadow_dir, "pginit")
        _docker("run", "-d", "--name", self.db, "--network", self.net, *self.labels(), *self.common(),
                "--user", "70:70", "--memory", "256m",
                "--tmpfs", "/var/lib/postgresql/data:rw,uid=70,gid=70,mode=0700",
                "--tmpfs", "/var/run/postgresql:rw,uid=70,gid=70", "--tmpfs", "/tmp:rw,mode=1777",
                "-v", "%s:/docker-entrypoint-initdb.d:ro" % pginit,
                "-e", "POSTGRES_PASSWORD=" + self.su_pw, "-e", "APP_DB_PASSWORD=" + self.app_pw,
                PG_IMAGE, "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off")
        from fleet.generic import pg_ready
        if not pg_ready(self.db):
            raise RunnerError("judge database did not start: %s" % _docker("logs", self.db, check=False).stderr[-400:])
        self.timing["db_s"] = round(time.time() - t0, 2)
        env = self.r.app_env("postgres://app:%s@127.0.0.1:5432/clone" % self.app_pw, "127.0.0.1")
        args = []
        for k, v in env.items():
            args += ["-e", "%s=%s" % (k, v)]
        _docker("run", "-d", "--name", self.app, "--network", self.net, *self.labels(), *self.common(),
                "--memory", "384m", "--tmpfs", "/tmp:rw,mode=1777", "-v", "%s:%s:ro" % (self.release_dir, f.workdir),
                *args, self.r.image, *f.command)
        cdir = os.path.join(proj.runtime_dir, "pipeline", "judge")
        os.makedirs(cdir, exist_ok=True)
        cpath = os.path.join(cdir, self.base + ".json")
        prof = "/profile/" + f.profile_file() if f.profile_module else None
        with open(cpath, "w") as fh:
            json.dump(sidecar_config(f, self.db, self.su_pw, prof), fh)
        os.chmod(cpath, 0o644)
        self.cpath = cpath
        mounts = ["-v", "%s:/opt/immune:ro" % self.r.home, "-v", "%s:/cfg/sidecar.json:ro" % cpath,
                  "-v", "%s:/markers/markers.json:ro" % proj.markers_path]
        for d in (os.path.join(self.r.home, "runtime"), os.path.join(self.r.home, ".git")):
            if os.path.isdir(d):
                mounts += ["--mount", "type=tmpfs,destination=/opt/immune/%s" % os.path.relpath(d, self.r.home)]
        if prof:
            mounts += ["-v", "%s:/profile:ro" % proj.dot_immune]
            rt = os.path.realpath(proj.runtime_dir)
            dot = os.path.realpath(proj.dot_immune)
            if rt.startswith(dot + os.sep):
                mounts += ["--mount", "type=tmpfs,destination=/profile/%s" % os.path.relpath(rt, dot)]
        _docker("run", "-d", "--name", self.obs, "--network", "container:" + self.app, "--pid", "container:" + self.app,
                *self.labels(), *self.common(), "--cap-add", "SYS_PTRACE", "--memory", "256m",
                "--tmpfs", "/tmp:rw,mode=1777", *mounts, "-e", "PYTHONPATH=/opt/immune", "-e", "PYTHONDONTWRITEBYTECODE=1",
                "-e", "SIDECAR_JUDGE=1", "-e", "CLONE_ID=judge", "-e", "RELEASE=" + os.path.basename(self.release_dir),
                "-e", "MARKERS_PATH=/markers/markers.json",
                SIDECAR_IMAGE, "python", "-m", "sidecar", "--config", "/cfg/sidecar.json")
        ip = _ip(self.app, self.net)
        self.url = "http://%s:8000" % ip
        end = time.time() + 90
        while time.time() < end:
            if _docker("inspect", "-f", "{{.State.Running}}", self.obs, check=False).stdout.strip() != "true":
                raise RunnerError("judge observer exited: %s" % _docker("logs", "--tail", "15", self.obs,
                                                                         check=False).stderr[-900:])
            try:
                if httpx.get(self.url + f.health, timeout=2).status_code < 500:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        else:
            raise RunnerError("judge observer not ready after 90s")
        self.timing["up_s"] = round(time.time() - t0, 2)
        return self

    def down(self):
        _docker("rm", "-f", self.obs, self.app, self.db, check=False, timeout=60)
        _docker("network", "rm", self.net, check=False, timeout=60)
        try:
            os.remove(self.cpath)
        except (OSError, AttributeError):
            pass

    def __enter__(self):
        try:
            return self.up()
        except Exception:
            self.down()
            raise

    def __exit__(self, *exc):
        self.down()

    # ------------------------------------------------------------ one request
    def send(self, rq: dict, mode: str = "L1") -> dict:
        target = rq.get("path") or "/"
        if rq.get("query"):
            target += "?" + rq["query"]
        hdrs = [(k, v) for k, v in (rq.get("headers") or {}).items()
                if k.lower() not in ("host", "content-length", "connection", "transfer-encoding")
                and not k.lower().startswith(wire.INTERNAL_PREFIX)]
        hdrs += [(wire.H_MODE, mode), (wire.H_RID, "judge-" + secrets.token_hex(4))]
        if rq.get("uid") is not None:
            hdrs += [(wire.H_UID, str(int(rq["uid"]))), (wire.H_ROLE, rq.get("role") or "user")]
        body = b""
        if rq.get("body_b64"):
            body = base64.b64decode(rq["body_b64"])
        url = httpx.URL(self.url + "/")
        with httpx.Client(timeout=60) as c:
            r = c.send(c.build_request(rq.get("method") or "GET", url.copy_with(raw_path=target.encode("latin-1")),
                                       headers=hdrs, content=body or None,
                                       extensions={"target": target.encode("latin-1")}))
        trace = {}
        if r.headers.get("x-imm-trace"):
            trace = json.loads(base64.b64decode(r.headers["x-imm-trace"]))
        return {"status": r.status_code, "body": r.content, "verdict": (r.headers.get(wire.H_VERDICT) or "").lower(),
                "trace": trace}

    def create_db(self, name: str):
        _docker("exec", self.db, "psql", "-q", "-U", "postgres", "-d", "postgres", "-c",
                'CREATE DATABASE "%s" TEMPLATE seed OWNER app' % name)
        return "postgres://app:%s@%s:5432/%s" % (self.app_pw, self.db, name)


def _body_info(body: bytes) -> dict:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("latin-1")
    return {"sha": hashlib.sha256(body or b"").hexdigest(), "len": len(body or b""), "head": text[:300]}


def _norm_body(body: bytes):
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return {"sha256": hashlib.sha256(body or b"").hexdigest(), "len": len(body or b"")}


def _short(v, n=400):
    s = v if isinstance(v, str) else json.dumps(v, default=str)
    return s if len(s) <= n else s[:n] + "..."


class JudgeRunner:
    """`run(release_dir, job, timeout)` like pipeline.runner.Runner, executed on clone triples."""

    def __init__(self, cfg):
        from immune import generic as ig
        self.cfg = cfg
        self.project = cfg.project
        self.facts = ig.facts(self.project)
        self.prefix = "%s-judge" % self.project.prefix
        self.home = os.path.realpath(cfg.repo_dir)
        self.image = self.facts.image(os.environ.get("JUDGE_BASE_RELEASE", "t0"))
        self.seq = itertools.count(1)
        self.calls = []
        self._lock = threading.Lock()

    def app_env(self, url: str, bind: str) -> dict:
        from immune.config import substitute
        f = self.facts
        out = {k: substitute(str(v), {"db": url, "secret": "judge", "static": ""}) for k, v in f.env.items()}
        out[f.url_env] = url
        if f.bind_env:
            out[f.bind_env] = bind
        return out

    def manifest(self) -> dict:
        try:
            with open(self.project.manifest_path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def markers(self) -> dict:
        try:
            with open(self.project.markers_path) as fh:
                return {k: int(v) for k, v in json.load(fh).items()}
        except (OSError, ValueError):
            return {}

    def run(self, release_dir: str, job: dict, timeout: float | None = None) -> dict:
        kind = job.get("kind")
        t0 = time.time()
        if not self.project.release_complete(release_dir):
            raise RunnerError("release %s lacks %s" % (release_dir, ", ".join(self.project.app.release_paths)))
        if kind == "harness" and not job.get("sequences"):
            return {"sequences": [], "manifest": self.manifest(), "ok_run": True}
        fn = getattr(self, "job_" + str(kind), None)
        if fn is None:
            raise RunnerError("runner job %s is not supported for app.runtime generic" % kind)
        with self._lock:     # one triple at a time (memory); jobs are short
            try:
                with Triple(self, release_dir) as tr:
                    up = tr.timing.get("up_s")
                    res = fn(tr, job)
            except RunnerError:
                raise
            except Exception as e:  # noqa: BLE001
                raise RunnerError("judge job %s failed: %s: %s" % (kind, type(e).__name__, e)) from e
        res["ok_run"] = True
        res["wall_s"] = round(time.time() - t0, 2)
        res["triple_up_s"] = up
        self.calls.append((kind, os.path.basename(os.path.normpath(release_dir)), res["wall_s"], up))
        log.info("judge %s on %s: %.1fs (triple up %.1fs)", kind, os.path.basename(os.path.normpath(release_dir)),
                 res["wall_s"], up or 0)
        return res

    # ------------------------------------------------------------ jobs
    def job_harness(self, tr: Triple, job: dict) -> dict:
        out = []
        for seq in job.get("sequences") or []:
            runs = []
            for _ in range(int(seq.get("repeat", 1))):
                items = seq.get("requests") or []
                res = []
                for i, rq in enumerate(items):
                    r = tr.send(rq, "L1" if i == len(items) - 1 else "L2")
                    t = r["trace"]
                    evs = [{"oracle": e.get("oracle"), "detail": {k: _short(v) for k, v in (e.get("detail") or {}).items()},
                            "stack": e.get("stack") or []} for e in t.get("events") or []]
                    res.append({"status": r["status"], "verdict": r["verdict"], "events": evs,
                                "marker_owners": t.get("marker_owners") or [], **_body_info(r["body"])})
                runs.append(res)
            out.append({"name": seq.get("name"), "runs": runs})
        return {"sequences": out, "manifest": self.manifest()}

    def roots(self) -> list:
        return [os.path.normpath(r) for r in self.facts.allowed_file_roots]

    def expand(self, release_dir: str, spec: dict) -> list:
        """Every file under the allowed roots (read from the release on the host), by every relative suffix."""
        from . import reqs as R
        out, seen = [], set()
        for root in self.roots():
            hroot = self.facts.host_path(release_dir, root)
            if not hroot or not os.path.isdir(hroot):
                continue
            for d, _dirs, files in os.walk(hroot):
                for fn in sorted(files):
                    full = os.path.join(d, fn)
                    rel = os.path.relpath(full, hroot).split(os.sep)
                    with open(full, "rb") as fh:
                        sha = hashlib.sha256(fh.read()).hexdigest()
                    for i in range(len(rel)):
                        val = "/".join(rel[i:])
                        if val in seen:
                            continue
                        seen.add(val)
                        rq = R.set_value(spec["base"], spec["param"], val, spec.get("template"))
                        rq.update(name="cand:" + val, expect_sha=sha)
                        out.append(rq)
        return out

    def job_plain(self, tr: Triple, job: dict) -> dict:
        requests = list(job.get("requests") or [])
        if job.get("expand"):
            requests = self.expand(tr.release_dir, job["expand"]) + requests
        warm = []
        for rq in job.get("warmup") or []:
            warm += tr.send(rq)["trace"].get("opens") or []
        results = []
        for rq in requests:
            r = tr.send(rq)
            t = r["trace"]
            results.append({"name": rq.get("name"), "status": r["status"], "sql": (t.get("sql") or [])[:50],
                            "opens": sorted(set(t.get("opens") or [])), "expect_sha": rq.get("expect_sha"),
                            "request": {k: rq.get(k) for k in ("method", "path", "query")}, **_body_info(r["body"])})
        return {"results": results, "roots": self.roots(), "warm_opens": sorted(set(warm)), "manifest": self.manifest()}

    def job_replay(self, tr: Triple, job: dict) -> dict:
        out = []
        for rq in job.get("requests") or []:
            r = tr.send(rq)
            out.append({"name": rq.get("name"), "method": rq.get("method", "GET"), "path": rq.get("path"),
                        "status": r["status"], "body": _norm_body(r["body"])})
        return {"results": out}

    def job_pytest(self, tr: Triple, job: dict) -> dict:
        """tests.command (any language) in the app image, release mounted at workdir, against a fresh seed copy."""
        cmd = self.project.tests_command
        if not cmd:
            return {"ok": True, "skipped": True, "summary": "skipped: no tests.command configured", "tail": ""}
        url = tr.create_db("tests")
        f = self.facts
        args = []
        for k, v in self.app_env(url, "127.0.0.1").items():
            args += ["-e", "%s=%s" % (k, v)]
        name = tr.base + "-tests"
        t0 = time.time()
        try:
            p = subprocess.run(["docker", "run", "--rm", "--name", name, "--network", tr.net, *tr.labels(), *tr.common(),
                                "--memory", "512m", "--tmpfs", "/tmp:rw,mode=1777", "-e", "HOME=/tmp",
                                "-v", "%s:%s:ro" % (tr.release_dir, f.workdir), "-w", f.workdir, *args,
                                "--entrypoint", "/bin/sh", self.image, "-c", cmd],
                               capture_output=True, text=True, timeout=float(job.get("timeout", 600)))
            out, code = (p.stdout or "") + (p.stderr or ""), p.returncode
        except subprocess.TimeoutExpired:
            _docker("rm", "-f", name, check=False)
            out, code = "timeout", -9
        lines = [l for l in out.strip().splitlines() if l.strip()]
        counts = {k: v for k, v in re.findall(r"^# (tests|pass|fail|cancelled|skipped) (\d+)", out, re.M)}
        summary = ", ".join("%s %s" % kv for kv in counts.items()) if counts else (lines[-1] if lines else "no output")
        failed = ["FAILED %s" % m.strip() for m in re.findall(r"^\s*not ok \d+ - (.+)$", out, re.M)]
        failed += [l for l in lines if l.startswith(("FAILED ", "ERROR "))]
        return {"ok": code == 0, "code": code, "summary": summary, "failed": failed[:20], "tail": "\n".join(lines[-40:]),
                "seconds": round(time.time() - t0, 1)}


# ---------------------------------------------------------------------------- policy for any language
DEP_FILES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "go.mod",
             "go.sum", "cargo.toml", "cargo.lock", "gemfile", "gemfile.lock", "pom.xml", "build.gradle",
             "build.gradle.kts", "composer.json", "composer.lock", "requirements.txt", "pipfile", "pipfile.lock",
             "pyproject.toml", "setup.py", "setup.cfg", "mix.exs", "mix.lock", "pubspec.yaml", "packages.config",
             "dockerfile", ".dockerignore", "makefile"}
DEP_DIRS = {"node_modules", "vendor", "third_party", ".venv", "site-packages"}
TEST_RE = re.compile(r"(^|/)(tests?|__tests__|spec|specs|testdata)(/|$)|(\.|_|-)(test|spec)s?\.[A-Za-z0-9]+$|(^|/)test_[^/]*$")
SOURCE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".go", ".rb", ".php", ".java", ".kt", ".cs", ".rs",
              ".c", ".h", ".cc", ".cpp", ".hpp", ".scala", ".ex", ".exs", ".lua", ".pl", ".swift", ".dart", ".sql"}
# lexical checks (no parser for these languages): module loading, process/network/env/dynamic-code access
IMPORT_RES = [re.compile(r"""\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
              re.compile(r"""^\s*import\s+(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]""", re.M),
              re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
              re.compile(r"""^\s*import\s+\(?\s*"([^"]+)\"""", re.M),                # go
              re.compile(r"""^\s*#\s*include\s*[<"]([^>"]+)[>"]""", re.M),           # c/c++
              re.compile(r"""^\s*use\s+([A-Za-z0-9_:\\]+)""", re.M),                  # rust/php/perl
              re.compile(r"""^\s*(?:require|require_relative|load)\s+['"]([^'"]+)['"]""", re.M)]  # ruby
DANGER_RE = re.compile(r"\b(child_process|execSync|execFile|spawnSync|spawn|fork|eval|Function|vm\.run\w*|"
                       r"process\.env|process\.binding|dlopen|os\.(?:Getenv|Setenv|LookupEnv|exec\w*|system)|exec\.Command|"
                       r"getenv|setenv|system|popen|Runtime\.getRuntime|ProcessBuilder|net\.(?:connect|createConnection|Socket)|"
                       r"dgram|http\.request|https\.request|fetch|XMLHttpRequest|WebSocket|socket)\b")
AUTH_RE = re.compile(r"\b(401|403)\b|requireUser|requireAuth|authenticate|authorize|isAdmin|currentUser|"
                     r"Unauthorized|Forbidden")
STRING_RE = re.compile(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`""")
COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/|#[^\n]*", re.S)


def _strip_comments(src: str) -> str:
    return COMMENT_RE.sub(" ", src)


def _imports(src: str) -> set:
    out = set()
    for r in IMPORT_RES:
        out.update(m.group(1) for m in r.finditer(src))
    return out


def _count(regex, src: str) -> dict:
    c = {}
    for m in regex.finditer(src):
        c[m.group(0)] = c.get(m.group(0), 0) + 1
    return c


def _entropy_tokens(src: str) -> set:
    out = set()
    for s in STRING_RE.findall(src):
        out.update(policy.high_entropy_tokens(s[1:-1]))
    return out


GENERIC_MISSING = ("no parser for this language: the checks are lexical (regex over comment-stripped source), so "
                   "they do not cover: new route handlers, new reads of request data (params/headers/cookies), "
                   "comparisons against new literals (value special-casing), or syntax errors; a removed auth check "
                   "is only caught when the count of 401/403/auth-helper tokens drops")


def check_generic(diff: str, base_dir: str, patched_dir: str, max_lines: int = 120, max_files: int = 4, dirs=None):
    """Policy gate for any language. -> (ok, detail, violations).

    Kept from the Python gate: allow-list of `app.source_dirs`, only existing regular files modified (no new,
    deleted, renamed, binary, mode or symlink changes), size bound (lines, files), no test edits, no
    dependency / build files (lock files, manifests, vendored dirs, Dockerfile), high-entropy string literals.
    `.py` files additionally get every AST check of `pipeline.policy.check`. Other source files get lexical
    checks only: new imports/requires/includes, new process/network/env/dynamic-code tokens, fewer 401/403/
    auth-helper tokens. See GENERIC_MISSING for what does not exist for non-Python code.
    """
    dirs = policy.source_dirs(dirs)
    area = ", ".join(d + "/" for d in dirs) or "(no app.source_dirs)"
    v = []
    try:
        changes = diffs.parse(diff)
    except diffs.DiffError as e:
        return False, "REJECTED: %s" % e, [str(e)]
    py, other = [], []
    for ch in changes:
        if ch.flags:
            v.append("%s: %s changes are not allowed" % (ch.path or "?", ", ".join(ch.flags)))
        if ch.old is None or ch.new is None:
            v.append("%s: creating or deleting files is not allowed" % (ch.path or "?"))
            continue
        if ch.old != ch.new:
            v.append("%s -> %s: renames are not allowed" % (ch.old, ch.new))
        p = ch.new
        norm = os.path.normpath(p).replace(os.sep, "/")
        parts = norm.split("/")
        low = parts[-1].lower()
        if p.startswith("/") or ".." in p.split("/") or norm != p or not policy._allowed(norm, dirs):
            v.append("%s: only files under %s may change" % (p, area))
        elif TEST_RE.search(norm):
            v.append("%s: test files may not change" % p)
        elif low in DEP_FILES or any(x in DEP_DIRS for x in parts):
            v.append("%s: dependency/build files may not change" % p)
        elif os.path.splitext(low)[1] not in SOURCE_EXT:
            v.append("%s: only source files may change" % p)
        elif os.path.islink(os.path.join(base_dir, p)) or os.path.islink(os.path.join(patched_dir, p)):
            v.append("%s: symlinks are not allowed" % p)
        else:
            (py if p.endswith(".py") else other).append(p)
    lines = sum(c.added + c.removed for c in changes)
    if lines > max_lines:
        v.append("diff too large: %d changed lines (max %d)" % (lines, max_lines))
    if len(changes) > max_files:
        v.append("too many files: %d (max %d)" % (len(changes), max_files))
    if py:   # every AST check of the Python gate, on the .py files (its verdict on other files is ours, above)
        _ok, _d, pv = policy.check(diff, base_dir, patched_dir, max_lines, max_files, dirs=dirs)
        skip = tuple("%s: only Python sources may change" % p for p in other)
        v += [x for x in pv if x not in v and not x.startswith(skip)]
    for p in sorted(set(other)):
        try:
            with open(os.path.join(base_dir, p), encoding="utf-8") as fh:
                before = _strip_comments(fh.read())
            with open(os.path.join(patched_dir, p), encoding="utf-8") as fh:
                after_raw = fh.read()
        except (OSError, UnicodeDecodeError) as e:
            v.append("%s: unreadable before or after the patch (%s)" % (p, e))
            continue
        after = _strip_comments(after_raw)
        new_imp = _imports(after) - _imports(before)
        if new_imp:
            v.append("%s: new import(s)/require(s) %s" % (p, ", ".join(sorted(new_imp))))
        db, da = _count(DANGER_RE, before), _count(DANGER_RE, after)
        grew = sorted(k for k, n in da.items() if n > db.get(k, 0))
        if grew:
            v.append("%s: new use of %s (process, network, environment or dynamic code)" % (p, ", ".join(grew)))
        ab, aa = sum(_count(AUTH_RE, before).values()), sum(_count(AUTH_RE, after).values())
        if aa < ab:
            v.append("%s: fewer authentication/authorisation checks (%d -> %d 401/403/auth-helper tokens)" % (p, ab, aa))
        ent = _entropy_tokens(after_raw) - _entropy_tokens(open(os.path.join(base_dir, p), encoding="utf-8").read())
        if ent:
            v.append("%s: high-entropy string constant %r" % (p, sorted(ent)[0][:12] + "..."))
    if v:
        return False, "REJECTED: " + "; ".join(v), v
    added = sum(c.added for c in changes)
    removed = sum(c.removed for c in changes)
    files = sorted(set(py + other))
    return True, ("OK: %d file(s) (%s), +%d/-%d lines; inside %s, no tests/dependency files, no new imports, "
                  "process/network/env access, secrets or dropped auth checks (lexical for non-Python sources)"
                  % (len(files), ", ".join(files), added, removed, area)), []


class JudgeValidator(Validator):
    """The five gates for app.runtime generic: same gate logic, judged on clone triples; language-neutral policy."""

    def __init__(self, cfg, runner=None):
        super().__init__(cfg, runner or JudgeRunner(cfg))

    def gate_policy(self, ctx):
        return check_generic(ctx["diff"], ctx["base_dir"], ctx["patched_dir"], self.cfg.policy_max_lines,
                             self.cfg.policy_max_files, dirs=self.cfg.project.app.source_dirs)[:2]
