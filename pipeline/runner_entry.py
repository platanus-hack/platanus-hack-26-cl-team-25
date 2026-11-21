"""Runner entry point: one JSON job on stdin -> one JSON result on stdout.

Runs INSIDE the sandbox (docker --network none, read-only, release mounted at /app,
the working directory). This is the only pipeline module that executes application code.
App facts (ASGI entry, shadow profile, db env var, app env, seed and tests commands) come
in the job as "app" (immune.config.Config.facts()).

    python -m pipeline.runner_entry < job.json

Job kinds
  harness    sequences of requests through the shadow in-process harness (oracles)
  plain      requests against the plain app on a fresh PROD-like seed, recording
             executed SQL (text + bound params) and file opens per request
  pytest     the release's own test suite (tests.command; skipped when absent)
  scenarios  the legit scenarios (sim.scenarios or the stand-in) on fresh PROD-like seeds
  replay     recorded clean GET requests (legit gate without scenarios) on fresh PROD-like seeds

The last stdout line is  @@RESULT@@ <json>.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback

MARK = "@@RESULT@@"
MARKER_RE = re.compile(rb"MK[A-Z0-9]{10}")


APP: dict = {}        # the job's app facts


def _release_root() -> str:
    return os.path.realpath(os.getcwd())


def _db_env() -> str:
    return APP.get("db_env") or "APP_DB"


def _set_app_env(db: str, secret: str) -> None:
    """app.env ({db} {static} {secret}) into os.environ, plus the db path env var."""
    from immune.config import substitute
    root = _release_root()
    vals = {"db": db, "secret": secret, "static": os.path.join(root, APP["static"]) if APP.get("static") else ""}
    for k, v in (APP.get("env") or {}).items():
        os.environ[k] = substitute(str(v), vals)
    os.environ[_db_env()] = db
    os.environ["SHADOW_DB_ENV"] = _db_env()
    os.environ["SHADOW_RELEASE_ROOT"] = root
    os.environ["SHADOW_RELEASE_PATHS"] = ":".join(APP.get("release_paths") or [])


def _secret(default: str) -> str:
    os.environ.setdefault("RUNNER_APP_SECRET", default)
    return os.environ["RUNNER_APP_SECRET"]


def _seed(seed: int, job: dict | None = None) -> dict:
    d = tempfile.mkdtemp(prefix="runner-seed-")
    p = {k: os.path.join(d, v) for k, v in
         {"prod": "prod.db", "shadow": "shadow.db", "manifest": "manifest.json", "markers": "markers.json"}.items()}
    cmd = APP.get("seed_command") or ""
    sp = (job or {}).get("seed_paths") or {}
    if cmd:
        from immune.config import substitute
        line = substitute(cmd, {"prod_db": p["prod"], "shadow_db": p["shadow"], "manifest": p["manifest"],
                                "markers": p["markers"], "seed": str(seed)}, quote=True)
        subprocess.run(["/bin/sh", "-c", line], check=True, cwd=_release_root(), stdout=subprocess.DEVNULL, timeout=120)
    elif sp.get("dir"):
        # no seed command: the stack's synthetic shadow seed stands in for both databases (never prod data)
        _copy_db(os.path.join(sp["dir"], "seed.db"), p["shadow"])
        _copy_db(os.path.join(sp["dir"], "seed.db"), p["prod"])
        shutil.copyfile(os.path.join(sp["dir"], "markers.json"), p["markers"])
        shutil.copyfile(sp.get("manifest") or os.path.join(os.path.dirname(sp["dir"]), "manifest.json"), p["manifest"])
    else:
        raise RuntimeError("no data.seed_command and no shadow seed available to the runner")
    with open(p["manifest"]) as f:
        p["m"] = json.load(f)
    with open(p["markers"]) as f:
        p["k"] = {k: int(v) for k, v in json.load(f).items()}
    return p


def _copy_db(src: str, dst: str) -> None:
    a, b = sqlite3.connect(src), sqlite3.connect(dst)
    try:
        a.backup(b)
    finally:
        a.close()
        b.close()


def _short(v, n=400):
    s = v if isinstance(v, str) else json.dumps(v, default=str)
    return s if len(s) <= n else s[:n] + "..."


def _body_info(body: bytes, markers: dict) -> dict:
    found = sorted({m.decode() for m in MARKER_RE.findall(body or b"")})
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("latin-1")
    return {"sha": hashlib.sha256(body or b"").hexdigest(), "len": len(body or b""), "head": text[:300],
            "marker_owners": sorted({markers[m] for m in found if m in markers})}


def _b(req) -> bytes:
    try:
        return base64.b64decode(req.get("body_b64") or "")
    except Exception:
        return b""


# ------------------------------------------------------------------ harness
def job_harness(job: dict) -> dict:
    seed = _seed(int(job.get("seed", 1)), job)
    os.environ["MARKERS_PATH"] = seed["markers"]
    _set_app_env(os.path.join(tempfile.mkdtemp(prefix="runner-db-"), "app.db"), _secret("runner-shadow-secret"))
    from shadow.harness import Harness
    state = base64.b64decode(job["state_b64"]) if job.get("state_b64") else None
    h = Harness(profile=job.get("profile") or APP["profile"], seed_db=seed["shadow"], state=state)
    out = []
    try:
        for seq in job.get("sequences") or []:
            runs = []
            for _ in range(int(seq.get("repeat", 1))):
                res = []
                items = seq.get("requests") or []
                for i, rq in enumerate(items):
                    mode = "L1" if i == len(items) - 1 else "L2"
                    hdrs = {k: v for k, v in (rq.get("headers") or {}).items()}
                    r = h.send(rq.get("method", "GET"), rq.get("path", "/"), query=rq.get("query") or "",
                               headers=hdrs, body=_b(rq), uid=rq.get("uid"), role=rq.get("role") or "user", mode=mode)
                    evs = [{"oracle": e.get("oracle"), "detail": {k: _short(v) for k, v in (e.get("detail") or {}).items()},
                            "stack": e.get("stack") or []} for e in (r.events or [])]
                    item = {"status": r.status, "verdict": r.verdict, "events": evs, **_body_info(r.body, seed["k"])}
                    if seq.get("with_evidence") and r.evidence:
                        item["evidence"] = r.evidence
                    res.append(item)
                runs.append(res)
            out.append({"name": seq.get("name"), "runs": runs})
    finally:
        h.close()
    return {"sequences": out, "manifest": seed["m"]}


# ------------------------------------------------------------------ plain (prod-like, recorded)
class _Rec:
    current = None
    lock = threading.Lock()


def _install_recorders():
    orig = sqlite3.connect

    def note(sql, params):
        rec = _Rec.current
        if rec is not None and isinstance(sql, str):
            try:
                ps = list(params) if isinstance(params, (list, tuple)) else (dict(params) if isinstance(params, dict) else [])
            except Exception:
                ps = []
            rec["sql"].append({"sql": sql, "params": [p if isinstance(p, (int, float, str)) or p is None else repr(p)
                                                      for p in (ps if isinstance(ps, list) else list(ps.values()))]})

    class Cur(sqlite3.Cursor):
        def execute(self, sql, params=(), *a):
            r = super().execute(sql, params, *a)
            note(sql, params)
            return r

    class Conn(sqlite3.Connection):
        def cursor(self, factory=Cur):
            return super().cursor(factory)

        def execute(self, sql, params=()):
            cur = self.cursor()
            return cur.execute(sql, params)

    def connect(*a, **k):
        k.setdefault("factory", Conn)
        return orig(*a, **k)

    sqlite3.connect = connect

    def hook(event, args):
        if event != "open":
            return
        rec = _Rec.current
        if rec is None:
            return
        p = args[0] if args else None
        if p is None or isinstance(p, int):
            return
        try:
            p = os.fsdecode(os.fspath(p))
        except TypeError:
            return
        f = sys._getframe(1)
        while f is not None:
            fn = f.f_code.co_filename
            if fn.startswith("<frozen importlib") or "importlib" in fn or fn.endswith(("linecache.py", "tokenize.py")):
                return
            f = f.f_back
        rec["opens"].append(os.path.realpath(p))

    sys.addaudithook(hook)


def _asgi():
    mod, _, attr = (APP.get("asgi") or "").partition(":")
    obj = importlib.import_module(mod)
    for part in (attr or "app").split("."):
        obj = getattr(obj, part)
    return obj


def _client(db_path: str):
    os.environ[_db_env()] = db_path
    from starlette.testclient import TestClient
    return TestClient(_asgi(), raise_server_exceptions=False)


def _profile():
    return importlib.import_module(APP["profile"])


def _token(uid, role):
    """A credential the app accepts for uid, minted by the shadow profile (prod-like secret)."""
    return _profile().mint_token(dict(os.environ), int(uid), role or "user")


def _send_plain(client, rq):
    hdrs = {k: v for k, v in (rq.get("headers") or {}).items() if k.lower() not in ("host", "content-length")}
    if rq.get("uid") is not None:
        hdrs["authorization"] = "Bearer " + _token(rq["uid"], rq.get("role"))
    url = rq.get("path", "/") + (("?" + rq["query"]) if rq.get("query") else "")
    rec = {"sql": [], "opens": []}
    _Rec.current = rec
    try:
        r = client.request(rq.get("method", "GET"), url, headers=hdrs, content=_b(rq) or None)
        status, body = r.status_code, r.content
    except Exception as e:  # app crash = 500
        status, body = 599, repr(e).encode()
    finally:
        _Rec.current = None
    return status, body, rec


def _roots():
    return [os.path.realpath(r) for r in _profile().allowed_file_roots(dict(os.environ)) if r]


def _expand(spec: dict, base_req: dict) -> list:
    """Candidate legit values for a file parameter: every file under the allowed roots, by every relative suffix."""
    from pipeline import reqs as R
    out, seen = [], set()
    for root in _roots():
        for d, _dirs, files in os.walk(root):
            for fn in sorted(files):
                full = os.path.join(d, fn)
                rel = os.path.relpath(full, root).split(os.sep)
                with open(full, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
                for i in range(len(rel)):
                    val = "/".join(rel[i:])
                    if val in seen:
                        continue
                    seen.add(val)
                    rq = R.set_value(base_req, spec["param"], val, spec.get("template"))
                    rq["name"] = "cand:" + val
                    rq["expect_sha"] = sha
                    out.append(rq)
    return out


def job_plain(job: dict) -> dict:
    seed = _seed(int(job.get("seed", 1)), job)
    work = os.path.join(tempfile.mkdtemp(prefix="runner-plain-"), "app.db")
    _set_app_env(work, _secret("runner-prod-secret"))
    _install_recorders()
    requests = list(job.get("requests") or [])
    if job.get("expand"):
        requests = _expand(job["expand"], job["expand"]["base"]) + requests
    client = _client(work)
    results = []
    warm = []
    for rq in job.get("warmup") or []:
        _copy_db(seed["prod"], work)
        _s, _b2, rec = _send_plain(client, rq)
        warm += rec["opens"]
    for rq in requests:
        _copy_db(seed["prod"], work)   # every request starts from the seed
        status, body, rec = _send_plain(client, rq)
        info = _body_info(body, {})
        info.pop("marker_owners", None)
        results.append({"name": rq.get("name"), "status": status, "sql": rec["sql"][:50], "opens": sorted(set(rec["opens"])),
                        "expect_sha": rq.get("expect_sha"), "request": {k: rq.get(k) for k in ("method", "path", "query")},
                        **info})
    return {"results": results, "roots": _roots(), "warm_opens": sorted(set(warm)), "manifest": seed["m"]}


# ------------------------------------------------------------------ pytest
def job_pytest(job: dict) -> dict:
    cmd = APP.get("tests_command") or ""
    if not cmd:
        return {"ok": True, "skipped": True, "summary": "skipped: no tests.command configured", "tail": ""}
    t0 = time.time()
    env = dict(os.environ)
    env.pop("RUNNER_APP_SECRET", None)
    try:
        p = subprocess.run(["/bin/sh", "-c", cmd], cwd=_release_root(), capture_output=True, text=True, env=env,
                           timeout=float(job.get("timeout", 600)))
        out = (p.stdout or "") + (p.stderr or "")
        code = p.returncode
    except subprocess.TimeoutExpired as e:
        out, code = (e.stdout or "") if isinstance(e.stdout, str) else "", -9
    lines = [l for l in out.strip().splitlines() if l.strip()]
    summary = lines[-1] if lines else "no output"
    failed = [l for l in lines if l.startswith("FAILED ") or l.startswith("ERROR ")]
    return {"ok": code == 0, "code": code, "summary": summary.strip("= "), "failed": failed[:20],
            "tail": "\n".join(lines[-40:]), "seconds": round(time.time() - t0, 1)}


# ------------------------------------------------------------------ scenarios
def _norm_step(s):
    if isinstance(s, dict):
        return s
    if isinstance(s, (list, tuple)):
        s = list(s)
        if len(s) == 3:
            return {"step": s[0], "status": s[1], "body": s[2]}
        if len(s) >= 5:
            return {"step": s[0], "method": s[1], "path": s[2], "status": s[3], "body": s[4]}
    return {"step": repr(s)}


def job_scenarios(job: dict) -> dict:
    seed = _seed(int(job.get("seed", 1)), job)
    _set_app_env(os.path.join(tempfile.mkdtemp(prefix="runner-scn-"), "app.db"), _secret("runner-prod-secret"))
    used = job.get("module") or "sim.scenarios"
    note = ""
    try:
        mod = importlib.import_module(used)
    except Exception as e:  # noqa: BLE001
        fb = job.get("fallback")
        if not fb:
            raise
        note = "%s unavailable (%s); used %s" % (used, type(e).__name__, fb)
        used = fb
        mod = importlib.import_module(fb)
    out = []
    for i, fn in enumerate(getattr(mod, "SCENARIOS", [])):
        name = getattr(fn, "__name__", "scenario_%d" % i)
        work = os.path.join(tempfile.mkdtemp(prefix="runner-scn-"), "app.db")
        _copy_db(seed["prod"], work)
        client = _client(work)
        try:
            steps = [_norm_step(s) for s in (fn(client, seed["m"]) or [])]
            out.append({"name": name, "steps": json.loads(json.dumps(steps, default=str))})
        except Exception as e:  # noqa: BLE001
            out.append({"name": name, "error": "%s: %s" % (type(e).__name__, _short(str(e), 300))})
        finally:
            shutil.rmtree(os.path.dirname(work), ignore_errors=True)
    return {"module": used, "note": note, "scenarios": out}


def _norm_body(body: bytes):
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return {"sha256": hashlib.sha256(body or b"").hexdigest(), "len": len(body or b"")}


def job_replay(job: dict) -> dict:
    """Recorded clean GET requests, each on a fresh PROD-like seed: [{name, method, path, status, body}]."""
    seed = _seed(int(job.get("seed", 1)), job)
    work = os.path.join(tempfile.mkdtemp(prefix="runner-replay-"), "app.db")
    _set_app_env(work, _secret("runner-prod-secret"))
    client = _client(work)
    out = []
    for rq in job.get("requests") or []:
        _copy_db(seed["prod"], work)
        status, body, _rec = _send_plain(client, rq)
        out.append({"name": rq.get("name"), "method": rq.get("method", "GET"), "path": rq.get("path"),
                    "status": status, "body": _norm_body(body)})
    return {"results": out}


JOBS = {"harness": job_harness, "plain": job_plain, "pytest": job_pytest, "scenarios": job_scenarios,
        "replay": job_replay}


def main() -> int:
    job = json.loads(sys.stdin.read() or "{}")
    APP.clear()
    APP.update(job.get("app") or {})
    if job.get("app_now") and APP.get("frozen_time_env"):
        os.environ[APP["frozen_time_env"]] = str(job["app_now"])
    t0 = time.time()
    try:
        res = JOBS[job["kind"]](job)
        res = {"ok_run": True, **res}
    except Exception as e:  # noqa: BLE001
        res = {"ok_run": False, "error": "%s: %s" % (type(e).__name__, e), "trace": traceback.format_exc()[-3000:]}
    res["seconds"] = res.get("seconds") or round(time.time() - t0, 2)
    sys.stdout.write("\n" + MARK + " " + json.dumps(res, default=str) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
