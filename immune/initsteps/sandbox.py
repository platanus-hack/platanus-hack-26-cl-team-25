"""Run target-project code in a separate interpreter with a clean sys.path.

The installer never imports the target app (or its generated profile) in its own process.
Every probe runs ``<python> -I -c <bootstrap>``: ``-I`` drops PYTHONPATH, the user site and the
current directory; the bootstrap puts exactly ``[root, root/.immune (or the project's), IMMUNE_HOME]``
in front of sys.path and runs one module of ``immune.initsteps`` with a JSON job on stdin. The
result is the last stdout line (the app's own prints are redirected to stderr by the runner).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

from immune._cfg import IMMUNE_HOME

PY = sys.executable
SHADOW_SECRET = "immune-doctor-shadow-secret"

BOOT = (
    "import sys, runpy; sys.path[:0] = %r; sys.argv = [%r]; "
    "runpy.run_module(%r, run_name='__main__', alter_sys=True)"
)


def base_env(extra: dict | None = None) -> dict:
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR") if k in os.environ}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    for k, v in (extra or {}).items():
        if v is not None:
            env[str(k)] = str(v)
    return env


def roots_for(root: str, project: str | None = None) -> list[str]:
    root = os.path.realpath(root)
    dot = os.path.join(root, ".immune")
    if not os.path.isdir(dot) and project:
        dot = os.path.join(os.path.realpath(project), ".immune")
    return [root, dot, IMMUNE_HOME]


def run_module(module: str, job: dict, roots: list[str], env: dict, timeout: float = 180, cwd: str | None = None) -> dict:
    """Run ``python -I -m module`` (bootstrapped) with ``job`` on stdin; return its JSON result.
    Never raises for problems of the child: {"ok": False, "error": ...}."""
    code = BOOT % (list(roots), module, module)
    try:
        p = subprocess.run([PY, "-I", "-B", "-c", code], input=json.dumps(job), capture_output=True, text=True,
                           timeout=timeout, env=env, cwd=cwd or tempfile.gettempdir())
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout after %ds" % timeout}
    for line in reversed((p.stdout or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                out = json.loads(line)
                out.setdefault("stderr_tail", (p.stderr or "")[-1500:])
                return out
            except ValueError:
                continue
    return {"ok": False, "error": "exit %s: %s" % (p.returncode, ((p.stderr or "") + (p.stdout or ""))[-1500:])}


def app_env(cfg, db_path: str, root: str, secret: str = SHADOW_SECRET) -> dict:
    """The app's env for a probe on the host: config app.env rendered with release root ``root``."""
    env = cfg.app_env(db=db_path, secret=secret, root=root)
    out = {}
    for k, v in env.items():
        if isinstance(v, str) and v.startswith("/app/"):
            v = os.path.join(root, v[len("/app/"):])
        out[k] = v
    out.setdefault("APP_DB", db_path)
    out.setdefault("APP_SECRET", secret)
    return out


def profile_job(cfg, op: str, arg=None, root: str | None = None, timeout: float = 60) -> dict:
    root = root or cfg.project_dir
    tmp = tempfile.mkdtemp(prefix="immune-probe-")
    env = base_env(app_env(cfg, os.path.join(tmp, "app.db"), root))
    job = {"op": op, "profile": cfg.shadow.profile, "arg": arg, "asgi": cfg.app.asgi}
    return run_module("immune.initsteps.probe", job, roots_for(root, cfg.project_dir), env, timeout=timeout)


def profile_has(cfg, name: str) -> bool:
    r = profile_job(cfg, "inspect")
    return bool(r.get("ok")) and name in (r.get("functions") or [])


def call_profile(cfg, fn: str, arg):
    r = profile_job(cfg, "call", {"fn": fn, "arg": arg})
    if not r.get("ok"):
        raise RuntimeError("profile.%s failed: %s" % (fn, r.get("error")))
    return r.get("result")


def harness(cfg, root: str, job: dict, extra_env: dict | None = None, timeout: float = 300) -> dict:
    """Run immune.initsteps.harness_runner on release root ``root`` (see that module for the job format)."""
    tmp = tempfile.mkdtemp(prefix="immune-harness-")
    db = os.path.join(tmp, "app.db")
    env = app_env(cfg, db, root)
    env["APP_DB"] = db
    env.setdefault("MARKERS_PATH", job.get("markers") or cfg.markers_path)
    env.update(extra_env or {})
    job = dict(job)
    job.setdefault("profile", cfg.shadow.profile)
    job.setdefault("seed_db", cfg.shadow_seed)
    return run_module("immune.initsteps.harness_runner", job, roots_for(root, cfg.project_dir), base_env(env),
                      timeout=timeout)
