"""Bring up a private test stack: --internal network, Postgres seeded from a template, the Node demo
app, the sidecar attached to it, and a tiny evidence collector. All names start with ``sctest-``.

Used by the integration tests and by ``python -m sidecar.tests.bench``.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EX = os.path.join(ROOT, "sidecar", "examples")
SIDECAR_IMAGE = "immune-sidecar:1"
NODE_IMAGE = "node:22-alpine"
NPM_CI = ["npm", "ci", "--omit=dev", "--no-audit", "--no-fund"]


class DepsUnavailable(RuntimeError):
    """The Node fixture's dependencies are not installed and could not be installed."""


def ensure_node_deps(app_dir: str | None = None) -> None:
    """examples/node/node_modules is not in git. The app container runs on an --internal network with the
    fixture mounted read-only, so the dependencies are installed here, once, from package-lock.json: with the
    host's npm, else with a one-off container of the app's own image (default bridge network, as this user)."""
    d = app_dir or os.path.join(EX, "node")
    if os.path.isdir(os.path.join(d, "node_modules", "pg")):
        return
    if shutil.which("npm"):
        cmd, cwd = NPM_CI, d
    elif shutil.which("docker"):
        cmd, cwd = ["docker", "run", "--rm", "--label", "immune.test=sidecar", "--user", f"{os.getuid()}:{os.getgid()}",
                    "-e", "HOME=/tmp", "-e", "npm_config_cache=/tmp/npm", "-v", f"{d}:/app", "-w", "/app",
                    NODE_IMAGE, *NPM_CI], None
    else:
        raise DepsUnavailable(f"{d}/node_modules is missing and neither npm nor docker is available to install it")
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
        err = (r.stderr or r.stdout).strip()[-400:] if r.returncode else ""
    except (OSError, subprocess.TimeoutExpired) as e:
        err = repr(e)
    if err or not os.path.isdir(os.path.join(d, "node_modules", "pg")):
        raise DepsUnavailable(f"{d}/node_modules is missing and `{' '.join(cmd[:3])} ...` could not install it "
                              f"(network access to the npm registry is needed once): {err}")

COLLECTOR = r'''
import json, http.server
got = []
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0)); body = self.rfile.read(n)
        got.append({"headers": {k.lower(): v for k, v in self.headers.items()}, "body": body.decode()})
        self.send_response(200); self.send_header("content-length", "2"); self.end_headers(); self.wfile.write(b"{}")
    def do_GET(self):
        out = json.dumps(got).encode()
        if self.path == "/clear": got.clear(); out = b"[]"
        self.send_response(200); self.send_header("content-length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", 9000), H).serve_forever()
'''


def sh(*args, check=True, timeout=120) -> str:
    r = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {r.stderr.strip()}")
    return r.stdout.strip()


def ip_of(name: str, net: str) -> str:
    return sh("docker", "inspect", "-f", "{{(index .NetworkSettings.Networks \"%s\").IPAddress}}" % net, name)


def wait_until(fn, timeout=30.0, step=0.2, what=""):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            v = fn()
            if v:
                return v
        except Exception as e:  # noqa
            last = e
        time.sleep(step)
    raise RuntimeError(f"timeout waiting for {what}: {last!r}")


class Stack:
    def __init__(self, tag: str | None = None, app: str = "node", trace: bool = True, collector: bool = True,
                 collector_url: str | None = None, grace_ms: int | None = None, mode: str = "attach",
                 pg_durable: bool = False):
        self.pg_durable = pg_durable
        self.tag = tag or uuid.uuid4().hex[:6]
        self.net = f"sctest-net-{self.tag}"
        self.pg = f"sctest-pg-{self.tag}"
        self.app = f"sctest-app-{self.tag}"
        self.sc = f"sctest-sc-{self.tag}"
        self.col = f"sctest-col-{self.tag}"
        self.app_kind = app
        self.trace = trace
        self.with_collector = collector
        self.collector_url = collector_url
        self.grace_ms = grace_ms
        self.mode = mode
        self.tmp = tempfile.mkdtemp(prefix="sctest-")
        self.started = []

    # --------------------------------------------------------------- up / down
    def up(self):
        try:
            self._up()
        except Exception:
            print(self.logs())
            self.down()
            raise
        return self

    def _up(self):
        if self.app_kind == "node":
            ensure_node_deps()
        sh("docker", "network", "create", "--internal", self.net)
        self.started.append(("network", self.net))
        # the clone database is disposable: durability off makes the L1 reset ~2x faster (README)
        pg_args = [] if self.pg_durable else ["-c", "fsync=off", "-c", "synchronous_commit=off",
                                               "-c", "full_page_writes=off"]
        self._run(self.pg, ["--network", self.net, "-e", "POSTGRES_PASSWORD=pw", "postgres:16-alpine", *pg_args])
        if self.with_collector:
            self._run(self.col, ["--network", self.net, SIDECAR_IMAGE, "python", "-c", COLLECTOR])
        self.pg_ip = ip_of(self.pg, self.net)
        wait_until(lambda: asyncio.run(self._pg_ready()), 60, 0.5, "postgres")
        asyncio.run(self._seed())
        self._start_app()
        self.app_ip = ip_of(self.app, self.net)
        self._start_sidecar()
        self.url = f"http://{self.app_ip}:8000"
        wait_until(lambda: self._sidecar_ready(), 90, 0.3, "sidecar")
        if self.with_collector:
            self.col_url = f"http://{ip_of(self.col, self.net)}:9000"

    def _sidecar_ready(self):
        state = sh("docker", "inspect", "-f", "{{.State.Running}}", self.sc)
        if state != "true":
            raise RuntimeError("sidecar exited:\n" + sh("docker", "logs", self.sc, check=False))
        return httpx.get(f"http://{self.app_ip}:8000/health", timeout=2).status_code == 200

    def _run(self, name, args):
        sh("docker", "run", "-d", "--name", name, "--label", "immune.test=sidecar", *args)
        self.started.append(("container", name))

    async def _pg_ready(self):
        from sidecar.pgclient import PgConn
        c = await PgConn.connect(self.pg_ip, 5432, "postgres", "pw", "postgres", timeout=2)
        await c.query("SELECT 1")
        await c.close()
        return True

    async def _seed(self):
        from sidecar.pgclient import PgConn
        c = await PgConn.connect(self.pg_ip, 5432, "postgres", "pw", "postgres")
        await c.query("CREATE ROLE app LOGIN PASSWORD 'apppw'")
        await c.query("CREATE DATABASE seed OWNER app")
        await c.close()
        c = await PgConn.connect(self.pg_ip, 5432, "app", "apppw", "seed")
        with open(os.path.join(EX, "node", "seed.sql")) as f:
            await c.query(f.read())
        if self.app_kind == "c":
            # the C demo only speaks trust auth: a dedicated role with a trust line in pg_hba
            await c.close()
            c = await PgConn.connect(self.pg_ip, 5432, "postgres", "pw", "postgres")
            await c.query("CREATE ROLE capp LOGIN")
            await c.close()
            c = await PgConn.connect(self.pg_ip, 5432, "app", "apppw", "seed")
            await c.query("GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO capp")
            sh("docker", "exec", self.pg, "sh", "-c",
               "sed -i '1i host all capp all trust' /var/lib/postgresql/data/pg_hba.conf")
            await c.query("SELECT 1")
            await c.close()
            c = await PgConn.connect(self.pg_ip, 5432, "postgres", "pw", "postgres")
            await c.query("SELECT pg_reload_conf()")
        await c.close()

    def _start_app(self):
        env = ["-e", "DATABASE_URL=postgres://app:apppw@127.0.0.1:5432/clone", "-e", "APP_SECRET=shadowsecret",
               "-e", "APP_STATIC=/app/static", "-e", "PORT=3000"]
        if self.app_kind == "node":
            self._run(self.app, ["--network", self.net, "--read-only", "-v", f"{EX}/node:/app:ro", "-w", "/app", *env,
                                 NODE_IMAGE, "node", "/app/server.js"])
        elif self.app_kind in ("c", "cdyn"):
            cbin = os.path.join(self.tmp, "cbin")
            os.makedirs(cbin, exist_ok=True)
            env_ = {**os.environ, **({"DYNAMIC": "1"} if self.app_kind == "cdyn" else {})}
            subprocess.run([os.path.join(EX, "c", "build.sh"), cbin], check=True, capture_output=True, env=env_)
            os.chmod(cbin, 0o755)
            # static binary: any image works (NODE_IMAGE is used only because it is present); the dynamic
            # variant needs glibc, which the sidecar image has
            image = SIDECAR_IMAGE if self.app_kind == "cdyn" else NODE_IMAGE
            self._run(self.app, ["--network", self.net, "--read-only", "-v", f"{cbin}:/cbin:ro",
                                 "-v", f"{EX}/c/static:/app/static:ro", "-e", "APP_STATIC=/app/static",
                                 "-e", "PORT=3000", "-e", "PGUSER=capp", image, "/cbin/app"])
        else:
            raise ValueError(self.app_kind)

    def sidecar_config(self) -> dict:
        cfg = {"listen_port": 8000, "app_port": 3000, "health": "/health",
               "allowed_file_roots": ["/app/static"], "source_dirs": ["/app"], "warmup_paths": ["/"],
               "profile": "/opt/immune/sidecar/examples/node/profile.py",
               "postgres": {"listen": "127.0.0.1:5432", "upstream": f"{self.pg}:5432",
                            "admin_url": f"postgres://postgres:pw@{self.pg}:5432/postgres",
                            "database": "clone", "template": "seed"}}
        if self.app_kind in ("c", "cdyn"):
            del cfg["profile"]
            cfg["identity_command"] = 'echo "x-user: $IMM_UID"'
            cfg["public_paths"] = ["/health", "/search", "/safe-search", "/download", "/safe-download"]
            cfg["source_dirs"] = []
            # native call stacks in the evidence; the demo is built from /src (see examples/c/build.sh)
            cfg["native_stack"] = {"frame_limit": 48, "path_map": [["/src", "sidecar/examples/c"]]}
        if self.grace_ms is not None:
            cfg["grace_ms"] = self.grace_ms
        return cfg

    def _start_sidecar(self):
        path = os.path.join(self.tmp, "sidecar.json")
        with open(path, "w") as f:
            json.dump(self.sidecar_config(), f)
        os.chmod(self.tmp, 0o755); os.chmod(path, 0o644)
        col = self.collector_url or (f"http://{self.col}:9000" if self.with_collector else "http://192.0.2.1:9")
        args = ["--network", f"container:{self.app}", "--pid", f"container:{self.app}", "--cap-add", "SYS_PTRACE",
                "-v", f"{ROOT}:/opt/immune:ro", "-v", f"{self.tmp}:/cfg:ro", "-e", "PYTHONPATH=/opt/immune",
                "-e", "APP_SECRET=shadowsecret", "-e", "CLONE_ID=c1", "-e", "CLONE_KEY=k1", "-e", f"COLLECTOR_URL={col}",
                "-e", "RELEASE=t0", "-e", "MARKERS_PATH=/opt/immune/sidecar/examples/node/markers.json",
                SIDECAR_IMAGE, "python", "-m", "sidecar", "--config", "/cfg/sidecar.json"]
        if not self.trace:
            args.append("--no-trace")
        self._run(self.sc, args)

    def logs(self, name=None) -> str:
        out = []
        for kind, n in self.started:
            if kind == "container" and (name is None or n == name):
                out.append(f"--- {n}\n" + subprocess.run(["docker", "logs", "--tail", "200", n], capture_output=True,
                                                          text=True).stderr[-6000:])
        return "\n".join(out)

    def down(self):
        for kind, n in reversed(self.started):
            if kind == "container":
                subprocess.run(["docker", "rm", "-f", n], capture_output=True)
        for kind, n in reversed(self.started):
            if kind == "network":
                subprocess.run(["docker", "network", "rm", n], capture_output=True)
        self.started = []

    # --------------------------------------------------------------- helpers
    def evidence(self):
        return httpx.get(self.col_url + "/", timeout=5).json()

    def clear_evidence(self):
        httpx.get(self.col_url + "/clear", timeout=5)
