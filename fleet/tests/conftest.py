"""Real-Docker tests for fleet. Everything lives in a temp dir; containers are named wp4-* and labelled with a
test-specific immune.run value; networks are wp4-*. The real runtime/ and the compose stack are never touched."""
import os, shutil, sys, tempfile, threading, time, uuid

import docker
import pytest
import uvicorn
from fastapi import FastAPI, Request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for p in (ROOT, os.path.join(ROOT, "acceptance", "fixture")):
    if p not in sys.path:
        sys.path.insert(0, p)

from fleet.config import Config  # noqa: E402
from fleet.manager import Fleet  # noqa: E402

FIXTURE = os.path.join(ROOT, "acceptance", "fixture", "fixture_app")
TOKEN = "wp4-token"


class FakeGateway:
    def __init__(self):
        self.pool = {}  # id -> dict(addr,key,release,state)
        self.upstream = {"addr": "prod-blue:8000", "release": "?"}
        self.upstreams = []  # history of POSTed upstreams
        self.puts = []
        self.resets = 0
        self.prod_5xx = 0
        self.bump_after_switch = 0
        app = FastAPI()
        me = self

        def chk(r: Request):
            assert r.headers.get("x-admin-token") == TOKEN

        @app.get("/_admin/pool")
        def gp(r: Request):
            chk(r)
            return {"clones": [{"id": k, "state": v["state"], "session": None, "release": v["release"]}
                               for k, v in me.pool.items()]}

        @app.put("/_admin/pool")
        async def pp(r: Request):
            chk(r)
            body = await r.json()
            me.puts.append(body["clones"])
            new = {}
            for c in body["clones"]:
                old = me.pool.get(c["id"], {})
                new[c["id"]] = {**c, "state": old.get("state", "free")}
            me.pool = new
            return {"ok": True}

        @app.get("/_admin/upstream")
        def gu(r: Request):
            chk(r)
            return me.upstream

        @app.post("/_admin/upstream")
        async def pu(r: Request):
            chk(r)
            me.upstream = await r.json()
            me.upstreams.append(me.upstream)
            if me.bump_after_switch and len(me.upstreams) == 1 + 0:
                pass
            if me.bump_after_switch:
                threading.Timer(0.7, lambda: setattr(me, "prod_5xx", me.prod_5xx + me.bump_after_switch)).start()
            else:
                me.prod_5xx = 0
            return me.upstream

        @app.get("/_admin/stats")
        def st(r: Request):
            chk(r)
            return {"prod_requests": 0, "prod_5xx": me.prod_5xx}

        @app.post("/_admin/reset")
        def rs(r: Request):
            chk(r)
            me.resets += 1
            return {"ok": True}

        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        while not self.server.started:
            time.sleep(0.05)
        self.port = self.server.servers[0].sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.server.should_exit = True
        self.thread.join(5)


@pytest.fixture(scope="session")
def dk():
    c = docker.from_env()
    c.ping()
    return c


@pytest.fixture()
def gw():
    g = FakeGateway()
    g.start()
    yield g
    g.stop()


STUB = '''import http.server as h
class H(h.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
h.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
'''


def make_release(runtime, name, bad=False):
    dst = os.path.join(runtime, "releases", name, "fixture_app")
    shutil.copytree(FIXTURE, dst, ignore=shutil.ignore_patterns("__pycache__"))
    if bad:
        p = os.path.join(dst, "main.py")
        s = open(p).read().replace('return {"ok": True}', 'raise HTTPException(500, "broken")')
        open(p, "w").write(s)


@pytest.fixture()
def env(dk, gw):
    tmp = tempfile.mkdtemp(prefix="wp4-")
    repo = os.path.join(tmp, "repo")
    runtime = os.path.join(tmp, "runtime")
    os.makedirs(repo)
    shutil.copytree(os.path.join(ROOT, "immune_contracts"), os.path.join(repo, "immune_contracts"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    open(os.path.join(repo, "stubclone.py"), "w").write(STUB)
    for r in ("r1", "r2"):
        make_release(runtime, r)
    make_release(runtime, "rbad", bad=True)
    prod = os.path.join(runtime, "data", "prod")
    os.makedirs(prod)
    from acceptance.fixture.fixture_app import seed
    seed.make(os.path.join(prod, "app.db"), shadow=False)
    sfx = uuid.uuid4().hex[:6]
    nets = [dk.networks.create(f"wp4-prodnet-{sfx}", internal=True), dk.networks.create(f"wp4-clonenet-{sfx}", internal=True)]
    cfg = Config(
        repo_dir=repo, runtime_dir=runtime, run_id=f"wp4-test-{sfx}", admin_token=TOKEN, gateway_url=gw.url,
        bus_url="http://127.0.0.1:1", name_prefix="wp4", prodnet=nets[0].name, clonenet=nets[1].name,
        release_paths=["fixture_app"], asgi="fixture_app.main:app", shadow_profile="fixture_app.shadow_profile",
        app_env={"APP_DB": "{db}", "APP_STATIC": "{static}", "APP_SECRET": "{secret}"}, static="fixture_app/static",
        smoke_path="/openapi.json", project="wp4", clone_cmd="python /opt/immune/stubclone.py", prod_secret="ps", shadow_secret="ss",
        deploy_watch_s=1.5, watch_poll_s=0.3, health_timeout_s=30, reconcile_s=0.3)
    fleet = Fleet(cfg, dk)
    yield type("Env", (), dict(cfg=cfg, fleet=fleet, gw=gw, dk=dk, runtime=runtime, prod=prod, nets=nets))
    fleet.stop()
    for c in dk.containers.list(all=True, filters={"label": f"immune.run={cfg.run_id}"}):
        c.remove(force=True)
    for n in nets:
        try:
            n.remove()
        except Exception:
            pass
    shutil.rmtree(tmp, ignore_errors=True)


def sh(c, code):
    r = c.exec_run(["python", "-c", code])
    return r.exit_code, r.output.decode()
