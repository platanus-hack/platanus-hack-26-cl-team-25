"""A gateway run as a real process (python -m gateway) the way `immune up` starts it, configured through
IMMUNE_AUTH / GW_MODE; prod, one clone and the bus are fakes. Shared by the tests through the `world` fixture
(conftest.py)."""
import json
import os
import sys
import time

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from immune_contracts import wire

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "acceptance"))
from helpers import ThreadServer, free_port, kill, spawn, wait_http  # noqa: E402

ADMIN = {"x-admin-token": "adm"}
OPENAPI = os.path.join(ROOT, "acceptance", "fixture", "fixture_app", "openapi.yaml")


class World:
    pass


def _prod(w):
    app = FastAPI()

    @app.get("/api/me")
    async def me(request: Request):
        w.introspections.append({"authorization": request.headers.get("authorization"),
                                 "cookie": request.headers.get("cookie")})
        a = request.headers.get("authorization") or ""
        if a.startswith("Bearer good-"):
            return {"id": int(a.split("-", 1)[1]), "role": "user"}
        if a == "Bearer boss":
            return {"id": 1, "role": "admin"}
        if "session=s7" in (request.headers.get("cookie") or ""):
            return {"user": {"id": 7}, "role": "user"}
        return JSONResponse({"detail": "no"}, status_code=401)

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def any_(path: str, request: Request):
        w.prod_seen.append({"path": "/" + path, "query": request.url.query})
        return {"from": "prod"}
    return app


def _clone(w, cid, key, ingest):
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def any_(path: str, request: Request):
        h = dict(request.headers)
        w.clone_seen.append({"path": "/" + path, "query": request.url.query, "headers": h})
        text = "/" + path + "?" + request.url.query
        verdict = "oracle" if "ATTACK" in text else "inconclusive" if "UNSURE" in text else "clean"
        if verdict == "oracle":
            ev = {"clone": cid, "rid": h.get(wire.H_RID, ""), "mode": h.get(wire.H_MODE, "L1"), "release": "t0",
                  "verdict": "oracle", "uid": None, "role": None, "status": 200, "pre_state_b64": None,
                  "request": {"method": "GET", "path": "/" + path, "query": request.url.query, "headers": {},
                              "body_b64": ""},
                  "events": [{"oracle": "sql", "detail": {"statement": "x", "input": "x", "param": "q"}, "stack": []}]}
            raw = wire.dumps(ev)
            async with httpx.AsyncClient() as c:
                await c.post(ingest() + "/_clone/evidence", content=raw,
                             headers={wire.H_CLONE_ID: cid, wire.H_SIGNATURE: wire.sign(key, raw),
                                      "content-type": "application/json"})
        return JSONResponse({"from": cid, "synthetic": True}, status_code=401 if verdict == "inconclusive" else 200,
                            headers={wire.H_VERDICT: verdict})
    return app


def _bus(w):
    app = FastAPI()

    @app.post("/events")
    async def post(request: Request):
        d = await request.json()
        w.events.extend(d if isinstance(d, list) else [d])
        return {"ok": True}
    return app


def start(tmp_path, auth: dict, mode: str = "enforce", extra_env=None):
    w = World()
    w.prod_seen, w.clone_seen, w.events, w.introspections = [], [], [], []
    w.prod = ThreadServer(_prod(w))
    w.bus = ThreadServer(_bus(w))
    data, admin, ingest = free_port(), free_port(), free_port()
    w.c1 = ThreadServer(_clone(w, "c1", "k1", lambda: f"http://127.0.0.1:{ingest}"))
    (tmp_path / "manifest.json").write_text(json.dumps({"seed_max_uid": 2, "canaries": {"note_id": [7]}}))
    w.record = tmp_path / "requests.jsonl"
    env = {"GW_HOST": "127.0.0.1", "GW_DATA_PORT": str(data), "GW_ADMIN_PORT": str(admin),
           "GW_INGEST_PORT": str(ingest), "PROD_ADDR": w.prod.addr, "PROD_RELEASE": "t0",
           "PROD_APP_SECRET": "prodsecret", "SHADOW_APP_SECRET": "shadowsecret", "OPENAPI_PATH": OPENAPI,
           "MANIFEST_PATH": str(tmp_path / "manifest.json"), "RECORD_PATH": str(w.record), "BUS_URL": w.bus.url,
           "BUS_TOKEN": "bt", "ADMIN_TOKEN": "adm", "RUN_ID": "test", "GW_MODE": mode,
           "IMMUNE_AUTH": json.dumps(auth), **(extra_env or {})}
    w.proc = spawn(["-m", "gateway"], env)
    w.url, w.admin = f"http://127.0.0.1:{data}", f"http://127.0.0.1:{admin}"
    wait_http(w.admin + "/_admin/health", headers=ADMIN)
    assert httpx.put(w.admin + "/_admin/pool", headers=ADMIN, json={"clones": [
        {"id": "c1", "addr": w.c1.addr, "key": "k1", "release": "t0"}]}).status_code == 200
    return w


def stop(w):
    kill(w.proc)
    for s in (w.prod, w.bus, w.c1):
        s.stop()


def records(w):
    for _ in range(40):
        if w.record.exists() and w.record.read_text().strip():
            break
        time.sleep(0.05)
    return [json.loads(l) for l in w.record.read_text().splitlines() if l.strip()]


def wait_events(w, typ, n=1, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        got = [e for e in w.events if e.get("type") == typ]
        if len(got) >= n:
            return got
        time.sleep(0.05)
    return [e for e in w.events if e.get("type") == typ]


def bearer(t):
    return {"authorization": "Bearer " + t}
