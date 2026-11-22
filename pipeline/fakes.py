"""In-process fakes of the bus, gateway (admin + data plane) and fleet, for tests and the dry run.

They implement only the contract surface the pipeline uses (contracts/README.md §6, §8 and
immune_contracts/events.py) and record every call.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import threading
import time
import uuid

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from immune_contracts import events as E

from .bus import TYPES as BUS_TYPES


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ThreadServer:
    def __init__(self, app):
        self.port = free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning", interface="asgi3"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        end = time.time() + 10
        while not self.server.started and time.time() < end:
            time.sleep(0.02)
        self.url = "http://127.0.0.1:%d" % self.port

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=5)


class FakeBus:
    def __init__(self, token="t"):
        self.token = token
        self.events = []
        self.lock = threading.Lock()
        app = Starlette(routes=[Route("/events", self.post, methods=["POST"]), Route("/events", self.get, methods=["GET"]),
                                Route("/events/stream", self.stream, methods=["GET"])])
        self.srv = ThreadServer(app)
        self.url = self.srv.url

    def add(self, ev: dict) -> int:
        with self.lock:
            e = dict(ev)
            e["seq"] = len(self.events) + 1
            self.events.append(e)
            return e["seq"]

    async def post(self, request: Request):
        if request.headers.get("x-bus-token") != self.token:
            return JSONResponse({"error": "unauthorized"}, 401)
        body = json.loads(await request.body())
        items = body if isinstance(body, list) else [body]
        for it in items:
            if it.get("type") not in BUS_TYPES:
                return JSONResponse({"error": "unknown type"}, 400)
        return JSONResponse({"ok": True, "seqs": [self.add(it) for it in items]})

    async def get(self, request: Request):
        since = int(request.query_params.get("since") or 0)
        t = request.query_params.get("type")
        evs = [e for e in self.events if e["seq"] > since and (not t or e["type"].startswith(t))]
        return JSONResponse({"events": evs, "next": evs[-1]["seq"] if evs else len(self.events)})

    async def stream(self, request: Request):
        since = int(request.query_params.get("since") or 0)

        async def gen():
            last = since
            yield "retry: 1000\n\n"
            for _ in range(600):
                batch = [e for e in self.events if e["seq"] > last]
                for e in batch:
                    yield "id: %d\ndata: %s\n\n" % (e["seq"], json.dumps(e))
                    last = e["seq"]
                if not batch:
                    yield ": hb\n\n"
                    await asyncio.sleep(0.1)
        return StreamingResponse(gen(), media_type="text/event-stream")

    def pipeline_events(self):
        return [e for e in self.events if e.get("src") == "pipeline"]

    def stop(self):
        self.srv.stop()


class FakeGateway:
    """Admin API (rules, prodlog) and a data plane that forwards everything to "prod" and logs it on the bus."""

    def __init__(self, bus: FakeBus, token="adm", route="prod"):
        self.bus, self.token, self.route = bus, token, route
        self.rules, self.deleted, self.requests, self.prodlog = {}, [], [], {}
        admin = Starlette(routes=[Route("/_admin/rules", self.rules_post, methods=["POST"]),
                                  Route("/_admin/rules", self.rules_get, methods=["GET"]),
                                  Route("/_admin/rules/{rid}", self.rules_del, methods=["DELETE"]),
                                  Route("/_admin/prodlog", self.prodlog_get, methods=["GET"])])
        self.admin = ThreadServer(admin)
        self.data = ThreadServer(self.data_app)
        self.admin_url, self.data_url = self.admin.url, self.data.url

    def _ok(self, request):
        return request.headers.get("x-admin-token") == self.token

    async def rules_post(self, request):
        if not self._ok(request):
            return JSONResponse({"detail": "Not Found"}, 404)
        r = json.loads(await request.body())
        self.rules[r["id"]] = r
        self.bus.add(E.make(E.RULE_ACTIVE, "gateway", r, incident=r.get("incident")))
        return JSONResponse(r, 201)

    async def rules_get(self, request):
        return JSONResponse({"rules": list(self.rules.values())})

    async def rules_del(self, request):
        rid = request.path_params["rid"]
        if self.rules.pop(rid, None) is None:
            return JSONResponse({"detail": "Not Found"}, 404)
        self.deleted.append(rid)
        self.bus.add(E.make(E.RULE_EXPIRED, "gateway", {"id": rid, "reason": "deleted"}))
        return JSONResponse({"ok": True, "id": rid})

    async def prodlog_get(self, request):
        return JSONResponse(self.prodlog.get(request.query_params.get("rid", ""), {"forwarded": False, "status": None}))

    async def data_app(self, scope, receive, send):
        if scope["type"] != "http":
            return
        rid = uuid.uuid4().hex
        hdrs = {k.decode(): v.decode() for k, v in scope["headers"]}
        sid = None
        for part in hdrs.get("cookie", "").split(";"):
            if part.strip().startswith("gwsid="):
                sid = part.strip()[6:]
        new = sid is None
        sid = sid or uuid.uuid4().hex[:24]
        session = "gwsid:" + sid
        if hdrs.get("authorization"):
            from immune_contracts import authtoken
            tok = authtoken.bearer(hdrs)
            try:
                import base64
                payload = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "==="))
                session = "uid:%d" % payload["uid"]
            except Exception:  # noqa: BLE001
                pass
        raw = scope.get("raw_path", scope["path"].encode()).decode("latin-1").split("?")[0]
        self.requests.append({"rid": rid, "method": scope["method"], "path": raw,
                              "query": scope.get("query_string", b"").decode("latin-1"), "session": session})
        self.bus.add(E.make(E.REQ_CLASSIFIED, "gateway", {"class": "suspect", "reasons": [], "method": scope["method"],
                                                          "path": raw, "session": session, "uid": None}, rid=rid))
        self.bus.add(E.make(E.REQ_ROUTED, "gateway", {"route": self.route, "status": 404, "verdict": "clean", "ms": 1.0},
                            rid=rid))
        self.prodlog[rid] = {"forwarded": self.route == "prod", "status": 404}
        headers = [(b"content-type", b"application/json")]
        if new:
            headers.append((b"set-cookie", ("gwsid=%s; Path=/; HttpOnly" % sid).encode()))
        await send({"type": "http.response.start", "status": 404, "headers": headers})
        await send({"type": "http.response.body", "body": b'{"detail":"not found"}'})

    def stop(self):
        self.admin.stop()
        self.data.stop()


class FakeFleet:
    def __init__(self, bus: FakeBus, runtime_dir: str, token="adm", release="t0", outcome="ok"):
        self.bus, self.runtime, self.token = bus, runtime_dir, token
        self.release, self.outcome, self.deploys = release, outcome, []
        app = Starlette(routes=[Route("/deploy", self.deploy, methods=["POST"]), Route("/state", self.state, methods=["GET"])])
        self.srv = ThreadServer(app)
        self.url = self.srv.url

    async def deploy(self, request):
        if request.headers.get("x-admin-token") != self.token:
            return JSONResponse({"detail": "forbidden"}, 403)
        rel = json.loads(await request.body())["release"]
        self.deploys.append(rel)
        from immune import config as icfg
        if not icfg.current().release_complete(os.path.join(self.runtime, "releases", rel)):
            return JSONResponse({"detail": "unknown release"}, 404)
        self.bus.add(E.make(E.DEPLOY_STARTED, "fleet", {"release": rel}))
        if self.outcome == "rollback":
            res = {"ok": False, "rolled_back": True, "release": self.release, "detail": "prod_5xx grew after switch; rolled back"}
        else:
            self.release = rel
            res = {"ok": True, "rolled_back": False, "release": rel, "detail": "deployed"}
        self.bus.add(E.make(E.DEPLOY_DONE, "fleet", {"release": rel, "ok": res["ok"], "rolled_back": res["rolled_back"],
                                                     "detail": res["detail"]}))
        return JSONResponse(res)

    async def state(self, request):
        return JSONResponse({"prod": {"active": "blue", "release": self.release}, "clones": []})

    def stop(self):
        self.srv.stop()
