"""Gateway state and the three ASGI apps (data, admin, clone ingest)."""
from __future__ import annotations

import asyncio
import base64
import hmac
import http.cookiejar
import json
import logging
import os
import re
import secrets
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from immune_contracts import authtoken, events, wire

from . import l0
from .classifier import (CAPTIVE, CLEAN, EVIDENCE, SUSPECT, EnumTracker, Manifest, Result, Rule, View, Who, is_builtin_rule,
                         classify, redact_form, redact_json, redact_query, REDACTED)
from .pool import Clone, Pool
from .bus import Bus

log = logging.getLogger("gateway")

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length", "proxy-connection"}
RESP_DROP = HOP | {"content-encoding", "date", "server"}
DENY_BODY = b'{"detail":"Not Found"}'
SID_RE = re.compile(r"[A-Za-z0-9_\-]{16,64}")
MAX_BODY = 10 * 1024 * 1024
CLONE_WAIT_S = 0.3


class _NoJar(http.cookiejar.CookieJar):
    """A proxy must never keep upstream cookies between clients."""
    def set_cookie(self, cookie):  # noqa: D401
        return None

    def extract_cookies(self, response, request):
        return None


@dataclass
class Config:
    host: str = "0.0.0.0"
    data_port: int = 8080
    admin_port: int = 8081
    ingest_port: int = 9000
    prod_addr: str = "127.0.0.1:8000"
    prod_release: str = ""
    prod_secret: str = ""
    shadow_secret: str = ""
    admin_token: str = ""
    bus_url: str = ""
    bus_token: str = ""
    run_id: str = ""
    openapi_path: str = ""
    manifest_path: str = ""
    record_path: str = ""
    captive_ttl_s: float = 900.0

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        g = env.get
        return cls(host=g("GW_HOST", "0.0.0.0"), data_port=int(g("GW_DATA_PORT", "8080")),
                   admin_port=int(g("GW_ADMIN_PORT", "8081")), ingest_port=int(g("GW_INGEST_PORT", "9000")),
                   prod_addr=g("PROD_ADDR", "127.0.0.1:8000"), prod_release=g("PROD_RELEASE", ""),
                   prod_secret=g("PROD_APP_SECRET", ""), shadow_secret=g("SHADOW_APP_SECRET", ""),
                   admin_token=g("ADMIN_TOKEN", ""), bus_url=g("BUS_URL", ""), bus_token=g("BUS_TOKEN", ""),
                   run_id=g("RUN_ID", ""), openapi_path=g("OPENAPI_PATH", ""), manifest_path=g("MANIFEST_PATH", ""),
                   record_path=g("RECORD_PATH", ""), captive_ttl_s=float(g("GW_CAPTIVE_TTL_S", "900")))


@dataclass
class Upstream:
    status: int
    headers: list            # [(name, value)] lower-case names
    body: bytes
    verdict: str | None = None


@dataclass
class Ctx:
    rid: str
    t0: float
    method: str
    raw_path: str
    query: str
    headers: list            # filtered client headers [(k, v)]
    hmap: dict
    body: bytes
    who: Who
    session: str
    cookie_session: str | None
    new_sid: str | None
    res: Result = field(default_factory=Result)
    route: str = "prod"
    verdict: str | None = None
    status: int = 0


class Recorder:
    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def write(self, rec: dict):
        if not self.path:
            return
        try:
            if self._fh is None:
                d = os.path.dirname(self.path)
                if d:
                    os.makedirs(d, exist_ok=True)
                self._fh = open(self.path, "a", buffering=1)
            self._fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        except Exception as e:  # recording must never break traffic
            log.warning("recording failed: %s", e)
            self._fh = None


class Gateway:
    def __init__(self, cfg: Config):
        from .spec import Spec
        self.cfg = cfg
        self.spec = Spec.load(cfg.openapi_path)
        self.manifest = Manifest()
        self._manifest_mtime = None
        self.reload_manifest(force=True)
        self.bus = Bus(cfg.bus_url, cfg.bus_token, cfg.run_id)
        self.pool = Pool(idle_ttl_s=cfg.captive_ttl_s, on_release=self._on_release)
        self.rules: dict[str, Rule] = {}
        self.enum = EnumTracker()
        self.mode = "enforce"
        self.recorder = Recorder(cfg.record_path)
        self.prodlog: OrderedDict = OrderedDict()
        self.rid_ctx: OrderedDict = OrderedDict()
        # upstream + drain
        self.upstream = {"addr": cfg.prod_addr, "release": cfg.prod_release}
        self.inflight = 0
        self.gate = None          # asyncio.Event: open when not switching
        self.idle = None          # asyncio.Event: set when inflight == 0
        self.switch_lock = None
        self.stats = self._new_stats()
        self.prod_client = None
        self.clone_client = None
        self._tasks = []

    # ---------------------------------------------------------- lifecycle
    async def start(self):
        self.gate = asyncio.Event(); self.gate.set()
        self.idle = asyncio.Event(); self.idle.set()
        self.switch_lock = asyncio.Lock()
        limits = httpx.Limits(max_connections=256, max_keepalive_connections=64)
        self.prod_client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=3.0), limits=limits,
                                             trust_env=False, cookies=_NoJar(), follow_redirects=False)
        self.clone_client = httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=1.0), limits=limits,
                                              trust_env=False, cookies=_NoJar(), follow_redirects=False)
        self.bus.start()
        self._tasks.append(asyncio.create_task(self._housekeeping()))

    async def stop(self):
        for t in self._tasks:
            t.cancel()
        await self.bus.stop()
        for c in (self.prod_client, self.clone_client):
            if c is not None:
                await c.aclose()

    async def _housekeeping(self):
        n = 0
        while True:
            await asyncio.sleep(0.5)
            try:
                self.expire_rules()
                n += 1
                if n % 10 == 0:
                    await self.pool.expire_idle()
                    self.reload_manifest()
            except Exception as e:
                log.warning("housekeeping: %s", e)

    def _new_stats(self) -> dict:
        return {"prod_requests": 0, "prod_5xx": 0, "prod_conn_errors": 0, "requests": 0,
                "by_class": {}, "by_route": {}, "since": time.time(),
                "release": self.upstream["release"] if hasattr(self, "upstream") else "",
                "addr": self.upstream["addr"] if hasattr(self, "upstream") else ""}

    def reload_manifest(self, force: bool = False):
        path = self.cfg.manifest_path
        try:
            mtime = os.stat(path).st_mtime if path else None
        except OSError:
            mtime = None
        if force or mtime != self._manifest_mtime:
            self.manifest = Manifest.load(path) if mtime is not None else Manifest()
            self._manifest_mtime = mtime

    def _on_release(self, session, clone, reason):
        self.bus.publish(events.SESSION_RELEASED, {"session": session, "clone": clone, "reason": reason})

    # ---------------------------------------------------------- rules
    def active_rules(self) -> list[Rule]:
        now = time.time()
        return [r for r in self.rules.values() if r.expires > now]

    def expire_rules(self):
        now = time.time()
        for rid, r in list(self.rules.items()):
            if r.expires <= now:
                del self.rules[rid]
                self.bus.publish(events.RULE_EXPIRED, {"id": rid, "reason": "ttl"})

    # ---------------------------------------------------------- identity
    def identify(self, hmap: dict) -> Who:
        token = authtoken.bearer(hmap)
        if not token:
            return Who()
        ident = authtoken.verify(self.cfg.prod_secret, token) if self.cfg.prod_secret else None
        if ident is not None:
            return Who(uid=ident.uid, role=ident.role, trusted=ident.uid <= self.manifest.seed_max_uid)
        # shadow-secret token arriving from outside = honeytoken (expired ones too: now=0)
        if self.cfg.shadow_secret and authtoken.verify(self.cfg.shadow_secret, token, now=0) is not None:
            return Who(honeytoken=True)
        return Who()

    # ---------------------------------------------------------- data plane
    async def data_app(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        try:
            ctx = await self._read(scope, receive)
        except ValueError:
            await self._send(send, Upstream(413, [("content-type", "application/json")], b'{"detail":"Request Entity Too Large"}'), None)
            return
        try:
            resp = await self.handle(ctx)
        except Exception as e:  # never crash a request: fail-open is not safe here, so deny
            log.exception("handler error rid=%s: %s", ctx.rid, e)
            ctx.route, resp = "deny", self.deny()
        ctx.status = resp.status
        await self._send(send, resp, ctx.new_sid)
        self._finish(ctx)

    async def _read(self, scope, receive) -> Ctx:
        chunks, size = [], 0
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                break
            b = msg.get("body", b"")
            size += len(b)
            if size > MAX_BODY:
                raise ValueError("body too large")
            chunks.append(b)
            if not msg.get("more_body"):
                break
        body = b"".join(chunks)
        raw_path = scope.get("raw_path")
        raw_path = raw_path.decode("latin-1") if raw_path else quote(scope.get("path", "/"))
        query = (scope.get("query_string") or b"").decode("latin-1")
        headers = []
        for k, v in scope.get("headers", []):
            name = k.decode("latin-1").lower()
            if name.startswith(wire.INTERNAL_PREFIX):
                continue
            headers.append((name, v.decode("latin-1")))
        hmap: dict = {}
        for k, v in headers:
            hmap[k] = (hmap[k] + "; " + v) if (k == "cookie" and k in hmap) else v
        sid = _cookie(hmap.get("cookie", ""), "gwsid")
        new_sid = None
        if not sid or not SID_RE.fullmatch(sid):
            sid = new_sid = secrets.token_urlsafe(18)
        who = self.identify(hmap)
        cookie_session = f"gwsid:{sid}"
        session = f"uid:{who.uid}" if who.uid is not None else cookie_session
        return Ctx(rid=uuid.uuid4().hex, t0=time.monotonic(), method=scope["method"].upper(), raw_path=raw_path,
                   query=query, headers=headers, hmap=hmap, body=body, who=who, session=session,
                   cookie_session=cookie_session, new_sid=new_sid)

    async def handle(self, ctx: Ctx) -> Upstream:
        self.reload_manifest()
        if ctx.who.uid is not None:   # trust may change with a reloaded manifest
            ctx.who.trusted = ctx.who.uid <= self.manifest.seed_max_uid
        view = View(ctx.method, ctx.raw_path, ctx.query, ctx.hmap, ctx.body)

        if self.mode == "passthrough":
            ctx.res = classify(view, self.spec, ctx.who, self.manifest, self.active_rules(), ctx.session, None)
            return await self.to_prod(ctx)

        # 3. captive session -> its (lazily bound) L2 clone; never for a trusted identity
        if not ctx.who.trusted:
            cap = self.pool.captive_session(ctx.session)
            if cap is None and ctx.who.uid is not None:
                cap = self.pool.captive_session(ctx.cookie_session)
            if cap is not None:
                ctx.res = classify(view, self.spec, ctx.who, self.manifest, self.active_rules(), ctx.session, None)
                ctx.res.cls, ctx.res.reasons = CAPTIVE, ["captive"] + ctx.res.reasons
                self._publish_classified(ctx)
                return await self.captive(ctx, cap)

        # 4. L0 scanner paths (only if the app does not define the route)
        if l0.is_scanner_path(ctx.raw_path) and self.spec.match(ctx.method, ctx.raw_path)[0] is None:
            ctx.res = Result(cls=SUSPECT, reasons=["scanner"])
            self._publish_classified(ctx)
            ctx.route = "l0"
            status, ctype, body = l0.respond(ctx.raw_path, ctx.session)
            return Upstream(status, [("content-type", ctype)], body)

        # 5. classify
        ctx.res = classify(view, self.spec, ctx.who, self.manifest, self.active_rules(), ctx.session, self.enum)
        self._publish_classified(ctx)
        if ctx.res.cls == CLEAN:
            return await self.to_prod(ctx)
        if ctx.res.cls == EVIDENCE:
            return await self.evidence(ctx)
        return await self.detonate(ctx)

    # -- step 7
    async def detonate(self, ctx: Ctx) -> Upstream:
        builtin = is_builtin_rule(ctx.res.reasons)
        fail_closed = bool(ctx.res.rule_hit) or builtin or _high_signal(ctx.res.reasons)
        clone = await self.pool.acquire(CLONE_WAIT_S)
        if clone is None:
            await self._evict_oldest(ctx)
            ctx.verdict = "no_clone"
            return self.deny(ctx) if fail_closed else await self.to_prod(ctx)
        try:
            async with clone.lock:
                up = await self.to_clone(ctx, clone, "L1")
        except Exception as e:
            log.warning("clone %s failed: %s", clone.id, e)
            await self.pool.retire(clone)
            ctx.verdict = "no_clone"
            return self.deny(ctx) if fail_closed else await self.to_prod(ctx)
        ctx.verdict = up.verdict
        # L1: the wrapper already reset the clone, whatever the verdict
        await self.pool.release(clone)
        if up.verdict == wire.VERDICT_ORACLE:
            if ctx.who.trusted:
                return self.deny(ctx)
            self._mark_captive(ctx, "oracle")      # lazy: no clone held until the next request
            ctx.route = "shadow_l1"
            return up
        if builtin:   # a '..' path segment never reaches prod: no oracle sees every file, and browsers never send one
            return self.deny(ctx)
        if up.verdict == wire.VERDICT_CLEAN:
            return await self.to_prod(ctx)
        return self.deny(ctx) if ctx.res.rule_hit else await self.to_prod(ctx)   # inconclusive / unknown

    # -- step 8, evidence without detonation: mark captive, bind now, replay in L2
    async def evidence(self, ctx: Ctx) -> Upstream:
        if ctx.who.trusted:
            return self.deny(ctx)
        cap = self._mark_captive(ctx, ctx.res.reasons[0] if ctx.res.reasons else "evidence")
        return await self.captive(ctx, cap)

    async def captive(self, ctx: Ctx, cap) -> Upstream:
        """Serve a captive session from its bound clone, binding one first if needed. Never prod."""
        ctx.route = "shadow_l2"
        async with cap.lock:
            clone = self.pool.bound_clone(cap)
            if clone is None:
                clone = await self.pool.acquire(CLONE_WAIT_S)
                if clone is None and await self._evict_oldest(ctx) is not None:
                    clone = await self.pool.acquire(CLONE_WAIT_S)
                if clone is None or not self.pool.bind(clone, cap):
                    if clone is not None:
                        await self.pool.release(clone)
                    ctx.verdict = "no_clone"
                    return self.deny(ctx)
                self.bus.publish(events.SESSION_CAPTURED, {"session": cap.session, "clone": clone.id, "reason": "bound"},
                                 rid=ctx.rid)
        try:
            async with clone.lock:
                if clone.session != cap.session or clone.state != "captive":
                    return self.deny(ctx)
                self.pool.touch(cap, clone)
                up = await self.to_clone(ctx, clone, "L2")
                self.pool.touch(cap, clone)
        except Exception as e:
            log.warning("captive clone %s failed: %s", clone.id, e)
            await self.pool.retire(clone)
            return self.deny(ctx)
        ctx.verdict = up.verdict
        return up

    def _mark_captive(self, ctx: Ctx, reason: str):
        cap, created = self.pool.mark_captive(ctx.session)
        if created:
            self.bus.publish(events.SESSION_CAPTURED, {"session": ctx.session, "clone": None, "reason": reason},
                             rid=ctx.rid)
        return cap

    async def _evict_oldest(self, ctx: Ctx):
        clone = await self.pool.evict_oldest()
        if clone is not None:
            log.info("evicted clone %s (rid=%s)", clone.id, ctx.rid)
        return clone

    def deny(self, ctx: Ctx | None = None) -> Upstream:
        if ctx is not None:
            ctx.route = "deny"
        return Upstream(404, [("content-type", "application/json")], DENY_BODY)

    # ---------------------------------------------------------- upstream calls
    def _url(self, addr: str, ctx: Ctx) -> httpx.URL:
        host, _, port = addr.rpartition(":")
        if not host:
            host, port = addr, "80"
        raw = ctx.raw_path + ("?" + ctx.query if ctx.query else "")
        return httpx.URL(scheme="http", host=host, port=int(port), raw_path=raw.encode("latin-1"))

    def _target(self, ctx: Ctx) -> dict:
        """Forward the client's request target byte for byte: httpx would otherwise resolve dot segments
        ('/a/../b' -> '/b'), so clones would never see the request that prod would have received."""
        return {"target": (ctx.raw_path + ("?" + ctx.query if ctx.query else "")).encode("latin-1")}

    def _out_headers(self, ctx: Ctx) -> list:
        return [(k, v) for k, v in ctx.headers if k not in HOP]

    async def to_prod(self, ctx: Ctx) -> Upstream:
        ctx.route = "prod"
        await self.gate.wait()
        self.inflight += 1
        self.idle.clear()
        addr = self.upstream["addr"]
        try:
            try:
                req = self.prod_client.build_request(ctx.method, self._url(addr, ctx), headers=self._out_headers(ctx),
                                                     content=ctx.body if ctx.body else None,
                                                     extensions=self._target(ctx))
                r = await self.prod_client.send(req)
                up = Upstream(r.status_code, _clean_resp_headers(r.headers.multi_items()), r.content)
            except httpx.TimeoutException:
                self.stats["prod_conn_errors"] += 1
                up = Upstream(504, [("content-type", "application/json")], b'{"detail":"Gateway Timeout"}')
            except Exception:
                self.stats["prod_conn_errors"] += 1
                up = Upstream(502, [("content-type", "application/json")], b'{"detail":"Bad Gateway"}')
            self.stats["prod_requests"] += 1
            if up.status >= 500:
                self.stats["prod_5xx"] += 1
            self._prodlog(ctx.rid, {"forwarded": True, "status": up.status})
            return up
        finally:
            self.inflight -= 1
            if self.inflight == 0:
                self.idle.set()

    async def to_clone(self, ctx: Ctx, clone: Clone, mode: str) -> Upstream:
        headers = self._out_headers(ctx) + [(wire.H_RID, ctx.rid), (wire.H_MODE, mode)]
        if ctx.who.uid is not None:
            headers += [(wire.H_UID, str(ctx.who.uid)), (wire.H_ROLE, ctx.who.role or "user")]
        self.rid_ctx[ctx.rid] = (ctx.session, ctx.who.uid)
        while len(self.rid_ctx) > 20000:
            self.rid_ctx.popitem(last=False)
        req = self.clone_client.build_request(ctx.method, self._url(clone.addr, ctx), headers=headers,
                                              content=ctx.body if ctx.body else None, extensions=self._target(ctx))
        r = await self.clone_client.send(req)
        verdict = (r.headers.get(wire.H_VERDICT) or "").strip().lower()
        if verdict not in wire.VERDICTS:
            verdict = wire.VERDICT_INCONCLUSIVE   # no explicit confirmation = inconclusive
        return Upstream(r.status_code, _clean_resp_headers(r.headers.multi_items()), r.content, verdict)

    def _prodlog(self, rid: str, entry: dict):
        self.prodlog[rid] = entry
        while len(self.prodlog) > 50000:
            self.prodlog.popitem(last=False)

    # ---------------------------------------------------------- output
    async def _send(self, send, up: Upstream, new_sid: str | None):
        headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in up.headers]
        headers.append((b"content-length", str(len(up.body)).encode()))
        if new_sid:
            headers.append((b"set-cookie", f"gwsid={new_sid}; Path=/; HttpOnly; SameSite=Lax".encode()))
        await send({"type": "http.response.start", "status": up.status, "headers": headers})
        await send({"type": "http.response.body", "body": up.body})

    def _publish_classified(self, ctx: Ctx):
        self.bus.publish(events.REQ_CLASSIFIED, {"class": ctx.res.cls, "reasons": list(ctx.res.reasons),
                                                 "method": ctx.method, "path": ctx.raw_path,
                                                 "session": ctx.session, "uid": ctx.who.uid}, rid=ctx.rid)

    def _finish(self, ctx: Ctx):
        ms = round((time.monotonic() - ctx.t0) * 1000, 1)
        if ctx.rid not in self.prodlog:
            self._prodlog(ctx.rid, {"forwarded": False, "status": None})
        st = self.stats
        st["requests"] += 1
        st["by_class"][ctx.res.cls] = st["by_class"].get(ctx.res.cls, 0) + 1
        st["by_route"][ctx.route] = st["by_route"].get(ctx.route, 0) + 1
        self.bus.publish(events.REQ_ROUTED, {"route": ctx.route, "status": ctx.status, "verdict": ctx.verdict, "ms": ms},
                         rid=ctx.rid)
        self.recorder.write(self._record(ctx, ms))

    def _record(self, ctx: Ctx, ms: float) -> dict:
        sens = ctx.res.sensitive or {}
        headers = {}
        for k, v in ctx.headers:
            headers[k] = REDACTED if k in ("authorization", "cookie", "proxy-authorization") else v
        body = ctx.body
        ctype = (ctx.hmap.get("content-type") or "").lower()
        if body and sens.get("json"):
            body = redact_json(body, sens["json"])
        elif body and sens.get("form") and "x-www-form-urlencoded" in ctype:
            body = redact_form(body, sens["form"])
        return {"rid": ctx.rid, "ts": time.time(), "session": ctx.session, "uid": ctx.who.uid,
                "trusted": ctx.who.trusted, "method": ctx.method, "path": ctx.raw_path,
                "query": redact_query(ctx.query, sens.get("query") or set()), "headers": headers,
                "body_b64": base64.b64encode(body).decode(), "class": ctx.res.cls, "reasons": list(ctx.res.reasons),
                "route": ctx.route, "verdict": ctx.verdict, "status": ctx.status, "ms": ms,
                "release": self.upstream["release"], "mode": self.mode}

    # ---------------------------------------------------------- admin
    async def switch_upstream(self, addr: str, release: str):
        async with self.switch_lock:
            self.gate.clear()
            try:
                try:
                    await asyncio.wait_for(self.idle.wait(), timeout=30.0)
                except asyncio.TimeoutError:
                    log.warning("drain timeout; switching with %d in flight", self.inflight)
                self.upstream = {"addr": addr, "release": release}
                self.stats = self._new_stats()
            finally:
                self.gate.set()
        self.bus.publish(events.UPSTREAM_SWITCHED, {"release": release, "addr": addr})

    async def reset(self):
        await self.pool.release_all_sessions("reset")
        for rid in list(self.rules):
            self.bus.publish(events.RULE_EXPIRED, {"id": rid, "reason": "reset"})
        self.rules.clear()
        self.enum.clear()
        self.prodlog.clear()
        self.rid_ctx.clear()
        self.stats = self._new_stats()
        self.reload_manifest(force=True)

    def admin_app(self) -> Starlette:
        gw = self

        def authed(fn):
            async def wrapper(request: Request):
                tok = request.headers.get("x-admin-token", "")
                if not gw.cfg.admin_token or not hmac.compare_digest(tok.encode(), gw.cfg.admin_token.encode()):
                    return JSONResponse({"detail": "forbidden"}, status_code=403)
                return await fn(request)
            return wrapper

        async def body_json(request: Request):
            try:
                return await request.json()
            except Exception:
                return None

        @authed
        async def health(request):
            return JSONResponse({"ok": True, "mode": gw.mode, "upstream": gw.upstream, "pool": gw.pool.counts()})

        @authed
        async def pool_get(request):
            return JSONResponse({"clones": gw.pool.snapshot()})

        @authed
        async def pool_put(request):
            d = await body_json(request)
            clones = (d or {}).get("clones") if isinstance(d, dict) else None
            if not isinstance(clones, list) or not all(isinstance(c, dict) and c.get("id") and c.get("addr") for c in clones):
                return JSONResponse({"detail": "body must be {clones:[{id,addr,key,release}]}"}, status_code=422)
            await gw.pool.set_clones(clones)
            return JSONResponse({"clones": gw.pool.snapshot()})

        @authed
        async def rules_get(request):
            now = time.time()
            return JSONResponse({"rules": [r.to_dict(now) for r in gw.active_rules()]})

        @authed
        async def rules_post(request):
            d = await body_json(request)
            items = d if isinstance(d, list) else [d]
            created = []
            for item in items:
                try:
                    rule = Rule(item)
                except Exception as e:
                    return JSONResponse({"detail": f"invalid rule: {e}"}, status_code=422)
                created.append(rule)
            for rule in created:
                gw.rules[rule.id] = rule
                gw.bus.publish(events.RULE_ACTIVE, rule.to_dict(), incident=rule.raw.get("incident"))
            out = [r.to_dict() for r in created]
            return JSONResponse(out[0] if not isinstance(d, list) else out, status_code=201)

        @authed
        async def rules_delete(request):
            rid = request.path_params["rid"]
            if gw.rules.pop(rid, None) is None:
                return JSONResponse({"detail": "Not Found"}, status_code=404)
            gw.bus.publish(events.RULE_EXPIRED, {"id": rid, "reason": "deleted"})
            return JSONResponse({"ok": True, "id": rid})

        @authed
        async def upstream_get(request):
            return JSONResponse(dict(gw.upstream))

        @authed
        async def upstream_post(request):
            d = await body_json(request)
            if not isinstance(d, dict) or not isinstance(d.get("addr"), str) or not d["addr"]:
                return JSONResponse({"detail": "body must be {addr, release}"}, status_code=422)
            await gw.switch_upstream(d["addr"], str(d.get("release") or ""))
            return JSONResponse(dict(gw.upstream))

        @authed
        async def sessions(request):
            return JSONResponse({"captive": gw.pool.captives()})

        @authed
        async def mode(request):
            d = await body_json(request)
            m = d.get("mode") if isinstance(d, dict) else None
            if m not in ("enforce", "passthrough"):
                return JSONResponse({"detail": "mode must be enforce|passthrough"}, status_code=422)
            gw.mode = m
            return JSONResponse({"mode": gw.mode})

        @authed
        async def prodlog(request):
            rid = request.query_params.get("rid", "")
            return JSONResponse(gw.prodlog.get(rid) or {"forwarded": False, "status": None})

        @authed
        async def stats(request):
            st = dict(gw.stats)
            st["pool"] = gw.pool.counts()
            st["captive"] = len(gw.pool.captives())
            st["rules"] = len(gw.active_rules())
            st["mode"] = gw.mode
            st["bus_dropped"] = gw.bus.dropped
            return JSONResponse(st)

        @authed
        async def reset(request):
            await gw.reset()
            return JSONResponse({"ok": True})

        return Starlette(routes=[
            Route("/_admin/health", health, methods=["GET"]),
            Route("/_admin/pool", pool_get, methods=["GET"]),
            Route("/_admin/pool", pool_put, methods=["PUT"]),
            Route("/_admin/rules", rules_get, methods=["GET"]),
            Route("/_admin/rules", rules_post, methods=["POST"]),
            Route("/_admin/rules/{rid}", rules_delete, methods=["DELETE"]),
            Route("/_admin/upstream", upstream_get, methods=["GET"]),
            Route("/_admin/upstream", upstream_post, methods=["POST"]),
            Route("/_admin/sessions", sessions, methods=["GET"]),
            Route("/_admin/mode", mode, methods=["POST"]),
            Route("/_admin/prodlog", prodlog, methods=["GET"]),
            Route("/_admin/stats", stats, methods=["GET"]),
            Route("/_admin/reset", reset, methods=["POST"]),
        ])

    # ---------------------------------------------------------- clone ingest
    def ingest_app(self) -> Starlette:
        gw = self

        async def evidence(request: Request):
            raw = await request.body()
            cid = request.headers.get(wire.H_CLONE_ID, "")
            clone = gw.pool.get(cid)
            if clone is None or not clone.key or not wire.check(clone.key, raw, request.headers.get(wire.H_SIGNATURE, "")):
                return JSONResponse({"detail": "forbidden"}, status_code=403)
            try:
                ev = json.loads(raw)
                assert isinstance(ev, dict)
            except Exception:
                return JSONResponse({"detail": "invalid json"}, status_code=400)
            data = dict(ev)
            data["clone"] = cid
            session, uid = gw.rid_ctx.get(str(ev.get("rid", "")), (None, None))
            data["session"] = session
            data["uid"] = uid if uid is not None else ev.get("uid")
            gw.bus.publish(events.ORACLE_FIRED, data, rid=str(ev.get("rid") or "") or None)
            return JSONResponse({"ok": True})

        return Starlette(routes=[Route("/_clone/evidence", evidence, methods=["POST"])])


def _high_signal(reasons) -> bool:
    """Schema/grammar violation, duplicated parameter or traversal (contract §6 step 7)."""
    return any(r.startswith(("schema:", "grammar:", "dup_query:", "traversal:")) for r in reasons)


def _cookie(header: str, name: str) -> str | None:
    for part in header.split(";"):
        k, _, v = part.strip().partition("=")
        if k == name:
            return v.strip().strip('"')
    return None


def _clean_resp_headers(items) -> list:
    return [(k.lower(), v) for k, v in items
            if k.lower() not in RESP_DROP and not k.lower().startswith(wire.INTERNAL_PREFIX)]
