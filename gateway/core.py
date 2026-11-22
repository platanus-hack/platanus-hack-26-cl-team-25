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
from starlette.responses import JSONResponse
from starlette.routing import Route

from immune.auth import Authenticator, credential_key, prod_secret_for
from immune_contracts import authtoken, events, wire

from . import l0
from .classifier import (CAPTIVE, CLEAN, EVIDENCE, SUSPECT, EnumTracker, Manifest, Result, Rule, View, Who, is_builtin_rule,
                         classify, redact_form, redact_json, redact_multipart, redact_path, redact_query,
                         REDACTED)
from .pool import Clone, Pool
from .bus import Bus

log = logging.getLogger("gateway")

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length", "proxy-connection"}
RESP_DROP = HOP | {"content-encoding", "date", "server"}
DENY_BODY = b'{"detail":"Not Found"}'
SID_RE = re.compile(r"[A-Za-z0-9_\-]{16,64}")
MAX_BODY = 10 * 1024 * 1024
BODY_TIMEOUT_S = 30.0
RETRY_SAFE = ("GET", "HEAD", "OPTIONS")


class ClientGone(Exception):
    """The client disconnected before its request was complete: nothing to forward, nobody to answer."""


class BadRequest(Exception):
    """A request the gateway answers itself (4xx) because it cannot be read or forwarded as sent."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail
MODES = ("enforce", "observe", "passthrough")
CLONE_WAIT_S = 0.3
# after-check (contracts/product.md §3b): clean requests already answered by prod are replayed in a clone
AFTER_WAIT_S = 2.0        # how long a queued after-check waits for a free clone before it is given up
AFTER_QUEUE = 256         # pending after-checks; beyond this new ones are dropped (counted)
AFTER_SEEN = 4096         # identical requests (method, target, body, identity) are checked once per release


class _NoJar(http.cookiejar.CookieJar):
    """A proxy must never keep upstream cookies between clients."""
    # not dead code: httpx calls both on every response to fill its client-wide jar; overriding them keeps it empty
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
    state_path: str = ""             # upstream, rules and mode survive a gateway restart (same run only)
    captive_ttl_s: float = 900.0
    mode: str = "enforce"            # enforce | observe | passthrough (initial; POST /_admin/mode changes it)
    aftercheck: bool = False         # replay clean requests in a clone after prod has answered (enforce mode only)
    auth: dict = field(default_factory=lambda: {"kind": "immune-token"})   # the `auth` block of config.yaml

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        g = env.get
        try:
            auth = json.loads(g("IMMUNE_AUTH") or "{}") or {"kind": "immune-token"}
        except ValueError:
            auth = {"kind": "immune-token"}
        mode = g("GW_MODE", "enforce")
        return cls(mode=mode if mode in MODES else "enforce", auth=auth,
                   aftercheck=g("GW_AFTERCHECK", "").strip().lower() in ("1", "true", "yes", "on"),
                   prod_secret=prod_secret_for(auth, env), shadow_secret=g("SHADOW_APP_SECRET", ""),
                   host=g("GW_HOST", "0.0.0.0"), data_port=int(g("GW_DATA_PORT", "8080")),
                   admin_port=int(g("GW_ADMIN_PORT", "8081")), ingest_port=int(g("GW_INGEST_PORT", "9000")),
                   prod_addr=g("PROD_ADDR", "127.0.0.1:8000"), prod_release=g("PROD_RELEASE", ""),
                   admin_token=g("ADMIN_TOKEN", ""), bus_url=g("BUS_URL", ""), bus_token=g("BUS_TOKEN", ""),
                   run_id=g("RUN_ID", ""), openapi_path=g("OPENAPI_PATH", ""), manifest_path=g("MANIFEST_PATH", ""),
                   record_path=g("RECORD_PATH", ""), state_path=g("GW_STATE_PATH", ""),
                   captive_ttl_s=float(g("GW_CAPTIVE_TTL_S", "900")))


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
    would: str | None = None          # observe mode: the route enforce would have taken


class Recorder:
    """Append-only request log. Bounded: past `max_bytes` the file becomes <path>.1 (one generation kept) and a
    new one starts, so the recording never fills the disk. Readers use the tail (pipeline/gates.py)."""

    def __init__(self, path: str, max_bytes: int | None = None):
        self.path = path
        self._fh = None
        self._size = 0
        if max_bytes is None:
            try:
                max_bytes = int(float(os.environ.get("RECORD_MAX_MB") or 256) * 1024 * 1024)
            except ValueError:
                max_bytes = 256 * 1024 * 1024
        self.max_bytes = max_bytes

    def write(self, rec: dict):
        if not self.path:
            return
        try:
            if self._fh is None:
                d = os.path.dirname(self.path)
                if d:
                    os.makedirs(d, exist_ok=True)
                self._fh = open(self.path, "a", buffering=1)
                self._size = os.fstat(self._fh.fileno()).st_size
            line = json.dumps(rec, separators=(",", ":")) + "\n"
            self._fh.write(line)
            self._size += len(line)
            if self.max_bytes > 0 and self._size >= self.max_bytes:
                self._fh.close()
                self._fh = None
                os.replace(self.path, self.path + ".1")
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
        self.mode = cfg.mode if cfg.mode in MODES else "enforce"
        self.auth = Authenticator(cfg.auth, cfg.prod_secret, cfg.shadow_secret)
        self._introspect_cache: OrderedDict = OrderedDict()   # credential hash -> (expires, Who fields)
        self.recorder = Recorder(cfg.record_path)
        self.prodlog: OrderedDict = OrderedDict()
        self.rid_ctx: OrderedDict = OrderedDict()
        self.after_q = None       # asyncio.Queue of Ctx, created in start() when cfg.aftercheck
        self.after_seen: OrderedDict = OrderedDict()
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
        self._saved = None
        self.restore_state()

    # ---------------------------------------------------------- persisted state
    # A restarted gateway would otherwise point at the compose default upstream (a colour that may no longer
    # exist) and forget every containment rule, reopening confirmed attack points until the fleet and the
    # pipeline noticed. Kept in <runtime>/stack/gateway-state.json, valid for the run that wrote it.
    def _state_doc(self) -> dict:
        return {"run_id": self.cfg.run_id, "upstream": dict(self.upstream), "mode": self.mode,
                "rules": [dict(r.raw, _expires=r.expires) for r in self.rules.values()]}

    def save_state(self) -> None:
        path = self.cfg.state_path
        if not path:
            return
        doc = self._state_doc()
        if doc == self._saved:
            return
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(doc, f)
            os.replace(tmp, path)
            self._saved = doc
        except OSError as e:
            log.warning("cannot persist gateway state at %s: %s", path, e)

    def restore_state(self) -> bool:
        path = self.cfg.state_path
        if not path:
            return False
        try:
            with open(path) as f:
                doc = json.load(f)
        except (OSError, ValueError):
            return False
        if not isinstance(doc, dict) or doc.get("run_id") != self.cfg.run_id:
            return False
        up = doc.get("upstream")
        if isinstance(up, dict) and isinstance(up.get("addr"), str) and up["addr"]:
            self.upstream = {"addr": up["addr"], "release": str(up.get("release") or "")}
        if doc.get("mode") in MODES:
            self.mode = doc["mode"]
        now = time.time()
        for raw in doc.get("rules") or []:
            try:
                raw = dict(raw)
                expires = float(raw.pop("_expires"))
                if expires <= now:
                    continue
                rule = Rule(raw)
                rule.expires = expires
                self.rules[rule.id] = rule
            except Exception as e:  # noqa: BLE001
                log.warning("dropping an unreadable persisted rule: %s", e)
        self.stats = self._new_stats()
        self._saved = self._state_doc()
        log.info("restored state of run %s: upstream %s (%s), mode %s, %d rule(s)", self.cfg.run_id,
                 self.upstream["addr"], self.upstream["release"], self.mode, len(self.rules))
        return True

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
        if self.cfg.aftercheck:
            self.after_q = asyncio.Queue(maxsize=AFTER_QUEUE)
            # one worker: the after-check never holds more than one clone, the rest stay free for detonation
            self._tasks.append(asyncio.create_task(self._after_worker()))

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
                self.save_state()
                n += 1
                if n % 10 == 0:
                    await self.pool.expire_idle()
                    self.reload_manifest()
            except Exception as e:
                log.warning("housekeeping: %s", e)

    def _new_stats(self) -> dict:
        return {"prod_requests": 0, "prod_5xx": 0, "prod_conn_errors": 0, "requests": 0,
                "by_class": {}, "by_route": {}, "since": time.time(),
                "aftercheck": {"queued": 0, "checked": 0, "oracle": 0, "duplicate": 0, "dropped": 0, "no_clone": 0},
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
        """Identity from the request's own credentials (no network). Introspection: see resolve()."""
        ident = self.auth.from_token(authtoken.bearer(hmap))
        if ident.honeytoken:
            return Who(honeytoken=True)
        if ident.uid is not None:
            return Who(uid=ident.uid, role=ident.role, trusted=ident.uid <= self.manifest.seed_max_uid)
        return Who()

    async def resolve(self, hmap: dict) -> Who:
        if self.auth.kind != "introspect":
            return self.identify(hmap)
        authz = hmap.get("authorization", "")
        cookie = _strip_cookie(hmap.get("cookie", ""), "gwsid")
        if not authz and not cookie:
            return Who()
        key = credential_key(authz, cookie)
        now = time.monotonic()
        hit = self._introspect_cache.get(key)
        if hit is not None and hit[0] > now:
            uid, role = hit[1]
        else:
            uid, role = await self._introspect(authz, cookie)
            ttl = self.auth.cache_s if uid is not None else min(self.auth.cache_s, 5.0)
            self._introspect_cache[key] = (now + ttl, (uid, role))
            while len(self._introspect_cache) > 10000:
                self._introspect_cache.popitem(last=False)
        if uid is None:
            return Who()
        return Who(uid=uid, role=role, trusted=uid <= self.manifest.seed_max_uid)

    async def _introspect(self, authz: str, cookie: str):
        """GET <auth.path> on PROD with the client's credentials -> (uid, role) or (None, None)."""
        headers = [("accept", "application/json")]
        if authz:
            headers.append(("authorization", authz))
        if cookie:
            headers.append(("cookie", cookie))
        host, _, port = self.upstream["addr"].rpartition(":")
        try:
            url = httpx.URL(scheme="http", host=host or self.upstream["addr"], port=int(port or 80),
                            raw_path=self.auth.path.encode("latin-1"))
            r = await self.prod_client.get(url, headers=headers, timeout=3.0)
            ident = self.auth.from_introspection(r.status_code, r.content)
        except Exception as e:  # noqa: BLE001
            log.warning("introspection failed: %s", e)
            return None, None
        return ident.uid, ident.role

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
        except ClientGone:
            return        # a truncated body is never forwarded as if it were the whole request
        except BadRequest as e:
            # refused before it reaches production or a clone: not a production error (never counted as one)
            await self._send(send, Upstream(e.status, [("content-type", "application/json"), ("connection", "close")],
                                            json.dumps({"detail": e.detail}).encode()), None)
            return
        try:
            resp = await self.handle(ctx)
        except Exception as e:  # never crash a request: fail-open is not safe here, so deny
            log.exception("handler error rid=%s: %s", ctx.rid, e)
            ctx.route, resp = "deny", self.deny()
        ctx.status = resp.status
        await self._send(send, resp, ctx.new_sid)
        self._finish(ctx)
        self._after_enqueue(ctx)

    async def _read(self, scope, receive) -> Ctx:
        raw_path = scope.get("raw_path")
        raw_path = raw_path.decode("latin-1") if raw_path else quote(scope.get("path", "/"))
        if not raw_path.startswith("/"):                 # absolute-form or authority-form target: we are not a forward proxy
            raise BadRequest(400, "Bad Request")
        for k, v in scope.get("headers", []):
            if k.lower() == b"content-length":
                try:
                    if int(v) > MAX_BODY:
                        raise BadRequest(413, "Request Entity Too Large")
                except ValueError:
                    raise BadRequest(400, "Bad Request") from None
        chunks, size = [], 0
        deadline = time.monotonic() + BODY_TIMEOUT_S     # a client that never finishes its body does not hold a slot
        while True:
            try:
                msg = await asyncio.wait_for(receive(), timeout=max(0.1, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                raise BadRequest(408, "Request Timeout") from None
            if msg["type"] == "http.disconnect":
                raise ClientGone()
            b = msg.get("body", b"")
            size += len(b)
            if size > MAX_BODY:
                raise BadRequest(413, "Request Entity Too Large")
            chunks.append(b)
            if not msg.get("more_body"):
                break
        body = b"".join(chunks)
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
        who = await self.resolve(hmap)
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
        if self.mode == "observe":
            return await self.observe(ctx, view)

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

    # -- observe mode (contracts/product.md §3): classify and detonate as in enforce, answer from prod
    async def observe(self, ctx: Ctx, view: View) -> Upstream:
        """Nothing is denied, diverted or captured; ctx.would records what enforce would have done."""
        if l0.is_scanner_path(ctx.raw_path) and self.spec.match(ctx.method, ctx.raw_path)[0] is None:
            ctx.res = Result(cls=SUSPECT, reasons=["scanner"])
            self._publish_classified(ctx)
            ctx.would = "l0"
            return await self.to_prod(ctx)
        ctx.res = classify(view, self.spec, ctx.who, self.manifest, self.active_rules(), ctx.session, self.enum)
        self._publish_classified(ctx)
        if ctx.res.cls == CLEAN:
            ctx.would = "prod"
        elif ctx.res.cls == EVIDENCE:
            if ctx.who.trusted:
                ctx.would = "deny"
            else:   # enforce would capture and replay in L2 (deny without a clone); here: detonate in L1 for the evidence
                await self._detonation(ctx, act=False)
                ctx.would = "deny" if ctx.verdict == "no_clone" else "shadow_l2"
        else:
            ctx.would, _ = await self._detonation(ctx, act=False)
        return await self.to_prod(ctx)

    # -- after-check: the second net for what the classifier called clean
    def _after_enqueue(self, ctx: Ctx):
        """Queue a clean request that prod has already answered for a replay in an L1 clone. Never blocks."""
        if self.after_q is None or self.mode != "enforce" or ctx.route != "prod" or ctx.res.cls != CLEAN \
                or ctx.status in (502, 504):
            return
        st = self.stats["aftercheck"]
        key = hash((ctx.method, ctx.raw_path, ctx.query, ctx.body, ctx.who.uid))
        if key in self.after_seen:
            self.after_seen.move_to_end(key)
            st["duplicate"] += 1
            return
        try:
            self.after_q.put_nowait(ctx)
        except asyncio.QueueFull:
            st["dropped"] += 1
            return
        self.after_seen[key] = True
        while len(self.after_seen) > AFTER_SEEN:
            self.after_seen.popitem(last=False)
        st["queued"] += 1

    async def _after_worker(self):
        while True:
            ctx = await self.after_q.get()
            try:
                await self._aftercheck(ctx)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("after-check rid=%s: %s", ctx.rid, e)

    async def _aftercheck(self, ctx: Ctx):
        """Replay in an L1 clone. If an oracle fires there, the clone pushes the evidence as for any detonation
        (so the incident opens as usual) and the session is captive from its next request on."""
        st = self.stats["aftercheck"]
        up = await self._run_l1(ctx, AFTER_WAIT_S)
        if up is None:
            st["no_clone"] += 1
            return
        st["checked"] += 1
        if up.verdict != wire.VERDICT_ORACLE:
            return
        st["oracle"] += 1
        log.info("after-check rid=%s %s %s: oracle fired after prod answered %s", ctx.rid, ctx.method, ctx.raw_path,
                 ctx.status)
        self._prodlog(ctx.rid, {"forwarded": True, "status": ctx.status, "aftercheck": wire.VERDICT_ORACLE})
        # keeps the request out of the legitimate-traffic corpus (pipeline gate `legit`)
        self.recorder.write({"rid": ctx.rid, "ts": time.time(), "aftercheck": wire.VERDICT_ORACLE, "method": ctx.method,
                             "path": redact_path(ctx.raw_path, (ctx.res.sensitive or {}).get("path") or set()),
                             "query": redact_query(ctx.query, (ctx.res.sensitive or {}).get("query") or set()),
                             "uid": ctx.who.uid, "session": ctx.session})
        if not ctx.who.trusted:   # a trusted identity is never diverted (contract §6); the rule covers it
            self._mark_captive(ctx, "aftercheck")

    # -- step 7
    async def _run_l1(self, ctx: Ctx, wait_s: float, evict: bool = False) -> Upstream | None:
        """One request in a free L1 clone (the wrapper resets it afterwards, whatever the verdict). None when no
        clone could answer; `evict` then frees the oldest captive clone for the next detonation."""
        clone = await self.pool.acquire(wait_s)
        if clone is None:
            if evict:
                await self._evict_oldest(ctx)
            return None
        try:
            async with clone.lock:
                up = await self.to_clone(ctx, clone, "L1")
        except Exception as e:
            log.warning("clone %s failed (rid=%s): %s", clone.id, ctx.rid, e)
            await self.pool.retire(clone)
            return None
        await self.pool.release(clone)
        return up

    async def _detonation(self, ctx: Ctx, act: bool) -> tuple[str, Upstream | None]:
        """Detonate a suspect request in L1 and decide its route: "prod", "deny" or "shadow_l1" (answered by
        the clone, whose response is returned). The one place where that is decided, for enforce and observe;
        with act=False (observe) nothing is evicted or captured. Sets ctx.verdict."""
        builtin = is_builtin_rule(ctx.res.reasons)
        fail_closed = bool(ctx.res.rule_hit) or builtin or _high_signal(ctx.res.reasons)
        up = await self._run_l1(ctx, CLONE_WAIT_S, evict=act)
        if up is None:
            ctx.verdict = "no_clone"
            return ("deny" if fail_closed else "prod"), None
        ctx.verdict = up.verdict
        if up.verdict == wire.VERDICT_ORACLE:
            if ctx.who.trusted:
                return "deny", None
            if act:
                self._mark_captive(ctx, "oracle")      # lazy: no clone held until the next request
            return "shadow_l1", up
        if builtin:   # a '..' path segment never reaches prod: no oracle sees every file, and browsers never send one
            return "deny", None
        if up.verdict == wire.VERDICT_CLEAN:
            return "prod", None
        return ("deny" if ctx.res.rule_hit else "prod"), None   # inconclusive / unknown

    async def detonate(self, ctx: Ctx) -> Upstream:
        decision, up = await self._detonation(ctx, act=True)
        if decision == "shadow_l1":
            ctx.route = "shadow_l1"
            return up
        return self.deny(ctx) if decision == "deny" else await self.to_prod(ctx)

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
        """Client headers for prod or a clone: no hop-by-hop headers, and the Cookie header without `gwsid`."""
        out = []
        for k, v in ctx.headers:
            if k in HOP:
                continue
            if k == "cookie":
                v = _strip_cookie(v, "gwsid")
                if not v:
                    continue
            out.append((k, v))
        return out

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
            except Exception as e:  # noqa: BLE001
                # bytes that cannot be put on the wire as sent (header or target): the client's fault, not prod's.
                # Counting it as a production error would let anyone roll a deploy back with a malformed cookie.
                log.info("unforwardable request rid=%s: %s", ctx.rid, e)
                self._prodlog(ctx.rid, {"forwarded": False, "status": 400})
                return Upstream(400, [("content-type", "application/json")], b'{"detail":"Bad Request"}')
            try:
                try:
                    r = await self.prod_client.send(req)
                except httpx.ConnectError:
                    # nothing was sent: once more, for any method (the upstream may be restarting)
                    await asyncio.sleep(0.2)
                    r = await self.prod_client.send(req)
                except (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError):
                    # a pooled connection the upstream had already closed; replaying is only safe when idempotent
                    if ctx.method not in RETRY_SAFE:
                        raise
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

    def _obs(self, data: dict) -> dict:
        if self.mode == "observe":
            data["observe"] = True
        return data

    def _publish_classified(self, ctx: Ctx):
        self.bus.publish(events.REQ_CLASSIFIED, self._obs({"class": ctx.res.cls, "reasons": list(ctx.res.reasons),
                                                           "method": ctx.method, "path": ctx.raw_path,
                                                           "session": ctx.session, "uid": ctx.who.uid}), rid=ctx.rid)

    def _finish(self, ctx: Ctx):
        ms = round((time.monotonic() - ctx.t0) * 1000, 1)
        if ctx.rid not in self.prodlog:
            self._prodlog(ctx.rid, {"forwarded": False, "status": None})
        st = self.stats
        st["requests"] += 1
        st["by_class"][ctx.res.cls] = st["by_class"].get(ctx.res.cls, 0) + 1
        st["by_route"][ctx.route] = st["by_route"].get(ctx.route, 0) + 1
        data = {"route": ctx.route, "status": ctx.status, "verdict": ctx.verdict, "ms": ms}
        if ctx.would is not None:
            data["would_route"] = ctx.would
        self.bus.publish(events.REQ_ROUTED, self._obs(data), rid=ctx.rid)
        self.recorder.write(self._record(ctx, ms))

    def _record(self, ctx: Ctx, ms: float) -> dict:
        sens = ctx.res.sensitive or {}
        headers = {}
        for k, v in ctx.headers:
            headers[k] = REDACTED if k in ("authorization", "cookie", "proxy-authorization") \
                or k in (sens.get("header") or ()) else v
        body = ctx.body
        ctype = (ctx.hmap.get("content-type") or "").lower()
        if body and sens.get("json"):
            body = redact_json(body, sens["json"])
        elif body and sens.get("form") and "x-www-form-urlencoded" in ctype:
            body = redact_form(body, sens["form"])
        elif body and sens.get("form") and ctype.startswith("multipart/form-data"):
            body = redact_multipart(body, ctx.hmap.get("content-type") or "", sens["form"])
        return {"rid": ctx.rid, "ts": time.time(), "session": ctx.session, "uid": ctx.who.uid,
                "trusted": ctx.who.trusted, "method": ctx.method,
                "path": redact_path(ctx.raw_path, sens.get("path") or set()),
                "query": redact_query(ctx.query, sens.get("query") or set()), "headers": headers,
                "body_b64": base64.b64encode(body).decode(), "class": ctx.res.cls, "reasons": list(ctx.res.reasons),
                "route": ctx.route, "verdict": ctx.verdict, "status": ctx.status, "ms": ms,
                "release": self.upstream["release"], "mode": self.mode,
                **({"observe": True, "would_route": ctx.would} if ctx.would is not None else {})}

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
                self.after_seen.clear()
                self.save_state()
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
        self.after_seen.clear()
        self.stats = self._new_stats()
        self.reload_manifest(force=True)
        self.save_state()

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
            gw.save_state()
            out = [r.to_dict() for r in created]
            return JSONResponse(out[0] if not isinstance(d, list) else out, status_code=201)

        @authed
        async def rules_delete(request):
            rid = request.path_params["rid"]
            if gw.rules.pop(rid, None) is None:
                return JSONResponse({"detail": "Not Found"}, status_code=404)
            gw.bus.publish(events.RULE_EXPIRED, {"id": rid, "reason": "deleted"})
            gw.save_state()
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
            if m not in MODES:
                return JSONResponse({"detail": "mode must be enforce|observe|passthrough"}, status_code=422)
            gw.mode = m
            gw.save_state()
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
            gw.bus.publish(events.ORACLE_FIRED, gw._obs(data), rid=str(ev.get("rid") or "") or None)
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


def _strip_cookie(header: str, name: str) -> str:
    """The Cookie header without `name`: the gateway's own session cookie never reaches the app, neither on
    forwarded requests (_out_headers) nor on introspection (resolve)."""
    parts = [p.strip() for p in (header or "").split(";") if p.strip()]
    return "; ".join(p for p in parts if p.partition("=")[0].strip() != name)


def _clean_resp_headers(items) -> list:
    return [(k.lower(), v) for k, v in items
            if k.lower() not in RESP_DROP and not k.lower().startswith(wire.INTERNAL_PREFIX)]
