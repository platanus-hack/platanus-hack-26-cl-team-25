"""Event bus (POST/GET/SSE, JSONL persistence) and static dashboard, one Starlette app."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import unquote_plus

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from immune_contracts import events as ev_contract  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
HEARTBEAT_S = 15.0
POLL_S = 1.0   # how often an idle stream checks for shutdown and for a client that went away
TYPES = frozenset(ev_contract.TYPES)
FILES = {"app.js": "text/javascript; charset=utf-8", "state.js": "text/javascript; charset=utf-8",
         "replay.js": "text/javascript; charset=utf-8", "replay.json": "application/json; charset=utf-8",
         "style.css": "text/css; charset=utf-8", "inter.woff2": "font/woff2", "mono.woff2": "font/woff2"}
# sent on every response: the page is public and read-only
SECURITY_HEADERS = {
    "content-security-policy": CSP, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
    "x-frame-options": "DENY", "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}
# Readers without the bus token (the public page) never get credentials that travel inside events:
# evidence carries the attacker's request verbatim (headers, query string, body), the statement an oracle saw,
# a snapshot of the clone's database and the gateway session cookie; PR urls of the local repo carry a host path.
SENSITIVE_HEADER = re.compile(r"authorization|cookie|token|secret|api[-_]?key|passw|session|credential|signature", re.I)
REDACTED = "[redacted]"
HIDDEN_KEYS = frozenset({"body_b64", "pre_state_b64", "statement"})   # replaced by a marker that only says how long it was
QUERY_KEYS = frozenset({"query"})                                     # a raw query string: a=1&token=x
URL_KEYS = frozenset({"path", "url", "target"})                       # may carry ?query
SESSION_PREFIX = "gwsid:"                                             # gateway/core.py: the session key is the raw cookie
_SESSION_KEY = secrets.token_bytes(32)                                # per process: public session names are not reversible
MAX_STREAMS = 200
# Bounds (each one can be changed with the env var of the same name with DASH_ in front, see create_app and Bus)
EVENTS_LIMIT = 1000          # DASH_EVENTS_LIMIT: events per GET /events page when the client sends no limit
EVENTS_LIMIT_MAX = 5000      # DASH_EVENTS_LIMIT_MAX: largest page a client may ask for
MAX_BODY_MB = 32             # DASH_MAX_BODY_MB: largest POST /events body (evidence carries a request body and a db snapshot)
MAX_EVENTS = 50000           # DASH_MAX_EVENTS: events kept in memory (the JSONL store stays the durable record)
STORE_MAX_MB = 256           # DASH_STORE_MAX_MB: past this size the JSONL store becomes <store>.1 (one generation kept); 0 = never
TRAFFIC_TYPES = frozenset({ev_contract.REQ_CLASSIFIED, ev_contract.REQ_ROUTED})


def _mask(value) -> str:
    scheme, _, rest = str(value).partition(" ")
    return f"{scheme} {REDACTED}" if rest and scheme.isalpha() and len(scheme) <= 12 else REDACTED


def _public_path(url: str) -> str:
    """file:///home/user/repo/.git/prs/20.json#pr-20 -> file:///[redacted]/20.json#pr-20"""
    tail = url.rsplit("/", 1)[-1]
    return f"file:///{REDACTED}/{tail}"


def _hidden(v):
    """Marker for a value that is not published: says that there was one and how long, nothing else."""
    if v is None or v == "":
        return v
    return f"[redacted: {len(v)} chars]" if isinstance(v, str) else REDACTED


def _public_query(q: str) -> str:
    """a=1&token=abc -> a=1&token=[redacted] (same key pattern as the headers)"""
    parts = []
    for p in q.split("&"):
        k, eq, _ = p.partition("=")
        parts.append(f"{k}={REDACTED}" if eq and SENSITIVE_HEADER.search(unquote_plus(k)) else p)
    return "&".join(parts)


def _public_url(u: str) -> str:
    head, mark, rest = u.partition("?")
    if not mark:
        return u
    q, hash_, frag = rest.partition("#")
    return head + "?" + _public_query(q) + hash_ + frag


def public_session(s: str) -> str:
    """gwsid:<cookie> -> gwsid:~<12 hex>. Keyed and stable inside one process, so the page still tells sessions apart."""
    return SESSION_PREFIX + "~" + hmac.new(_SESSION_KEY, s.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]


def redact(v, key: str = ""):
    """Copy of an event (or any part of it) that is safe to show to anyone."""
    if key in HIDDEN_KEYS:
        return _hidden(v)
    if isinstance(v, dict):
        if key == "headers":
            return {k: (_mask(x) if SENSITIVE_HEADER.search(str(k)) else redact(x)) for k, x in v.items()}
        return {k: redact(x, str(k)) for k, x in v.items()}
    if isinstance(v, list):
        return [redact(x) for x in v]
    if isinstance(v, str):
        if v.startswith("file:///"):
            return _public_path(v)
        if v.startswith(SESSION_PREFIX):
            return public_session(v)
        if key in QUERY_KEYS:
            return _public_query(v)
        if key in URL_KEYS:
            return _public_url(v)
    return v


class SecurityHeaders:
    """ASGI wrapper: adds SECURITY_HEADERS to every http response."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                have = {k.lower() for k, _ in message.get("headers", [])}
                extra = [(k.encode(), v.encode()) for k, v in SECURITY_HEADERS.items() if k.encode() not in have]
                message = {**message, "headers": list(message.get("headers", [])) + extra}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _env_int(name: str, default: int) -> int:
    """Non-negative int from the environment; anything else is the default."""
    try:
        v = int(float(os.environ.get(name) or default))
    except ValueError:
        return default
    return v if v >= 0 else default


def _gen_of(first: dict) -> str:
    return hashlib.sha256(f"{first.get('seq')}:{first.get('ts')}:{first.get('type')}".encode()).hexdigest()[:16]


class Bus:
    def __init__(self, store: str | None, token: str):
        self.store = Path(store) if store else None
        self.token = token
        self.events: list[dict] = []
        self.max_events = _env_int("DASH_MAX_EVENTS", MAX_EVENTS) or MAX_EVENTS
        self.store_max = _env_int("DASH_STORE_MAX_MB", STORE_MAX_MB) * 1024 * 1024
        self._gen = "empty"
        self.seq = 0
        self.epoch = 0
        self.streams = 0
        self.closing = False                # set on shutdown: open streams end so the process can exit
        self.redact = os.environ.get("DASH_REDACT", "1") != "0"
        self._public: dict[int, str] = {}   # seq -> redacted json, built on first use
        self.cond = asyncio.Condition()
        self._load()

    @property
    def gen(self) -> str:
        """Identity of the stored history: survives a restart, changes when the store is cleared or replaced.
        A page that reconnects and sees another gen drops its state and replays from the start."""
        return self._gen     # fixed by the first event of the store: evicting old events from memory must not change it

    def dumps(self, e: dict, raw: bool) -> str:
        if raw or not self.redact:
            return json.dumps(e, separators=(",", ":"))
        s = self._public.get(e["seq"])
        if s is None:
            s = self._public[e["seq"]] = json.dumps(redact(e), separators=(",", ":"))
        return s

    @property
    def rotated(self) -> Path | None:
        return self.store.with_name(self.store.name + ".1") if self.store else None

    def _load(self) -> None:
        if not self.store:
            return
        for path in (self.rotated, self.store):      # the previous generation first: together they are the history
            if not path.exists():
                continue
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue  # torn last line after a crash
                    if isinstance(e, dict) and isinstance(e.get("seq"), int) and not isinstance(e["seq"], bool):
                        self.events.append(e)
                        self.seq = max(self.seq, e["seq"])
        self.events.sort(key=lambda e: e["seq"])
        if self.events:
            self._gen = _gen_of(self.events[0])
        self._evict()

    def _evict(self) -> None:
        """Keep at most max_events in memory; the JSONL store keeps everything.

        A page rebuilds its state by replaying what is in memory (static/app.js opens /events/stream?since=0), so
        what goes first is what the page needs least: events of earlier runs, then the request.* traffic of the
        current run (the page loses request counts and nothing else: incidents are rebuilt from the other
        events), and only then the oldest events of the current run."""
        over = len(self.events) - self.max_events
        if over <= 0:
            return
        over += self.max_events // 10                # make room for a while: this walks the whole list
        run = self.events[-1].get("run")
        for unwanted in (lambda e: e.get("run") != run, lambda e: e.get("type") in TRAFFIC_TYPES, lambda e: True):
            keep = []
            for e in self.events:
                if over > 0 and unwanted(e):
                    over -= 1
                    self._public.pop(e["seq"], None)
                else:
                    keep.append(e)
            self.events = keep
            if over <= 0:
                return

    def _persist(self, batch: list[dict]) -> None:
        if not self.store:
            return
        self.store.parent.mkdir(parents=True, exist_ok=True)
        try:
            if self.store_max and self.store.stat().st_size >= self.store_max:
                os.replace(self.store, self.rotated)
        except OSError:
            pass                                     # no store yet, or it cannot be moved: keep appending
        with self.store.open("a", encoding="utf-8") as f:
            for e in batch:
                f.write(json.dumps(e, separators=(",", ":")) + "\n")
            f.flush()

    def authorized(self, request: Request) -> bool:
        got = request.headers.get("x-bus-token", "")
        return bool(self.token) and hmac.compare_digest(got.encode(), self.token.encode())

    async def publish(self, items: list[dict]) -> list[int]:
        batch = []
        async with self.cond:
            for it in items:
                self.seq += 1
                e = dict(it)
                e["seq"] = self.seq
                batch.append(e)
            if batch and not self.events:
                self._gen = _gen_of(batch[0])
            self.events.extend(batch)
            self._persist(batch)
            self._evict()
            self.cond.notify_all()
        return [e["seq"] for e in batch]

    async def clear(self) -> None:
        async with self.cond:
            self.events = []
            self._public = {}
            self._gen = "empty"
            self.epoch += 1  # seq keeps counting so Last-Event-ID stays monotonic
            if self.store:
                self.store.parent.mkdir(parents=True, exist_ok=True)
                self.store.write_text("")
                self.rotated.unlink(missing_ok=True)
            self.cond.notify_all()

    def after(self, since: int, type_prefix: str | None = None, limit: int | None = None) -> list[dict]:
        lo, hi = 0, len(self.events)             # events are ordered by seq
        while lo < hi:
            mid = (lo + hi) // 2
            if self.events[mid]["seq"] > since:
                hi = mid
            else:
                lo = mid + 1
        out = self.events[lo:]
        if type_prefix:
            out = [e for e in out if str(e.get("type", "")).startswith(type_prefix)]
        return out[:limit] if limit and limit > 0 else out


def _validate(item) -> str | None:
    if not isinstance(item, dict):
        return "event must be an object"
    t = item.get("type")
    if t not in TYPES:
        return f"unknown type: {t!r}"
    if "data" in item and not isinstance(item["data"], dict):
        return "data must be an object"
    if "ts" in item and (isinstance(item["ts"], bool) or not isinstance(item["ts"], (int, float))):
        return "ts must be a number"
    return None


def _normalize(item: dict) -> dict:
    e = {k: v for k, v in item.items() if k != "seq"}
    e.setdefault("ts", time.time())
    e.setdefault("run", "")
    e.setdefault("src", "")
    e.setdefault("rid", None)
    e.setdefault("incident", None)
    e.setdefault("data", {})
    return e


def _int(v, default=0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def create_app(store: str | None = None, token: str | None = None, *, lifespan=None) -> Starlette:
    bus = Bus(store if store is not None else os.environ.get("BUS_STORE") or None,
              token if token is not None else os.environ.get("BUS_TOKEN", ""))
    max_streams = _int(os.environ.get("DASH_MAX_STREAMS"), MAX_STREAMS) or MAX_STREAMS
    page_max = _env_int("DASH_EVENTS_LIMIT_MAX", EVENTS_LIMIT_MAX) or EVENTS_LIMIT_MAX
    page = min(_env_int("DASH_EVENTS_LIMIT", EVENTS_LIMIT) or EVENTS_LIMIT, page_max)
    max_body = (_env_int("DASH_MAX_BODY_MB", MAX_BODY_MB) or MAX_BODY_MB) * 1024 * 1024
    subtitle = os.environ.get("DASHBOARD_SUBTITLE", "")
    no_store = {"Cache-Control": "no-store"}

    async def read_body(request: Request) -> bytes | None:
        """The request body, or None when it is larger than max_body (checked while reading, not after)."""
        if _int(request.headers.get("content-length")) > max_body:
            return None
        buf = bytearray()
        async for chunk in request.stream():
            buf += chunk
            if len(buf) > max_body:
                return None
        return bytes(buf)

    async def post_events(request: Request):
        if not bus.authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        raw = await read_body(request)
        if raw is None:
            return JSONResponse({"error": "body too large", "max_bytes": max_body}, status_code=413)
        try:
            body = json.loads(raw)
        except ValueError:
            return JSONResponse({"error": "invalid json"}, status_code=400)
        items = body if isinstance(body, list) else [body]
        for i, it in enumerate(items):
            err = _validate(it)
            if err:
                return JSONResponse({"error": err, "index": i}, status_code=400)
        seqs = await bus.publish([_normalize(it) for it in items])
        return JSONResponse({"ok": True, "seqs": seqs, "next": seqs[-1] if seqs else bus.seq})

    async def get_events(request: Request):
        q = request.query_params
        since = _int(q.get("since"))
        # always a page: a reader follows `next` (since=<next>) until it gets no events, as immune/metrics.py does
        limit = _int(q.get("limit"))
        limit = min(limit, page_max) if limit > 0 else page
        evs = bus.after(since, q.get("type") or None, limit)
        raw = bus.authorized(request)
        body = '{"events":[%s],"next":%d}' % (",".join(bus.dumps(e, raw) for e in evs), evs[-1]["seq"] if evs else bus.seq)
        return Response(body, media_type="application/json", headers=no_store)

    async def stream(request: Request):
        since = _int(request.headers.get("last-event-id") or request.query_params.get("since"))
        if since > bus.seq or since < 0:
            since = 0  # client is ahead of a store that was reset: replay everything
        if bus.streams >= max_streams:
            return JSONResponse({"error": "too many streams"}, status_code=503, headers={"Retry-After": "5", **no_store})
        raw = bus.authorized(request)

        def hello() -> str:
            data = {"gen": bus.gen, "seq": bus.seq}
            if subtitle:
                data["subtitle"] = subtitle
            return "event: hello\ndata: %s\n\n" % json.dumps(data, separators=(",", ":"))

        async def gen():
            bus.streams += 1
            try:
                last = since
                epoch = bus.epoch
                sent_gen = bus.gen
                idle = 0.0
                yield "retry: 2000\n\n" + hello()
                while True:
                    if bus.epoch != epoch:
                        epoch = bus.epoch
                        last = 0
                        yield "event: reset\ndata: {}\n\n"
                    batch = bus.after(last)
                    if batch:
                        chunks = []
                        if bus.gen != sent_gen:
                            sent_gen = bus.gen
                            chunks.append(hello())
                        for e in batch:
                            chunks.append(f"id: {e['seq']}\ndata: {bus.dumps(e, raw)}\n\n")
                        last = batch[-1]["seq"]
                        yield "".join(chunks)
                        continue
                    if bus.gen != sent_gen:
                        sent_gen = bus.gen
                        yield hello()
                    if bus.closing or await request.is_disconnected():
                        return
                    try:
                        async with bus.cond:
                            await asyncio.wait_for(
                                bus.cond.wait_for(lambda: bus.seq > last or bus.epoch != epoch), min(POLL_S, HEARTBEAT_S))
                        idle = 0.0
                    except asyncio.TimeoutError:
                        idle += min(POLL_S, HEARTBEAT_S)
                        if idle >= HEARTBEAT_S:
                            idle = 0.0
                            yield ": hb\nevent: hb\ndata: {}\n\n"  # comment for plain readers, event for the page watchdog
            finally:
                bus.streams -= 1

        return StreamingResponse(gen(), media_type="text/event-stream", headers={
            "Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"})

    async def admin_clear(request: Request):
        if not bus.authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        await bus.clear()
        return JSONResponse({"ok": True})

    async def health(request: Request):
        return JSONResponse({"ok": True, "events": len(bus.events), "seq": bus.seq}, headers=no_store)

    def _static(name: str, media: str):
        async def h(request: Request):
            cache = "public, max-age=604800" if media.startswith("font/") else "no-cache"
            return FileResponse(STATIC / name, media_type=media, headers={"Cache-Control": cache})
        return h

    routes = [
        Route("/", _static("index.html", "text/html; charset=utf-8")),
        Route("/events", post_events, methods=["POST"]),
        Route("/events", get_events, methods=["GET"]),
        Route("/events/stream", stream, methods=["GET"]),
        Route("/admin/clear", admin_clear, methods=["POST"]),
        Route("/health", health, methods=["GET"]),
    ]
    for n, m in FILES.items():
        routes.append(Route(f"/static/{n}", _static(n, m), methods=["GET"]))

    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.bus = bus
    app.add_middleware(SecurityHeaders)
    return app
