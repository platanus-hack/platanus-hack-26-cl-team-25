"""Event bus (POST/GET/SSE, JSONL persistence) and static dashboard, one Starlette app."""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import sys
import time
from pathlib import Path

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
# pipeline audit.* events (pipeline/bus.py), accepted until immune_contracts/events.py lists them
EXTRA_TYPES = ("audit.started", "audit.finding", "audit.done")
TYPES = frozenset(ev_contract.TYPES) | frozenset(EXTRA_TYPES)
FILES = {"app.js": "text/javascript", "state.js": "text/javascript", "style.css": "text/css"}


class Bus:
    def __init__(self, store: str | None, token: str):
        self.store = Path(store) if store else None
        self.token = token
        self.events: list[dict] = []
        self.seq = 0
        self.epoch = 0
        self.cond = asyncio.Condition()
        self._load()

    def _load(self) -> None:
        if not self.store or not self.store.exists():
            return
        with self.store.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue  # torn last line after a crash
                if isinstance(e, dict) and isinstance(e.get("seq"), int):
                    self.events.append(e)
                    self.seq = max(self.seq, e["seq"])

    def _persist(self, batch: list[dict]) -> None:
        if not self.store:
            return
        self.store.parent.mkdir(parents=True, exist_ok=True)
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
            self.events.extend(batch)
            self._persist(batch)
            self.cond.notify_all()
        return [e["seq"] for e in batch]

    async def clear(self) -> None:
        async with self.cond:
            self.events = []
            self.epoch += 1  # seq keeps counting so Last-Event-ID stays monotonic
            if self.store:
                self.store.parent.mkdir(parents=True, exist_ok=True)
                self.store.write_text("")
            self.cond.notify_all()

    def after(self, since: int, type_prefix: str | None = None, limit: int | None = None) -> list[dict]:
        out = [e for e in self.events if e["seq"] > since
               and (not type_prefix or str(e.get("type", "")).startswith(type_prefix))]
        return out[:limit] if limit else out


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

    async def post_events(request: Request):
        if not bus.authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            body = json.loads(await request.body())
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
        limit = _int(q.get("limit")) or None
        evs = bus.after(since, q.get("type") or None, limit)
        return JSONResponse({"events": evs, "next": evs[-1]["seq"] if evs else bus.seq})

    async def stream(request: Request):
        since = _int(request.headers.get("last-event-id") or request.query_params.get("since"))
        if since > bus.seq:
            since = 0  # client is ahead of a store that was reset: replay everything

        async def gen():
            last = since
            epoch = bus.epoch
            yield "retry: 2000\n\n"
            while True:
                if bus.epoch != epoch:
                    epoch = bus.epoch
                    last = 0
                    yield "event: reset\ndata: {}\n\n"
                batch = bus.after(last)
                if batch:
                    chunks = []
                    for e in batch:
                        chunks.append(f"id: {e['seq']}\ndata: {json.dumps(e, separators=(',', ':'))}\n\n")
                    last = batch[-1]["seq"]
                    yield "".join(chunks)
                    continue
                if await request.is_disconnected():
                    return
                try:
                    async with bus.cond:
                        await asyncio.wait_for(
                            bus.cond.wait_for(lambda: bus.seq > last or bus.epoch != epoch), HEARTBEAT_S)
                except asyncio.TimeoutError:
                    yield ": hb\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream", headers={
            "Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Content-Security-Policy": CSP})

    async def admin_clear(request: Request):
        if not bus.authorized(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        await bus.clear()
        return JSONResponse({"ok": True})

    async def health(request: Request):
        return JSONResponse({"ok": True, "events": len(bus.events), "seq": bus.seq})

    def _static(name: str, media: str):
        async def h(request: Request):
            return FileResponse(STATIC / name, media_type=media,
                                headers={"Content-Security-Policy": CSP, "Cache-Control": "no-cache"})
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
    return app
