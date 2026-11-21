"""In-process harness (no network): the judge used by the patch-validation runner.

    h = Harness(profile="victim.shadow_profile", seed_db="/path/seed.db", state=None)
    r = h.send("GET", "/api/products", query="q=x", headers={}, body=b"", uid=None, role="user", mode="L1")
    r.status, r.headers, r.body, r.verdict, r.events
    h.snapshot() -> bytes ; h.close()

It drives exactly the same ``Engine.handle``/``Engine.finish`` as ``shadow.run``,
on a private event loop thread, so verdicts are identical to server mode. The app
uses ``APP_DB`` from the environment (a temp file if unset).

L1 resets to the harness' base state: the seed when ``state`` is None, else the
given ``state`` bytes. Evidence is built (``r.evidence``) but never pushed.
"""
from __future__ import annotations

import asyncio
import threading

from immune_contracts import wire

from .core import Engine, Result

_LOCK = threading.Lock()  # instrumentation is process-wide: one request at a time per process


class Harness:
    def __init__(self, profile: str, seed_db: str | None, state: bytes | None = None):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name="shadow-harness", daemon=True)
        self._thread.start()
        with _LOCK:
            self.engine = Engine(profile, seed_db, state=state)
            self._call(self.engine.start())
        self._closed = False

    def _call(self, coro, timeout=120):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    def send(self, method: str, path: str, query: str = "", headers: dict | None = None, body: bytes = b"",
             uid: int | None = None, role: str = "user", mode: str = "L1") -> Result:
        hdrs = [(str(k).lower().encode("latin-1"), str(v).encode("latin-1")) for k, v in (headers or {}).items()]
        hdrs = [(k, v) for k, v in hdrs if not k.startswith(wire.INTERNAL_PREFIX.encode())]
        if not any(k == b"host" for k, _ in hdrs):
            hdrs.insert(0, (b"host", b"shadow.local"))
        if body and not any(k == b"content-length" for k, _ in hdrs):
            hdrs.append((b"content-length", str(len(body)).encode()))
        hdrs.append((wire.H_MODE.encode(), mode.encode()))
        hdrs.append((wire.H_RID.encode(), b"harness"))
        if uid is not None:
            hdrs.append((wire.H_UID.encode(), str(uid).encode()))
            hdrs.append((wire.H_ROLE.encode(), (role or "user").encode()))
        if isinstance(body, str):
            body = body.encode()
        if isinstance(query, bytes):
            query = query.decode("latin-1")
        with _LOCK:
            res = self._call(self.engine.handle(method, path, (query or "").lstrip("?").encode("latin-1"), hdrs, body or b""))
            self.engine.finish(res)
        return res

    def snapshot(self) -> bytes:
        with _LOCK:
            return self.engine.snapshot()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._call(self.engine.stop(), timeout=20)
        finally:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)
            self._loop.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
