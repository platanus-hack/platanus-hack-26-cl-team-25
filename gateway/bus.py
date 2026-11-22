"""Fire-and-forget event publisher. Never blocks a request.

`request.*` events are telemetry: dropped on failure or overflow. Every other event is kept and retried for
RETRY_S (at most KEEP_MAX of them) before it is dropped; `dropped` counts both."""
from __future__ import annotations

import asyncio
import logging

import httpx

from immune_contracts import events

log = logging.getLogger("gateway.bus")


RETRY_S = 120.0           # how long an event that matters is retried while the bus is down
KEEP_MAX = 2000


def _matters(ev: dict) -> bool:
    """request.* events are telemetry: dropping some loses a line on the dashboard. The rest drive the
    pipeline (an oracle.fired that is lost is a confirmed attack nobody acts on) and are kept for retry."""
    return not str(ev.get("type", "")).startswith("request.")


class Bus:
    def __init__(self, url: str, token: str, run: str, maxsize: int = 5000):
        self.url = (url or "").rstrip("/")
        self.token = token or ""
        self.run = run or ""
        self.q: asyncio.Queue | None = None
        self.maxsize = maxsize
        self.dropped = 0
        self.sent = 0
        self.retry_s = RETRY_S
        self._kept: list = []          # (deadline, event) not delivered yet, oldest first
        self._task: asyncio.Task | None = None

    def start(self):
        self.q = asyncio.Queue(maxsize=self.maxsize)
        if self.url:
            self._task = asyncio.create_task(self._worker())

    def publish(self, type_: str, data: dict, rid: str | None = None, incident: str | None = None) -> None:
        if not self.url or self.q is None:
            return
        try:
            ev = events.make(type_, "gateway", data, run=self.run, rid=rid, incident=incident)
        except Exception:  # never let publishing break a request
            self.dropped += 1
            return
        try:
            self.q.put_nowait(ev)
        except asyncio.QueueFull:
            if _matters(ev):
                self._keep([ev])       # the queue is full of telemetry while the bus is down: do not lose this one
            else:
                self.dropped += 1

    def _keep(self, evs: list) -> None:
        import time
        deadline = time.monotonic() + self.retry_s
        self._kept.extend((deadline, e) for e in evs)
        over = len(self._kept) - KEEP_MAX
        if over > 0:
            del self._kept[:over]
            self.dropped += over

    async def _post(self, client, batch: list) -> bool:
        try:
            r = await client.post(self.url + "/events", json=batch, headers={"x-bus-token": self.token})
            return r.status_code < 500
        except Exception as e:  # noqa: BLE001
            log.debug("bus publish failed: %s", e)
            return False

    async def _worker(self):
        import time
        timeout = httpx.Timeout(1.0, connect=0.3)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            while True:
                try:
                    # with events waiting for a retry, wake up even if nothing new arrives
                    ev = await asyncio.wait_for(self.q.get(), timeout=0.5 if self._kept else None)
                    batch = [ev]
                except asyncio.TimeoutError:
                    batch = []
                while len(batch) < 200:
                    try:
                        batch.append(self.q.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                now = time.monotonic()
                live = [(d, e) for d, e in self._kept if d > now]
                self.dropped += len(self._kept) - len(live)       # retried for retry_s and never delivered
                self._kept = []
                send = [e for _, e in live] + batch               # older first: the bus numbers them on arrival
                if not send:
                    continue
                if await self._post(client, send):
                    self.sent += len(send)
                    continue
                self.dropped += sum(1 for e in batch if not _matters(e))
                self._kept = live + [(now + self.retry_s, e) for e in batch if _matters(e)]
                over = len(self._kept) - KEEP_MAX
                if over > 0:
                    del self._kept[:over]
                    self.dropped += over
                await asyncio.sleep(0.3)

    async def stop(self):
        if self._task:
            self._task.cancel()
