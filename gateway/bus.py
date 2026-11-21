"""Fire-and-forget event publisher. Never blocks a request; drops on failure or overflow."""
from __future__ import annotations

import asyncio
import logging

import httpx

from immune_contracts import events

log = logging.getLogger("gateway.bus")


class Bus:
    def __init__(self, url: str, token: str, run: str, maxsize: int = 5000):
        self.url = (url or "").rstrip("/")
        self.token = token or ""
        self.run = run or ""
        self.q: asyncio.Queue | None = None
        self.maxsize = maxsize
        self.dropped = 0
        self.sent = 0
        self._task: asyncio.Task | None = None

    def start(self):
        self.q = asyncio.Queue(maxsize=self.maxsize)
        if self.url:
            self._task = asyncio.create_task(self._worker())

    def publish(self, type_: str, data: dict, rid: str | None = None, incident: str | None = None) -> None:
        if not self.url or self.q is None:
            return
        try:
            self.q.put_nowait(events.make(type_, "gateway", data, run=self.run, rid=rid, incident=incident))
        except asyncio.QueueFull:
            self.dropped += 1
        except Exception:  # never let publishing break a request
            self.dropped += 1

    async def _worker(self):
        timeout = httpx.Timeout(0.5, connect=0.05)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            while True:
                ev = await self.q.get()
                batch = [ev]
                while len(batch) < 200:
                    try:
                        batch.append(self.q.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                try:
                    await client.post(self.url + "/events", json=batch, headers={"x-bus-token": self.token})
                    self.sent += len(batch)
                except Exception as e:
                    self.dropped += len(batch)
                    log.debug("bus publish failed: %s", e)

    async def stop(self):
        if self._task:
            self._task.cancel()
