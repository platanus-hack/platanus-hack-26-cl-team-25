"""Clone pool state machine.

States: free -> busy (one L1 detonation) -> free | captive(session)
        captive -> retired (evicted / idle TTL / reset)
A clone is used by one request at a time (per-clone asyncio.Lock); captive
sessions are therefore serialised on their clone. Retired clones are never used
again: fleet destroys and replaces them, then PUTs the new set.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

FREE, BUSY, CAPTIVE, RETIRED = "free", "busy", "captive", "retired"


@dataclass
class Clone:
    id: str
    addr: str
    key: str
    release: str = ""
    state: str = FREE
    session: str | None = None
    since: float | None = None        # capture time
    last_used: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def public(self) -> dict:
        return {"id": self.id, "state": self.state, "session": self.session, "release": self.release,
                "addr": self.addr, "since": self.since}


class Pool:
    def __init__(self, idle_ttl_s: float = 900.0, on_release=None):
        self.clones: dict[str, Clone] = {}
        self.sessions: dict[str, str] = {}       # session -> clone id
        self.idle_ttl_s = idle_ttl_s
        self.on_release = on_release or (lambda session, clone, reason: None)
        self._cond: asyncio.Condition | None = None

    @property
    def cond(self) -> asyncio.Condition:
        if self._cond is None:
            self._cond = asyncio.Condition()
        return self._cond

    async def _notify(self):
        async with self.cond:
            self.cond.notify_all()

    # ---------------------------------------------------------- registration
    async def set_clones(self, specs: list[dict]) -> None:
        """Full set of registered clones. Unknown ids are added as free; missing ids are forgotten."""
        new: dict[str, Clone] = {}
        for s in specs:
            cid = str(s["id"])
            old = self.clones.get(cid)
            if old is not None and old.addr == str(s["addr"]):
                old.key = str(s.get("key", old.key))
                old.release = str(s.get("release", old.release) or "")
                new[cid] = old
            else:
                if old is not None:
                    self._drop(old, "patched")
                new[cid] = Clone(id=cid, addr=str(s["addr"]), key=str(s.get("key", "")), release=str(s.get("release", "") or ""))
        for cid, old in self.clones.items():
            if cid not in new:
                self._drop(old, "patched")
        self.clones = new
        await self._notify()

    def _drop(self, clone: Clone, reason: str):
        if clone.session is not None:
            self.sessions.pop(clone.session, None)
            self.on_release(clone.session, clone.id, reason)
            clone.session = None
        clone.state = RETIRED

    # ---------------------------------------------------------- queries
    def get(self, cid: str) -> Clone | None:
        return self.clones.get(cid)

    def captive_clone(self, session: str | None) -> Clone | None:
        if not session:
            return None
        cid = self.sessions.get(session)
        c = self.clones.get(cid) if cid else None
        if c is None or c.state != CAPTIVE or c.session != session:
            if cid is not None:
                self.sessions.pop(session, None)
            return None
        return c

    def snapshot(self) -> list[dict]:
        return [c.public() for c in self.clones.values()]

    def captives(self) -> list[dict]:
        return [{"session": c.session, "clone": c.id, "since": c.since}
                for c in self.clones.values() if c.state == CAPTIVE]

    # ---------------------------------------------------------- transitions
    def _take_free(self) -> Clone | None:
        free = [c for c in self.clones.values() if c.state == FREE and not c.lock.locked()]
        if not free:
            return None
        c = min(free, key=lambda c: c.last_used)
        c.state = BUSY
        c.last_used = time.time()
        return c

    async def acquire(self, wait_s: float = 0.3) -> Clone | None:
        """Take a free clone (state -> busy), waiting at most wait_s."""
        c = self._take_free()
        if c is not None or wait_s <= 0:
            return c
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_s
        async with self.cond:
            while True:
                c = self._take_free()
                if c is not None:
                    return c
                left = deadline - loop.time()
                if left <= 0:
                    return None
                try:
                    await asyncio.wait_for(self.cond.wait(), timeout=left)
                except asyncio.TimeoutError:
                    return self._take_free()

    async def release(self, clone: Clone) -> None:
        """busy -> free (after an L1 detonation; the wrapper already reset it)."""
        if self.clones.get(clone.id) is clone and clone.state == BUSY:
            clone.state = FREE
        await self._notify()

    async def retire(self, clone: Clone, reason: str = "evicted") -> None:
        if self.clones.get(clone.id) is clone:
            self._drop(clone, reason)
        await self._notify()

    def capture(self, clone: Clone, session: str) -> bool:
        """busy -> captive(session)."""
        if self.clones.get(clone.id) is not clone or clone.state not in (BUSY, FREE):
            return False
        clone.state = CAPTIVE
        clone.session = session
        clone.since = clone.last_used = time.time()
        self.sessions[session] = clone.id
        return True

    def touch(self, clone: Clone) -> None:
        clone.last_used = time.time()

    async def evict_oldest(self) -> Clone | None:
        caps = [c for c in self.clones.values() if c.state == CAPTIVE]
        if not caps:
            return None
        oldest = min(caps, key=lambda c: c.since or 0)
        await self.retire(oldest, "evicted")
        return oldest

    async def expire_idle(self, now: float | None = None) -> list[Clone]:
        now = time.time() if now is None else now
        out = []
        for c in list(self.clones.values()):
            if c.state == CAPTIVE and not c.lock.locked() and now - c.last_used > self.idle_ttl_s:
                self._drop(c, "ttl")
                out.append(c)
        if out:
            await self._notify()
        return out

    async def release_all_sessions(self, reason: str = "evicted") -> None:
        for c in list(self.clones.values()):
            if c.state == CAPTIVE:
                self._drop(c, reason)
        self.sessions.clear()
        await self._notify()

    def counts(self) -> dict:
        out = {FREE: 0, BUSY: 0, CAPTIVE: 0, RETIRED: 0}
        for c in self.clones.values():
            out[c.state] = out.get(c.state, 0) + 1
        return out
