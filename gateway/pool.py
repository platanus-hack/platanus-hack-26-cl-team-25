"""Clone pool and captive sessions (contracts/README.md §6.3 step 8; binding is lazy).

Clone states: free -> busy (one request) -> free | captive (bound to a session) -> retired.
Captive sessions exist independently of clones: a session confirmed by an L1
detonation is captive but holds no clone until its next request, which binds
one. A clone is used by one request at a time (per-clone asyncio.Lock), so a
bound session is serialised on its clone. Retired clones are never reused:
fleet destroys and replaces them, then PUTs the new set.
"""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
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
    since: float | None = None        # bind time
    last_used: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def public(self) -> dict:
        return {"id": self.id, "state": self.state, "session": self.session, "release": self.release,
                "addr": self.addr, "since": self.since}


@dataclass
class Captive:
    session: str
    since: float
    last_used: float
    clone: str | None = None          # bound clone id, None until bound
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)   # serialises binding for this session


class Pool:
    def __init__(self, idle_ttl_s: float = 900.0, on_release=None, max_sessions: int = 50000):
        self.clones: dict[str, Clone] = {}
        self.captive: OrderedDict[str, Captive] = OrderedDict()
        self.idle_ttl_s = idle_ttl_s
        self.max_sessions = max_sessions
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
        """Full set of registered clones. New ids join as free; missing ids are forgotten
        and the sessions bound to them are released (reason clone_gone)."""
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
                    self._gone(old)
                new[cid] = Clone(id=cid, addr=str(s["addr"]), key=str(s.get("key", "")),
                                 release=str(s.get("release", "") or ""))
        for cid, old in self.clones.items():
            if cid not in new:
                self._gone(old)
        self.clones = new
        await self._notify()

    def _gone(self, clone: Clone):
        if clone.session is not None:
            self.captive.pop(clone.session, None)
            self.on_release(clone.session, clone.id, "clone_gone")
        clone.session = None
        clone.state = RETIRED

    def _unbind(self, clone: Clone):
        """Retire a clone; its session (if any) stays captive but unbound."""
        if clone.session is not None:
            cap = self.captive.get(clone.session)
            if cap is not None and cap.clone == clone.id:
                cap.clone = None
        clone.session = None
        clone.state = RETIRED

    # ---------------------------------------------------------- queries
    def get(self, cid: str) -> Clone | None:
        return self.clones.get(cid)

    def captive_session(self, session: str | None) -> Captive | None:
        return self.captive.get(session) if session else None

    def bound_clone(self, cap: Captive) -> Clone | None:
        c = self.clones.get(cap.clone) if cap.clone else None
        if c is None or c.state != CAPTIVE or c.session != cap.session:
            cap.clone = None
            return None
        return c

    def snapshot(self) -> list[dict]:
        return [c.public() for c in self.clones.values()]

    def captives(self) -> list[dict]:
        out = []
        for cap in self.captive.values():
            self.bound_clone(cap)
            out.append({"session": cap.session, "clone": cap.clone, "since": cap.since})
        return out

    def counts(self) -> dict:
        out = {FREE: 0, BUSY: 0, CAPTIVE: 0, RETIRED: 0}
        for c in self.clones.values():
            out[c.state] = out.get(c.state, 0) + 1
        out["sessions"] = len(self.captive)
        return out

    # ---------------------------------------------------------- clone transitions
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
        """busy -> free (after an L1 request; the wrapper already reset it)."""
        if self.clones.get(clone.id) is clone and clone.state == BUSY:
            clone.state = FREE
        await self._notify()

    async def retire(self, clone: Clone) -> None:
        """Any -> retired (clone failure / eviction). A bound session stays captive, unbound."""
        if self.clones.get(clone.id) is clone:
            self._unbind(clone)
        await self._notify()

    async def evict_oldest(self) -> Clone | None:
        """Retire the clone of the oldest clone-bound captive (fleet replaces it)."""
        bound = [c for c in self.clones.values() if c.state == CAPTIVE]
        if not bound:
            return None
        oldest = min(bound, key=lambda c: c.since or 0)
        await self.retire(oldest)
        return oldest

    # ---------------------------------------------------------- captive sessions
    def mark_captive(self, session: str) -> tuple[Captive, bool]:
        """-> (captive, created). Idempotent."""
        cap = self.captive.get(session)
        if cap is not None:
            return cap, False
        now = time.time()
        cap = self.captive[session] = Captive(session=session, since=now, last_used=now)
        while len(self.captive) > self.max_sessions:
            # drop the oldest unbound session (bound ones are limited by the pool size anyway)
            victim = next((s for s, c in self.captive.items() if c.clone is None and s != session), None)
            if victim is None:
                break
            self.captive.pop(victim)
            self.on_release(victim, None, "evicted")
        return cap, True

    def bind(self, clone: Clone, cap: Captive) -> bool:
        """busy -> captive, bound to cap.session."""
        if self.clones.get(clone.id) is not clone or clone.state not in (BUSY, FREE):
            return False
        now = time.time()
        clone.state, clone.session, clone.since, clone.last_used = CAPTIVE, cap.session, now, now
        cap.clone = clone.id
        return True

    def touch(self, cap: Captive, clone: Clone | None = None) -> None:
        cap.last_used = time.time()
        if clone is not None:
            clone.last_used = cap.last_used

    async def expire_idle(self, now: float | None = None) -> list[str]:
        now = time.time() if now is None else now
        out = []
        for s, cap in list(self.captive.items()):
            c = self.bound_clone(cap)
            if now - cap.last_used <= self.idle_ttl_s or cap.lock.locked() or (c is not None and c.lock.locked()):
                continue
            self.captive.pop(s, None)
            if c is not None:
                c.session, c.state = None, RETIRED
            self.on_release(s, c.id if c else None, "ttl")
            out.append(s)
        if out:
            await self._notify()
        return out

    async def release_all_sessions(self, reason: str = "reset") -> None:
        for s, cap in list(self.captive.items()):
            c = self.bound_clone(cap)
            if c is not None:
                c.session, c.state = None, RETIRED
            self.on_release(s, c.id if c else None, reason)
        self.captive.clear()
        await self._notify()
