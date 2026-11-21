import asyncio, time

from gateway.pool import BUSY, CAPTIVE, FREE, RETIRED, Pool

SPECS = [{"id": "c1", "addr": "a:1", "key": "k1", "release": "t0"}, {"id": "c2", "addr": "a:2", "key": "k2", "release": "t0"}]


def mk():
    released = []
    p = Pool(idle_ttl_s=900, on_release=lambda s, c, r: released.append((s, c, r)))
    return p, released


def states(p):
    return {c["id"]: c["state"] for c in p.snapshot()}


async def bound(p, session):
    cap, _ = p.mark_captive(session)
    c = await p.acquire(0)
    assert p.bind(c, cap)
    return cap, c


async def test_acquire_release():
    p, _ = mk()
    await p.set_clones(SPECS)
    a = await p.acquire(0)
    b = await p.acquire(0)
    assert {a.id, b.id} == {"c1", "c2"} and a.state == BUSY and await p.acquire(0) is None
    await p.release(a)
    assert a.state == FREE and (await p.acquire(0)) is a


async def test_lazy_captivity_holds_no_clone():
    p, _ = mk()
    await p.set_clones(SPECS)
    for i in range(10):                       # a flood of one-shot captures costs nothing
        cap, created = p.mark_captive(f"gwsid:{i}")
        assert created and cap.clone is None
    assert p.mark_captive("gwsid:0")[1] is False
    assert states(p) == {"c1": FREE, "c2": FREE}
    assert all(x["clone"] is None for x in p.captives()) and len(p.captives()) == 10


async def test_bind_and_lookup():
    p, _ = mk()
    await p.set_clones(SPECS)
    cap, c = await bound(p, "gwsid:x")
    assert c.state == CAPTIVE and c.session == "gwsid:x" and p.bound_clone(cap) is c
    assert p.captive_session("gwsid:x") is cap and p.captive_session("gwsid:y") is None
    assert p.captives() == [{"session": "gwsid:x", "clone": c.id, "since": cap.since}]


async def test_wait_for_free_clone_up_to_deadline():
    p, _ = mk()
    await p.set_clones(SPECS[:1])
    a = await p.acquire(0)
    t = time.monotonic()
    assert await p.acquire(0.1) is None
    assert 0.08 <= time.monotonic() - t < 0.5

    async def later():
        await asyncio.sleep(0.05)
        await p.release(a)
    asyncio.create_task(later())
    got = await p.acquire(0.3)
    assert got is a and got.state == BUSY


async def test_evict_oldest_bound_retires_clone_session_stays_captive():
    p, rel = mk()
    await p.set_clones(SPECS)
    p.mark_captive("unbound")
    cap1, a = await bound(p, "s1")
    await asyncio.sleep(0.01)
    cap2, b = await bound(p, "s2")
    ev = await p.evict_oldest()
    assert ev is a and a.state == RETIRED and cap1.clone is None and p.bound_clone(cap1) is None
    assert p.captive_session("s1") is cap1 and p.bound_clone(cap2) is b   # still captive, newer keeps its clone
    assert rel == []
    assert await p.acquire(0) is None   # retired clones are never reused
    assert sorted(states(p).values()) == [CAPTIVE, RETIRED]


async def test_evict_with_no_bound_captive():
    p, _ = mk()
    await p.set_clones(SPECS)
    p.mark_captive("s")
    assert await p.evict_oldest() is None


async def test_idle_ttl():
    p, rel = mk()
    p.idle_ttl_s = 10
    await p.set_clones(SPECS)
    cap, a = await bound(p, "s1")
    p.mark_captive("s2")
    assert await p.expire_idle(now=time.time() + 5) == []
    assert sorted(await p.expire_idle(now=time.time() + 11)) == ["s1", "s2"]
    assert a.state == RETIRED and ("s1", a.id, "ttl") in rel and ("s2", None, "ttl") in rel


async def test_put_keeps_known_forgets_missing():
    p, rel = mk()
    await p.set_clones(SPECS)
    cap, c = await bound(p, "s1")
    other = "c2" if c.id == "c1" else "c1"
    keep = p.get(other)
    await p.set_clones([s for s in SPECS if s["id"] == other] + [{"id": "c3", "addr": "a:3", "key": "k3", "release": "r2"}])
    assert set(states(p)) == {other, "c3"} and states(p)["c3"] == FREE
    assert p.captive_session("s1") is None and rel == [("s1", c.id, "clone_gone")]
    assert p.get(other) is keep


async def test_retired_stays_retired_on_same_put():
    p, _ = mk()
    await p.set_clones(SPECS)
    a = await p.acquire(0)
    await p.retire(a)
    await p.set_clones(SPECS)
    assert states(p)[a.id] == RETIRED


async def test_release_all_sessions():
    p, rel = mk()
    await p.set_clones(SPECS)
    _, c = await bound(p, "s1")
    p.mark_captive("s2")
    await p.release_all_sessions("reset")
    assert p.captives() == [] and c.state == RETIRED and {r[2] for r in rel} == {"reset"} and len(rel) == 2


async def test_session_cap_drops_oldest_unbound():
    p = Pool(max_sessions=3)
    await p.set_clones(SPECS)
    _, c = await bound(p, "b")
    for s in "wxyz":
        p.mark_captive(s)
    assert p.captive_session("b") is not None and len(p.captive) == 3 and p.captive_session("w") is None
