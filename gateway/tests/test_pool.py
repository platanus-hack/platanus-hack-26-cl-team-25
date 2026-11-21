import asyncio, time

from gateway.pool import BUSY, CAPTIVE, FREE, RETIRED, Pool

SPECS = [{"id": "c1", "addr": "a:1", "key": "k1", "release": "t0"}, {"id": "c2", "addr": "a:2", "key": "k2", "release": "t0"}]


def mk():
    released = []
    p = Pool(idle_ttl_s=900, on_release=lambda s, c, r: released.append((s, c, r)))
    return p, released


def states(p):
    return {c["id"]: c["state"] for c in p.snapshot()}


async def test_acquire_release_capture():
    p, rel = mk()
    await p.set_clones(SPECS)
    a = await p.acquire(0)
    b = await p.acquire(0)
    assert {a.id, b.id} == {"c1", "c2"} and a.state == BUSY and await p.acquire(0) is None
    await p.release(a)
    assert a.state == FREE
    assert p.capture(b, "gwsid:x") and b.state == CAPTIVE
    assert p.captive_clone("gwsid:x") is b and p.captive_clone("gwsid:y") is None
    assert p.captives() == [{"session": "gwsid:x", "clone": b.id, "since": b.since}]


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


async def test_evict_oldest_retires_it():
    p, rel = mk()
    await p.set_clones(SPECS)
    a = await p.acquire(0); p.capture(a, "s1")
    await asyncio.sleep(0.01)
    b = await p.acquire(0); p.capture(b, "s2")
    ev = await p.evict_oldest()
    assert ev is a and a.state == RETIRED and p.captive_clone("s1") is None
    assert rel == [("s1", a.id, "evicted")]
    assert await p.acquire(0) is None   # retired clones are never reused


async def test_idle_ttl():
    p, rel = mk()
    p.idle_ttl_s = 10
    await p.set_clones(SPECS)
    a = await p.acquire(0); p.capture(a, "s1")
    assert await p.expire_idle(now=time.time() + 5) == []
    assert await p.expire_idle(now=time.time() + 11) == [a]
    assert a.state == RETIRED and rel[-1] == ("s1", a.id, "ttl")


async def test_put_keeps_known_forgets_missing():
    p, rel = mk()
    await p.set_clones(SPECS)
    a = p.get("c1"); b = p.get("c2")
    p.capture(await p.acquire(0), "s1")
    cap = p.captive_clone("s1")
    other = "c2" if cap.id == "c1" else "c1"
    # drop the captive clone, keep the other, add a new one
    await p.set_clones([s for s in SPECS if s["id"] == other] + [{"id": "c3", "addr": "a:3", "key": "k3", "release": "r2"}])
    assert set(states(p)) == {other, "c3"} and states(p)["c3"] == FREE
    assert p.captive_clone("s1") is None and rel == [("s1", cap.id, "patched")]
    assert p.get(other) in (a, b)   # same object, state preserved


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
    p.capture(await p.acquire(0), "s1")
    await p.release_all_sessions()
    assert p.captives() == [] and len(rel) == 1
