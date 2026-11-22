"""After-check (contracts/product.md §3b): a request the classifier called clean is answered by prod and then
replayed in a clone; an oracle firing there opens the usual flow and captures the session from its next request."""
import time

import httpx

from .world import ADMIN, records, wait_events

AUTH = {"kind": "immune-token"}


def stats(w):
    return httpx.get(w.admin + "/_admin/stats", headers=ADMIN).json()["aftercheck"]


def wait_stat(w, key, n, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end and stats(w)[key] < n:
        time.sleep(0.05)
    return stats(w)


def test_clean_request_that_fires_in_the_clone_captures_the_session(world):
    w = world(AUTH, extra_env={"GW_AFTERCHECK": "1"})
    with httpx.Client(base_url=w.url) as c:
        r = c.get("/search", params={"q": "ATTACK"})
        assert r.json() == {"from": "prod"}                      # prod answered: the first request is not stopped
        cap = wait_events(w, "session.captured")
        assert cap and cap[0]["data"]["reason"] == "aftercheck"
        fired = wait_events(w, "oracle.fired")
        assert fired and fired[0]["data"]["session"] == cap[0]["data"]["session"] and fired[0]["rid"] == cap[0]["rid"]
        assert wait_stat(w, "oracle", 1) == {"queued": 1, "checked": 1, "oracle": 1, "duplicate": 0, "dropped": 0,
                                             "no_clone": 0}
        seen = len(w.prod_seen)
        r = c.get("/search", params={"q": "anything"})          # same session: now captive, served by its clone
        assert r.json()["synthetic"] is True and len(w.prod_seen) == seen
    recs = records(w)
    first = [x for x in recs if x.get("path") == "/search" and x.get("query") == "q=ATTACK"]
    assert [(x.get("class"), x.get("route"), x.get("aftercheck")) for x in first] == [("clean", "prod", None),
                                                                                      (None, None, "oracle")]
    log = httpx.get(w.admin + "/_admin/prodlog", params={"rid": first[0]["rid"]}, headers=ADMIN).json()
    assert log == {"forwarded": True, "status": 200, "aftercheck": "oracle"}


def test_clean_request_that_stays_clean_is_checked_once(world):
    w = world(AUTH, extra_env={"GW_AFTERCHECK": "1"})
    with httpx.Client(base_url=w.url) as c:
        for _ in range(3):
            assert c.get("/search", params={"q": "hello"}).json() == {"from": "prod"}
        st = wait_stat(w, "checked", 1)
        assert (st["queued"], st["checked"], st["oracle"], st["duplicate"]) == (1, 1, 0, 2)
        assert c.get("/search", params={"q": "again"}).json() == {"from": "prod"}   # not captive
    assert not [e for e in w.events if e.get("type") in ("session.captured", "oracle.fired")]


def test_off_by_default_and_never_in_observe_mode(world):
    for kw in ({}, {"mode": "observe", "extra_env": {"GW_AFTERCHECK": "1"}}):
        w = world(AUTH, **kw)
        assert httpx.get(w.url + "/search", params={"q": "ATTACK"}).json() == {"from": "prod"}
        time.sleep(0.4)
        assert w.clone_seen == [] and stats(w)["queued"] == 0
