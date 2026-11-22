import json
import threading
import time

import httpx
from starlette.testclient import TestClient

from dashboard.server import create_app
from .conftest import TOKEN, ev

H = {"x-bus-token": TOKEN}


def client(tmp_path, name="e.jsonl"):
    return TestClient(create_app(str(tmp_path / name), TOKEN))


def test_auth(tmp_path):
    c = client(tmp_path)
    assert c.post("/events", json=ev()).status_code == 401
    assert c.post("/events", json=ev(), headers={"x-bus-token": "nope"}).status_code == 401
    assert c.post("/admin/clear").status_code == 401
    assert c.post("/events", json=ev(), headers=H).status_code == 200


def test_no_token_configured_rejects_everything(tmp_path):
    c = TestClient(create_app(str(tmp_path / "x.jsonl"), ""))
    assert c.post("/events", json=ev(), headers={"x-bus-token": ""}).status_code == 401


def test_validation(tmp_path):
    c = client(tmp_path)
    assert c.post("/events", json={"type": "bogus.type"}, headers=H).status_code == 400
    assert c.post("/events", json={"nope": 1}, headers=H).status_code == 400
    assert c.post("/events", json=[ev(), {"type": "x"}], headers=H).status_code == 400
    assert c.get("/events").json()["events"] == []  # whole batch rejected
    assert c.post("/events", content=b"{not json", headers=H).status_code == 400
    assert c.post("/events", json={"type": "pool.state", "data": "str"}, headers=H).status_code == 400


def test_pipeline_audit_events_accepted(tmp_path):
    from pipeline import bus as pbus
    c = client(tmp_path)
    for t, data in ((pbus.AUDIT_STARTED, {"incident": "i1", "vuln_class": "sqli", "candidates": 3}),
                    (pbus.AUDIT_FINDING, {"incident": "i2", "parent": "i1", "route": "/r", "param": {"in": "query", "name": "q"}}),
                    (pbus.AUDIT_DONE, {"incident": "i1", "checked": 3, "findings": 1, "seconds": 1.5})):
        e = pbus.make(t, data, run="r", incident=data["incident"])
        assert c.post("/events", json=e, headers=H).status_code == 200, t
    assert [e["type"] for e in c.get("/events", params={"type": "audit."}).json()["events"]] == list(pbus.AUDIT_TYPES)


def test_seq_monotonic_and_batch(tmp_path):
    c = client(tmp_path)
    r = c.post("/events", json=[ev(), ev(), ev()], headers=H).json()
    assert r["seqs"] == [1, 2, 3]
    assert c.post("/events", json=ev(), headers=H).json()["seqs"] == [4]
    evs = c.get("/events").json()["events"]
    assert [e["seq"] for e in evs] == [1, 2, 3, 4]
    assert evs[0]["incident"] is None and "ts" in evs[0]


def test_client_cannot_choose_seq(tmp_path):
    c = client(tmp_path)
    e = ev()
    e["seq"] = 999
    c.post("/events", json=e, headers=H)
    assert c.get("/events").json()["events"][0]["seq"] == 1


def test_since_and_type_filter(tmp_path):
    c = client(tmp_path)
    c.post("/events", json=[ev(), ev("pool.state", l1_free=1, l2_busy=0, size=1), ev(), ev("pool.state", l1_free=0, l2_busy=1, size=1)], headers=H)
    r = c.get("/events?since=2").json()
    assert [e["seq"] for e in r["events"]] == [3, 4] and r["next"] == 4
    r = c.get("/events?type=pool").json()
    assert [e["seq"] for e in r["events"]] == [2, 4]
    assert c.get("/events?since=4").json() == {"events": [], "next": 4}


def test_persistence_across_restart(tmp_path):
    c = client(tmp_path)
    c.post("/events", json=[ev(), ev()], headers=H)
    c2 = client(tmp_path)  # same store, fresh process state
    assert [e["seq"] for e in c2.get("/events").json()["events"]] == [1, 2]
    assert c2.post("/events", json=ev(), headers=H).json()["seqs"] == [3]
    lines = (tmp_path / "e.jsonl").read_text().strip().splitlines()
    assert len(lines) == 3 and json.loads(lines[2])["seq"] == 3


def test_torn_line_ignored(tmp_path):
    c = client(tmp_path)
    c.post("/events", json=ev(), headers=H)
    with open(tmp_path / "e.jsonl", "a") as f:
        f.write('{"type": "attack.att')
    assert len(client(tmp_path).get("/events").json()["events"]) == 1


def test_clear(tmp_path):
    c = client(tmp_path)
    c.post("/events", json=[ev(), ev()], headers=H)
    assert c.post("/admin/clear", headers=H).json()["ok"]
    assert c.get("/events").json()["events"] == []
    assert (tmp_path / "e.jsonl").read_text() == ""
    assert client(tmp_path).get("/events").json()["events"] == []
    assert c.post("/events", json=ev(), headers=H).json()["seqs"] == [3]  # seq stays monotonic


def test_health(tmp_path):
    assert client(tmp_path).get("/health").json()["ok"] is True


def _read_sse(url, want, out, headers=None):
    """Collect `want` (seq, event) pairs from the stream into `out`."""
    with httpx.stream("GET", url, headers=headers or {}, timeout=10) as r:
        assert r.headers["content-type"].startswith("text/event-stream")
        cur = None
        for line in r.iter_lines():
            if line.startswith("id:"):
                cur = int(line[3:])
            elif line.startswith("data:") and cur is not None:
                out.append((cur, json.loads(line[5:])))
                cur = None
                if len(out) >= want:
                    return


def test_sse_history_then_live_two_subscribers(live):
    pub = httpx.Client(base_url=live.url, headers=H)
    pub.post("/events", json=[ev(), ev()])
    outs = [[], []]
    ts = [threading.Thread(target=_read_sse, args=(live.url + "/events/stream?since=0", 4, o)) for o in outs]
    for t in ts:
        t.start()
    time.sleep(0.5)
    pub.post("/events", json=ev())
    pub.post("/events", json=ev())
    for t in ts:
        t.join(8)
        assert not t.is_alive()
    for o in outs:
        assert [s for s, _ in o] == [1, 2, 3, 4]
        assert o[0][1]["seq"] == 1 and o[0][1]["type"] == "attack.attempt"


def test_sse_since_and_last_event_id(live):
    pub = httpx.Client(base_url=live.url, headers=H)
    pub.post("/events", json=[ev(), ev(), ev()])
    a, b = [], []
    _read_sse(live.url + "/events/stream?since=2", 1, a)
    _read_sse(live.url + "/events/stream", 1, b, headers={"Last-Event-ID": "1"})
    assert [s for s, _ in a] == [3]
    assert [s for s, _ in b] == [2]


def test_sse_heartbeat(live, monkeypatch):
    import dashboard.server as srv
    monkeypatch.setattr(srv, "HEARTBEAT_S", 0.2)
    seen = []
    with httpx.stream("GET", live.url + "/events/stream", timeout=5) as r:
        for line in r.iter_lines():
            if line.startswith(": hb"):
                seen.append(line)
                break
    assert seen


# ---- bounds: page size, body size, events in memory, size of the store

def test_get_events_is_always_a_page(tmp_path, monkeypatch):
    import dashboard.server as srv
    assert (srv.EVENTS_LIMIT, srv.EVENTS_LIMIT_MAX) == (1000, 5000)
    monkeypatch.setenv("DASH_EVENTS_LIMIT", "3")
    monkeypatch.setenv("DASH_EVENTS_LIMIT_MAX", "5")
    c = client(tmp_path)
    c.post("/events", json=[ev() for _ in range(12)], headers=H)
    r = c.get("/events").json()                                   # no limit: the default page, not the whole history
    assert [e["seq"] for e in r["events"]] == [1, 2, 3] and r["next"] == 3
    for params in ({"limit": 0}, {"limit": -4}, {"limit": "x"}):
        assert len(c.get("/events", params=params).json()["events"]) == 3, params
    assert len(c.get("/events", params={"limit": 4}).json()["events"]) == 4
    assert len(c.get("/events", params={"limit": 999999}).json()["events"]) == 5      # the maximum, also with the token
    assert len(c.get("/events", params={"limit": 999999}, headers=H).json()["events"]) == 5
    # a reader that follows `next` until it gets nothing (immune/metrics.py fetch) still reads everything, in order
    seen, since = [], 0
    while True:
        r = c.get("/events", params={"since": since}).json()
        if not r["events"]:
            break
        seen += [e["seq"] for e in r["events"]]
        since = r["next"]
    assert seen == list(range(1, 13))


def test_default_page_holds_a_normal_run(tmp_path):
    c = client(tmp_path)
    c.post("/events", json=[ev() for _ in range(1200)], headers=H)
    assert len(c.get("/events").json()["events"]) == 1000
    assert len(c.get("/events", params={"limit": 100000}).json()["events"]) == 1200


def test_post_body_size_is_capped(tmp_path, monkeypatch):
    monkeypatch.setenv("DASH_MAX_BODY_MB", "1")
    c = client(tmp_path)
    big = ev("oracle.fired", pre_state_b64="A" * (1024 * 1024 + 10))
    r = c.post("/events", json=big, headers=H)
    assert r.status_code == 413 and r.json()["max_bytes"] == 1024 * 1024
    assert c.post("/events", content=b"[" + b" " * (1024 * 1024 + 10) + b"]", headers=H).status_code == 413     # counted, not parsed

    def chunks():                                                 # no content-length: counted while it is read
        for _ in range(200):
            yield b" " * 8192
    assert c.post("/events", content=chunks(), headers=H).status_code == 413
    assert c.get("/events").json()["events"] == [] and not (tmp_path / "e.jsonl").exists()
    assert c.post("/events", json=big).status_code == 401         # the token is checked first
    assert c.post("/events", json=ev("oracle.fired", pre_state_b64="A" * 500000), headers=H).status_code == 200


def run_ev(run, type_="attack.attempt"):
    e = ev(type_)
    e["run"] = run
    return e


def test_memory_is_capped_and_the_store_keeps_everything(tmp_path, monkeypatch):
    monkeypatch.setenv("DASH_MAX_EVENTS", "20")
    app = create_app(str(tmp_path / "e.jsonl"), TOKEN)
    c, bus = TestClient(app), app.state.bus
    c.post("/events", json=ev(), headers=H)
    gen = bus.gen
    for _ in range(30):
        c.post("/events", json=[ev() for _ in range(5)], headers=H)
        assert len(bus.events) <= 20
    assert bus.seq == 151 and len(bus._public) <= 20
    seqs = [e["seq"] for e in c.get("/events").json()["events"]]
    assert seqs == sorted(seqs) and seqs[-1] == 151 and seqs[0] > 100          # oldest first out
    assert set(bus._public) <= set(seqs)                          # the redacted copies go with their events
    assert bus.gen == gen                                         # pages are not told to start over on every eviction
    assert c.get("/events", params={"since": 149}).json() == {"events": c.get("/events").json()["events"][-2:], "next": 151}
    lines = (tmp_path / "e.jsonl").read_text().splitlines()
    assert [json.loads(x)["seq"] for x in lines] == list(range(1, 152))        # the durable record is complete
    again = create_app(str(tmp_path / "e.jsonl"), TOKEN).state.bus             # a restart loads within the same bound
    assert len(again.events) <= 20 and again.events[-1]["seq"] == 151 and again.seq == 151 and again.gen == gen


def test_eviction_keeps_what_the_page_needs_to_rebuild_the_current_run(tmp_path, monkeypatch):
    monkeypatch.setenv("DASH_MAX_EVENTS", "30")
    app = create_app(str(tmp_path / "e.jsonl"), TOKEN)
    c, bus = TestClient(app), app.state.bus
    c.post("/events", json=[run_ev("old") for _ in range(25)], headers=H)
    c.post("/events", json=[run_ev("new", "incident.opened"), run_ev("new", "rule.active")], headers=H)
    c.post("/events", json=[run_ev("new", "request.routed") for _ in range(10)], headers=H)
    # 1st: events of earlier runs
    assert len(bus.events) <= 30 and [e["type"] for e in bus.events if e["run"] == "new"][:2] == ["incident.opened", "rule.active"]
    assert sum(e["run"] == "new" for e in bus.events) == 12 and sum(e["run"] == "old" for e in bus.events) < 25
    # 2nd: request traffic of the current run, before anything an incident is rebuilt from
    for _ in range(20):
        c.post("/events", json=[run_ev("new", "request.classified"), run_ev("new", "request.routed"), run_ev("new", "gate.result")], headers=H)
    assert len(bus.events) <= 30 and not any(e["run"] == "old" for e in bus.events)
    kinds = [e["type"] for e in bus.events]
    assert kinds[:2] == ["incident.opened", "rule.active"] and kinds.count("gate.result") == 20
    # 3rd: the bound holds even when the current run has nothing else left to give
    c.post("/events", json=[run_ev("new", "gate.result") for _ in range(40)], headers=H)
    assert len(bus.events) <= 30 and bus.events[-1]["seq"] == bus.seq
    assert len((tmp_path / "e.jsonl").read_text().splitlines()) == bus.seq


def test_stream_replays_what_is_in_memory_after_eviction(live, monkeypatch):
    live.app.state.bus.max_events = 10
    pub = httpx.Client(base_url=live.url, headers=H)
    for _ in range(5):
        pub.post("/events", json=[ev() for _ in range(5)])
    kept = [e["seq"] for e in live.app.state.bus.events]
    out = []
    _read_sse(live.url + "/events/stream?since=0", len(kept), out)
    assert [s for s, _ in out] == kept and kept[-1] == 25


def test_store_rotates_by_size_and_one_generation_is_kept(tmp_path, monkeypatch):
    import dashboard.server as srv
    assert (srv.MAX_EVENTS, srv.STORE_MAX_MB, srv.MAX_BODY_MB) == (50000, 256, 32)
    store, old = tmp_path / "e.jsonl", tmp_path / "e.jsonl.1"
    app = create_app(str(store), TOKEN)
    c, bus = TestClient(app), app.state.bus
    bus.store_max = 2000                                          # bytes (DASH_STORE_MAX_MB is in MiB)
    for _ in range(40):
        c.post("/events", json=ev(), headers=H)
    assert old.exists() and 0 < store.stat().st_size < 2000 + 400 and old.stat().st_size < 2000 + 400
    on_disk = [json.loads(x)["seq"] for p in (old, store) for x in p.read_text().splitlines()]
    assert on_disk == sorted(on_disk) and on_disk[-1] == 40 and len(on_disk) < 40          # only one old generation
    assert [e["seq"] for e in bus.events] == list(range(1, 41))                            # rotation does not touch memory
    again = create_app(str(store), TOKEN).state.bus                                        # a restart reads both files
    assert [e["seq"] for e in again.events] == on_disk and again.seq == 40
    assert c.post("/admin/clear", headers=H).status_code == 200
    assert not old.exists() and store.read_text() == ""
    assert create_app(str(store), TOKEN).state.bus.events == []


def test_store_rotation_can_be_switched_off(tmp_path, monkeypatch):
    monkeypatch.setenv("DASH_STORE_MAX_MB", "0")
    app = create_app(str(tmp_path / "e.jsonl"), TOKEN)
    assert app.state.bus.store_max == 0
    c = TestClient(app)
    for _ in range(5):
        c.post("/events", json=ev(), headers=H)
    assert not (tmp_path / "e.jsonl.1").exists() and len((tmp_path / "e.jsonl").read_text().splitlines()) == 5
