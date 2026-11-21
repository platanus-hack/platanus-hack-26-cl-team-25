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
