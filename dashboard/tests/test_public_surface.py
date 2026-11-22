"""The dashboard is published read-only: what an anonymous reader can do and see, and that the page agrees
with `python -m immune.metrics` on a recorded run."""
import json
import shutil
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

import dashboard.server as srv
from dashboard.server import create_app
from immune import metrics
from .conftest import TOKEN, ev

H = {"x-bus-token": TOKEN}
HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "real_run.jsonl"   # a recorded run (3 attacks -> 7 incidents), credentials already redacted
NODE = shutil.which("node")
SECRET = "Bearer eyJ1aWQiOjYxfQ.c01405048f1ad59cd71f7dd4f91e4729"


def client(tmp_path):
    return TestClient(create_app(str(tmp_path / "e.jsonl"), TOKEN))


def evidence():
    return {"type": "oracle.fired", "rid": "r1", "data": {
        "rid": "r1", "session": "uid:61", "request": {
            "method": "GET", "path": "/api/orders/5", "query": "", "body_b64": "",
            "headers": {"accept": "*/*", "authorization": SECRET, "Cookie": "sid=abc123", "X-Api-Key": "k-999",
                        "x-csrf-token": "t0k", "user-agent": "curl/8"}},
        "events": [{"oracle": "owner", "detail": {"marker_owner": 6}, "stack": []}]}}


def test_every_route_that_changes_state_needs_the_token(tmp_path):
    app = create_app(str(tmp_path / "e.jsonl"), TOKEN)
    c = TestClient(app)
    c.post("/events", json=ev(), headers=H)
    writable = []
    for route in app.routes:
        for method in sorted(route.methods - {"GET", "HEAD"}):
            writable.append((method, route.path))
            for headers in ({}, {"x-bus-token": "wrong"}, {"x-bus-token": ""}, {"authorization": "Bearer " + TOKEN}):
                r = c.request(method, route.path, json=ev(), headers=headers)
                assert r.status_code == 401, (method, route.path, headers)
    assert sorted(writable) == [("POST", "/admin/clear"), ("POST", "/events")]   # a new write route must be added here on purpose
    for method in ("PUT", "PATCH", "DELETE"):
        for path in ("/", "/events", "/events/stream", "/admin/clear", "/health", "/static/app.js"):
            assert c.request(method, path).status_code == 405, (method, path)
    assert c.get("/events").json()["events"][0]["seq"] == 1      # nothing was added or cleared
    assert len(c.get("/events").json()["events"]) == 1


def test_static_serves_only_the_listed_files(tmp_path):
    c = client(tmp_path)
    for path in ("/static/", "/static/../server.py", "/static/%2e%2e/server.py", "/static/..%2fserver.py", "/server.py",
                 "/static/index.html", "/static/app.js.map", "/.env", "/admin", "/admin/clear"):
        assert c.get(path).status_code in (404, 405), path
    for path in ("/static/app.js", "/static/state.js", "/static/style.css"):
        assert "charset=utf-8" in c.get(path).headers["content-type"]


def test_security_headers_on_every_response(tmp_path):
    c = client(tmp_path)
    for path in ("/", "/static/app.js", "/events", "/health", "/nope"):
        h = c.get(path).headers
        assert "default-src 'self'" in h["content-security-policy"] and "unsafe" not in h["content-security-policy"], path
        assert h["x-content-type-options"] == "nosniff", path
        assert h["referrer-policy"] == "no-referrer", path
        assert h["x-frame-options"] == "DENY", path
    assert c.post("/events", json=ev()).headers["x-content-type-options"] == "nosniff"
    assert "access-control-allow-origin" not in c.get("/events", headers={"origin": "https://evil.example"}).headers
    assert c.get("/events").headers["cache-control"] == "no-store"


def test_anonymous_readers_never_get_credentials(tmp_path):
    c = client(tmp_path)
    pr = "file:///home/someone/project/runtime/repo/.git/immune/prs/20.json#pr-20"
    c.post("/events", json=[evidence(),
                            {"type": "poc.ready", "incident": "i", "data": {"poc": {"requests": [{"headers": {"Authorization": SECRET}}]}}},
                            {"type": "pr.opened", "incident": "i", "data": {"incident": "i", "url": pr, "branch": "b"}},
                            {"type": "pr.merged", "incident": "i", "data": {"incident": "i", "url": "https://github.com/o/r/pull/1", "sha": "abc"}}],
           headers=H)
    public = c.get("/events").text
    for leaked in ("eyJ1aWQ", "c01405048f", "abc123", "k-999", "t0k", "/home/someone", "runtime/repo"):
        assert leaked not in public, leaked
    evs = json.loads(public)["events"]
    hdr = evs[0]["data"]["request"]["headers"]
    assert hdr == {"accept": "*/*", "authorization": "Bearer [redacted]", "Cookie": "[redacted]", "X-Api-Key": "[redacted]",
                   "x-csrf-token": "[redacted]", "user-agent": "curl/8"}
    assert evs[1]["data"]["poc"]["requests"][0]["headers"]["Authorization"] == "Bearer [redacted]"
    assert evs[2]["data"]["url"] == "file:///[redacted]/20.json#pr-20"
    assert evs[3]["data"]["url"] == "https://github.com/o/r/pull/1"
    # everything else is untouched: the pipeline correlates on these
    assert evs[0]["data"]["session"] == "uid:61" and evs[0]["rid"] == "r1" and evs[0]["data"]["request"]["path"] == "/api/orders/5"
    # the type filter and a wrong token get the same redacted view; the bus token gets the stored event
    assert "eyJ1aWQ" not in c.get("/events", params={"type": "oracle."}).text
    assert "eyJ1aWQ" not in c.get("/events", headers={"x-bus-token": "wrong"}).text
    raw = c.get("/events", headers=H).json()["events"]
    assert raw[0]["data"]["request"]["headers"]["authorization"] == SECRET and raw[2]["data"]["url"] == pr
    assert (tmp_path / "e.jsonl").read_text().count(SECRET) == 2          # the store keeps what the pipeline needs


def test_redaction_can_be_switched_off(tmp_path, monkeypatch):
    monkeypatch.setenv("DASH_REDACT", "0")
    c = client(tmp_path)
    c.post("/events", json=evidence(), headers=H)
    assert SECRET in c.get("/events").text


def _sse(url, stop, headers=None, timeout=8):
    """Parsed SSE messages [(event, id, data)] until stop(messages) is true."""
    out, kind, eid, data = [], "message", None, []
    with httpx.stream("GET", url, headers=headers or {}, timeout=timeout) as r:
        for line in r.iter_lines():
            if line == "":
                if data:
                    out.append((kind, eid, "\n".join(data)))
                    if stop(out):
                        return out
                kind, eid, data = "message", None, []
            elif line.startswith("event:"):
                kind = line[6:].strip()
            elif line.startswith("id:"):
                eid = line[3:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].strip())
    return out


def test_stream_is_redacted_and_says_hello(live):
    pub = httpx.Client(base_url=live.url, headers=H)
    pub.post("/events", json=[evidence(), ev()])
    msgs = _sse(live.url + "/events/stream", lambda o: len(o) >= 3)
    assert msgs[0][0] == "hello"
    hello = json.loads(msgs[0][2])
    assert hello["seq"] == 2 and isinstance(hello["gen"], str) and hello["gen"] != "empty"
    assert [m[1] for m in msgs[1:]] == ["1", "2"]
    assert "eyJ1aWQ" not in msgs[1][2] and "Bearer [redacted]" in msgs[1][2]
    raw = _sse(live.url + "/events/stream", lambda o: len(o) >= 2, headers=H)
    assert SECRET in raw[1][2]


def test_gen_survives_restart_and_changes_when_the_store_is_cleared(tmp_path):
    store = str(tmp_path / "e.jsonl")
    a = create_app(store, TOKEN)
    assert a.state.bus.gen == "empty"
    c = TestClient(a)
    c.post("/events", json=[ev(), ev()], headers=H)
    g1 = a.state.bus.gen
    assert g1 != "empty"
    c.post("/events", json=ev(), headers=H)
    assert a.state.bus.gen == g1                                 # appending does not change it
    assert create_app(store, TOKEN).state.bus.gen == g1          # restart on the same store: pages resume, no replay
    c.post("/admin/clear", headers=H)
    assert a.state.bus.gen == "empty"
    time.sleep(0.01)
    c.post("/events", json=ev(), headers=H)
    assert a.state.bus.gen not in ("empty", g1)                  # a page that was away sees a new store and starts over


def test_stream_announces_a_new_store_before_its_first_event(live):
    got = []
    import threading
    t = threading.Thread(target=lambda: got.extend(_sse(live.url + "/events/stream", lambda o: len(o) >= 3)))
    t.start()
    time.sleep(0.4)
    httpx.post(live.url + "/events", json=ev(), headers=H)
    t.join(8)
    assert [m[0] for m in got] == ["hello", "hello", "message"]
    assert json.loads(got[0][2])["gen"] == "empty" and json.loads(got[1][2])["gen"] != "empty"


def test_heartbeat_is_also_a_named_event(live, monkeypatch):
    monkeypatch.setattr(srv, "HEARTBEAT_S", 0.2)
    msgs = _sse(live.url + "/events/stream", lambda o: any(m[0] == "hb" for m in o))
    assert msgs[-1][0] == "hb"


def test_stream_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("DASH_MAX_STREAMS", "2")
    app = create_app(str(tmp_path / "e.jsonl"), TOKEN)
    app.state.bus.streams = 2                                    # two pages already connected
    r = TestClient(app).get("/events/stream")
    assert r.status_code == 503 and r.headers["retry-after"] == "5"
    assert app.state.bus.streams == 2


def test_stream_counter_goes_back_down(live):
    bus = live.app.state.bus
    httpx.post(live.url + "/events", json=ev(), headers=H)
    _sse(live.url + "/events/stream", lambda o: len(o) >= 2)
    for _ in range(100):
        if bus.streams == 0:
            break
        httpx.post(live.url + "/events", json=ev(), headers=H)   # wakes the generator so it notices the disconnect
        time.sleep(0.05)
    assert bus.streams == 0


def test_history_is_loaded_in_seq_order_and_since_is_exact(tmp_path):
    store = tmp_path / "e.jsonl"
    rows = [{"type": "attack.attempt", "seq": s, "ts": 1.0, "data": {}} for s in (3, 1, 2, 7, 5)]
    store.write_text("".join(json.dumps(r) + "\n" for r in rows) + '{"seq": true}\n[1]\n')
    c = TestClient(create_app(str(store), TOKEN))
    assert [e["seq"] for e in c.get("/events").json()["events"]] == [1, 2, 3, 5, 7]
    for since, want in ((0, [1, 2, 3, 5, 7]), (2, [3, 5, 7]), (4, [5, 7]), (7, []), (99, []), (-5, [1, 2, 3, 5, 7])):
        assert [e["seq"] for e in c.get("/events", params={"since": since}).json()["events"]] == want, since
    assert c.get("/events", params={"since": 2, "limit": 2}).json()["next"] == 5


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_page_timings_match_immune_metrics_on_a_recorded_run():
    events = [json.loads(line) for line in FIXTURE.read_text().splitlines() if line]
    assert "eyJ1aWQ" not in FIXTURE.read_text() and "/home/" not in FIXTURE.read_text()
    out = subprocess.run([NODE, str(HERE / "reducer.test.js"), "--timings", str(FIXTURE)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    page = json.loads(out.stdout)
    rows = metrics.incidents(events)
    assert len(rows) == 7 and set(page["incidents"]) == {r["incident"] for r in rows}
    for r in rows:
        p = page["incidents"][r["incident"]]
        assert r["outcome"] == "patched" and p["status"] == "cured"
        assert p["origin"] == r["origin"] and p["parent"] == r["parent"]
        for key in ("queue", "to_rule", "to_diff", "to_merged", "to_prod", "to_verified"):
            assert p[key] == pytest.approx(r[key], abs=1e-6), (r["incident"], key)
        assert all(s.endswith(":done") for s in p["steps"]), p["steps"]       # every stage of the incident happened and is shown
        assert p["prod_addr"] in ("prod-blue:8000", "prod-green:8000")
    # each live incident shows its own request, although three of them share the sink victim/app/db.py:25
    assert [page["incidents"][i]["evidence"] for i in ("inc-0001", "inc-0002", "inc-0003")] == \
        ["/api/products", "/api/files/download", "/api/orders/5"]
    assert [page["incidents"][i]["hits"] for i in ("inc-0001", "inc-0002", "inc-0003")] == [1, 1, 1]
    summary = metrics.summary(rows)
    det = metrics.detection(events)
    score = page["score"]
    assert score["prodMedian"] == pytest.approx(summary["to_prod"]["median"], abs=1e-6) and score["prodN"] == 7
    assert (score["cured"], score["open"], score["contained"], score["audit"]) == (7, 0, 0, det["incidents_by_origin"]["audit"])
    assert score["detonated"] == det["detonated"] and score["total"] == det["requests"]
    assert len(page["audits"]) == det["audits"]["n"] == 3
    assert page["upstream"]["addr"] == "prod-green:8000"
    assert page["ignored"] == 0                                  # no event type of the contract is dropped silently


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_reducer_understands_every_event_type_of_the_contract(tmp_path):
    from immune_contracts import events as contract
    script = (
        "const S = require(process.argv[1]); const st = S.newState();"
        "JSON.parse(process.argv[2]).forEach((t) => S.reduce(st, {type: t, ts: 1, incident: 'i', rid: 'r', data: {incident: 'i', id: 'x', session: 's', vuln: 'v'}}));"
        "console.log(st.ignored);")
    out = subprocess.run([NODE, "-e", script, str(HERE.parent / "static" / "state.js"), json.dumps(sorted(srv.TYPES))],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "0"
    assert set(contract.TYPES) <= set(srv.TYPES)


def test_open_streams_end_on_shutdown(live, monkeypatch):
    """uvicorn waits for open connections before exiting; a stream that never ends kept the old process alive
    after SIGTERM with the pages still attached to it (dashboard/__main__.py sets bus.closing on the signal)."""
    monkeypatch.setattr(srv, "POLL_S", 0.1)
    httpx.post(live.url + "/events", json=ev(), headers=H)
    done = []
    import threading

    def read():
        with httpx.stream("GET", live.url + "/events/stream", timeout=10) as r:
            for _ in r.iter_lines():
                pass
        done.append(time.time())

    t = threading.Thread(target=read)
    t.start()
    time.sleep(0.5)
    assert not done
    live.app.state.bus.closing = True
    t.join(5)
    assert done, "the stream stayed open after shutdown was requested"
    assert live.app.state.bus.streams == 0


def test_main_wires_the_shutdown_signal():
    src = (HERE.parent / "__main__.py").read_text()
    assert "bus.closing = True" in src and "handle_exit" in src


def test_anonymous_readers_get_no_bodies_snapshots_statements_query_secrets_or_session_cookies(tmp_path):
    import base64
    body = base64.b64encode(b'{"email": "ana@example.com", "password": "hunter2-very-secret"}').decode()
    snapshot = base64.b64encode(b"SQLite format 3\x00" + b"users|ana|pw-hash-0f3a" * 40).decode()
    cookie = "gwsid:Zm9vYmFyLXNlc3Npb24tY29va2ll"
    stmt = "SELECT id FROM users WHERE email = 'ana@example.com' AND password_hash = 'c0ffee11'"
    oracle = {"type": "oracle.fired", "rid": "r9", "data": {
        "rid": "r9", "session": cookie, "pre_state_b64": snapshot, "uid": None,
        "request": {"method": "POST", "path": "/api/login", "body_b64": body, "headers": {"user-agent": "curl/8"},
                    "query": "next=%2Fhome&token=tok-111&API_KEY=key-222&password=pw-333&q=shoes&flag&passw%6Frd=pw-444"},
        "events": [{"oracle": "sql", "detail": {"statement": stmt, "tainted": True}, "stack": [{"file": "app/db.py", "line": 25}]}]}}
    c = client(tmp_path)
    c.post("/events", json=[
        oracle,
        {"type": "session.captured", "rid": "r9", "data": {"session": cookie, "clone": None, "reason": "oracle"}},
        {"type": "session.released", "data": {"session": cookie, "reason": "ttl"}},
        {"type": "session.captured", "data": {"session": "gwsid:another-cookie-value", "clone": None, "reason": "oracle"}},
        {"type": "request.classified", "rid": "r10", "data": {"class": "clean", "method": "GET", "session": "uid:61",
                                                              "path": "/api/reset?token=tok-555&step=2#top"}},
        {"type": "incident.opened", "incident": "i", "data": {"incident": "i", "route": "/api/login", "request": {
            "method": "POST", "path": "/api/login", "query": "", "body_b64": body}}},
        {"type": "poc.ready", "incident": "i", "data": {"incident": "i", "reproducible": True, "runs": 3, "poc": {
            "requests": [{"method": "GET", "url": "http://clone/api/x?secret=s-666&id=5", "body_b64": body}]}}},
    ], headers=H)
    public = c.get("/events").text
    for leaked in (body, body[:24], "hunter2", snapshot[:24], "Zm9vYmFy", "another-cookie", "ana@example.com", "c0ffee11", "SELECT",
                   "tok-111", "key-222", "pw-333", "pw-444", "tok-555", "s-666"):
        assert leaked not in public, leaked
    evs = json.loads(public)["events"]
    d = evs[0]["data"]
    # a marker says that there was a value and how long it was; an empty one stays empty
    assert d["request"]["body_b64"] == "[redacted: %d chars]" % len(body)
    assert d["pre_state_b64"] == "[redacted: %d chars]" % len(snapshot)
    assert d["events"][0]["detail"] == {"statement": "[redacted: %d chars]" % len(stmt), "tainted": True}
    assert evs[5]["data"]["request"]["body_b64"].startswith("[redacted: ") and evs[5]["data"]["request"]["query"] == ""
    assert c.get("/events", params={"since": 0}).json()["events"][0]["data"]["uid"] is None
    # query strings: only the values of parameters with a sensitive name
    assert d["request"]["query"] == ("next=%2Fhome&token=[redacted]&API_KEY=[redacted]&password=[redacted]&q=shoes&flag"
                                     "&passw%6Frd=[redacted]")
    assert evs[4]["data"]["path"] == "/api/reset?token=[redacted]&step=2#top"
    assert evs[6]["data"]["poc"]["requests"][0]["url"] == "http://clone/api/x?secret=[redacted]&id=5"
    # the session cookie becomes a short name that is the same for the same session and different for another one
    name = d["session"]
    assert name.startswith("gwsid:~") and len(name) == len("gwsid:~") + 12
    assert evs[1]["data"]["session"] == name == evs[2]["data"]["session"]
    assert evs[3]["data"]["session"] not in (name, "gwsid:another-cookie-value") and evs[3]["data"]["session"].startswith("gwsid:~")
    assert evs[4]["data"]["session"] == "uid:61"                 # an app user id is not a credential
    assert c.get("/events").text == public                       # stable inside one process
    # what stays: what the page draws and what correlates events
    assert (d["request"]["method"], d["request"]["path"], evs[0]["rid"]) == ("POST", "/api/login", "r9")
    assert d["events"][0]["stack"] == [{"file": "app/db.py", "line": 25}]
    # the bus token gets the stored events, and so does the store
    raw = c.get("/events", headers=H).json()["events"]
    assert raw[0]["data"] == oracle["data"]
    assert raw[4]["data"]["path"] == "/api/reset?token=tok-555&step=2#top"
    assert cookie in (tmp_path / "e.jsonl").read_text() and snapshot in (tmp_path / "e.jsonl").read_text()


def test_session_names_are_keyed_per_process(monkeypatch):
    a = srv.public_session("gwsid:abc")
    assert a == srv.public_session("gwsid:abc") != srv.public_session("gwsid:abd")
    monkeypatch.setattr(srv, "_SESSION_KEY", b"k" * 32)          # another process: another key, another name
    assert srv.public_session("gwsid:abc") != a


def test_stream_hides_the_same_fields(live):
    httpx.post(live.url + "/events", headers=H, json={"type": "oracle.fired", "rid": "r", "data": {
        "session": "gwsid:cookie-value-1", "pre_state_b64": "U1FMaXRl", "request": {"path": "/x", "query": "api_key=k-1", "body_b64": "cHc9MQ=="},
        "events": [{"oracle": "sql", "detail": {"statement": "SELECT secret-1"}}]}})
    msg = _sse(live.url + "/events/stream", lambda o: len(o) >= 2)[1][2]
    for leaked in ("cookie-value-1", "U1FMaXRl", "k-1", "cHc9MQ==", "secret-1"):
        assert leaked not in msg, leaked
    assert "cookie-value-1" in _sse(live.url + "/events/stream", lambda o: len(o) >= 2, headers=H)[1][2]


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_page_draws_the_redacted_shapes(tmp_path):
    """The reducer fed with what an anonymous reader really gets: nothing decoded as a body, the marker kept."""
    c = client(tmp_path)
    c.post("/events", headers=H, json=[
        {"type": "oracle.fired", "rid": "r1", "ts": 10, "data": {"rid": "r1", "session": "gwsid:c1", "pre_state_b64": "QUFB" * 100, "request": {
            "method": "POST", "path": "/api/login", "query": "token=t1", "body_b64": "eyJwIjogMX0="},
            "events": [{"oracle": "sql", "detail": {"statement": "SELECT 1"}, "stack": []}]}},
        {"type": "session.captured", "ts": 11, "data": {"session": "gwsid:c1"}},
        {"type": "session.released", "ts": 12, "data": {"session": "gwsid:c1"}},
        {"type": "incident.opened", "ts": 13, "incident": "i", "data": {"incident": "i", "route": "/api/login", "evidence_rid": "r1"}}])
    (tmp_path / "evs.json").write_text(json.dumps(c.get("/events").json()["events"]))
    script = (
        "const S = require(process.argv[1]); const st = S.newState();"
        "JSON.parse(require('fs').readFileSync(process.argv[2], 'utf8')).forEach((e) => S.reduce(st, e, e.seq));"
        "const o = st.incidents.i.oracles[0].data;"
        "console.log(JSON.stringify({body: o.request.body_b64, hidden: o.request.body_hidden, query: o.request.query,"
        " stmt: o.events[0].detail.statement, captive: S.scoreboard(st).captive, ignored: st.ignored, all: JSON.stringify(st)}));")
    out = subprocess.run([NODE, "-e", script, str(HERE.parent / "static" / "state.js"), str(tmp_path / "evs.json")], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    assert (got["body"], got["hidden"], got["query"], got["stmt"]) == ("", "[redacted: 12 chars]", "token=[redacted]", "[redacted: 8 chars]")
    assert got["captive"] == 0 and got["ignored"] == 0           # captured and released still pair up under the public name
    assert "QUFB" not in got["all"] and "gwsid:c1" not in got["all"]
