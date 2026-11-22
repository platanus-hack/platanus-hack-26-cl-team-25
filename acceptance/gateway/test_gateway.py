"""Acceptance tests for gateway/. Run: .venv/bin/pytest acceptance/gateway -q

Prod, clones and the bus are fakes. The fake clone decides its verdict from the request text:
  contains "ATTACK" -> oracle (and pushes signed evidence) ; contains "INCONC" -> inconclusive ; else clean.
"""
import json, os, time
import httpx, pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from immune_contracts import authtoken, wire
from helpers import ROOT, ThreadServer, free_port, kill, spawn, wait_http

ADMIN = {"x-admin-token": "adm"}
PROD_SECRET, SHADOW_SECRET = "prodsecret", "shadowsecret"


def fake_prod(name, seen):
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def any_(path: str, request: Request):
        seen.append({"name": name, "path": "/" + path, "query": request.url.query, "headers": dict(request.headers),
                     "body": await request.body()})
        return JSONResponse({"from": name}, headers={"x-imm-verdict": "leak-test"})
    return app


def fake_clone(cid, key, seen, collector):
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def any_(path: str, request: Request):
        body = await request.body()
        text = "/" + path + "?" + request.url.query + body.decode(errors="replace")
        h = dict(request.headers)
        seen.append({"clone": cid, "path": "/" + path, "query": request.url.query, "headers": h, "body": body})
        verdict = "oracle" if "ATTACK" in text else "inconclusive" if "INCONC" in text else "clean"
        if verdict == "oracle":
            ev = {"clone": cid, "rid": h.get(wire.H_RID, ""), "mode": h.get(wire.H_MODE, "L1"), "release": "t0", "verdict": "oracle",
                  "uid": None, "role": None, "status": 200, "pre_state_b64": None,
                  "request": {"method": request.method, "path": "/" + path, "query": request.url.query, "headers": {}, "body_b64": ""},
                  "events": [{"oracle": "sql", "detail": {"statement": "x", "input": "x", "param": "q"}, "stack": []}]}
            raw = wire.dumps(ev)
            async with httpx.AsyncClient() as c:
                await c.post(collector() + "/_clone/evidence", content=raw,
                             headers={wire.H_CLONE_ID: cid, wire.H_SIGNATURE: wire.sign(key, raw), "content-type": "application/json"})
        return JSONResponse({"from": cid, "synthetic": True}, status_code=404 if verdict == "inconclusive" else 200,
                            headers={wire.H_VERDICT: verdict, wire.H_EVENTS: "1" if verdict == "oracle" else "0"})
    return app


def fake_bus(events):
    app = FastAPI()

    @app.post("/events")
    async def post(request: Request):
        data = await request.json()
        events.extend(data if isinstance(data, list) else [data])
        return {"ok": True}
    return app


class Sys:
    pass


@pytest.fixture()
def s(tmp_path):
    x = Sys()
    x.prod_seen, x.clone_seen, x.events = [], [], []
    x.prod = ThreadServer(fake_prod("prod-a", x.prod_seen))
    x.prod2 = ThreadServer(fake_prod("prod-b", x.prod_seen))
    x.bus = ThreadServer(fake_bus(x.events))
    data, admin, ingest = free_port(), free_port(), free_port()
    x.c1 = ThreadServer(fake_clone("c1", "k1", x.clone_seen, lambda: f"http://127.0.0.1:{ingest}"))
    x.c2 = ThreadServer(fake_clone("c2", "k2", x.clone_seen, lambda: f"http://127.0.0.1:{ingest}"))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"seed_max_uid": 2, "canaries": {"note_id": [7]}}))
    x.record = tmp_path / "requests.jsonl"
    x.proc = spawn(["-m", "gateway"], {
        "GW_HOST": "127.0.0.1", "GW_DATA_PORT": str(data), "GW_ADMIN_PORT": str(admin), "GW_INGEST_PORT": str(ingest),
        "PROD_ADDR": x.prod.addr, "PROD_RELEASE": "t0", "PROD_APP_SECRET": PROD_SECRET, "SHADOW_APP_SECRET": SHADOW_SECRET,
        "OPENAPI_PATH": os.path.join(ROOT, "acceptance/fixture/fixture_app/openapi.yaml"), "MANIFEST_PATH": str(manifest),
        "RECORD_PATH": str(x.record), "BUS_URL": x.bus.url, "BUS_TOKEN": "bt", "ADMIN_TOKEN": "adm", "RUN_ID": "test"})
    x.url, x.admin, x.ingest = f"http://127.0.0.1:{data}", f"http://127.0.0.1:{admin}", f"http://127.0.0.1:{ingest}"
    try:
        wait_http(x.admin + "/_admin/health", headers=ADMIN)
        x.pool = [{"id": "c1", "addr": x.c1.addr, "key": "k1", "release": "t0"}, {"id": "c2", "addr": x.c2.addr, "key": "k2", "release": "t0"}]
        assert httpx.put(x.admin + "/_admin/pool", json={"clones": x.pool}, headers=ADMIN).status_code == 200
        yield x
    finally:
        out = kill(x.proc)
        for srv in (x.prod, x.prod2, x.bus, x.c1, x.c2):
            srv.stop()
        print(out[-4000:])


def tok(uid, secret=PROD_SECRET, role="user"):
    return {"authorization": "Bearer " + authtoken.mint(secret, uid, role)}


def test_clean_goes_to_prod_only(s):
    r = httpx.get(s.url + "/search", params={"q": "usb"})
    assert r.json() == {"from": "prod-a"} and s.clone_seen == [] and len(s.prod_seen) == 1
    assert not any(k.lower().startswith("x-imm-") for k in r.headers)
    assert "gwsid" in r.cookies


def test_admin_requires_token(s):
    assert httpx.get(s.admin + "/_admin/pool").status_code in (401, 403)


def test_suspect_clean_verdict_detonates_then_prod(s):
    r = httpx.get(s.url + "/search", params={"q": "O'Brien"})
    assert r.json() == {"from": "prod-a"}
    assert len(s.clone_seen) == 1 and len(s.prod_seen) == 1
    ch = s.clone_seen[0]["headers"]
    assert ch[wire.H_MODE] == "L1" and ch[wire.H_RID]
    assert s.clone_seen[0]["query"] == s.prod_seen[0]["query"]  # same bytes
    assert not any(k.startswith("x-imm-") for k in s.prod_seen[0]["headers"])


def test_attack_never_reaches_prod_and_session_is_captive(s):
    with httpx.Client() as c:
        r = c.get(s.url + "/search", params={"q": "ATTACK' OR 1=1--"})
        assert r.json()["synthetic"] is True and s.prod_seen == []
        assert not any(k.lower().startswith("x-imm-") for k in r.headers)
        assert s.clone_seen[-1]["headers"][wire.H_MODE] == "L1"
        sess = httpx.get(s.admin + "/_admin/sessions", headers=ADMIN).json()["captive"]
        assert len(sess) == 1 and sess[0]["clone"] is None                     # lazy: no clone held yet
        states = [x["state"] for x in httpx.get(s.admin + "/_admin/pool", headers=ADMIN).json()["clones"]]
        assert states == ["free", "free"]
        r2 = c.get(s.url + "/search", params={"q": "usb"})  # clean request, same cookie -> bound to a clone, L2
        assert r2.json()["synthetic"] is True and s.prod_seen == []
        assert s.clone_seen[-1]["headers"][wire.H_MODE] == "L2"
        r3 = c.get(s.url + "/search", params={"q": "cable"})
        assert r3.json()["from"] == r2.json()["from"]
        sess = httpx.get(s.admin + "/_admin/sessions", headers=ADMIN).json()["captive"]
        assert len(sess) == 1 and sess[0]["clone"] == r2.json()["from"]
    assert httpx.get(s.url + "/search", params={"q": "usb"}).json() == {"from": "prod-a"}  # other session unaffected


def test_cookieless_attack_flood_cannot_exhaust_pool(s):
    for i in range(8):
        r = httpx.get(s.url + "/search", params={"q": f"ATTACK' {i}"})
        assert r.json()["synthetic"] is True
    assert s.prod_seen == []
    states = [x["state"] for x in httpx.get(s.admin + "/_admin/pool", headers=ADMIN).json()["clones"]]
    assert states == ["free", "free"]


def test_first_request_attack_without_cookie_is_not_forwarded(s):
    r = httpx.get(s.url + "/search", params={"q": "ATTACK'"})
    assert r.json()["synthetic"] is True and s.prod_seen == []
    rid = s.clone_seen[0]["headers"][wire.H_RID]
    log = httpx.get(s.admin + "/_admin/prodlog", params={"rid": rid}, headers=ADMIN).json()
    assert log["forwarded"] is False


def test_evidence_is_published_on_bus(s):
    httpx.get(s.url + "/search", params={"q": "ATTACK'"})
    end = time.time() + 3
    while time.time() < end and not [e for e in s.events if e["type"] == "oracle.fired"]:
        time.sleep(0.05)
    fired = [e for e in s.events if e["type"] == "oracle.fired"]
    assert len(fired) == 1 and fired[0]["data"]["events"][0]["oracle"] == "sql" and fired[0]["run"] == "test"
    assert "session" in fired[0]["data"]


def test_ingest_rejects_bad_signature(s):
    raw = wire.dumps({"clone": "c1", "rid": "zz"})
    r = httpx.post(s.ingest + "/_clone/evidence", content=raw, headers={wire.H_CLONE_ID: "c1", wire.H_SIGNATURE: "00"})
    assert r.status_code in (401, 403)
    assert not [e for e in s.events if e["type"] == "oracle.fired"]


def test_inconclusive_fails_open_without_rule_and_closed_with_rule(s):
    assert httpx.get(s.url + "/search", params={"q": "INCONC'"}).json() == {"from": "prod-a"}
    s.prod_seen.clear()
    rule = {"id": "r1", "incident": "i1", "method": "GET", "route": "/search", "param": {"in": "query", "name": "q"},
            "grammar": r"[A-Za-z0-9 ]{0,40}", "scope": "param", "ttl_s": 600}
    assert httpx.post(s.admin + "/_admin/rules", json=rule, headers=ADMIN).status_code in (200, 201)
    r = httpx.get(s.url + "/search", params={"q": "INCONC'"})
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"} and s.prod_seen == []
    assert httpx.get(s.url + "/search", params={"q": "usb"}).json() == {"from": "prod-a"}  # inside grammar: untouched
    assert httpx.delete(s.admin + "/_admin/rules/r1", headers=ADMIN).status_code in (200, 204)
    assert httpx.get(s.url + "/search", params={"q": "INCONC'"}).json() == {"from": "prod-a"}


def test_no_clones_high_signal_denied_low_signal_fails_open(s):
    httpx.put(s.admin + "/_admin/pool", json={"clones": []}, headers=ADMIN)
    r = httpx.get(s.url + "/search", params={"q": "ATTACK'"}, timeout=5)          # grammar violation = high signal
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"} and s.prod_seen == []
    assert httpx.get(s.url + "/notes/1", headers=tok(50), timeout=5).json() == {"from": "prod-a"}  # owner-scoped untrusted = low signal
    assert httpx.get(s.url + "/search", params={"q": "usb"}).json() == {"from": "prod-a"}
    s.prod_seen.clear()
    rule = {"id": "r2", "incident": None, "method": "GET", "route": "/notes/{note_id}", "param": None, "grammar": None,
            "scope": "all", "ttl_s": 600}
    httpx.post(s.admin + "/_admin/rules", json=rule, headers=ADMIN)
    assert httpx.get(s.url + "/notes/1", headers=tok(50), timeout=5).status_code == 404 and s.prod_seen == []   # rule: fail closed


def test_rule_applies_to_trusted_identities(s):
    rule = {"id": "r3", "incident": None, "method": "GET", "route": "/notes/{note_id}", "param": None, "grammar": None,
            "scope": "all", "ttl_s": 600}
    httpx.post(s.admin + "/_admin/rules", json=rule, headers=ADMIN)
    httpx.get(s.url + "/notes/1", headers=tok(1))
    assert len(s.clone_seen) == 1 and s.clone_seen[0]["headers"][wire.H_UID] == "1"


def test_owner_scoped_untrusted_is_detonated_trusted_is_not(s):
    assert httpx.get(s.url + "/notes/1", headers=tok(1)).json() == {"from": "prod-a"}
    assert s.clone_seen == []
    assert httpx.get(s.url + "/notes/1", headers=tok(50)).json() == {"from": "prod-a"}
    h = s.clone_seen[0]["headers"]
    assert h[wire.H_UID] == "50" and h[wire.H_ROLE] == "user" and h[wire.H_MODE] == "L1"


def test_trusted_identity_never_gets_synthetic_data(s):
    r = httpx.get(s.url + "/search", params={"q": "ATTACK'"}, headers=tok(1))
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"} and s.prod_seen == []
    assert httpx.get(s.admin + "/_admin/sessions", headers=ADMIN).json()["captive"] == []
    assert httpx.get(s.url + "/search", params={"q": "usb"}, headers=tok(1)).json() == {"from": "prod-a"}


def test_untrusted_identity_is_captured_by_uid(s):
    r = httpx.get(s.url + "/search", params={"q": "ATTACK'"}, headers=tok(50))
    assert r.json()["synthetic"] is True
    r2 = httpx.get(s.url + "/search", params={"q": "usb"}, headers=tok(50))  # new connection, no cookie, same uid
    assert r2.json()["synthetic"] is True and s.prod_seen == []


def test_client_internal_headers_are_stripped(s):
    httpx.get(s.url + "/notes/1", headers={**tok(50), "x-imm-uid": "1", "x-imm-mode": "L2", "x-imm-verdict": "clean"})
    h = s.clone_seen[0]["headers"]
    assert h[wire.H_UID] == "50" and h[wire.H_MODE] == "L1" and "x-imm-verdict" not in h
    assert not any(k.startswith("x-imm-") for k in s.prod_seen[0]["headers"])


def test_honeytoken_is_evidence(s):
    r = httpx.get(s.url + "/search", params={"q": "usb"}, headers=tok(1, SHADOW_SECRET))
    assert r.json().get("synthetic") is True and s.prod_seen == []
    assert s.clone_seen[-1]["headers"][wire.H_MODE] == "L2"


def test_canary_is_evidence(s):
    r = httpx.get(s.url + "/notes/7", headers=tok(50))
    assert r.json().get("synthetic") is True and s.prod_seen == []


def test_duplicate_query_param_is_suspect(s):
    httpx.get(s.url + "/search?q=usb&q=cable")
    assert len(s.clone_seen) == 1


def test_json_body_is_classified_and_forwarded_intact(s):
    body = json.dumps({"body": "it's <b>fine</b>"}).encode()
    r = httpx.post(s.url + "/notes", content=body, headers={**tok(1), "content-type": "application/json"})
    assert r.json() == {"from": "prod-a"} and len(s.clone_seen) == 1
    assert s.clone_seen[0]["body"] == body and s.prod_seen[0]["body"] == body


def test_passthrough_mode(s):
    httpx.post(s.admin + "/_admin/mode", json={"mode": "passthrough"}, headers=ADMIN)
    assert httpx.get(s.url + "/search", params={"q": "ATTACK'"}).json() == {"from": "prod-a"} and s.clone_seen == []
    httpx.post(s.admin + "/_admin/mode", json={"mode": "enforce"}, headers=ADMIN)
    assert httpx.get(s.url + "/search", params={"q": "ATTACK'"}).json()["synthetic"] is True


def test_upstream_switch(s):
    r = httpx.post(s.admin + "/_admin/upstream", json={"addr": s.prod2.addr, "release": "r2"}, headers=ADMIN)
    assert r.status_code == 200
    assert httpx.get(s.url + "/search", params={"q": "usb"}).json() == {"from": "prod-b"}
    assert httpx.get(s.admin + "/_admin/upstream", headers=ADMIN).json()["release"] == "r2"


def test_prod_down_is_not_a_crash_and_stats_count_it(s):
    httpx.post(s.admin + "/_admin/upstream", json={"addr": "127.0.0.1:9", "release": "dead"}, headers=ADMIN)
    assert httpx.get(s.url + "/search", params={"q": "usb"}, timeout=10).status_code in (502, 503, 504)
    assert httpx.get(s.admin + "/_admin/stats", headers=ADMIN).json()["prod_5xx"] >= 1


def test_bus_down_does_not_slow_requests(s):
    s.bus.stop()
    t = time.time()
    for _ in range(5):
        assert httpx.get(s.url + "/search", params={"q": "usb"}).status_code == 200
    assert time.time() - t < 3


def test_pool_state_and_eviction(s):
    with httpx.Client() as a, httpx.Client() as b, httpx.Client() as c:
        for cl in (a, b):
            cl.get(s.url + "/search", params={"q": "ATTACK'"}); cl.get(s.url + "/search", params={"q": "usb"})
        states = {x["id"]: x["state"] for x in httpx.get(s.admin + "/_admin/pool", headers=ADMIN).json()["clones"]}
        assert states == {"c1": "captive", "c2": "captive"}
        r = c.get(s.url + "/search", params={"q": "ATTACK'"}, timeout=5)   # no free clone, high signal: denied, oldest captive evicted
        assert r.status_code == 404 and s.prod_seen == []
        states = [x["state"] for x in httpx.get(s.admin + "/_admin/pool", headers=ADMIN).json()["clones"]]
        assert sorted(states) == ["captive", "retired"]
        assert len(httpx.get(s.admin + "/_admin/sessions", headers=ADMIN).json()["captive"]) >= 1
        r = b.get(s.url + "/search", params={"q": "usb"}, timeout=5)        # the newer captive keeps its clone
        assert r.json()["synthetic"] is True


def test_recording_is_written_and_redacted(s):
    httpx.get(s.url + "/search", params={"q": "usb"}, headers=tok(1))
    time.sleep(0.3)
    lines = [json.loads(l) for l in s.record.read_text().splitlines()]
    assert lines and lines[-1]["path"] == "/search" and lines[-1]["class"] == "clean" and lines[-1]["route"] == "prod"
    assert lines[-1]["uid"] == 1 and lines[-1]["trusted"] is True
    assert PROD_SECRET not in s.record.read_text() and "Bearer " + authtoken.mint(PROD_SECRET, 1)[:20] not in s.record.read_text()


def test_reset(s):
    httpx.get(s.url + "/search", params={"q": "ATTACK'"}, headers=tok(50))
    httpx.post(s.admin + "/_admin/reset", headers=ADMIN)
    assert httpx.get(s.admin + "/_admin/sessions", headers=ADMIN).json()["captive"] == []
