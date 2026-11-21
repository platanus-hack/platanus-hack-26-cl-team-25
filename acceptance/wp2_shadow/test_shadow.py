"""Acceptance for WP2 (shadow/). Run: .venv/bin/pytest acceptance/wp2_shadow -q"""
import base64, json, os, sqlite3, time
import httpx, jsonschema, pytest
from fastapi import FastAPI, Request
from immune_contracts import wire
from helpers import ROOT, ThreadServer, free_port, kill, spawn, wait_http

UP = "../" * 14


@pytest.fixture()
def env(tmp_path, monkeypatch):
    from fixture_app import seed
    seed_db = str(tmp_path / "seed.db"); seed.make(seed_db, shadow=True)
    work = str(tmp_path / "work.db")
    monkeypatch.setenv("APP_DB", work); monkeypatch.setenv("APP_SECRET", "shadowsecret")
    monkeypatch.setenv("SHADOW_SEED_DB", seed_db)
    return {"seed": seed_db, "work": work, "tmp": tmp_path}


@pytest.fixture()
def h(env):
    from shadow.harness import Harness
    hh = Harness(profile="fixture_app.shadow_profile", seed_db=env["seed"], state=None)
    yield hh
    hh.close()


def kinds(r):
    return [e["oracle"] for e in r.events]


def test_sqli_union_fires(h):
    r = h.send("GET", "/search", query="q=x%27%20UNION%20SELECT%20id%2C%20body%20FROM%20notes--")
    assert r.status == 200 and r.verdict == "oracle" and "sql" in kinds(r)
    ev = next(e for e in r.events if e["oracle"] == "sql")
    assert "UNION" in ev["detail"]["statement"]
    assert any(f["file"].endswith("main.py") and f["func"] == "search" for f in ev["stack"])


def test_sqli_comment_fires(h):
    r = h.send("GET", "/search", query="q=cable%27--")
    assert r.status == 200 and "sql" in kinds(r)


def test_benign_search_clean(h):
    r = h.send("GET", "/search", query="q=usb")
    assert r.status == 200 and r.verdict == "clean" and r.events == []


def test_apostrophe_syntax_error_is_inconclusive_not_oracle(h):
    r = h.send("GET", "/search", query="q=O%27Brien")
    assert r.status >= 500 and r.verdict == "inconclusive" and "sql" not in kinds(r)


def test_apostrophe_parameterised_is_clean(h):
    r = h.send("GET", "/safe-search", query="q=O%27Brien")
    assert r.status == 200 and r.verdict == "clean" and b"stout" in r.body


def test_sqli_payload_on_parameterised_query_is_clean(h):
    r = h.send("GET", "/safe-search", query="q=x%27%20UNION%20SELECT%20id%2C%20body%20FROM%20notes--")
    assert r.status == 200 and r.verdict == "clean"


def test_traversal_fires(h):
    r = h.send("GET", "/download", query="name=" + UP.replace("/", "%2F") + "etc%2Fhostname")
    assert r.status == 200 and r.verdict == "oracle" and "file" in kinds(r)
    ev = next(e for e in r.events if e["oracle"] == "file")
    assert ev["detail"]["realpath"] == os.path.realpath("/etc/hostname")
    assert r.body.strip() == open("/etc/hostname", "rb").read().strip()


def test_legit_download_clean(h):
    r = h.send("GET", "/download", query="name=manual.v1.txt")
    assert r.status == 200 and r.verdict == "clean" and r.events == []
    r = h.send("GET", "/download", query="name=manual.v1.txt")  # second time too (no warm-up noise)
    assert r.verdict == "clean"


def test_owner_oracle(h):
    r = h.send("GET", "/notes/2", uid=1, role="user")
    assert r.status == 200 and r.verdict == "oracle" and kinds(r) == ["owner"]
    assert r.events[0]["detail"] == {"marker_owner": 2, "requester": 1}
    assert h.send("GET", "/notes/1", uid=1, role="user").verdict == "clean"
    assert h.send("GET", "/notes/2", uid=1, role="admin").verdict == "clean"


def test_unknown_user_is_created_and_judged(h):
    r = h.send("GET", "/notes/1", uid=99, role="user")
    assert r.status == 200 and r.verdict == "oracle" and kinds(r) == ["owner"]


def test_fixed_endpoint_is_inconclusive(h):
    r = h.send("GET", "/safe-notes/2", uid=1, role="user")
    assert r.status == 404 and r.verdict == "inconclusive"


def test_sqli_dump_of_private_rows_also_owner(h):
    r = h.send("GET", "/search", query="q=x%27%20UNION%20SELECT%20id%2C%20body%20FROM%20notes--")
    assert "owner" in kinds(r)  # anonymous requester sees markers


def test_l1_resets_and_l2_keeps_state(h):
    body = json.dumps({"body": "hello"}).encode()
    hd = {"content-type": "application/json"}
    r = h.send("POST", "/notes", headers=hd, body=body, uid=1, mode="L1")
    nid = json.loads(r.body)["id"]
    assert h.send("GET", f"/safe-notes/{nid}", uid=1, mode="L1").status == 404  # gone after reset
    r = h.send("POST", "/notes", headers=hd, body=body, uid=1, mode="L2")
    nid = json.loads(r.body)["id"]
    assert h.send("GET", f"/safe-notes/{nid}", uid=1, mode="L2").status == 200
    snap = h.snapshot()
    assert snap[:15] == b"SQLite format 3"


def test_state_roundtrip(env, tmp_path):
    from shadow.harness import Harness
    a = Harness(profile="fixture_app.shadow_profile", seed_db=env["seed"], state=None)
    r = a.send("POST", "/notes", headers={"content-type": "application/json"}, body=b'{"body":"keep"}', uid=1, mode="L2")
    nid = json.loads(r.body)["id"]; snap = a.snapshot(); a.close()
    b = Harness(profile="fixture_app.shadow_profile", seed_db=env["seed"], state=snap)
    assert b.send("GET", f"/safe-notes/{nid}", uid=1, mode="L2").status == 200
    b.close()


# ---- server mode: wire protocol ----
@pytest.fixture()
def server(env):
    got = []
    col = FastAPI()

    @col.post("/_clone/evidence")
    async def ev(request: Request):
        got.append((dict(request.headers), await request.body()))
        return {"ok": True}

    collector = ThreadServer(col)
    port = free_port()
    proc = spawn(["-m", "shadow.run", "--profile", "fixture_app.shadow_profile", "--host", "127.0.0.1", "--port", str(port)],
                 {"APP_DB": env["work"], "APP_SECRET": "shadowsecret", "SHADOW_SEED_DB": env["seed"],
                  "CLONE_ID": "c1", "CLONE_KEY": "k1", "COLLECTOR_URL": collector.url, "RELEASE": "t0"})
    try:
        wait_http(f"http://127.0.0.1:{port}/health")
        yield f"http://127.0.0.1:{port}", got
    finally:
        out = kill(proc); collector.stop()
        print(out[-3000:])


def test_wire_clean(server):
    url, got = server
    r = httpx.get(url + "/search", params={"q": "usb"}, headers={wire.H_RID: "r1", wire.H_MODE: "L1"})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "clean" and r.headers[wire.H_EVENTS] == "0"
    assert got == []


def test_wire_evidence_signed_and_valid(server):
    url, got = server
    r = httpx.get(url + "/download", params={"name": UP + "etc/hostname"}, headers={wire.H_RID: "r2", wire.H_MODE: "L2"})
    assert r.headers[wire.H_VERDICT] == "oracle" and int(r.headers[wire.H_EVENTS]) >= 1
    assert len(got) == 1  # pushed BEFORE the response was released
    headers, body = got[0]
    assert headers[wire.H_CLONE_ID] == "c1" and wire.check("k1", body, headers[wire.H_SIGNATURE])
    ev = json.loads(body)
    schema = json.load(open(os.path.join(ROOT, "contracts/schemas/evidence.schema.json")))
    jsonschema.validate(ev, schema)
    assert ev["rid"] == "r2" and ev["mode"] == "L2" and ev["release"] == "t0"
    assert base64.b64decode(ev["pre_state_b64"])[:15] == b"SQLite format 3"
    assert not any(k.startswith("x-imm-") for k in ev["request"]["headers"])


def test_wire_identity_injection(server):
    url, _ = server
    r = httpx.get(url + "/notes/1", headers={wire.H_RID: "r3", wire.H_MODE: "L1", wire.H_UID: "1", wire.H_ROLE: "user",
                                              "authorization": "Bearer garbage-prod-token"})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "clean"


def test_wire_collector_down_does_not_break(env):
    port = free_port()
    proc = spawn(["-m", "shadow.run", "--profile", "fixture_app.shadow_profile", "--host", "127.0.0.1", "--port", str(port)],
                 {"APP_DB": env["work"], "APP_SECRET": "s", "SHADOW_SEED_DB": env["seed"], "CLONE_ID": "c1", "CLONE_KEY": "k1",
                  "COLLECTOR_URL": "http://127.0.0.1:9", "RELEASE": "t0"})
    try:
        wait_http(f"http://127.0.0.1:{port}/health")
        t = time.time()
        r = httpx.get(f"http://127.0.0.1:{port}/search", params={"q": "cable'--"}, headers={wire.H_RID: "r", wire.H_MODE: "L1"}, timeout=10)
        assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle" and time.time() - t < 3
    finally:
        kill(proc)
