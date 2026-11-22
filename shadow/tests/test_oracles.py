import json, os

import pytest

from immune_contracts import authtoken


@pytest.fixture()
def h(tmp_path, monkeypatch):
    from demo_app import seed
    from shadow.harness import Harness
    s = str(tmp_path / "seed.db"); seed.make(s)
    monkeypatch.setenv("APP_DB", str(tmp_path / "work.db"))
    monkeypatch.setenv("APP_SECRET", "sec")
    hh = Harness(profile="demo_app.profile", seed_db=s, state=None)
    yield hh
    hh.close()


def kinds(r):
    return [e["oracle"] for e in r.events]


# ---------- sql
@pytest.mark.parametrize("path,query", [
    ("/search", "q=usb"), ("/search", "q=items"), ("/safe", "q=O%27Brien"), ("/safe", "q=id%2C%20name"),
    ("/item/12", ""), ("/raw", "id=12"), ("/sorted", "sort=cheap"), ("/col", "c=name"), ("/escaped", "q=O%27Brien"),
    ("/escaped", "q=x%27%20OR%20%271%27%3D%271"), ("/upper", "q=usb"),
])
def test_sql_negative(h, path, query):
    r = h.send("GET", path, query=query)
    assert "sql" not in kinds(r), r.events


@pytest.mark.parametrize("path,query", [
    ("/search", "q=x%27%20OR%201%3D1--"), ("/search", "q=zz%27%20OR%20%271%27%3D%271"), ("/raw", "id=1%20OR%201%3D1"),
    ("/col", "c=price%20DESC"), ("/upper", "q=x%27%20or%20%271%27%3D%271"),
])
def test_sql_positive(h, path, query):
    r = h.send("GET", path, query=query)
    assert r.status == 200 and "sql" in kinds(r)
    ev = next(e for e in r.events if e["oracle"] == "sql")
    assert set(ev["detail"]) >= {"statement", "input", "param"}
    assert ev["stack"] and ev["stack"][0]["file"] == "demo_app/main.py"


def test_sql_syntax_error_does_not_fire(h):
    r = h.send("GET", "/search", query="q=O%27Brien")
    assert r.status == 500 and r.verdict == "inconclusive" and r.events == []


def test_sql_json_leaf_and_executescript(h):
    r = h.send("POST", "/script", headers={"content-type": "application/json"}, body=json.dumps({"name": "a'; DROP TABLE items; --"}).encode())
    assert "sql" in kinds(r) and r.events[0]["detail"]["param"] == "name"
    r = h.send("POST", "/script", headers={"content-type": "application/json"}, body=b'{"name": "plain name"}')
    assert r.verdict == "clean"


def test_sql_param_named_after_route(h):
    r = h.send("GET", "/raw", query="id=1%20OR%201%3D1")
    assert r.events[0]["detail"]["param"] == "id" and r.events[0]["detail"]["location"] == "query"
    # a path parameter is reported under the name the router gave it, not as a positional segment
    r = h.send("GET", "/tag/x%27%20OR%20%271%27%3D%271")
    ev = next(e for e in r.events if e["oracle"] == "sql")
    assert (ev["detail"]["location"], ev["detail"]["param"], ev["detail"]["input"]) == ("path", "tag", "x' OR '1'='1")
    assert "sql" not in kinds(h.send("GET", "/tag/usb%20cable"))


# ---------- file
def test_file_negative(h):
    for p in ("/file", "/send"):
        assert h.send("GET", p, query="name=guide.v1.txt").verdict == "clean"
    assert h.send("GET", "/lazy").verdict == "clean"  # lazy import + linecache are not request file reads
    assert h.send("GET", "/ls").verdict == "clean"


def test_file_positive(h):
    # A real file outside the allowed roots: /etc/hostname on POSIX, win.ini on Windows.
    tail = "etc/hostname" if os.name != "nt" else "Windows/win.ini"
    for p in ("/file", "/send"):
        r = h.send("GET", p, query="name=../../../../../../../../../../" + tail)
        assert r.verdict == "oracle" and kinds(r) == ["file"], r.events
        ev = r.events[0]
        assert ev["detail"]["realpath"] == os.path.realpath("/" + tail)
        assert ev["stack"] and ev["stack"][-1]["file"] == "demo_app/main.py"
    r = h.send("GET", "/ls", query="d=../../../../../../../../etc")
    assert kinds(r) == ["file"]


# ---------- proc / net
def test_proc(h):
    r = h.send("GET", "/ping")
    assert "proc" in kinds(r) and r.verdict == "oracle"
    assert h.send("GET", "/health").verdict == "clean"


def test_net(h):
    r = h.send("GET", "/fetch")
    assert "net" in kinds(r)
    assert any(f["func"] == "fetch" for f in r.events[0]["stack"])
    assert h.send("GET", "/health").events == []


# ---------- owner
def test_owner_positive(h):
    r = h.send("GET", "/note/2", uid=1)
    assert kinds(r) == ["owner"] and r.events[0]["detail"] == {"marker_owner": 2, "requester": 1}
    assert kinds(h.send("GET", "/gz", uid=1)) == ["owner"]  # compressed body is scanned too
    assert kinds(h.send("GET", "/dump")) == ["owner"] * 3  # public path, but a bulk dump of several owners
    tok = authtoken.mint("sec", 2, "user")  # identity from the client's own (shadow) token
    assert h.send("GET", "/note/1", headers={"authorization": "Bearer " + tok}).events[0]["detail"] == {"marker_owner": 1, "requester": 2}


def test_owner_negative(h):
    assert h.send("GET", "/note/1", uid=1).verdict == "clean"
    assert h.send("GET", "/note/2", uid=3, role="admin").verdict == "clean"
    assert h.send("GET", "/gz", uid=2).verdict == "clean"
    # login is public and echoes the caller's own private data while the caller is still anonymous
    r = h.send("POST", "/login", headers={"content-type": "application/json"}, body=b'{"uid": 1}')
    assert r.status == 200 and r.verdict == "clean"
    tok = authtoken.mint("sec", 3, "admin")
    assert h.send("GET", "/dump", headers={"authorization": "Bearer " + tok}).verdict == "clean"


def test_owner_public_path_with_sqli(h):
    r = h.send("GET", "/search", query="q=x%27%20UNION%20SELECT%20id%2C%20body%20FROM%20notes%20WHERE%20id%3D1--")
    assert "sql" in kinds(r) and "owner" in kinds(r)


# ---------- verdicts, state
def test_verdicts(h):
    assert h.send("GET", "/boom").verdict == "inconclusive"
    assert h.send("GET", "/note/1").verdict == "inconclusive"  # 401
    assert h.send("GET", "/nope").verdict == "inconclusive"  # 404
    r = h.send("GET", "/health")
    assert r.verdict == "clean" and r.headers["x-imm-verdict"] == "clean" and r.headers["x-imm-events"] == "0"


def test_l1_reset_with_connection_kept_open(h):
    hd = {"content-type": "application/json"}
    nid = json.loads(h.send("POST", "/note", headers=hd, body=b'{"body":"x"}', uid=1).body)["id"]
    assert h.send("GET", f"/note/{nid}", uid=1).status == 404
    nid = json.loads(h.send("POST", "/note", headers=hd, body=b'{"body":"x"}', uid=1, mode="L2").body)["id"]
    assert h.send("GET", f"/note/{nid}", uid=1, mode="L2").status == 200
    snap = h.snapshot()
    assert h.send("GET", "/health").status == 200  # L1 -> back to seed
    assert h.send("GET", f"/note/{nid}", uid=1, mode="L2").status == 404
    assert snap[:15] == b"SQLite format 3"


def test_state_harness_resets_to_its_base_state(tmp_path, monkeypatch):
    from demo_app import seed
    from shadow.harness import Harness
    s = str(tmp_path / "seed.db"); seed.make(s)
    monkeypatch.setenv("APP_DB", str(tmp_path / "w.db")); monkeypatch.setenv("APP_SECRET", "sec")
    a = Harness("demo_app.profile", s)
    nid = json.loads(a.send("POST", "/note", headers={"content-type": "application/json"}, body=b'{"body":"k"}', uid=1, mode="L2").body)["id"]
    snap = a.snapshot(); a.close()
    b = Harness("demo_app.profile", s, state=snap)
    assert b.send("GET", f"/note/{nid}", uid=1).status == 200  # L1 on a state harness keeps the base state
    assert b.send("GET", f"/note/{nid}", uid=1).status == 200
    b.close()


def test_evidence_built_in_harness(h):
    r = h.send("GET", "/raw", query="id=1%20OR%201%3D1", mode="L2", uid=1)
    ev = r.evidence
    assert ev["verdict"] == "oracle" and ev["mode"] == "L2" and ev["uid"] == 1 and ev["pre_state_b64"]
    assert not any(k.startswith("x-imm-") for k in ev["request"]["headers"])


# ---------- multi-step (stored) taint across a captive session (shadow/taint.py)
def test_stored_xss_fires_on_the_request_that_renders_an_earlier_requests_input(h):
    # plant markup in a note (L2, kept), then render the wall (L1): the stored value is reflected unescaped
    payload = "<script>alert(91)</script>"
    import json as _j
    plant = h.send("POST", "/note", headers={"content-type": "application/json"},
                   body=_j.dumps({"body": payload}).encode(), uid=1, mode="L2")
    assert plant.status == 200 and "xss" not in kinds(plant)      # planting alone is not an XSS
    r = h.send("GET", "/wall", uid=1, mode="L1")
    assert r.status == 200 and "xss" in kinds(r)
    ev = next(e for e in r.events if e["oracle"] == "xss")
    assert ev["detail"]["stored"] is True and payload in ev["detail"]["input"]
    assert ev["stack"] and ev["stack"][0]["file"] == "demo_app/main.py"


def test_stored_xss_quiet_for_a_note_without_markup(h):
    import json as _j
    h.send("POST", "/note", headers={"content-type": "application/json"},
           body=_j.dumps({"body": "an ordinary note"}).encode(), uid=1, mode="L2")
    assert "xss" not in kinds(h.send("GET", "/wall", uid=1, mode="L1"))


def test_second_order_sql_fires_when_a_stored_note_reaches_a_query(h):
    import json as _j
    plant = h.send("POST", "/note", headers={"content-type": "application/json"},
                   body=_j.dumps({"body": "x' OR '1'='1"}).encode(), uid=1, mode="L2")
    assert "sql" not in kinds(plant)                              # the INSERT is parameterised
    r = h.send("GET", "/note_search", uid=1, mode="L1")
    assert r.status == 200 and "sql" in kinds(r)
    ev = next(e for e in r.events if e["oracle"] == "sql")
    assert ev["detail"]["second_order"] is True


def test_second_order_sql_quiet_for_a_benign_stored_note(h):
    import json as _j
    h.send("POST", "/note", headers={"content-type": "application/json"},
           body=_j.dumps({"body": "usb cable"}).encode(), uid=1, mode="L2")
    assert "sql" not in kinds(h.send("GET", "/note_search", uid=1, mode="L1"))
