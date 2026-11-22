"""Gateway with `auth.kind` immune-token / jwt-hs256 / introspect / none, and `mode: observe`
(contracts/product.md §2, §3). The gateway runs as a real process (python -m gateway) configured
through IMMUNE_AUTH / GW_MODE, the way `immune up` starts it; prod, clones and the bus are fakes."""
import base64
import hashlib
import hmac
import json
import os
import sys
import time

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from immune import auth as A
from immune_contracts import authtoken, wire

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "acceptance"))
from helpers import ThreadServer, free_port, kill, spawn, wait_http  # noqa: E402

ADMIN = {"x-admin-token": "adm"}
OPENAPI = os.path.join(ROOT, "acceptance", "fixture", "fixture_app", "openapi.yaml")


class World:
    pass


def _prod(w):
    app = FastAPI()

    @app.get("/api/me")
    async def me(request: Request):
        w.introspections.append({"authorization": request.headers.get("authorization"),
                                 "cookie": request.headers.get("cookie")})
        a = request.headers.get("authorization") or ""
        if a.startswith("Bearer good-"):
            return {"id": int(a.split("-", 1)[1]), "role": "user"}
        if a == "Bearer boss":
            return {"id": 1, "role": "admin"}
        if "session=s7" in (request.headers.get("cookie") or ""):
            return {"user": {"id": 7}, "role": "user"}
        return JSONResponse({"detail": "no"}, status_code=401)

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def any_(path: str, request: Request):
        w.prod_seen.append({"path": "/" + path, "query": request.url.query})
        return {"from": "prod"}
    return app


def _clone(w, cid, key, ingest):
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def any_(path: str, request: Request):
        h = dict(request.headers)
        w.clone_seen.append({"path": "/" + path, "query": request.url.query, "headers": h})
        text = "/" + path + "?" + request.url.query
        verdict = "oracle" if "ATTACK" in text else "inconclusive" if "UNSURE" in text else "clean"
        if verdict == "oracle":
            ev = {"clone": cid, "rid": h.get(wire.H_RID, ""), "mode": h.get(wire.H_MODE, "L1"), "release": "t0",
                  "verdict": "oracle", "uid": None, "role": None, "status": 200, "pre_state_b64": None,
                  "request": {"method": "GET", "path": "/" + path, "query": request.url.query, "headers": {},
                              "body_b64": ""},
                  "events": [{"oracle": "sql", "detail": {"statement": "x", "input": "x", "param": "q"}, "stack": []}]}
            raw = wire.dumps(ev)
            async with httpx.AsyncClient() as c:
                await c.post(ingest() + "/_clone/evidence", content=raw,
                             headers={wire.H_CLONE_ID: cid, wire.H_SIGNATURE: wire.sign(key, raw),
                                      "content-type": "application/json"})
        return JSONResponse({"from": cid, "synthetic": True}, status_code=401 if verdict == "inconclusive" else 200,
                            headers={wire.H_VERDICT: verdict})
    return app


def _bus(w):
    app = FastAPI()

    @app.post("/events")
    async def post(request: Request):
        d = await request.json()
        w.events.extend(d if isinstance(d, list) else [d])
        return {"ok": True}
    return app


def start(tmp_path, auth: dict, mode: str = "enforce", extra_env=None):
    w = World()
    w.prod_seen, w.clone_seen, w.events, w.introspections = [], [], [], []
    w.prod = ThreadServer(_prod(w))
    w.bus = ThreadServer(_bus(w))
    data, admin, ingest = free_port(), free_port(), free_port()
    w.c1 = ThreadServer(_clone(w, "c1", "k1", lambda: f"http://127.0.0.1:{ingest}"))
    (tmp_path / "manifest.json").write_text(json.dumps({"seed_max_uid": 2, "canaries": {"note_id": [7]}}))
    w.record = tmp_path / "requests.jsonl"
    env = {"GW_HOST": "127.0.0.1", "GW_DATA_PORT": str(data), "GW_ADMIN_PORT": str(admin),
           "GW_INGEST_PORT": str(ingest), "PROD_ADDR": w.prod.addr, "PROD_RELEASE": "t0",
           "PROD_APP_SECRET": "prodsecret", "SHADOW_APP_SECRET": "shadowsecret", "OPENAPI_PATH": OPENAPI,
           "MANIFEST_PATH": str(tmp_path / "manifest.json"), "RECORD_PATH": str(w.record), "BUS_URL": w.bus.url,
           "BUS_TOKEN": "bt", "ADMIN_TOKEN": "adm", "RUN_ID": "test", "GW_MODE": mode,
           "IMMUNE_AUTH": json.dumps(auth), **(extra_env or {})}
    w.proc = spawn(["-m", "gateway"], env)
    w.url, w.admin = f"http://127.0.0.1:{data}", f"http://127.0.0.1:{admin}"
    wait_http(w.admin + "/_admin/health", headers=ADMIN)
    assert httpx.put(w.admin + "/_admin/pool", headers=ADMIN, json={"clones": [
        {"id": "c1", "addr": w.c1.addr, "key": "k1", "release": "t0"}]}).status_code == 200
    return w


def stop(w):
    kill(w.proc)
    for s in (w.prod, w.bus, w.c1):
        s.stop()


@pytest.fixture()
def world(tmp_path):
    made = []

    def make(*a, **k):
        w = start(tmp_path, *a, **k)
        made.append(w)
        return w
    yield make
    for w in made:
        stop(w)


def records(w):
    for _ in range(40):
        if w.record.exists() and w.record.read_text().strip():
            break
        time.sleep(0.05)
    return [json.loads(l) for l in w.record.read_text().splitlines() if l.strip()]


def wait_events(w, typ, n=1, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        got = [e for e in w.events if e.get("type") == typ]
        if len(got) >= n:
            return got
        time.sleep(0.05)
    return [e for e in w.events if e.get("type") == typ]


def bearer(t):
    return {"authorization": "Bearer " + t}


# ------------------------------------------------------------------ HS256 (stdlib) unit level
def test_jwt_hs256_roundtrip_and_rejections():
    now = time.time()
    t = A.jwt_encode("k", {"sub": "5", "exp": now + 60})
    assert A.jwt_decode("k", t)["sub"] == "5"
    assert A.jwt_decode("other", t) is None                                     # wrong key
    assert A.jwt_decode("k", A.jwt_encode("k", {"sub": "5", "exp": now - 3600})) is None   # expired
    assert A.jwt_decode("k", A.jwt_encode("k", {"sub": "5", "nbf": now + 3600})) is None   # not yet valid
    h, p, s = t.split(".")
    none_hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    assert A.jwt_decode("k", none_hdr + "." + p + ".") is None                  # alg none
    hs512 = A.jwt_encode("k", {"sub": "5"}, header={"alg": "HS512"})
    assert A.jwt_decode("k", hs512) is None                                     # only HS256
    tampered = h + "." + base64.urlsafe_b64encode(b'{"sub":"1"}').rstrip(b"=").decode() + "." + s
    assert A.jwt_decode("k", tampered) is None
    # interoperable with a hand-made HS256 token
    seg = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=") + b"." + \
        base64.urlsafe_b64encode(b'{"sub":42}').rstrip(b"=")
    sig = base64.urlsafe_b64encode(hmac.new(b"k", seg, hashlib.sha256).digest()).rstrip(b"=")
    assert A.jwt_decode("k", (seg + b"." + sig).decode()) == {"sub": 42}
    au = A.Authenticator({"kind": "jwt-hs256", "role_claim": "role"}, "k", "sk")
    assert (au.from_token(au.mint(9, "admin")).uid, au.from_token(au.mint(9, "admin")).role) == (9, "admin")
    assert au.from_token(A.jwt_encode("k", {"sub": "alice"})).uid is None       # non-integer subject: anonymous


# ------------------------------------------------------------------ immune-token / none
def test_immune_token_kind(world):
    w = world({"kind": "immune-token"})
    httpx.get(w.url + "/search", params={"q": "usb"}, headers=bearer(authtoken.mint("prodsecret", 1)))
    httpx.get(w.url + "/search", params={"q": "usb"}, headers=bearer(authtoken.mint("prodsecret", 9)))
    httpx.get(w.url + "/search", params={"q": "usb"}, headers=bearer(authtoken.mint("forged", 1)))
    r = records(w)
    assert [(x["uid"], x["trusted"]) for x in r[:3]] == [(1, True), (9, False), (None, False)]
    rh = httpx.get(w.url + "/search", params={"q": "usb"}, headers=bearer(authtoken.mint("shadowsecret", 1)))
    assert rh.json()["synthetic"] is True and records(w)[-1]["class"] == "evidence"   # honeytoken


def test_none_kind_ignores_credentials(world):
    w = world({"kind": "none"})
    httpx.get(w.url + "/search", params={"q": "usb"}, headers=bearer(authtoken.mint("prodsecret", 1)))
    assert records(w)[0]["uid"] is None and records(w)[0]["session"].startswith("gwsid:")


# ------------------------------------------------------------------ jwt-hs256
def test_jwt_hs256_kind(world):
    w = world({"kind": "jwt-hs256", "secret_env": "APP_JWT_KEY", "uid_claim": "sub", "role_claim": "role",
               "admin_values": ["superuser"]}, extra_env={"APP_JWT_KEY": "jwt-prod-key"})
    good = A.jwt_encode("jwt-prod-key", {"sub": "2", "role": "superuser", "exp": time.time() + 60})
    untrusted = A.jwt_encode("jwt-prod-key", {"sub": "40", "exp": time.time() + 60})
    forged = A.jwt_encode("prodsecret", {"sub": "1"})            # PROD_APP_SECRET is not the jwt key
    expired = A.jwt_encode("jwt-prod-key", {"sub": "1", "exp": time.time() - 3600})
    for t in (good, untrusted, forged, expired):
        assert httpx.get(w.url + "/search", params={"q": "usb"}, headers=bearer(t)).json() == {"from": "prod"}
    r = records(w)
    assert [(x["uid"], x["trusted"], x["session"].split(":")[0]) for x in r] == [
        (2, True, "uid"), (40, False, "uid"), (None, False, "gwsid"), (None, False, "gwsid")]
    # identified requests reach a clone with x-imm-uid/role derived from the claims
    httpx.get(w.url + "/search", params={"q": "O'Brien"}, headers=bearer(good))
    h = w.clone_seen[-1]["headers"]
    assert h[wire.H_UID] == "2" and h[wire.H_ROLE] == "admin"
    # a token signed with the shadow secret (handed out by a clone) is a honeytoken
    honey = A.jwt_encode("shadowsecret", {"sub": "1", "exp": 1})
    rh = httpx.get(w.url + "/search", params={"q": "usb"}, headers=bearer(honey))
    assert rh.json()["synthetic"] is True and records(w)[-1]["class"] == "evidence"


# ------------------------------------------------------------------ introspect
def test_introspect_kind_calls_prod_and_caches(world):
    w = world({"kind": "introspect", "path": "/api/me", "uid_field": "id", "role_field": "role", "cache_s": 30})
    with httpx.Client() as c:
        c.get(w.url + "/search", params={"q": "usb"})                        # no credentials: no call
        assert w.introspections == []
        c.get(w.url + "/search", params={"q": "usb"}, headers=bearer("good-2"))
        c.get(w.url + "/search", params={"q": "cable"}, headers=bearer("good-2"))   # cached
        c.get(w.url + "/search", params={"q": "usb"}, headers=bearer("good-30"))
        c.get(w.url + "/search", params={"q": "usb"}, headers=bearer("bad"))
    assert [x["authorization"] for x in w.introspections] == ["Bearer good-2", "Bearer good-30", "Bearer bad"]
    assert all("gwsid" not in (x["cookie"] or "") for x in w.introspections)   # the gateway cookie stays out
    r = records(w)
    assert [(x["uid"], x["trusted"]) for x in r] == [(None, False), (2, True), (2, True), (30, False), (None, False)]
    # cookie credentials, nested uid field
    w2 = world({"kind": "introspect", "path": "/api/me", "uid_field": "user.id"})
    httpx.get(w2.url + "/search", params={"q": "usb"}, headers={"cookie": "gwsid=" + "a" * 24 + "; session=s7"})
    assert w2.introspections[-1]["cookie"] == "session=s7"
    assert records(w2)[-1]["uid"] == 7 and records(w2)[-1]["trusted"] is False
    # introspection never counts as client traffic to prod
    assert all(p["path"] != "/api/me" for p in w.prod_seen + w2.prod_seen)


# ------------------------------------------------------------------ observe mode
def test_observe_mode_detonates_but_answers_from_prod(world):
    w = world({"kind": "immune-token"}, mode="observe")
    with httpx.Client() as c:
        r = c.get(w.url + "/search", params={"q": "ATTACK' OR 1=1--"})
        assert r.json() == {"from": "prod"}                                      # answered by prod
        assert w.clone_seen and w.clone_seen[-1]["headers"][wire.H_MODE] == "L1"   # but detonated
        r2 = c.get(w.url + "/search", params={"q": "usb"})                      # same session: not captive
        assert r2.json() == {"from": "prod"} and len(w.clone_seen) == 1
    assert httpx.get(w.admin + "/_admin/sessions", headers=ADMIN).json()["captive"] == []
    # canary hit (evidence): enforce would capture and replay in L2; observe detonates and answers from prod
    rc = httpx.get(w.url + "/notes/7", headers=bearer(authtoken.mint("prodsecret", 9)))
    assert rc.json() == {"from": "prod"}
    # trusted identity on an evidence request: enforce would deny
    rt = httpx.get(w.url + "/notes/7", headers=bearer(authtoken.mint("prodsecret", 1)))
    assert rt.json() == {"from": "prod"}
    recs = records(w)
    assert [(x["route"], x.get("would_route"), x.get("observe")) for x in recs] == [
        ("prod", "shadow_l1", True), ("prod", "prod", True), ("prod", "shadow_l2", True), ("prod", "deny", True)]
    fired = wait_events(w, "oracle.fired")
    assert fired and all(e["data"].get("observe") is True for e in fired)
    routed = wait_events(w, "request.routed", 4)
    assert [e["data"].get("would_route") for e in routed[:4]] == ["shadow_l1", "prod", "shadow_l2", "deny"]
    assert all(e["data"].get("observe") for e in routed)
    # rules are recorded but not enforced
    rule = {"id": "r-obs", "route": "/search", "method": "GET", "param": {"in": "query", "name": "q"},
            "grammar": "^[a-z ]{1,20}$", "scope": "param", "ttl_s": 600, "incident": "i1", "created": time.time()}
    assert httpx.post(w.admin + "/_admin/rules", json=rule, headers=ADMIN).status_code in (200, 201)
    httpx.put(w.admin + "/_admin/pool", headers=ADMIN, json={"clones": []})   # no clone: enforce would deny
    rr = httpx.get(w.url + "/search", params={"q": "zz' --"})
    assert rr.json() == {"from": "prod"} and records(w)[-1]["would_route"] == "deny"
    # switching to enforce at runtime restores the normal behaviour
    assert httpx.post(w.admin + "/_admin/mode", json={"mode": "enforce"}, headers=ADMIN).json() == {"mode": "enforce"}
    assert httpx.get(w.url + "/search", params={"q": "zz' --"}).status_code == 404
    assert httpx.post(w.admin + "/_admin/mode", json={"mode": "bogus"}, headers=ADMIN).status_code == 422
