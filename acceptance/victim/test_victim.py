"""Acceptance tests for victim/. Run: .venv/bin/pytest acceptance/victim -q"""
import json, os, re, sqlite3, subprocess
import pytest, yaml
from helpers import PY, ROOT

MK = re.compile(r"MK[A-Z0-9]{10}")
UP = "../" * 14


@pytest.fixture(scope="module")
def data(tmp_path_factory):
    d = tmp_path_factory.mktemp("seed")
    paths = {k: str(d / v) for k, v in {"prod": "prod.db", "shadow": "shadow.db", "manifest": "manifest.json", "markers": "markers.json"}.items()}
    subprocess.run([PY, "-m", "victim.seed", "--out-prod", paths["prod"], "--out-shadow", paths["shadow"],
                    "--manifest", paths["manifest"], "--markers", paths["markers"], "--seed", "1"], check=True, cwd=ROOT)
    paths["m"] = json.load(open(paths["manifest"])); paths["mk"] = json.load(open(paths["markers"]))
    return paths


def client(db, monkeypatch, secret="prodsecret"):
    import importlib, sys
    monkeypatch.setenv("APP_DB", db); monkeypatch.setenv("APP_SECRET", secret)
    monkeypatch.setenv("APP_STATIC", os.path.join(ROOT, "victim", "static"))
    for m in [m for m in sys.modules if m == "victim" or m.startswith("victim.")]:
        del sys.modules[m]
    from starlette.testclient import TestClient
    return TestClient(importlib.import_module("victim.app.main").app)


def copy(db, tmp_path):
    out = str(tmp_path / "work.db")
    src = sqlite3.connect(db); dst = sqlite3.connect(out); src.backup(dst); src.close(); dst.close()
    return out


@pytest.fixture()
def prod(data, tmp_path, monkeypatch):
    return client(copy(data["prod"], tmp_path), monkeypatch)


def login(c, user):
    r = c.post("/api/login", json={"email": user["email"], "password": user["password"]})
    assert r.status_code == 200, r.text
    return {"authorization": "Bearer " + r.json()["token"]}


def test_manifest_and_skeleton(data):
    m = data["m"]
    assert m["seed_max_uid"] >= 30 and m["seed_max_order_id"] >= 100 and len(m["legit_users"]) >= 5
    assert m["canaries"]["order_id"] and m["canaries"]["user_id"] and m["admin"]["id"]
    p, s = sqlite3.connect(data["prod"]), sqlite3.connect(data["shadow"])
    assert p.execute("SELECT id, user_id FROM orders ORDER BY id").fetchall() == s.execute("SELECT id, user_id FROM orders ORDER BY id").fetchall()
    assert p.execute("SELECT id, role FROM users ORDER BY id").fetchall() == s.execute("SELECT id, role FROM users ORDER BY id").fetchall()
    assert p.execute("SELECT * FROM products ORDER BY id").fetchall() == s.execute("SELECT * FROM products ORDER BY id").fetchall()
    assert p.execute("SELECT max(id) FROM users").fetchone()[0] == m["seed_max_uid"]
    own = {int(k): v for k, v in m["ownership"]["orders"].items()}
    assert own == dict(p.execute("SELECT id, user_id FROM orders").fetchall())
    assert p.execute("SELECT email FROM users ORDER BY id").fetchall() != s.execute("SELECT email FROM users ORDER BY id").fetchall()
    for uid in m["canaries"]["user_id"]:
        assert uid not in [u["id"] for u in m["legit_users"]]


def test_markers(data):
    prod_dump = "\n".join(sqlite3.connect(data["prod"]).iterdump())
    assert not MK.search(prod_dump)
    s = sqlite3.connect(data["shadow"])
    assert all(MK.fullmatch(k) for k in data["mk"]) and len(set(data["mk"].values())) == len(data["mk"])
    inv = {v: k for k, v in data["mk"].items()}
    for oid, uid in s.execute("SELECT id, user_id FROM orders").fetchall():
        row = " ".join(str(x) for x in s.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone())
        assert inv[uid] in row, f"order {oid} lacks its owner's marker"
    for (uid,) in s.execute("SELECT id FROM users").fetchall():
        row = " ".join(str(x) for x in s.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone())
        assert inv[uid] in row


def test_routes_match_openapi(prod):
    spec = yaml.safe_load(open(os.path.join(ROOT, "contracts/openapi.yaml")))
    have = {(m, p) for p, item in prod.app.openapi()["paths"].items() for m in item}
    want = {(m, p) for p, item in spec["paths"].items() for m in item}
    assert want <= have, want - have


def test_legit_flow(prod, data):
    u = data["m"]["legit_users"][0]
    h = login(prod, u)
    assert prod.get("/api/me", headers=h).json()["id"] == u["id"]
    assert prod.get("/api/products", params={"q": "a"}).json()["total"] >= 1
    # the shipped (unpatched) app concatenates q into SQL: a legitimate apostrophe is a syntax error, answered 500
    assert prod.get("/api/products", params={"q": "O'Brien"}).status_code == 500
    pid = prod.get("/api/products").json()["items"][0]["id"]
    o = prod.post("/api/orders", headers=h, json={"items": [{"product_id": pid, "qty": 2}], "note": "it's a gift"})
    assert o.status_code == 201
    oid = o.json()["id"]
    assert oid > data["m"]["seed_max_order_id"]
    assert prod.get(f"/api/orders/{oid}", headers=h).json()["user_id"] == u["id"]
    assert prod.get(f"/api/orders/{oid}/invoice", headers=h).status_code == 200
    assert all(x["user_id"] == u["id"] for x in prod.get("/api/orders", headers=h).json()["items"])
    assert prod.get("/api/admin/orders", headers=h).status_code == 403
    assert prod.get("/api/admin/orders", headers=login(prod, data["m"]["admin"])).status_code == 200
    r = prod.post("/api/register", json={"email": "new.user@example.com", "password": "pw12345", "name": "New User"})
    assert r.status_code == 201 and r.json()["id"] > data["m"]["seed_max_uid"]
    assert prod.get("/api/orders").status_code == 401


def test_static_files(prod):
    manuals = sorted(os.listdir(os.path.join(ROOT, "victim/static/manuals")))
    images = sorted(os.listdir(os.path.join(ROOT, "victim/static/images")))
    assert any(n.count(".") >= 2 for n in manuals), "need a legit file name with two dots"
    assert prod.get("/api/files/download", params={"name": manuals[0]}).status_code == 200
    assert prod.get("/api/products/1/image", params={"file": images[0]}).status_code == 200
    assert prod.get("/api/files/download", params={"name": "nope.txt"}).status_code == 404


def test_frozen_time(data, tmp_path, monkeypatch):
    monkeypatch.setenv("APP_NOW", "1700000000")
    c = client(copy(data["prod"], tmp_path), monkeypatch)
    h = login(c, data["m"]["legit_users"][0])
    pid = c.get("/api/products").json()["items"][0]["id"]
    a = c.post("/api/orders", headers=h, json={"items": [{"product_id": pid, "qty": 1}]}).json()
    assert "2023-11-14" in json.dumps(a)


# ---- the planted vulnerabilities must really be exploitable at t0 ----
def test_vuln_sqli_search(prod):
    total = prod.get("/api/products").json()["total"]
    r = prod.get("/api/products", params={"q": "zzzzzz' OR '1'='1"})
    assert r.status_code == 200 and r.json()["total"] == total and total > 0
    assert prod.get("/api/products", params={"q": "zzzzzz"}).json()["total"] == 0


def test_vuln_sqli_login(prod, data):
    admin = data["m"]["admin"]
    r = prod.post("/api/login", json={"email": admin["email"] + "' --", "password": "wrong"})
    assert r.status_code == 200 and r.json()["id"] == admin["id"]
    assert prod.post("/api/login", json={"email": admin["email"], "password": "wrong"}).status_code == 401


def test_vuln_traversal_download_and_image(prod):
    want = open("/etc/hostname", "rb").read()
    assert prod.get("/api/files/download", params={"name": UP + "etc/hostname"}).content == want
    assert prod.get("/api/products/1/image", params={"file": UP + "etc/hostname"}).content == want


def test_vuln_idor_order_invoice_profile(prod, data):
    m = data["m"]; me = m["legit_users"][0]; h = login(prod, me)
    other = next(int(o) for o, u in m["ownership"]["orders"].items() if u != me["id"])
    r = prod.get(f"/api/orders/{other}", headers=h)
    assert r.status_code == 200 and r.json()["user_id"] != me["id"]
    assert prod.get(f"/api/orders/{other}/invoice", headers=h).status_code == 200
    other_uid = m["legit_users"][1]["id"]
    assert prod.get(f"/api/users/{other_uid}/profile", headers=h).json()["id"] == other_uid


def test_vulns_documented():
    text = open(os.path.join(ROOT, "docs/demo/respuestas/tienda.md")).read()
    assert len(re.findall(r"victim/app/\S+\.py:\d+", text)) >= 7
    src = "".join(open(os.path.join(dp, f)).read() for dp, _, fs in os.walk(os.path.join(ROOT, "victim/app")) for f in fs if f.endswith(".py"))
    assert not re.search(r"(?i)vuln|insecure|\bsqli\b|idor|traversal|exploit|todo|fixme|hack", src)


def test_shadow_profile_and_suite(data, tmp_path, monkeypatch):
    c = client(copy(data["shadow"], tmp_path), monkeypatch, secret="shadowsecret")
    import victim.shadow_profile as sp
    env = {"APP_SECRET": "shadowsecret", "APP_STATIC": os.path.join(ROOT, "victim/static"), "MARKERS_PATH": data["markers"]}
    assert sp.APP == "victim.app.main:app" and sp.load_markers(env) == data["mk"]
    conn = sqlite3.connect(os.environ["APP_DB"]); sp.ensure_user(conn, 9001, "user"); conn.close()
    h = {"authorization": "Bearer " + sp.mint_token(env, 9001, "user")}
    assert c.get("/api/me", headers=h).json()["id"] == 9001
    oid, uid = next(iter(data["m"]["ownership"]["orders"].items()))
    inv = {v: k for k, v in data["mk"].items()}
    assert inv[uid] in c.get(f"/api/orders/{oid}", headers=h).text          # IDOR in shadow leaks the owner's marker
    assert inv[uid] in c.get(f"/api/orders/{oid}/invoice", headers=h).text
    assert os.path.realpath(os.path.join(ROOT, "victim/static")) in [os.path.realpath(p) for p in sp.allowed_file_roots(env)]
    assert any("/api/products".startswith(p) or p.startswith("/api/products") for p in sp.public_paths())


def test_own_suite_passes():
    r = subprocess.run([PY, "-m", "pytest", "victim/tests", "-q", "-x"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-3000:]
