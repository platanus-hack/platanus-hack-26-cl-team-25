import os

from .conftest import ROOT, auth_header

STATIC = os.path.join(ROOT, "victim", "static")


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"ok": True}


# ---- accounts ----
def test_register_login_me(client):
    r = client.post("/api/register", json={"email": "conan.obrien@example.com", "password": "pw12345", "name": "Conan O'Brien"})
    assert r.status_code == 201
    uid = r.json()["id"]
    h = {"authorization": "Bearer " + r.json()["token"]}
    me = client.get("/api/me", headers=h).json()
    assert me["id"] == uid and me["name"] == "Conan O'Brien" and me["email"] == "conan.obrien@example.com" and me["role"] == "user"
    assert set(me) >= {"id", "email", "name", "address", "phone", "role"}
    r = client.post("/api/login", json={"email": "conan.obrien@example.com", "password": "pw12345"})
    assert r.status_code == 200 and r.json()["id"] == uid and r.json()["token"]


def test_register_duplicate_email(client, manifest):
    u = manifest["legit_users"][0]
    r = client.post("/api/register", json={"email": u["email"], "password": "x", "name": "Dup"})
    assert r.status_code == 409


def test_register_validation(client):
    assert client.post("/api/register", json={"email": "a@b.cl", "password": "x"}).status_code == 422
    assert client.post("/api/register", json={"email": "a@b.cl", "password": "x", "name": "n" * 81}).status_code == 422


def test_login_rejects_bad_credentials(client, manifest):
    u = manifest["legit_users"][0]
    assert client.post("/api/login", json={"email": u["email"], "password": "wrong"}).status_code == 401
    assert client.post("/api/login", json={"email": "nobody@example.com", "password": u["password"]}).status_code == 401
    r = client.post("/api/login", json={"email": u["email"], "password": u["password"]})
    assert r.status_code == 200 and r.json()["id"] == u["id"]


def test_login_admin_token_has_admin_rights(client, manifest, admin_h):
    assert client.get("/api/admin/orders", headers=admin_h).status_code == 200


def test_me_requires_token(client):
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/me", headers={"authorization": "Bearer garbage"}).status_code == 401
    assert client.get("/api/me", headers={"authorization": "Bearer a.b"}).status_code == 401


def test_me_returns_own_record(client, user_h):
    u, h = user_h
    me = client.get("/api/me", headers=h).json()
    assert me["id"] == u["id"] and me["email"] == u["email"] and me["role"] == "user"


# ---- products ----
def test_products_default_listing(client):
    r = client.get("/api/products")
    assert r.status_code == 200
    body = r.json()
    assert body["page"] == 1 and body["total"] >= 40 and len(body["items"]) == 10
    assert set(body["items"][0]) == {"id", "name", "category", "price", "description"}
    names = [i["name"] for i in body["items"]]
    assert names == sorted(names)


def test_products_search(client):
    body = client.get("/api/products", params={"q": "SSD"}).json()
    assert body["total"] >= 2 and all("ssd" in i["name"].lower() for i in body["items"])
    assert client.get("/api/products", params={"q": "zzzzzz"}).json()["total"] == 0


def test_products_category_and_sort(client):
    body = client.get("/api/products", params={"category": "cables", "sort": "price"}).json()
    assert body["total"] == 10 and all(i["category"] == "cables" for i in body["items"])
    prices = [i["price"] for i in body["items"]]
    assert prices == sorted(prices)
    newest = client.get("/api/products", params={"sort": "newest"}).json()["items"]
    ids = [i["id"] for i in newest]
    assert ids == sorted(ids, reverse=True)


def test_products_enum_validation(client):
    assert client.get("/api/products", params={"category": "weapons"}).status_code == 422
    assert client.get("/api/products", params={"sort": "price; drop table users"}).status_code == 422
    assert client.get("/api/products", params={"page": 0}).status_code == 422
    assert client.get("/api/products", params={"page": 1001}).status_code == 422
    assert client.get("/api/products", params={"q": "x" * 81}).status_code == 422


def test_products_pagination(client):
    p1 = client.get("/api/products", params={"page": 1}).json()
    p2 = client.get("/api/products", params={"page": 2}).json()
    assert p2["page"] == 2 and p1["total"] == p2["total"]
    assert not {i["id"] for i in p1["items"]} & {i["id"] for i in p2["items"]}
    assert client.get("/api/products", params={"page": 1000}).json()["items"] == []


def test_product_detail(client):
    r = client.get("/api/products/1")
    assert r.status_code == 200
    assert r.json()["id"] == 1 and r.json()["name"] and r.json()["price"] > 0
    assert client.get("/api/products/999999").status_code == 404


# ---- files ----
def test_download_manuals_including_dotted_names(client):
    names = sorted(os.listdir(os.path.join(STATIC, "manuals")))
    assert any(n.count(".") >= 2 for n in names)
    for n in names:
        r = client.get("/api/files/download", params={"name": n})
        assert r.status_code == 200
        assert r.content == open(os.path.join(STATIC, "manuals", n), "rb").read()
    assert b"manual v2" in client.get("/api/files/download", params={"name": "usb-hub.v2.txt"}).content


def test_download_missing_file(client):
    assert client.get("/api/files/download", params={"name": "nope.txt"}).status_code == 404
    assert client.get("/api/files/download", params={"name": "manuals"}).status_code == 404
    assert client.get("/api/files/download").status_code == 422


def test_product_images(client):
    for n in sorted(os.listdir(os.path.join(STATIC, "images"))):
        r = client.get("/api/products/1/image", params={"file": n})
        assert r.status_code == 200
        assert r.content == open(os.path.join(STATIC, "images", n), "rb").read()
    assert client.get("/api/products/1/image", params={"file": "missing.png"}).status_code == 404
    assert client.get("/api/products/999999/image", params={"file": "audio.png"}).status_code == 404


# ---- orders ----
def test_orders_requires_auth(client):
    assert client.get("/api/orders").status_code == 401
    assert client.post("/api/orders", json={"items": [{"product_id": 1, "qty": 1}]}).status_code == 401
    assert client.get("/api/orders/1").status_code == 401
    assert client.get("/api/orders/1/invoice").status_code == 401
    assert client.get("/api/admin/orders").status_code == 401


def test_orders_listing_only_own(client, manifest, user_h):
    u, h = user_h
    items = client.get("/api/orders", headers=h).json()["items"]
    mine = sorted(int(o) for o, uid in manifest["ownership"]["orders"].items() if uid == u["id"])
    assert mine and sorted(i["id"] for i in items) == mine
    assert all(i["user_id"] == u["id"] for i in items)
    assert all(i["items"] for i in items)
    other = manifest["legit_users"][1]
    oh = auth_header(client, other)
    theirs = sorted(i["id"] for i in client.get("/api/orders", headers=oh).json()["items"])
    assert not set(theirs) & set(mine)


def test_create_order_with_apostrophes(client, manifest, user_h):
    u, h = user_h
    prods = client.get("/api/products").json()["items"][:2]
    r = client.post("/api/orders", headers=h, json={
        "note": "Mom's gift, don't ring", "items": [{"product_id": prods[0]["id"], "qty": 2}, {"product_id": prods[1]["id"], "qty": 1}]})
    assert r.status_code == 201
    o = r.json()
    assert o["id"] > manifest["seed_max_order_id"] and o["user_id"] == u["id"] and o["status"] == "new"
    assert o["note"] == "Mom's gift, don't ring"
    assert o["total"] == prods[0]["price"] * 2 + prods[1]["price"]
    assert [(i["product_id"], i["qty"]) for i in o["items"]] == [(prods[0]["id"], 2), (prods[1]["id"], 1)]
    got = client.get(f"/api/orders/{o['id']}", headers=h).json()
    assert got["note"] == "Mom's gift, don't ring" and got["total"] == o["total"] and got["user_id"] == u["id"]
    assert o["id"] in [i["id"] for i in client.get("/api/orders", headers=h).json()["items"]]


def test_create_order_validation(client, user_h):
    _, h = user_h
    assert client.post("/api/orders", headers=h, json={"items": []}).status_code == 422
    assert client.post("/api/orders", headers=h, json={"items": [{"product_id": 1, "qty": 0}]}).status_code == 422
    assert client.post("/api/orders", headers=h, json={"items": [{"product_id": 1, "qty": 100}]}).status_code == 422
    assert client.post("/api/orders", headers=h, json={"items": [{"product_id": 0, "qty": 1}]}).status_code == 422
    assert client.post("/api/orders", headers=h, json={"items": [{"product_id": 1, "qty": 1}], "note": "n" * 201}).status_code == 422
    assert client.post("/api/orders", headers=h, json={"items": [{"product_id": 999999, "qty": 1}]}).status_code in (404, 422)


def test_get_own_order_and_invoice(client, manifest, user_h):
    u, h = user_h
    oid = next(int(o) for o, uid in manifest["ownership"]["orders"].items() if uid == u["id"])
    o = client.get(f"/api/orders/{oid}", headers=h).json()
    assert o["id"] == oid and o["user_id"] == u["id"]
    assert set(o) >= {"id", "user_id", "status", "total", "note", "shipping_address", "created_at", "items"}
    r = client.get(f"/api/orders/{oid}/invoice", headers=h)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    me = client.get("/api/me", headers=h).json()
    assert me["name"] in r.text and str(o["total"]) in r.text and f"#{oid}" in r.text
    for it in o["items"]:
        assert it["name"] in r.text


def test_missing_order(client, user_h):
    _, h = user_h
    assert client.get("/api/orders/999999", headers=h).status_code == 404
    assert client.get("/api/orders/999999/invoice", headers=h).status_code == 404


def test_new_user_has_no_orders(client):
    r = client.post("/api/register", json={"email": "fresh@example.com", "password": "pw", "name": "Fresh"})
    h = {"authorization": "Bearer " + r.json()["token"]}
    assert client.get("/api/orders", headers=h).json() == {"items": []}


def test_admin_orders(client, manifest, user_h, admin_h):
    _, h = user_h
    assert client.get("/api/admin/orders", headers=h).status_code == 403
    items = client.get("/api/admin/orders", headers=admin_h).json()["items"]
    assert len(items) == manifest["seed_max_order_id"]
    assert {i["user_id"] for i in items} > {manifest["legit_users"][0]["id"], manifest["legit_users"][1]["id"]}


# ---- profiles ----
def test_profile(client, manifest, user_h):
    u, h = user_h
    r = client.get(f"/api/users/{u['id']}/profile", headers=h)
    assert r.status_code == 200
    p = r.json()
    assert p["id"] == u["id"] and p["email"] == u["email"] and set(p) >= {"id", "name", "email", "address", "phone"}
    assert client.get("/api/users/999999/profile", headers=h).status_code == 404
    assert client.get(f"/api/users/{u['id']}/profile").status_code == 401


def test_frozen_time(seeded, tmp_path, monkeypatch):
    import sqlite3
    from .conftest import make_client
    work = str(tmp_path / "w.db")
    src, dst = sqlite3.connect(seeded["prod"]), sqlite3.connect(work)
    src.backup(dst)
    monkeypatch.setenv("APP_NOW", "1700000000")
    c = make_client(work, monkeypatch)
    monkeypatch.setenv("APP_NOW", "1700000000")
    h = auth_header(c, seeded["m"]["legit_users"][0])
    o = c.post("/api/orders", headers=h, json={"items": [{"product_id": 1, "qty": 1}]}).json()
    assert o["created_at"].startswith("2023-11-14")
