"""Deterministic legitimate scenarios (contract: contracts/interfaces.md, `sim.scenarios`).

Each scenario is ``(client, manifest) -> list[step]`` with
``step = {"step", "method", "path", "status", "body"}``.

The legit gate runs each scenario with its own client on its own copy of a
freshly seeded database with ``APP_NOW`` frozen (pipeline/runner_entry.py,
job_scenarios); sim/tests runs them in list order on one client.  They use only the HTTP interface (no import
of the app), so they work against any release.  Tokens are replaced by
``<token>``; binary bodies by a ``{"binary_sha256", "bytes"}`` summary.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import quote

TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,}\.[0-9a-f]{64}")
CATEGORIES = ["audio", "cables", "storage", "accessories"]
SORTS = ["name", "price", "newest"]
MANUALS = ["audifonos.pro.guia.txt", "garantia.txt", "guia-cables.txt", "instalacion-ssd.txt", "usb-hub.v2.txt"]
IMAGES = {1: "audio.png", 11: "cables.png", 21: "storage.png", 31: "accessories.png"}


def _scrub(obj):
    if isinstance(obj, dict):
        return {k: ("<token>" if k == "token" and isinstance(v, str) else _scrub(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    if isinstance(obj, str):
        return TOKEN_RE.sub("<token>", obj)
    return obj


def normalise(resp):
    ctype = resp.headers.get("content-type", "")
    if "json" in ctype:
        try:
            return _scrub(resp.json())
        except ValueError:
            pass
    if ctype.startswith("text/"):
        return TOKEN_RE.sub("<token>", resp.text)
    return {"binary_sha256": hashlib.sha256(resp.content).hexdigest(), "bytes": len(resp.content)}


def qs(**params):
    return "?" + "&".join("%s=%s" % (k, quote(str(v), safe="")) for k, v in params.items())


class Recorder:
    def __init__(self, client):
        self.client = client
        self.steps = []

    def call(self, step, method, path, token=None, json_body=None, view=None):
        headers = {"authorization": "Bearer " + token} if token else {}
        kw = {"headers": headers}
        if json_body is not None:
            kw["json"] = json_body
        resp = self.client.request(method, path, **kw)
        body = normalise(resp)
        if view:
            body = view(body)
        self.steps.append({"step": step, "method": method, "path": path, "status": resp.status_code, "body": body})
        return resp

    def get(self, step, path, token=None, view=None):
        return self.call(step, "GET", path, token=token, view=view)

    def login(self, step, email, password):
        r = self.call(step, "POST", "/api/login", json_body={"email": email, "password": password})
        assert r.status_code == 200, "legit login failed for %s: %s" % (email, r.text)
        return r.json()


# ---- scenarios -------------------------------------------------------------

def anonymous_catalog(client, manifest):
    rec = Recorder(client)
    rec.get("health", "/health")
    rec.get("list default", "/api/products")
    for cat in CATEGORIES:
        rec.get("list category " + cat, "/api/products" + qs(category=cat))
    for sort in SORTS:
        rec.get("list sort " + sort, "/api/products" + qs(sort=sort))
    for page in (1, 2, 3, 4, 5):
        rec.get("list page %d" % page, "/api/products" + qs(page=page))
    rec.get("list category+sort+page", "/api/products" + qs(category="cables", sort="price", page=2))
    rec.get("list all filters", "/api/products" + qs(q="usb", category="accessories", sort="newest", page=1))
    rec.get("search normal word", "/api/products" + qs(q="audifonos"))
    rec.get("search with space", "/api/products" + qs(q="Hub USB"))
    rec.get("search with hyphen", "/api/products" + qs(q="Cable USB-C"))
    rec.get("search space and hyphen", "/api/products" + qs(q="Soporte para Notebook", sort="price"))
    rec.get("search no results", "/api/products" + qs(q="zzzzzz"))
    rec.get("search category name", "/api/products" + qs(q="audio"))
    for pid in (1, 12, 27, 40):
        rec.get("product %d" % pid, "/api/products/%d" % pid)
    rec.get("product not found", "/api/products/99999")
    for pid, fname in IMAGES.items():
        rec.get("image product %d" % pid, "/api/products/%d/image" % pid + qs(file=fname))
    rec.get("image missing file", "/api/products/1/image" + qs(file="nope.png"))
    rec.get("image unknown product", "/api/products/99999/image" + qs(file="audio.png"))
    for name in MANUALS:
        rec.get("manual " + name, "/api/files/download" + qs(name=name))
    rec.get("manual missing", "/api/files/download" + qs(name="no-existe.txt"))
    rec.get("mistyped url", "/api/prodcuts")
    rec.get("mistyped product url", "/api/product/1")
    rec.get("me without token", "/api/me")
    rec.get("orders without token", "/api/orders")
    rec.get("me with garbage token", "/api/me", token="garbage")
    rec.call("create order without token", "POST", "/api/orders", json_body={"items": [{"product_id": 1, "qty": 1}]})
    return rec.steps


def new_customer_obrien(client, manifest):
    rec = Recorder(client)
    email = "conan.obrien@example.com"
    reg = rec.call("register O'Brien", "POST", "/api/register",
                   json_body={"email": email, "password": "obrien-clave-2026", "name": "Conan O'Brien"})
    assert reg.status_code == 201, reg.text
    uid, token = reg.json()["id"], reg.json()["token"]
    rec.call("register duplicate email", "POST", "/api/register",
             json_body={"email": email, "password": "otra", "name": "Otro"})
    rec.call("register missing name", "POST", "/api/register", json_body={"email": "x@example.com", "password": "pw"})
    rec.get("me", "/api/me", token=token)
    login = rec.login("login O'Brien", email, "obrien-clave-2026")
    token = login["token"]
    rec.call("login wrong password", "POST", "/api/login", json_body={"email": email, "password": "mala"})
    rec.call("login unknown email", "POST", "/api/login", json_body={"email": "nadie@example.com", "password": "x"})
    rec.get("own profile", "/api/users/%d/profile" % uid, token=token)
    rec.get("orders empty", "/api/orders", token=token)
    note = "Dejar con la señora María, it's a gift: ¡frágil! Ñandú 5º piso"
    order = rec.call("create order with note", "POST", "/api/orders", token=token,
                     json_body={"note": note, "items": [{"product_id": 3, "qty": 2}, {"product_id": 25, "qty": 1}]})
    assert order.status_code == 201, order.text
    oid = order.json()["id"]
    rec.call("create order without note", "POST", "/api/orders", token=token,
             json_body={"items": [{"product_id": 40, "qty": 99}]})
    rec.call("create order empty items", "POST", "/api/orders", token=token, json_body={"items": []})
    rec.call("create order bad qty", "POST", "/api/orders", token=token,
             json_body={"items": [{"product_id": 1, "qty": 0}]})
    rec.call("create order unknown product", "POST", "/api/orders", token=token,
             json_body={"items": [{"product_id": 99999, "qty": 1}]})
    rec.get("list own orders", "/api/orders", token=token)
    rec.get("own order", "/api/orders/%d" % oid, token=token)
    rec.get("own invoice", "/api/orders/%d/invoice" % oid, token=token)
    rec.get("admin orders as user", "/api/admin/orders", token=token)
    rec.get("order not found", "/api/orders/999999", token=token)
    rec.get("invoice not found", "/api/orders/999999/invoice", token=token)
    rec.get("profile not found", "/api/users/999999/profile", token=token)
    return rec.steps


def existing_customer(client, manifest):
    rec = Recorder(client)
    user = manifest["legit_users"][0]
    token = rec.login("login", user["email"], user["password"])["token"]
    rec.get("me", "/api/me", token=token)
    rec.get("own profile", "/api/users/%d/profile" % user["id"], token=token)
    listing = rec.get("list own orders", "/api/orders", token=token).json()["items"]
    for o in listing[:3]:
        rec.get("own order %d" % o["id"], "/api/orders/%d" % o["id"], token=token)
        rec.get("own invoice %d" % o["id"], "/api/orders/%d/invoice" % o["id"], token=token)
    r = rec.call("create order", "POST", "/api/orders", token=token,
                 json_body={"note": "Llamar antes de llegar", "items": [{"product_id": 7, "qty": 1}, {"product_id": 16, "qty": 3}]})
    assert r.status_code == 201, r.text
    rec.get("own order after create", "/api/orders/%d" % r.json()["id"], token=token)
    rec.get("own invoice after create", "/api/orders/%d/invoice" % r.json()["id"], token=token)
    rec.get("browse while logged in", "/api/products" + qs(category="storage", sort="price"), token=token)
    rec.get("manual while logged in", "/api/files/download" + qs(name="usb-hub.v2.txt"), token=token)
    rec.get("admin orders as user", "/api/admin/orders", token=token)
    return rec.steps


def second_customer(client, manifest):
    rec = Recorder(client)
    user = manifest["legit_users"][1]
    token = rec.login("login", user["email"], user["password"])["token"]
    rec.get("me", "/api/me", token=token)
    rec.get("own profile", "/api/users/%d/profile" % user["id"], token=token)
    listing = rec.get("list own orders", "/api/orders", token=token).json()["items"]
    if listing:
        o = listing[-1]
        rec.get("own order %d" % o["id"], "/api/orders/%d" % o["id"], token=token)
        rec.get("own invoice %d" % o["id"], "/api/orders/%d/invoice" % o["id"], token=token)
    r = rec.call("create order with apostrophe note", "POST", "/api/orders", token=token,
                 json_body={"note": "Don't ring the bell, bebé durmiendo", "items": [{"product_id": 2, "qty": 2}]})
    assert r.status_code == 201, r.text
    rec.get("list own orders again", "/api/orders", token=token)
    return rec.steps


def admin(client, manifest):
    rec = Recorder(client)
    adm = manifest["admin"]
    token = rec.login("login admin", adm["email"], adm["password"])["token"]
    rec.get("me", "/api/me", token=token)
    limit = manifest["seed_max_order_id"]

    def seeded_only(body):
        # Orders created by other scenarios must not change this step.
        return {"items": [o for o in body["items"] if o["id"] <= limit]}

    rec.get("admin orders (seeded rows)", "/api/admin/orders", token=token, view=seeded_only)
    rec.get("admin reads user profile", "/api/users/%d/profile" % manifest["legit_users"][0]["id"], token=token)
    return rec.steps


SCENARIOS = [anonymous_catalog, new_customer_obrien, existing_customer, second_customer, admin]
