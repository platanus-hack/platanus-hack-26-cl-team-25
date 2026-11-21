"""Stand-in for `sim.scenarios` (contracts/interfaces.md), used only when that module is
not importable (it is built in parallel by WP8). Same signature and output shape:

    SCENARIOS: list[Callable[[client, manifest], list[dict]]]
    -> [{"step", "method", "path", "status", "body"}]

Like the real ones these are written for the victim app: legitimate flows only
(apostrophes, dotted file names, own orders), deterministic under a frozen clock.
"""
from __future__ import annotations

import hashlib
import re

TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{20,}\.[0-9a-f]{64}")


def _norm(r):
    ctype = r.headers.get("content-type", "")
    if "json" in ctype:
        try:
            body = r.json()
        except ValueError:
            body = r.text
    elif ctype.startswith("text/"):
        body = r.text
    else:
        body = "sha256:" + hashlib.sha256(r.content).hexdigest()

    def scrub(x):
        if isinstance(x, dict):
            return {k: ("<token>" if k == "token" else scrub(v)) for k, v in x.items()}
        if isinstance(x, list):
            return [scrub(v) for v in x]
        if isinstance(x, str):
            return TOKEN_RE.sub("<token>", x)
        return x
    return scrub(body)


class _Rec:
    def __init__(self, client):
        self.c = client
        self.steps = []

    def call(self, step, method, path, **kw):
        r = self.c.request(method, path, **kw)
        url = path + (("?" + "&".join("%s=%s" % kv for kv in kw["params"].items())) if kw.get("params") else "")
        self.steps.append({"step": step, "method": method, "path": path, "query": url[len(path) + 1:],
                           "status": r.status_code, "body": _norm(r)})
        return r


def _login(rec, user, step="login"):
    r = rec.call(step, "POST", "/api/login", json={"email": user["email"], "password": user["password"]})
    return {"authorization": "Bearer " + r.json().get("token", "")} if r.status_code == 200 else {}


def browse(client, manifest):
    s = _Rec(client)
    s.call("health", "GET", "/health")
    s.call("list", "GET", "/api/products")
    s.call("page 2", "GET", "/api/products", params={"page": 2})
    s.call("cables by price", "GET", "/api/products", params={"category": "cables", "sort": "price"})
    s.call("newest", "GET", "/api/products", params={"sort": "newest"})
    s.call("search SSD", "GET", "/api/products", params={"q": "SSD"})
    s.call("search apostrophe", "GET", "/api/products", params={"q": "O'Brien"})
    s.call("search usb hub", "GET", "/api/products", params={"q": "Hub USB"})
    s.call("product", "GET", "/api/products/1")
    s.call("missing product", "GET", "/api/products/999999")
    return s.steps


def files(client, manifest):
    s = _Rec(client)
    for name in ("garantia.txt", "usb-hub.v2.txt", "audifonos.pro.guia.txt", "guia-cables.txt", "nope.txt"):
        s.call("manual " + name, "GET", "/api/files/download", params={"name": name})
    for pid, f in ((1, "audio.png"), (2, "cables.png"), (1, "missing.png")):
        s.call("image %s" % f, "GET", "/api/products/%d/image" % pid, params={"file": f})
    return s.steps


def shopper(client, manifest):
    s = _Rec(client)
    u = manifest["legit_users"][0]
    h = _login(s, u)
    s.call("me", "GET", "/api/me", headers=h)
    mine = s.call("my orders", "GET", "/api/orders", headers=h).json().get("items", [])
    for o in mine[:3]:
        s.call("order", "GET", "/api/orders/%d" % o["id"], headers=h)
        s.call("invoice", "GET", "/api/orders/%d/invoice" % o["id"], headers=h)
    r = s.call("create order", "POST", "/api/orders", headers=h,
               json={"note": "Mom's gift, don't ring", "items": [{"product_id": 3, "qty": 2}]})
    if r.status_code == 201:
        oid = r.json()["id"]
        s.call("new order", "GET", "/api/orders/%d" % oid, headers=h)
        s.call("new invoice", "GET", "/api/orders/%d/invoice" % oid, headers=h)
    s.call("my profile", "GET", "/api/users/%d/profile" % u["id"], headers=h)
    return s.steps


def newcomer(client, manifest):
    s = _Rec(client)
    r = s.call("register", "POST", "/api/register",
               json={"email": "conan.obrien@example.com", "password": "pw-12345", "name": "Conan O'Brien"})
    h = {"authorization": "Bearer " + r.json().get("token", "")} if r.status_code == 201 else {}
    s.call("me", "GET", "/api/me", headers=h)
    s.call("no orders", "GET", "/api/orders", headers=h)
    if r.status_code == 201:
        s.call("own profile", "GET", "/api/users/%d/profile" % r.json()["id"], headers=h)
    s.call("login", "POST", "/api/login", json={"email": "conan.obrien@example.com", "password": "pw-12345"})
    return s.steps


def admin(client, manifest):
    s = _Rec(client)
    h = _login(s, manifest["admin"], "admin login")
    r = s.call("all orders", "GET", "/api/admin/orders", headers=h)
    s.steps[-1]["body"] = {"count": len(r.json().get("items", []))} if r.status_code == 200 else s.steps[-1]["body"]
    s.call("order as admin", "GET", "/api/orders/2", headers=h)
    return s.steps


SCENARIOS = [browse, files, shopper, newcomer, admin]
