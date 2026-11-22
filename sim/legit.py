"""Continuous legitimate-traffic generator.

    python -m sim.legit --base http://127.0.0.1:8080 [--users N] [--rate R] [--duration S]
                        [--anon N] [--manifest PATH] [--json OUT] [--seed S]

Simulated actors (manifest legit users + anonymous visitors, each with its own
cookie jar and token) run random legitimate journeys.  Every response is
checked for: no ``x-imm-*`` header, no synthetic-data marker ``MK[A-Z0-9]{10}``,
the expected status, and that answers about the actor's own resources carry
the actor's own id.  Exit status is non-zero on any violation or 5xx.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import re
import signal
import sys
import time
from collections import Counter
from urllib.parse import quote

import httpx

MARKER_RE = re.compile(r"MK[A-Z0-9]{10}")
CATEGORIES = ["audio", "cables", "storage", "accessories"]
SORTS = ["name", "price", "newest"]
MANUALS = ["audifonos.pro.guia.txt", "garantia.txt", "guia-cables.txt", "instalacion-ssd.txt", "usb-hub.v2.txt"]
IMAGES = ["audio.png", "cables.png", "storage.png", "accessories.png"]
WORDS = ["audifonos", "cable", "usb", "ssd", "mouse", "parlante", "hub", "teclado", "disco", "cargador",
         "Cable USB-C", "Hub USB", "Soporte para Notebook", "SSD NVMe", "Disco Externo", "Mouse Inalambrico"]
NOTES = ["", "", "Dejar con el conserje", "Llamar antes de llegar", "It's a gift", "Regalo para María, frágil",
         "Entregar después de las 18h", "Factura a nombre de la empresa"]
VISITOR_NAMES = ["Conan O'Brien", "Sinéad O'Connor", "Ana María Núñez", "Luis Pérez", "Dara O'Hara", "Josefa Muñoz"]
ADMIN_FORBIDDEN = 403


class Stop(Exception):
    pass


class Stats:
    def __init__(self):
        self.start = time.time()
        self.requests = 0
        self.by_status = Counter()
        self.violations = Counter()
        self.server_errors = 0
        self.conn_errors = 0
        self.problems = []

    def problem(self, kind, actor, method, path, detail):
        if len(self.problems) < 200:
            self.problems.append({"kind": kind, "actor": actor, "method": method, "path": path, "detail": detail})

    def violation(self, kind, actor, method, path, detail):
        self.violations[kind] += 1
        self.problem(kind, actor, method, path, detail)

    @property
    def bad(self):
        return sum(self.violations.values()) + self.server_errors + self.conn_errors

    def line(self):
        el = max(time.time() - self.start, 1e-9)
        st = ",".join("%s:%d" % (k, v) for k, v in sorted(self.by_status.items()))
        return "t=%3ds reqs=%d rps=%.1f status={%s} violations=%d 5xx=%d conn_err=%d" % (
            el, self.requests, self.requests / el, st, sum(self.violations.values()),
            self.server_errors, self.conn_errors)

    def summary(self):
        return {"duration_s": round(time.time() - self.start, 2), "requests": self.requests,
                "by_status": dict(self.by_status), "violations": dict(self.violations),
                "server_errors": self.server_errors, "conn_errors": self.conn_errors,
                "ok": self.bad == 0, "problems": self.problems}


class Actor:
    def __init__(self, name, base, stats, interval, deadline, stop, rng, user=None, product_max=40):
        self.name, self.stats, self.interval, self.deadline, self.stop, self.rng = name, stats, interval, deadline, stop, rng
        self.user = user          # dict(id, email, password, name?) or None
        self.uid = user["id"] if user else None
        self.token = None
        self.orders = []          # ids of own orders seen
        self.product_max = product_max
        self.http = httpx.AsyncClient(base_url=base, timeout=15.0, follow_redirects=False)

    async def close(self):
        await self.http.aclose()

    # -- request + checks
    async def req(self, method, path, expect=(200,), auth=True, json_body=None):
        if self.stop.is_set() or time.time() >= self.deadline:
            raise Stop()
        await asyncio.sleep(self.interval * self.rng.uniform(0.5, 1.5))
        headers = {"authorization": "Bearer " + self.token} if (auth and self.token) else {}
        st = self.stats
        try:
            r = await self.http.request(method, path, headers=headers, json=json_body)
        except httpx.HTTPError as e:
            st.requests += 1
            st.conn_errors += 1
            st.problem("conn_error", self.name, method, path, repr(e))
            return None
        st.requests += 1
        st.by_status[r.status_code] += 1
        if r.status_code >= 500:
            st.server_errors += 1
            st.problem("5xx", self.name, method, path, "status %d body %s" % (r.status_code, r.text[:200]))
        elif r.status_code not in expect:
            st.violation("unexpected_status", self.name, method, path,
                         "got %d expected %s body %s" % (r.status_code, list(expect), r.text[:200]))
        bad = [k for k in r.headers if k.lower().startswith("x-imm-")]
        if bad:
            st.violation("x-imm-header", self.name, method, path, ",".join(bad))
        m = MARKER_RE.search(r.content.decode("latin-1"))
        if m:
            st.violation("synthetic_marker", self.name, method, path, m.group(0))
        if r.status_code in (200, 201):
            self.check_own(method, path, r)
        return r

    def check_own(self, method, path, r):
        if self.uid is None:
            return
        base = path.split("?")[0]
        fail = lambda d: self.stats.violation("wrong_owner", self.name, method, path, d)  # noqa: E731
        try:
            if base == "/api/me":
                if r.json()["id"] != self.uid:
                    fail("me.id=%r expected %r" % (r.json()["id"], self.uid))
            elif re.fullmatch(r"/api/users/\d+/profile", base):
                j = r.json()
                if j["id"] != self.uid or (self.user.get("email") and j["email"] != self.user["email"]):
                    fail("profile %r expected uid %r" % ({"id": j["id"], "email": j["email"]}, self.uid))
            elif base == "/api/orders" and method == "GET":
                for o in r.json()["items"]:
                    if o["user_id"] != self.uid:
                        fail("order %r owned by %r" % (o["id"], o["user_id"]))
            elif base == "/api/orders" and method == "POST" or re.fullmatch(r"/api/orders/\d+", base):
                if r.json()["user_id"] != self.uid:
                    fail("order %r owned by %r" % (r.json()["id"], r.json()["user_id"]))
            elif re.fullmatch(r"/api/orders/\d+/invoice", base):
                if self.user.get("email") and ("<%s>" % self.user["email"]) not in r.text:
                    fail("invoice not addressed to %s" % self.user["email"])
        except (KeyError, ValueError, TypeError) as e:
            fail("unparseable response: %r" % e)

    # -- account helpers
    async def login(self):
        r = await self.req("POST", "/api/login", expect=(200,), auth=False,
                           json_body={"email": self.user["email"], "password": self.user["password"]})
        if r is not None and r.status_code == 200:
            j = r.json()
            self.token = j["token"]
            if j["id"] != self.uid:
                self.stats.violation("wrong_owner", self.name, "POST", "/api/login", "login id %r expected %r" % (j["id"], self.uid))

    async def register(self, n):
        email = "visitor.%s.%d@tienda.example" % (RUN_NONCE, n)
        name = self.rng.choice(VISITOR_NAMES)
        pw = "pw-%s-%d" % (RUN_NONCE, n)
        r = await self.req("POST", "/api/register", expect=(201,), auth=False,
                           json_body={"email": email, "password": pw, "name": name})
        if r is not None and r.status_code == 201:
            j = r.json()
            self.user = {"id": j["id"], "email": email, "password": pw, "name": name}
            self.uid, self.token = j["id"], j["token"]
            return True
        return False

    def pid(self):
        return self.rng.randint(1, self.product_max)

    # -- journeys
    async def j_browse(self):
        params = []
        if self.rng.random() < 0.5:
            params.append("category=" + self.rng.choice(CATEGORIES))
        if self.rng.random() < 0.5:
            params.append("sort=" + self.rng.choice(SORTS))
        if self.rng.random() < 0.5:
            params.append("page=%d" % self.rng.randint(1, 4))
        r = await self.req("GET", "/api/products" + ("?" + "&".join(params) if params else ""))
        if r is not None and r.status_code == 200:
            self.product_max = max(self.product_max, r.json().get("total", 0))
        for _ in range(self.rng.randint(1, 3)):
            await self.req("GET", "/api/products/%d" % self.pid())
        if self.rng.random() < 0.6:
            await self.req("GET", "/api/products/%d/image?file=%s" % (self.pid(), self.rng.choice(IMAGES)))

    async def j_search(self):
        q = quote(self.rng.choice(WORDS), safe="")
        await self.req("GET", "/api/products?q=" + q)
        if self.rng.random() < 0.4:
            await self.req("GET", "/api/products?q=%s&sort=%s" % (q, self.rng.choice(SORTS)))

    async def j_manual(self):
        await self.req("GET", "/api/files/download?name=" + quote(self.rng.choice(MANUALS), safe=""))

    async def j_mistakes(self):
        await self.req("GET", self.rng.choice(["/api/prodcuts", "/api/product/1", "/api/ordenes"]), expect=(404,))
        await self.req("GET", "/api/products/99999", expect=(404,))
        if self.token is None:
            await self.req("GET", self.rng.choice(["/api/me", "/api/orders"]), expect=(401,))

    async def j_profile(self):
        await self.req("GET", "/api/me")
        await self.req("GET", "/api/users/%d/profile" % self.uid)

    async def j_orders(self):
        r = await self.req("GET", "/api/orders")
        if r is not None and r.status_code == 200:
            items = r.json()["items"]
            self.orders = [o["id"] for o in items]
            if items:
                oid = self.rng.choice(self.orders)
                await self.req("GET", "/api/orders/%d" % oid)
                await self.req("GET", "/api/orders/%d/invoice" % oid)

    async def j_order(self):
        lines = [{"product_id": self.pid(), "qty": self.rng.randint(1, 3)} for _ in range(self.rng.randint(1, 3))]
        body = {"items": lines}
        note = self.rng.choice(NOTES)
        if note:
            body["note"] = note
        r = await self.req("POST", "/api/orders", expect=(201,), json_body=body)
        if r is not None and r.status_code == 201:
            oid = r.json()["id"]
            await self.req("GET", "/api/orders/%d" % oid)
            await self.req("GET", "/api/orders/%d/invoice" % oid)

    async def j_admin_denied(self):
        await self.req("GET", "/api/admin/orders", expect=(ADMIN_FORBIDDEN,))

    async def run(self):
        public = [(self.j_browse, 5), (self.j_search, 3), (self.j_manual, 1), (self.j_mistakes, 1)]
        private = [(self.j_profile, 2), (self.j_orders, 3), (self.j_order, 2), (self.j_admin_denied, 1)]
        global REG_COUNTER
        try:
            if self.user and self.token is None:
                await self.login()
            while True:
                if self.user is None and self.rng.random() < 0.08:
                    REG_COUNTER += 1
                    await self.register(REG_COUNTER)
                    continue
                pool = public + (private if self.token else [])
                fn = self.rng.choices([f for f, _ in pool], weights=[w for _, w in pool])[0]
                await fn()
        except Stop:
            pass
        finally:
            await self.close()


RUN_NONCE = "%06x" % random.randrange(1 << 24)
REG_COUNTER = 0


async def run(base, users, anon, rate, duration, manifest, seed, quiet=False, report_every=2.0):
    stats = Stats()
    rng = random.Random(seed)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    legit = list(manifest.get("legit_users", []))
    chosen = legit[: max(users, 0)]
    n = len(chosen) + anon
    if n == 0:
        raise SystemExit("no actors: need --users > 0 or --anon > 0")
    interval = n / max(rate, 0.01)
    deadline = time.time() + duration if duration > 0 else float("inf")
    actors = [Actor("user%d" % u["id"], base, stats, interval, deadline, stop, random.Random(rng.random()), user=u)
              for u in chosen]
    actors += [Actor("anon%d" % i, base, stats, interval, deadline, stop, random.Random(rng.random())) for i in range(anon)]
    tasks = [asyncio.create_task(a.run()) for a in actors]

    async def reporter():
        while True:
            await asyncio.sleep(report_every)
            if not quiet:
                print(stats.line(), flush=True)

    rep = asyncio.create_task(reporter())
    await asyncio.gather(*tasks)
    rep.cancel()
    if not quiet:
        print("FINAL " + stats.line(), flush=True)
    return stats


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m sim.legit")
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--users", type=int, default=6, help="manifest legit users to simulate")
    ap.add_argument("--anon", type=int, default=3, help="anonymous visitors (some register and become customers)")
    ap.add_argument("--rate", type=float, default=5.0, help="total requests per second")
    ap.add_argument("--duration", type=float, default=0, help="seconds; 0 = until interrupted")
    ap.add_argument("--manifest", default="runtime/data/manifest.json")
    ap.add_argument("--json", dest="json_out", default=None, help="write final summary here")
    ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args(argv)
    with open(a.manifest) as f:
        manifest = json.load(f)
    seed = a.seed if a.seed is not None else random.randrange(1 << 30)
    stats = asyncio.run(run(a.base.rstrip("/"), a.users, a.anon, a.rate, a.duration, manifest, seed))
    summ = stats.summary()
    summ["seed"] = seed
    if a.json_out:
        with open(a.json_out, "w") as f:
            json.dump(summ, f, indent=2)
    for p in stats.problems[:20]:
        print("PROBLEM %(kind)s %(actor)s %(method)s %(path)s: %(detail)s" % p, file=sys.stderr)
    return 0 if stats.bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
