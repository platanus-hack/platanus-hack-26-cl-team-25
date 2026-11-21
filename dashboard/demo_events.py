"""Post a scripted two-incident sequence to a running dashboard (no other component needed).

  BUS_TOKEN=... python dashboard/demo_events.py [--url http://127.0.0.1:8090] [--speed 1.0] [--clear]
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from immune_contracts import events as E  # noqa: E402

RUN = "demo"
XSS = "<img src=x onerror=alert(1)>"


class Poster:
    def __init__(self, url: str, token: str, speed: float):
        self.url, self.token, self.speed = url.rstrip("/"), token, speed
        self.n = 0

    def _post(self, path: str, body) -> dict:
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"content-type": "application/json", "x-bus-token": self.token})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def clear(self):
        self._post("/admin/clear", {})

    def emit(self, type_, src, data, *, rid=None, incident=None, wait=0.0):
        self._post("/events", E.make(type_, src, data, run=RUN, rid=rid, incident=incident))
        self.n += 1
        if wait:
            time.sleep(wait / self.speed)


def evidence(rid, method, path, query, body, kind, detail, stack, status=200):
    return {
        "clone": "clone-1", "rid": rid, "mode": "L2", "release": "r0", "verdict": "oracle", "uid": 7, "role": "user",
        "request": {"method": method, "path": path, "query": query, "headers": {"user-agent": "attacker-bot"},
                    "body_b64": base64.b64encode(body.encode()).decode()},
        "status": status, "events": [{"oracle": kind, "detail": detail, "stack": stack}], "session": "sess-1",
    }


def traffic(p: Poster, k: int, start: int = 0):
    routes = [("GET", "/api/products", "prod"), ("GET", "/api/products/12", "prod"), ("POST", "/api/cart", "prod"),
              ("GET", "/api/orders", "prod"), ("GET", "/static/app.css", "prod")]
    for i in range(k):
        m, path, route = routes[(start + i) % len(routes)]
        rid = f"t{start + i}"
        p.emit(E.REQ_CLASSIFIED, "gateway", {"class": "clean", "reasons": [], "method": m, "path": path, "session": "s-ok", "uid": 3}, rid=rid)
        p.emit(E.REQ_ROUTED, "gateway", {"route": route, "status": 200, "verdict": "ok", "ms": 4 + i}, rid=rid, wait=0.08)


def attack_round(p: Poster, results: dict[str, list[tuple[bool, bool]]], idx: int):
    for vuln, seq in results.items():
        ok, saw = seq[idx]
        p.emit(E.ATTACK_ATTEMPT, "sim", {"vuln": vuln, "ok": ok, "saw_real_data": saw}, wait=0.12)


def run(p: Poster):
    p.emit(E.POOL_STATE, "fleet", {"l1_free": 4, "l2_busy": 0, "size": 4})
    traffic(p, 6)

    # attack rounds: sqli and traversal succeed at first, then fewer (T = ok, saw / F = blocked)
    sqli = [(True, True), (True, True), (True, False), (False, False), (False, False), (False, False)]
    trav = [(True, True), (True, True), (True, True), (True, False), (False, False), (False, False)]
    idor = [(True, True)] * 6  # stays open: shows an unpatched vuln
    plan = {"sqli:/api/search": sqli, "traversal:/api/download": trav, "idor:/api/orders": idor}
    attack_round(p, plan, 0)

    # ---- incident 1: SQL injection, patched on the first attempt
    rid1 = "r-sqli-1"
    p.emit(E.REQ_CLASSIFIED, "gateway", {"class": "suspect", "reasons": ["sql-meta"], "method": "GET", "path": "/api/search", "session": "sess-1", "uid": 7}, rid=rid1)
    p.emit(E.SESSION_CAPTURED, "gateway", {"session": "sess-1", "clone": "clone-1", "reason": "suspect"}, rid=rid1)
    p.emit(E.POOL_STATE, "fleet", {"l1_free": 3, "l2_busy": 1, "size": 4})
    p.emit(E.REQ_ROUTED, "gateway", {"route": "shadow_l2", "status": 200, "verdict": "oracle", "ms": 31}, rid=rid1, wait=0.5)
    q = f"q={XSS}' OR '1'='1' --"
    p.emit(E.ORACLE_FIRED, "gateway", evidence(
        rid1, "GET", "/api/search", q, "",
        "sql", {"statement": f"SELECT * FROM products WHERE name LIKE '%{XSS}' OR '1'='1' --%'", "tainted": True},
        [{"file": "app/routes/search.py", "line": 41, "func": "search"}, {"file": "app/db.py", "line": 18, "func": "query"}]) | {"uid": 7}, rid=rid1, wait=1.2)
    traffic(p, 3, 10)
    p.emit(E.INCIDENT_OPENED, "pipeline", {"incident": "inc-sqli-1", "vuln_class": "sqli", "route": "/api/search", "param": {"in": "query", "name": "q"},
                                          "sink": {"file": "app/routes/search.py", "line": 41}}, incident="inc-sqli-1", wait=1.0)
    p.emit(E.POC_READY, "pipeline", {"incident": "inc-sqli-1", "reproducible": True, "runs": 3, "poc": {"method": "GET", "path": "/api/search"}}, incident="inc-sqli-1", wait=1.0)
    p.emit(E.RULE_ACTIVE, "gateway", {"id": "rule-sqli-1", "incident": "inc-sqli-1", "method": "GET", "route": "/api/search",
                                      "param": {"in": "query", "name": "q"}, "grammar": "^[\\w \\-]{0,64}$", "scope": "param", "ttl_s": 600, "created": time.time()},
           incident="inc-sqli-1", wait=1.0)
    attack_round(p, plan, 1)
    inc = "inc-sqli-1"
    p.emit(E.PATCH_ATTEMPT, "pipeline", {"incident": inc, "attempt": 1, "source": "llm"}, incident=inc, wait=2.0)
    diff1 = """--- a/app/routes/search.py
+++ b/app/routes/search.py
@@ -38,7 +38,7 @@ def search(request):
     q = request.query_params.get("q", "")
-    sql = "SELECT * FROM products WHERE name LIKE '%" + q + "%'"
-    rows = db.execute(sql).fetchall()
+    sql = "SELECT * FROM products WHERE name LIKE ?"
+    rows = db.execute(sql, (f"%{q}%",)).fetchall()
     return JSONResponse([dict(r) for r in rows])
"""
    p.emit(E.PATCH_DIFF, "pipeline", {"incident": inc, "attempt": 1, "diff": diff1}, incident=inc, wait=0.8)
    for g, det in [("policy", "diff toca 1 archivo, sin imports nuevos"), ("properties", "consulta parametrizada, sin concatenacion"),
                   ("poc", "el PoC ya no devuelve filas ajenas (3/3)"), ("tests", "42 passed"), ("legit", "8/8 escenarios legitimos iguales")]:
        p.emit(E.GATE_RESULT, "pipeline", {"incident": inc, "attempt": 1, "gate": g, "ok": True, "detail": det}, incident=inc, wait=0.9)
    gh = "https://github.com/demo-org/victim/pull/1"
    p.emit(E.PR_OPENED, "pipeline", {"incident": inc, "url": gh, "branch": "run/demo/fix-sqli-1"}, incident=inc, wait=0.8)
    p.emit(E.PR_MERGED, "pipeline", {"incident": inc, "url": gh, "sha": "a1b2c3d4e5f6"}, incident=inc, wait=0.6)
    p.emit(E.DEPLOY_STARTED, "fleet", {"release": "a1b2c3d4e5f6"}, wait=1.5)
    p.emit(E.UPSTREAM_SWITCHED, "gateway", {"release": "a1b2c3d4e5f6", "addr": "prod-b:8000"})
    p.emit(E.DEPLOY_DONE, "fleet", {"release": "a1b2c3d4e5f6", "ok": True, "rolled_back": False, "detail": "healthy after 2.1s"}, wait=0.8)
    p.emit(E.VERIFY_RESULT, "pipeline", {"incident": inc, "exploit_blocked_on_prod": True}, incident=inc, wait=0.4)
    p.emit(E.RULE_EXPIRED, "gateway", {"id": "rule-sqli-1", "reason": "patched"}, incident=inc)
    p.emit(E.SESSION_RELEASED, "gateway", {"session": "sess-1", "reason": "patched"})
    p.emit(E.POOL_STATE, "fleet", {"l1_free": 4, "l2_busy": 0, "size": 4})
    p.emit(E.INCIDENT_CLOSED, "pipeline", {"incident": inc, "outcome": "patched", "seconds_to_rule": 3.2, "seconds_to_patch": 11.8}, incident=inc, wait=0.6)
    traffic(p, 4, 20)
    attack_round(p, plan, 2)

    # ---- incident 2: path traversal, first attempt rejected by a gate
    rid2 = "r-trav-1"
    p.emit(E.REQ_CLASSIFIED, "gateway", {"class": "suspect", "reasons": ["path-dotdot"], "method": "GET", "path": "/api/download", "session": "sess-2", "uid": 9}, rid=rid2)
    p.emit(E.SESSION_CAPTURED, "gateway", {"session": "sess-2", "clone": "clone-2", "reason": "suspect"}, rid=rid2)
    p.emit(E.POOL_STATE, "fleet", {"l1_free": 3, "l2_busy": 1, "size": 4})
    p.emit(E.REQ_ROUTED, "gateway", {"route": "shadow_l2", "status": 200, "verdict": "oracle", "ms": 27}, rid=rid2, wait=0.4)
    p.emit(E.ORACLE_FIRED, "gateway", evidence(
        rid2, "GET", "/api/download", "file=../../../etc/passwd", "",
        "file", {"path": "/etc/passwd", "op": "open"},
        [{"file": "app/routes/files.py", "line": 27, "func": "download"}]) | {"uid": 9}, rid=rid2, wait=1.2)
    inc = "inc-trav-1"
    p.emit(E.INCIDENT_OPENED, "pipeline", {"incident": inc, "vuln_class": "path_traversal", "route": "/api/download", "param": {"in": "query", "name": "file"},
                                          "sink": {"file": "app/routes/files.py", "line": 27}}, incident=inc, wait=0.8)
    p.emit(E.POC_READY, "pipeline", {"incident": inc, "reproducible": True, "runs": 3, "poc": {}}, incident=inc, wait=0.8)
    p.emit(E.RULE_ACTIVE, "gateway", {"id": "rule-trav-1", "incident": inc, "method": "GET", "route": "/api/download",
                                      "param": {"in": "query", "name": "file"}, "grammar": "^[A-Za-z0-9_.-]+$", "scope": "param", "ttl_s": 600, "created": time.time()},
           incident=inc, wait=1.0)
    attack_round(p, plan, 3)
    p.emit(E.PATCH_ATTEMPT, "pipeline", {"incident": inc, "attempt": 1, "source": "llm"}, incident=inc, wait=2.0)
    diff_a = """--- a/app/routes/files.py
+++ b/app/routes/files.py
@@ -24,5 +24,6 @@ def download(request):
     name = request.query_params["file"]
-    path = os.path.join(BASE, name)
+    # TODO <img src=x onerror=alert(1)> must never run
+    path = os.path.join(BASE, name.replace("../", ""))
     return FileResponse(path)
"""
    p.emit(E.PATCH_DIFF, "pipeline", {"incident": inc, "attempt": 1, "diff": diff_a}, incident=inc, wait=0.8)
    for g, ok, det in [("policy", True, "diff toca 1 archivo"), ("properties", True, "usa os.path"),
                       ("poc", False, "el PoC con ....// sigue leyendo /etc/passwd (filtro ingenuo)")]:
        p.emit(E.GATE_RESULT, "pipeline", {"incident": inc, "attempt": 1, "gate": g, "ok": ok, "detail": det}, incident=inc, wait=0.9)
    p.emit(E.PATCH_ATTEMPT, "pipeline", {"incident": inc, "attempt": 2, "source": "llm"}, incident=inc, wait=1.8)
    diff_b = """--- a/app/routes/files.py
+++ b/app/routes/files.py
@@ -24,5 +24,8 @@ def download(request):
     name = request.query_params["file"]
-    path = os.path.join(BASE, name)
+    path = os.path.realpath(os.path.join(BASE, name))
+    if os.path.commonpath([BASE, path]) != BASE:
+        return JSONResponse({"error": "not found"}, status_code=404)
     return FileResponse(path)
"""
    p.emit(E.PATCH_DIFF, "pipeline", {"incident": inc, "attempt": 2, "diff": diff_b}, incident=inc, wait=0.8)
    for g, det in [("policy", "diff toca 1 archivo"), ("properties", "realpath + commonpath dentro de BASE"),
                   ("poc", "el PoC falla (404) 3/3"), ("tests", "42 passed"), ("legit", "8/8 escenarios legitimos iguales")]:
        p.emit(E.GATE_RESULT, "pipeline", {"incident": inc, "attempt": 2, "gate": g, "ok": True, "detail": det}, incident=inc, wait=0.9)
    gh = "https://github.com/demo-org/victim/pull/2"
    p.emit(E.PR_OPENED, "pipeline", {"incident": inc, "url": gh, "branch": "run/demo/fix-trav-1"}, incident=inc, wait=0.8)
    p.emit(E.PR_MERGED, "pipeline", {"incident": inc, "url": gh, "sha": "f6e5d4c3b2a1"}, incident=inc, wait=0.6)
    p.emit(E.DEPLOY_STARTED, "fleet", {"release": "f6e5d4c3b2a1"}, wait=1.5)
    p.emit(E.DEPLOY_DONE, "fleet", {"release": "f6e5d4c3b2a1", "ok": True, "rolled_back": False, "detail": "healthy after 1.9s"}, wait=0.8)
    p.emit(E.VERIFY_RESULT, "pipeline", {"incident": inc, "exploit_blocked_on_prod": True}, incident=inc, wait=0.4)
    p.emit(E.RULE_EXPIRED, "gateway", {"id": "rule-trav-1", "reason": "patched"}, incident=inc)
    p.emit(E.INCIDENT_CLOSED, "pipeline", {"incident": inc, "outcome": "patched", "seconds_to_rule": 2.9, "seconds_to_patch": 19.4}, incident=inc, wait=0.6)
    attack_round(p, plan, 4)
    traffic(p, 4, 30)
    attack_round(p, plan, 5)
    p.emit(E.REQ_CLASSIFIED, "gateway", {"class": "evidence", "reasons": ["known-bad"], "method": "GET", "path": "/api/download", "session": "sess-3", "uid": None}, rid="r-deny")
    p.emit(E.REQ_ROUTED, "gateway", {"route": "deny", "status": 403, "verdict": "rule", "ms": 1}, rid="r-deny")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.environ.get("DASH_URL", "http://127.0.0.1:8090"))
    ap.add_argument("--token", default=os.environ.get("BUS_TOKEN", ""))
    ap.add_argument("--speed", type=float, default=1.0, help="2.0 = twice as fast")
    ap.add_argument("--clear", action="store_true", help="empty the bus store first")
    a = ap.parse_args(argv)
    if not a.token:
        print("set BUS_TOKEN or --token", file=sys.stderr)
        return 2
    p = Poster(a.url, a.token, a.speed)
    try:
        if a.clear:
            p.clear()
        run(p)
    except urllib.error.URLError as e:
        print(f"cannot reach dashboard: {e}", file=sys.stderr)
        return 1
    print(f"posted {p.n} events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
