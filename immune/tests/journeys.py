"""Acceptance journeys run through the harness with the GENERATED profile and shadow seed.

    python -m immune.tests.journeys victim <project>      # docs/demo/respuestas/tienda.md requests + a legitimate journey
"""
from __future__ import annotations

import json
import sys

from immune import _cfg
from immune.doctor import build_release
from immune.initsteps import hostrun


def run(project: str, requests: list[dict]) -> list[dict]:
    cfg = _cfg.load(project)
    release = build_release(cfg)
    res = hostrun.harness(cfg, release, {"requests": requests})
    if not res.get("ok"):
        raise RuntimeError("harness failed: %s\n%s" % (res.get("error"), res.get("trace", "")[-2000:]))
    return res["results"]


def manifest(project: str) -> dict:
    cfg = _cfg.load(project)
    with open(cfg.manifest_path) as f:
        return json.load(f)


def victim_requests(m: dict) -> tuple[list[dict], dict]:
    """(requests, expected oracle per name) for docs/demo/respuestas/tienda.md + a legitimate journey."""
    legit = m["legit_users"][0]
    own = next(int(k) for k, v in m["ownership"]["orders"].items() if v == legit["id"])
    foreign_uid = next(u["id"] for u in m["legit_users"] if u["id"] not in (7,))
    reqs = [
        {"name": "v1 sqli products", "path": "/api/products", "query": "q=zzzzzz%27%20OR%20%271%27%3D%271"},
        {"name": "v2 sqli login", "method": "POST", "path": "/api/login",
         "json": {"email": "admin@tienda.example' --", "password": "x"}},
        {"name": "v3 traversal download", "path": "/api/files/download", "query": "name=../../../../../../etc/hostname"},
        {"name": "v4 traversal image", "path": "/api/products/1/image", "query": "file=../../../../../../etc/hostname"},
        {"name": "v5 idor order", "path": "/api/orders/12", "uid": foreign_uid},
        {"name": "v6 idor invoice", "path": "/api/orders/12/invoice", "uid": foreign_uid},
        {"name": "v7 idor profile", "path": "/api/users/7/profile", "uid": foreign_uid},
    ]
    expected = {"v1 sqli products": "sql", "v2 sqli login": "sql", "v3 traversal download": "file",
                "v4 traversal image": "file", "v5 idor order": "owner", "v6 idor invoice": "owner",
                "v7 idor profile": "owner"}
    if legit.get("password"):
        reqs.append({"name": "legit login", "method": "POST", "path": "/api/login",
                     "json": {"email": legit["email"], "password": legit["password"]}})
        expected["legit login"] = "clean"
    reqs += [{"name": "legit products", "path": "/api/products", "uid": legit["id"]},
             {"name": "legit search", "path": "/api/products", "query": "q=usb&sort=price", "uid": legit["id"]},
             {"name": "legit own order", "path": "/api/orders/%d" % own, "uid": legit["id"]},
             {"name": "legit own orders", "path": "/api/orders", "uid": legit["id"]},
             {"name": "legit manual", "path": "/api/files/download", "query": "name=audifonos.pro.guia.txt"}]
    for n in ("legit products", "legit search", "legit own order", "legit own orders", "legit manual"):
        expected[n] = "clean"
    return reqs, expected


def notas_requests(m: dict, project: str) -> tuple[list[dict], dict]:
    """(requests, expected) for examples/notas: the 4 defects of docs/demo/respuestas/notas.md and the legitimate
    journeys of its tests/test_app.py, against the generated shadow seed."""
    import sqlite3
    cfg = _cfg.load(project)
    c = sqlite3.connect("file:%s?mode=ro" % cfg.shadow_seed, uri=True)
    try:
        legit = m["legit_users"][0]
        uid = legit["id"]
        own_note = c.execute("SELECT id FROM notes WHERE owner_id = ? ORDER BY id LIMIT 1", (uid,)).fetchone()[0]
        foreign_note = c.execute("SELECT id FROM notes WHERE owner_id != ? AND id < 100000 ORDER BY id LIMIT 1",
                                 (uid,)).fetchone()[0]
        mine = {t for (t,) in c.execute("SELECT team_id FROM memberships WHERE user_id = ?", (uid,))}
        teams = [t for (t,) in c.execute("SELECT id FROM teams ORDER BY id")]
        own_team = sorted(mine)[0]
        foreign_team = next(t for t in teams if t not in mine)
    finally:
        c.close()
    adm = m["admin"]
    reqs = [
        {"name": "d1 sqli notes q", "path": "/notes", "query": "q=zz%27%29%20OR%201%3D1%20--%20", "uid": uid},
        {"name": "d2 traversal template", "path": "/templates/download", "query": "name=../../../../../../etc/hostname",
         "uid": uid},
        {"name": "d3 idor export", "path": "/notes/%d/export" % foreign_note, "uid": uid},
        {"name": "d4 idor team members", "path": "/teams/%d/members" % foreign_team, "uid": uid},
        {"name": "legit login", "method": "POST", "path": "/auth/login",
         "json": {"email": legit["email"], "password": legit["password"]}},
        {"name": "legit register", "method": "POST", "path": "/auth/register",
         "json": {"email": "prueba.x1@notas.example", "name": "Usuario de Prueba", "password": "secreto1"}},
        {"name": "legit me", "path": "/auth/me", "uid": uid},
        {"name": "legit list notes", "path": "/notes", "uid": uid},
        {"name": "legit search spaces", "path": "/notes", "query": "q=plan+de+lanz", "uid": uid},
        {"name": "legit sort title", "path": "/notes", "query": "sort=title", "uid": uid},
        {"name": "legit create note", "method": "POST", "path": "/notes", "json": {"title": "Primera", "body": "Hola"},
         "uid": uid},
        {"name": "legit apostrophe title", "method": "POST", "path": "/notes",
         "json": {"title": "Reunión con O'Higgins", "body": "D'Alessandro"}, "uid": uid},
        {"name": "legit note in own team", "method": "POST", "path": "/notes",
         "json": {"title": "Del equipo", "team_id": own_team}, "uid": uid},
        {"name": "legit get own note", "path": "/notes/%d" % own_note, "uid": uid},
        {"name": "legit update own note", "method": "PUT", "path": "/notes/%d" % own_note,
         "json": {"title": "Nuevo", "body": "Nuevo texto"}, "uid": uid},
        {"name": "legit delete own note", "method": "DELETE", "path": "/notes/%d" % own_note, "uid": uid},
        {"name": "legit export own note", "path": "/notes/%d/export" % own_note, "uid": uid},
        {"name": "legit templates", "path": "/templates", "uid": uid},
        {"name": "legit template dots", "path": "/templates/download", "query": "name=retro.sprint.2024.v1.txt", "uid": uid},
        {"name": "legit template md", "path": "/templates/download", "query": "name=acta.semanal.v2.md", "uid": uid},
        {"name": "legit team members as member", "path": "/teams/%d/members" % own_team, "uid": uid},
        {"name": "legit admin users", "path": "/admin/users", "uid": adm["id"], "role": "admin"},
    ]
    expected = {"d1 sqli notes q": "sql", "d2 traversal template": "file", "d3 idor export": "owner",
                "d4 idor team members": "owner"}
    for r in reqs:
        if r["name"].startswith("legit"):
            expected[r["name"]] = "clean"
    return reqs, expected


def evaluate(results: list[dict], expected: dict) -> list[tuple[str, str, str, bool]]:
    out = []
    for r in results:
        want = expected.get(r["name"])
        if want is None:
            continue
        got = "clean" if r["verdict"] == "clean" else (",".join(r["oracles"]) or r["verdict"])
        ok = (want == "clean" and r["verdict"] == "clean" and r["status"] < 400) or \
             (want != "clean" and want in r["oracles"])
        out.append((r["name"], want, "%s (status %s)" % (got, r["status"]), ok))
    return out


def main(argv):
    kind, project = argv[0], argv[1]
    m = manifest(project)
    if kind == "victim":
        reqs, exp = victim_requests(m)
    elif kind == "notas":
        reqs, exp = notas_requests(m, project)
    else:
        raise SystemExit("unknown journey set %r" % kind)
    rows = evaluate(run(project, reqs), exp)
    for name, want, got, ok in rows:
        print("%-30s expected %-6s got %-28s %s" % (name, want, got, "OK" if ok else "MISMATCH"))
    return 0 if all(r[3] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
