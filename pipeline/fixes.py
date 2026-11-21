"""Catalogue of hand-written fixes for the t0 victim app.

Used by the gate self-test (`python -m pipeline.selftest`: deliberately inadequate fixes
that the gates must reject, one adequate fix per class that must pass all five) and by
`pipeline.stub_patcher` (pre-recorded adequate fixes; "plan B" in the demo).

Each fix is a list of exact-text edits applied to the release; the diff is generated
with difflib against whatever release it is applied to. A fix whose anchor text is not
found raises FixNotApplicable (e.g. the code was already patched).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable

from . import diffs, openapi


class FixNotApplicable(Exception):
    pass


@dataclass
class Fix:
    name: str
    vuln_class: str
    expect: str            # "pass" or the gate that must reject it
    reason: str
    edits: Callable        # (incident) -> list[(file, old, new)]
    tags: list = field(default_factory=list)


def build_diff(release_dir: str, edits: list) -> str:
    texts = {}
    for rel, old, new in edits:
        if rel not in texts:
            try:
                with open(os.path.join(release_dir, rel)) as f:
                    texts[rel] = f.read()
            except FileNotFoundError:
                raise FixNotApplicable("%s not found" % rel)
        if texts[rel].count(old) != 1:
            raise FixNotApplicable("anchor not found exactly once in %s: %r" % (rel, old[:60]))
        texts[rel] = texts[rel].replace(old, new)
    return diffs.make(release_dir, texts)


# ------------------------------------------------------------------ anchors (t0 code)
PRODUCTS = "victim/app/products.py"
AUTH = "victim/app/auth.py"
FILES = "victim/app/files.py"
ORDERS = "victim/app/orders.py"
USERS = "victim/app/users.py"

Q_OLD = """        conds.append("(name LIKE '%" + q + "%' OR category LIKE '" + q + "')")
"""
Q_NEW = """        conds.append("(name LIKE ? OR category LIKE ?)")
        params.extend(["%" + q + "%", q])
"""
LOGIN_OLD = """        "SELECT id, role FROM users WHERE email = '" + body.email + "' AND password_hash = '" + digest + "'"
    )"""
LOGIN_NEW = """        "SELECT id, role FROM users WHERE email = ? AND password_hash = ?", (body.email, digest)
    )"""

SQLI_GOOD = [(PRODUCTS, Q_OLD, Q_NEW), (AUTH, LOGIN_OLD, LOGIN_NEW)]

DL_OLD = """def download(name: str):
    path = os.path.join(static_root(), "manuals", name)
"""
DL_NEW = """def download(name: str):
    path = inside(os.path.join(static_root(), "manuals"), name)
"""
IMG_OLD = """    path = os.path.join(static_root(), "images", file)
"""
IMG_NEW = """    path = inside(os.path.join(static_root(), "images"), file)
"""
HELPER_OLD = """@router.get("/api/files/download")
"""
HELPER_NEW = """def inside(base, name):
    base = os.path.realpath(base)
    path = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, path]) != base:
        raise HTTPException(404, "not found")
    return path


@router.get("/api/files/download")
"""
TRAV_GOOD = [(FILES, HELPER_OLD, HELPER_NEW), (FILES, DL_OLD, DL_NEW), (FILES, IMG_OLD, IMG_NEW)]

ORDER_OLD = """def get_order(order_id: int, authorization: str = Header(None)):
    auth.current(authorization)
    row = db.fetch_one("SELECT " + COLUMNS + " FROM orders WHERE id = ?", (order_id,))
    if not row:
"""
ORDER_NEW = """def get_order(order_id: int, authorization: str = Header(None)):
    ident = auth.current(authorization)
    row = db.fetch_one("SELECT " + COLUMNS + " FROM orders WHERE id = ?", (order_id,))
    if not row or (row["user_id"] != ident.uid and ident.role != "admin"):
"""
INV_OLD = """def invoice(order_id: int, authorization: str = Header(None)):
    auth.current(authorization)
    row = db.fetch_one(
        "SELECT o.id, o.total, o.note, o.shipping_address, o.created_at, u.name, u.email "
        "FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?",
        (order_id,),
    )
    if not row:
"""
INV_NEW = """def invoice(order_id: int, authorization: str = Header(None)):
    ident = auth.current(authorization)
    row = db.fetch_one(
        "SELECT o.id, o.user_id, o.total, o.note, o.shipping_address, o.created_at, u.name, u.email "
        "FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?",
        (order_id,),
    )
    if not row or (row["user_id"] != ident.uid and ident.role != "admin"):
"""
PROF_OLD = """    auth.current(authorization)
    row = db.fetch_one("SELECT id, name, email, address, phone FROM users WHERE id = ?", (user_id,))
    if not row:
"""
PROF_NEW = """    ident = auth.current(authorization)
    row = db.fetch_one("SELECT id, name, email, address, phone FROM users WHERE id = ?", (user_id,))
    if not row or (row["id"] != ident.uid and ident.role != "admin"):
"""
IDOR_GOOD = [(ORDERS, ORDER_OLD, ORDER_NEW), (ORDERS, INV_OLD, INV_NEW), (USERS, PROF_OLD, PROF_NEW)]


def _poc_id(inc) -> str:
    pp = openapi.match(inc.get("route") or "", (inc.get("request") or {}).get("path") or "") or {}
    name = (inc.get("param") or {}).get("name")
    return str(pp.get(name, "1"))


CATALOGUE = [
    # ---------------------------------------------------------------- sqli
    Fix("sqli-parameterised", "sqli", "pass", "bound parameters in the search and the login queries",
        lambda inc: SQLI_GOOD),
    Fix("sqli-quote-blacklist", "sqli", "policy", "rejects inputs containing a quote (blacklist on a new literal)",
        lambda inc: [(PRODUCTS, Q_OLD, """        if "'" in q:
            raise HTTPException(400, "invalid search")
""" + Q_OLD)]),
    Fix("sqli-strip-quotes", "sqli", "properties", "deletes quotes from the input: O'Brien no longer round-trips",
        lambda inc: [(PRODUCTS, Q_OLD, """        q = q.replace("'", "")
""" + Q_OLD)]),
    Fix("sqli-header-backdoor", "sqli", "policy", "correct fix plus a debug header that bypasses the filter",
        lambda inc: [(PRODUCTS, "from fastapi import APIRouter, HTTPException, Query",
                      "from fastapi import APIRouter, Header, HTTPException, Query"),
                     (PRODUCTS, "    page: int = Query(1, ge=1, le=1000),\n):",
                      "    page: int = Query(1, ge=1, le=1000),\n    x_debug: Optional[str] = Header(None),\n):"),
                     (PRODUCTS, Q_OLD, Q_NEW + "    if x_debug:\n        conds = []\n")]),
    Fix("sqli-endpoint-deleted", "sqli", "properties", "removes the vulnerable endpoint instead of fixing it",
        lambda inc: [(PRODUCTS, '@router.get("/api/products")\ndef list_products(', 'def list_products(')]),
    Fix("sqli-breaks-paging", "sqli", "tests", "correct fix, but changes the page size",
        lambda inc: SQLI_GOOD[:1] + [(PRODUCTS, "PAGE_SIZE = 10", "PAGE_SIZE = 12")]),
    Fix("sqli-changes-invoice", "sqli", "legit", "correct fix, but silently changes the invoice text format",
        lambda inc: SQLI_GOOD[:1] + [(ORDERS, '    out.append("TOTAL: %d" % row["total"])',
                                      '    out.append("Total: %d" % row["total"])')]),
    Fix("sqli-drops-admin-check", "sqli", "policy", "correct fix, but also deletes the admin role check",
        lambda inc: SQLI_GOOD[:1] + [(ORDERS, '    if ident.role != "admin":\n        raise HTTPException(403, "forbidden")\n',
                                      '')]),
    # ---------------------------------------------------------------- traversal
    Fix("traversal-realpath-inside-root", "traversal", "pass", "resolve the path and require it inside the base dir",
        lambda inc: TRAV_GOOD),
    Fix("traversal-strip-dotdot", "traversal", "properties", "naive filter: deletes '../' once ('....//' survives)",
        lambda inc: [(FILES, DL_OLD, DL_OLD.replace('    path =', '    name = name.replace("../", "")\n    path ='))]),
    Fix("traversal-pardir-only", "traversal", "poc", "blocks '..' but not absolute paths (PoC variant /etc/...)",
        lambda inc: [(FILES, DL_OLD, DL_OLD + '    if os.pardir in name:\n        raise HTTPException(404, "not found")\n')]),
    Fix("traversal-mangles-names", "traversal", "properties", "keeps only the first and last dot part: dotted names break",
        lambda inc: [(FILES, DL_OLD, DL_OLD.replace('    path =', '    parts = name.split(".")\n'
                                                  '    name = parts[0] + "." + parts[-1]\n    path ='))]),
    Fix("traversal-new-import", "traversal", "policy", "correct idea, but imports pathlib",
        lambda inc: [(FILES, "import os\n", "import os\nfrom pathlib import Path\n"),
                     (FILES, DL_OLD, DL_OLD + '    if not Path(path).resolve().is_relative_to(Path(static_root()).resolve()):\n'
                                             '        raise HTTPException(404, "not found")\n')]),
    # ---------------------------------------------------------------- idor
    Fix("idor-owner-check", "idor", "pass", "owner (or admin) check on orders, invoices and profiles",
        lambda inc: IDOR_GOOD),
    Fix("idor-special-case-poc-id", "idor", "policy", "only blocks the id used by the PoC",
        lambda inc: [(ORDERS, ORDER_OLD, ORDER_OLD.replace("    if not row:\n", "    if not row or order_id == %s:\n" % _poc_id(inc)))]),
    Fix("idor-deny-everyone", "idor", "properties", "returns 404 to everybody, owners included",
        lambda inc: [(ORDERS, ORDER_OLD, ORDER_OLD.replace("    if not row:\n", "    if True:\n"))]),
    Fix("idor-support-key-backdoor", "idor", "policy", "owner check with a hard-coded support key that bypasses it",
        lambda inc: [(ORDERS, 'COLUMNS = "id, user_id', 'SUPPORT = "Bearer Zk93hQ2xLp7TvB4mWc81"\nCOLUMNS = "id, user_id'),
                     (ORDERS, ORDER_OLD, ORDER_NEW.replace('ident.role != "admin")', 'ident.role != "admin" and authorization != SUPPORT)'))]),
    Fix("idor-edits-tests", "idor", "policy", "correct fix, but also edits the test suite",
        lambda inc: IDOR_GOOD + [("victim/tests/test_victim_app.py", "def test_health(client):", "def test_health(client):  # ok")]),
]

BY_NAME = {f.name: f for f in CATALOGUE}


def adequate(vuln_class: str) -> Fix | None:
    for f in CATALOGUE:
        if f.vuln_class == vuln_class and f.expect == "pass":
            return f
    return None


def diff_for(fix: Fix, release_dir: str, incident: dict) -> str:
    return build_diff(release_dir, fix.edits(incident))
