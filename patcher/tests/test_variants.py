import base64
import copy
import json
import shutil
from urllib.parse import parse_qsl

import pytest

from patcher import variants
from patcher.checks import patched_copy, replay
from patcher.fallback import fallback_path

KEYS = {"method", "path", "query", "headers", "body_b64"}


def _login_incident():
    body = json.dumps({"email": "admin@tienda.example' --", "password": "x"}).encode()
    req = {"method": "POST", "path": "/api/login", "query": "", "headers": {"content-type": "application/json"},
           "body_b64": base64.b64encode(body).decode()}
    ev = {"request": req, "uid": None, "role": None, "events": [{"oracle": "sql", "stack": [],
          "detail": {"param": "email", "location": "json", "input": "admin@tienda.example' --"}}]}
    poc = {"incident": "fx-login", "release": "t0", "state_b64": None, "requests": [dict(req, uid=None, role=None)],
           "expect": {"oracle": "sql"}}
    return {"incident": "fx-login", "vuln_class": "sqli", "method": "POST", "route": "/api/login",
            "param": {"in": "json", "name": "email"}, "sink": {"file": "victim/app/auth.py", "line": 55},
            "request": req, "evidence": ev, "poc": poc}


@pytest.mark.parametrize("oracle", ["sql", "file", "owner"])
def test_shape_count_determinism(incidents, oracle):
    inc = incidents[oracle]
    a = variants(inc["poc"], inc["evidence"])
    b = variants(copy.deepcopy(inc["poc"]), copy.deepcopy(inc["evidence"]))
    assert a == b
    assert 15 <= len(a) <= 40
    orig = inc["poc"]["requests"][0]
    for v in a:
        assert KEYS <= set(v)
        assert v["method"] == orig["method"]
        assert (v["path"], v["query"], v["body_b64"], v.get("uid")) != (orig["path"], orig["query"], orig["body_b64"], orig.get("uid"))
    keys = {json.dumps([v["path"], v["query"], v["body_b64"], v.get("uid")]) for v in a}
    assert len(keys) == len(a)


def test_query_variants_only_mutate_the_param(incidents):
    inc = incidents["sql"]
    for v in variants(inc["poc"], inc["evidence"]):
        assert v["path"] == "/api/products"
        names = {k for k, _ in parse_qsl(v["query"], keep_blank_values=True)}
        assert names == {"q"}


def test_idor_variants_use_other_ids_and_requesters(incidents):
    inc = incidents["owner"]
    vs = variants(inc["poc"], inc["evidence"])
    assert all(v["path"].startswith("/api/orders/") for v in vs)
    assert len({v["path"] for v in vs}) >= 15
    assert any(v["path"] == "/api/orders/5" and v["uid"] != 61 for v in vs)


def test_json_param_variants():
    inc = _login_incident()
    vs = variants(inc["poc"], inc["evidence"])
    assert 15 <= len(vs) <= 40
    emails = []
    for v in vs:
        body = json.loads(base64.b64decode(v["body_b64"]))
        assert set(body) == {"email", "password"} and body["password"] == "x"
        emails.append(body["email"])
    assert len(set(emails)) >= 15


def test_no_padding_with_copies_of_the_captured_request():
    """Nothing to mutate (no parameter, no id in the path): no variants, not replays of the PoC."""
    req = {"method": "GET", "path": "/api/health", "query": "", "headers": {}, "body_b64": ""}
    ev = {"request": req, "uid": None, "role": None, "events": [{"oracle": "net", "detail": {}, "stack": []}]}
    poc = {"requests": [dict(req, uid=None, role=None)], "expect": {"oracle": "net"}}
    assert variants(poc, ev) == []
    # one mutable query value under an oracle without payload families: still nothing equal to the PoC
    req2 = dict(req, path="/api/items", query="tag=a")
    poc2 = {"requests": [dict(req2, uid=None, role=None)], "expect": {"oracle": "net"}}
    assert variants(poc2, dict(ev, request=req2)) == []


@pytest.mark.parametrize("oracle,n", [("sql", 31), ("file", 26), ("owner", 26)])
def test_variant_counts_for_the_demo_incidents(incidents, oracle, n):
    inc = incidents[oracle]
    vs = variants(inc["poc"], inc["evidence"])
    assert len(vs) == n and inc["poc"]["requests"][0] not in vs


def _fires(root, reqs):
    return [r["verdict"] == "oracle" for r in replay(root, reqs)]


def _apply_to_t0(t0, diff):
    root, errs = patched_copy(t0, [diff] if diff else [])
    assert not errs, errs
    return root


NAIVE = {
    # fixes that only handle the captured value: the variants must still fire on them
    "sql": ("victim/app/products.py", "    if q:\n",
            "    if q == \"zzzzzz' OR '1'='1\":\n        raise HTTPException(400, \"bad\")\n    if q:\n"),
    "file": ("victim/app/files.py", '    path = os.path.join(static_root(), "manuals", name)\n',
             '    name = name.replace("../../../../../../../../", "")\n'
             '    path = os.path.join(static_root(), "manuals", name)\n'),
    "owner": ("victim/app/orders.py", '    row = db.fetch_one("SELECT " + COLUMNS + " FROM orders WHERE id = ?", (order_id,))\n    if not row:\n',
              '    if order_id == 5:\n        raise HTTPException(404, "not found")\n'
              '    row = db.fetch_one("SELECT " + COLUMNS + " FROM orders WHERE id = ?", (order_id,))\n    if not row:\n'),
}


@pytest.mark.parametrize("oracle", ["sql", "file", "owner"])
def test_variants_fire_on_t0_and_on_naive_fix_but_not_on_root_fix(incidents, t0_release, oracle):
    import os
    inc = incidents[oracle]
    vs = variants(inc["poc"], inc["evidence"])
    poc = inc["poc"]["requests"]

    root = _apply_to_t0(t0_release, "")
    try:
        f = _fires(root, poc + vs)
        assert f[0], "PoC must fire on t0"
        assert sum(f[1:]) >= 12, f
        # naive special-case fix: PoC is blocked but variants still fire
        path, old, new = NAIVE[oracle]
        p = os.path.join(root, path)
        src = open(p).read()
        assert src.count(old) == 1
        open(p, "w").write(src.replace(old, new))
        f = _fires(root, poc + vs)
        assert not f[0], "naive fix should stop the exact PoC"
        assert sum(f[1:]) >= 5, "variants must catch a fix that only handles the captured value"
    finally:
        shutil.rmtree(root)

    root = _apply_to_t0(t0_release, open(fallback_path(inc)).read())
    try:
        f = _fires(root, poc + vs)
        assert not any(f), f
    finally:
        shutil.rmtree(root)
