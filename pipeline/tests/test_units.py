"""Pure unit tests: no app code runs, no Docker, no network beyond 127.0.0.1 fakes."""
import base64
import copy
import json
import os

import pytest

from pipeline import bus, diffs, fixes, incident, openapi, poc, policy, reqs, rules
from pipeline.state import State

from .conftest import ROOT


# ------------------------------------------------------------------ incident derivation
def test_incidents_from_real_events(events, spec):
    s = incident.build(events["sqli"], spec)
    assert (s["vuln_class"], s["method"], s["route"], s["param"]) == ("sqli", "GET", "/api/products", {"in": "query", "name": "q"})
    assert s["sink"] == {"file": "victim/app/db.py", "line": 25}          # innermost frame of the first sql event
    t = incident.build(events["traversal"], spec)
    assert (t["vuln_class"], t["route"], t["param"]) == ("traversal", "/api/files/download", {"in": "query", "name": "name"})
    assert t["sink"] == {"file": "victim/app/files.py", "line": 20}
    i = incident.build(events["idor"], {**spec}, {"canaries": {"order_id": [12, 31]}})
    assert (i["vuln_class"], i["route"], i["param"]) == ("idor", "/api/orders/{order_id}", {"in": "path", "name": "order_id"})
    assert i["evidence_rid"] == events["idor"]["rid"]
    assert len({s["key"], t["key"], i["key"]}) == 3


def test_oracle_preference_sql_then_file_then_owner(events, spec):
    ev = copy.deepcopy(events["sqli"])
    owner = {"oracle": "owner", "detail": {"marker_owner": 3, "requester": 70}, "stack": [{"file": "victim/app/x.py", "line": 1, "func": "f"}]}
    ev["data"]["events"] = [owner] + ev["data"]["events"]
    assert incident.build(ev, spec)["vuln_class"] == "sqli"
    ev["data"]["events"] = [owner, copy.deepcopy(events["traversal"]["data"]["events"][0])]
    assert incident.primary_event(ev["data"])["oracle"] == "file"


def test_dedupe_key_ignores_concrete_values(events, spec):
    a = incident.build(events["idor"], spec)
    ev = copy.deepcopy(events["idor"])
    ev["data"]["request"]["path"] = "/api/orders/31"
    assert incident.build(ev, spec)["key"] == a["key"]


# ------------------------------------------------------------------ requests / openapi
def test_set_value_locations():
    base = {"method": "GET", "path": "/api/products/1/image", "query": "file=a.png&x=1", "headers": {}, "body_b64": ""}
    r = reqs.set_value(base, {"in": "query", "name": "file"}, "../../etc/passwd", "/api/products/{product_id}/image")
    assert reqs.get_value(r, {"in": "query", "name": "file"}) == "../../etc/passwd" and "x=1" in r["query"]
    r = reqs.set_value(base, {"in": "path", "name": "product_id"}, "7", "/api/products/{product_id}/image")
    assert r["path"] == "/api/products/7/image"
    j = reqs.with_body(dict(base, method="POST"), b'{"email":"a@b","password":"x"}')
    r = reqs.set_value(j, {"in": "json", "name": "email"}, "O'Brien")
    assert json.loads(reqs.body_of(r))["email"] == "O'Brien"


def test_openapi_match_prefers_static(spec):
    tpl, _op, pp = openapi.find(spec, "GET", "/api/products/3/image")
    assert tpl == "/api/products/{product_id}/image" and pp == {"product_id": "3"}
    assert openapi.find(spec, "GET", "/api/products")[0] == "/api/products"


# ------------------------------------------------------------------ PoC
def test_poc_schema_and_identity(events, spec):
    inc = incident.build(events["idor"], spec)
    inc["incident"] = "inc-1"
    p = poc.build(inc, "t0")
    r = p["requests"][0]
    assert r["uid"] == 61 and "authorization" not in r["headers"] and "host" not in r["headers"]
    assert p["expect"] == {"oracle": "owner", "sink": inc["sink"]}


# ------------------------------------------------------------------ diffs
def test_diff_apply_and_reject(t0):
    d = fixes.build_diff(t0, fixes.SQLI_GOOD)
    assert [c.path for c in diffs.parse(d)] == ["victim/app/auth.py", "victim/app/products.py"]
    work = diffs.copy_release(t0, os.path.dirname(t0))
    diffs.apply(d, work)
    assert "LIKE ? OR category LIKE ?" in open(os.path.join(work, "victim/app/products.py")).read()
    with pytest.raises(diffs.DiffError):
        diffs.apply(d, work)          # already applied
    with pytest.raises(diffs.DiffError):
        diffs.apply("--- a/victim/app/nope.py\n+++ b/victim/app/nope.py\n@@ -1 +1 @@\n-x\n+y\n", work)
    with pytest.raises(diffs.DiffError):
        diffs.parse("")


# ------------------------------------------------------------------ policy gate (AST)
def _policy(t0, diff):
    work = diffs.copy_release(t0, os.path.dirname(t0))
    diffs.apply(diff, work)
    return policy.check(diff, t0, work)


@pytest.mark.parametrize("name", sorted(os.listdir(os.path.join(ROOT, "patcher", "fallbacks"))))
def test_known_good_fallbacks_pass_policy(t0, name):
    ok, detail, v = _policy(t0, open(os.path.join(ROOT, "patcher", "fallbacks", name)).read())
    assert ok, detail


@pytest.mark.parametrize("fix", [f for f in fixes.CATALOGUE if f.expect == "policy"], ids=lambda f: f.name)
def test_bad_fixes_rejected_by_policy(t0, fix, spec, events):
    inc = incident.build(events[{"sqli": "sqli", "traversal": "traversal", "idor": "idor"}[fix.vuln_class]], spec)
    d = fixes.diff_for(fix, t0, inc)
    ok, detail, v = policy.check(d, t0, _applied(t0, d))
    assert not ok and detail.startswith("REJECTED")


def _applied(t0, d):
    work = diffs.copy_release(t0, os.path.dirname(t0))
    diffs.apply(d, work)
    return work


def test_policy_role_check_with_existing_literal_is_allowed(t0):
    edits = [("victim/app/users.py", "    auth.current(authorization)\n",
              "    ident = auth.current(authorization)\n    if user_id != ident.uid and ident.role != \"admin\":\n"
              "        raise HTTPException(404, \"not found\")\n")]
    d = fixes.build_diff(t0, edits)
    ok, detail, _ = policy.check(d, t0, _applied(t0, d))
    assert ok, detail


def test_policy_specific_rejections(t0):
    lit = fixes.build_diff(t0, [("victim/app/users.py", "    if not row:\n", "    if not row or user_id == 7:\n")])
    assert "new literal" in policy.check(lit, t0, _applied(t0, lit))[1]
    syn = fixes.build_diff(t0, [("victim/app/users.py", "    if not row:\n", "    if not row\n")])
    assert "syntax error" in policy.check(syn, t0, _applied(t0, syn))[1]
    new = "--- /dev/null\n+++ b/victim/app/extra.py\n@@ -0,0 +1 @@\n+x = 1\n"
    assert "creating or deleting" in policy.check(new, t0, t0)[1]
    auth = fixes.build_diff(t0, [("victim/app/users.py", "    auth.current(authorization)\n", "")])
    assert "authentication check removed" in policy.check(auth, t0, _applied(t0, auth))[1]
    env = fixes.build_diff(t0, [("victim/app/users.py", "    if not row:\n", "    if not row or os.environ:\n")])
    assert not policy.check(env, t0, _applied(t0, env))[0]
    big = fixes.build_diff(t0, [("victim/app/users.py", "    if not row:\n", "    if not row:\n" + "        pass\n" * 130)])
    assert "too large" in policy.check(big, t0, _applied(t0, big))[1]


# ------------------------------------------------------------------ rules
def test_rules_validate_and_fallback(events, spec):
    inc = incident.build(events["sqli"], spec)
    inc["incident"] = "inc-9"
    r, note = rules.finalize({"id": "x", "method": "GET", "route": "/api/products", "scope": "param",
                              "param": {"in": "query", "name": "q"}, "grammar": "[a-z]{0,10}", "ttl_s": 60}, inc, spec, 600)
    assert not note and r["incident"] == "inc-9"
    r, note = rules.finalize({"route": "/other"}, inc, spec, 600)
    assert note and r["route"] == "/api/products" and r["scope"] == "param"
    poc.validate(r, "rule.schema.json")
    i = incident.build(events["idor"], spec)
    i["incident"] = "inc-10"
    assert rules.default_rule(i, spec)["scope"] == "all"


# ------------------------------------------------------------------ bus
def test_sse_parser():
    lines = ["retry: 2000", "", ": hb", "id: 3", 'data: {"a":1}', "", "event: reset", "data: {}", ""]
    got = [x for x in bus.parse_sse(lines) if x[2]]
    assert got == [("message", "3", '{"a":1}'), ("reset", None, "{}")]


def test_publisher_enforces_contract_fields(tmp_path):
    p = bus.Publisher("http://127.0.0.1:9", "t", "r", log_path=str(tmp_path / "ev.jsonl"), timeout=0.2)
    with pytest.raises(ValueError):
        p.publish("gate.result", {"incident": "i", "gate": "policy", "ok": True})
    ev = p.publish("verify.result", {"incident": "i", "exploit_blocked_on_prod": True}, incident="i")
    assert ev["src"] == "pipeline" and p.dropped == 1          # bus down: dropped, not raised
    assert json.loads(open(tmp_path / "ev.jsonl").read())["type"] == "verify.result"


def test_follower_resumes_from_seq():
    from pipeline.fakes import FakeBus
    from immune_contracts import events as E
    import threading
    import time
    b = FakeBus()
    try:
        for i in range(5):
            b.add(E.make(E.POOL_STATE, "fleet", {"l1_free": i, "l2_busy": 0, "size": 4}))
        got, done = [], threading.Event()

        def on(seq, ev):
            got.append(seq)
            if seq == 5:
                done.set()
        f = bus.Follower(b.url, lambda: 3, on)
        f.start()
        assert done.wait(5)
        f.stop()
        assert got == [4, 5]
    finally:
        b.stop()


# ------------------------------------------------------------------ state
def test_state_survives_restart(tmp_path):
    s = State(str(tmp_path / "s.json"))
    iid = s.new_id()
    s.data["incidents"][iid] = {"status": "queued"}
    s.touch_seq(42, force=True)
    s2 = State(str(tmp_path / "s.json"))
    assert s2.data["last_seq"] == 42 and iid in s2.data["incidents"] and s2.new_id() == "inc-0002"


def test_git_style_diff_inside_enclosing_repo(tmp_path, t0):
    """A release copy inside another git work tree: `diff --git` paths must not resolve against that repo."""
    import subprocess
    outer = tmp_path / "outer"
    outer.mkdir()
    subprocess.run(["git", "init", "-q", str(outer)], check=True)
    work = diffs.copy_release(t0, str(outer))
    d = open(os.path.join(ROOT, "patcher", "fallbacks", "traversal__get-api-files-download.diff")).read()
    diffs.apply(d, work)
    assert "commonpath" in open(os.path.join(work, "victim/app/files.py")).read()
    assert not (outer / "victim").exists()


def test_catchall_route_and_rule():
    from immune_contracts import grammar
    from pipeline import openapi, rules
    tpl = "/public/plugins/{pluginId}/{path*}"
    assert openapi.match(tpl, "/public/plugins/a/../../etc/passwd") == {"pluginId": "a", "path": "../../etc/passwd"}
    assert openapi.path_params(tpl) == ["pluginId", "path"]
    assert openapi.fill(tpl, {"pluginId": "a", "path": "img/x.svg"}) == "/public/plugins/a/img/x.svg"
    inc = {"incident": "inc-1", "method": "GET", "route": tpl, "vuln_class": "traversal",
           "param": {"in": "path", "name": "path"}}
    r = rules.default_rule(inc, {})
    assert r["grammar"] == grammar.PATH_SAFE and grammar.matches(r["grammar"], "img/x.svg")
    assert not grammar.matches(r["grammar"], "../../etc/passwd")
