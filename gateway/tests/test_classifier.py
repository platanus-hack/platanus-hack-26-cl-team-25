import json, os

import pytest

from gateway.classifier import (CLEAN, EVIDENCE, SUSPECT, EnumTracker, Manifest, Rule, View, Who, classify,
                                redact_json, redact_query)
from gateway.spec import Spec

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VICTIM = Spec.load(os.path.join(ROOT, "contracts/openapi.yaml"))
FIXTURE = Spec.load(os.path.join(ROOT, "acceptance/fixture/fixture_app/openapi.yaml"))
MAN = Manifest.from_dict({"seed_max_uid": 60, "canaries": {"user_id": [7], "order_id": [12]},
                          "ownership": {"orders": {"12": 7, "5": 3}}})
TRUSTED = Who(uid=3, role="user", trusted=True)
UNTRUSTED = Who(uid=99, role="user", trusted=False)
ADMIN = Who(uid=1, role="admin", trusted=True)
ANON = Who()


def c(method, path, query="", body=b"", ctype=None, who=TRUSTED, rules=(), spec=VICTIM, enum=None, session="s"):
    headers = {"content-type": ctype} if ctype else {}
    return classify(View(method, path, query, headers, body), spec, who, MAN, list(rules), session, enum)


def test_clean_requests():
    assert c("GET", "/api/products", "q=usb+cable&category=audio&sort=price&page=2").cls == CLEAN
    assert c("GET", "/api/products/5").cls == CLEAN
    assert c("GET", "/api/files/download", "name=manual.v1.2.pdf").cls == CLEAN
    assert c("GET", "/api/orders/5", who=TRUSTED).cls == CLEAN
    body = json.dumps({"items": [{"product_id": 1, "qty": 2}], "note": "leave at door"}).encode()
    assert c("POST", "/api/orders", body=body, ctype="application/json").cls == CLEAN


@pytest.mark.parametrize("query,reason", [
    ("q=a'b", "grammar:query.q"),
    ("category=weapons", "schema:query.category:enum"),
    ("page=0", "schema:query.page:bounds"),
    ("page=1001", "schema:query.page:bounds"),
    ("page=1%20OR%201", "schema:query.page:type"),
    ("q=" + "a" * 81, "schema:query.q:length"),
    ("q=a&q=b", "dup_query:q"),
    ("zzz=..%2Fetc", "grammar:query.zzz"),
])
def test_query_violations(query, reason):
    r = c("GET", "/api/products", query)
    assert r.cls == SUSPECT and reason in r.reasons


def test_path_param_violations():
    assert "schema:path.product_id:type" in c("GET", "/api/products/1%27").reasons
    assert "schema:path.product_id:bounds" in c("GET", "/api/products/0").reasons
    assert c("GET", "/api/files/download", "name=..%2F..%2Fetc%2Fpasswd").cls == SUSPECT


def test_json_body():
    bad = json.dumps({"items": [{"product_id": "1 OR 1=1", "qty": 1}]}).encode()
    r = c("POST", "/api/orders", body=bad, ctype="application/json")
    assert r.cls == SUSPECT and "schema:json.items.product_id:type" in r.reasons
    r = c("POST", "/api/orders", body=json.dumps({"items": [{"product_id": 1, "qty": 100}]}).encode(), ctype="application/json")
    assert "schema:json.items.qty:bounds" in r.reasons
    r = c("POST", "/api/orders", body=b"{not json", ctype="application/json")
    assert r.cls == SUSPECT
    r = c("POST", "/api/orders", body=json.dumps({"items": [{"product_id": 1, "qty": 1}], "note": "x'; --"}).encode(),
          ctype="application/json")
    assert "grammar:json.note" in r.reasons


def test_sensitive_is_skipped_and_redacted():
    body = json.dumps({"email": "a@b.cl", "password": "p'\"; DROP--"}).encode()
    r = c("POST", "/api/login", body=body, ctype="application/json", who=ANON)
    assert r.cls == CLEAN and "password" in r.sensitive["json"]
    red = json.loads(redact_json(body, r.sensitive["json"]))
    assert red == {"email": "a@b.cl", "password": "<redacted>"}
    assert redact_query("a=1&pw=secret", {"pw"}) == "a=1&pw=%3Credacted%3E"


def test_owner_scoped_identity():
    assert c("GET", "/api/orders/5", who=TRUSTED).cls == CLEAN
    assert "owner_scoped:untrusted" in c("GET", "/api/orders/5", who=UNTRUSTED).reasons
    assert "owner_scoped:anonymous" in c("GET", "/api/orders/5", who=ANON).reasons


def test_canaries():
    r = c("GET", "/api/users/7/profile", who=TRUSTED)
    assert r.cls == EVIDENCE and "canary:user_id" in r.reasons
    assert c("GET", "/api/orders/12/invoice", who=UNTRUSTED).cls == EVIDENCE
    assert c("GET", "/api/orders/12", who=ADMIN).cls == CLEAN          # admins exempt
    assert c("GET", "/api/orders/12", who=Who(uid=7, role="user", trusted=True)).cls == CLEAN  # owner exempt


def test_honeytoken():
    assert c("GET", "/api/products", who=Who(honeytoken=True)).cls == EVIDENCE


def test_rules():
    rule = Rule({"id": "r", "method": "GET", "route": "/api/files/download", "param": {"in": "query", "name": "name"},
                 "grammar": r"[A-Za-z0-9.]{1,40}", "scope": "param", "ttl_s": 60})
    assert c("GET", "/api/files/download", "name=manual.pdf", rules=[rule]).rule_hit == []
    r = c("GET", "/api/files/download", "name=a%20b", rules=[rule])
    assert r.rule_hit == ["r"] and r.cls == SUSPECT
    allr = Rule({"id": "a", "method": "GET", "route": "/api/orders/{order_id}", "scope": "all", "ttl_s": 60})
    assert c("GET", "/api/orders/3", who=TRUSTED, rules=[allr]).rule_hit == ["a"]
    assert c("POST", "/api/orders/3", who=TRUSTED, rules=[allr]).rule_hit == []
    jr = Rule({"id": "j", "method": "POST", "route": "/api/orders", "param": {"in": "json", "name": "items.qty"},
               "grammar": r"[0-9]{1,2}", "scope": "param", "ttl_s": 60})
    body = json.dumps({"items": [{"product_id": 1, "qty": 2}, {"product_id": 1, "qty": 2.5}]}).encode()
    assert c("POST", "/api/orders", body=body, ctype="application/json", rules=[jr]).rule_hit == ["j"]
    with pytest.raises(ValueError):
        Rule({"id": "x", "method": "GET", "route": "/a", "scope": "param", "param": None, "ttl_s": 5})


def test_unknown_path_is_clean_and_head_maps_to_get():
    assert c("GET", "/totally/unknown", "x=1").cls == CLEAN
    assert c("HEAD", "/api/products", "q=a'").cls == SUSPECT
    assert c("GET", "/api/products/", "q=a'").cls == SUSPECT   # trailing slash still matched


def test_template_precedence():
    op, params = FIXTURE.match("GET", "/notes/3")
    assert op.template == "/notes/{note_id}" and params == {"note_id": "3"}
    op, _ = FIXTURE.match("POST", "/notes")
    assert op.template == "/notes"


def test_form_body():
    spec = Spec({"paths": {"/f": {"post": {"requestBody": {"content": {"application/x-www-form-urlencoded": {
        "schema": {"type": "object", "properties": {"a": {"type": "integer"}, "pw": {"type": "string", "x-sensitive": True}}}}}}}}}})
    ok = classify(View("POST", "/f", "", {"content-type": "application/x-www-form-urlencoded"}, b"a=3&pw=%27%22"),
                  spec, TRUSTED, MAN, [], "s")
    assert ok.cls == CLEAN and ok.sensitive["form"] == {"pw"}
    bad = classify(View("POST", "/f", "", {"content-type": "application/x-www-form-urlencoded"}, b"a=3x"),
                   spec, TRUSTED, MAN, [], "s")
    assert "schema:form.a:type" in bad.reasons


def test_enumeration():
    enum = EnumTracker(window_s=30, threshold=3)
    results = [c("GET", f"/api/orders/{i}", who=TRUSTED, enum=enum, session="uid:3").reasons for i in range(1, 6)]
    assert "enumeration" not in results[2] and "enumeration" in results[4]
    # another session is unaffected
    assert c("GET", "/api/orders/1", who=TRUSTED, enum=enum, session="uid:4").cls == CLEAN


# ---- built-in rule: classic path traversal (any route, on- or off-spec)
from gateway.classifier import traversal_in_path, traversal_in_value  # noqa: E402

OFF_SPEC = Spec(None)


@pytest.mark.parametrize("path", [
    "/public/plugins/alertlist/../../../../etc/passwd",
    "/cgi-bin/.%2e/.%2e/etc/passwd",
    "/icons/.%%32%65/.%%32%65/etc/passwd",
    "/a/%252e%252e/%252e%252e/x",
    "/a/..%5c..%5cwin.ini",
    "/a/%c0%ae%c0%ae/x",
    "/x/..;/admin",
])
def test_traversal_path_detected_off_spec(path):
    assert traversal_in_path(path)
    r = c("GET", path, who=ANON, spec=OFF_SPEC)
    assert r.cls == SUSPECT and "traversal:path" in r.reasons


@pytest.mark.parametrize("path", [
    "/public/plugins/alertlist/img/icn.svg", "/api/dashboards/uid/a..b", "/files/manual.v1..2.pdf",
    "/a/.../b", "/a/.hidden/b", "/a/%2e/b", "/a/..b/c", "/",
])
def test_traversal_path_benign(path):
    assert not traversal_in_path(path)
    assert c("GET", path, who=ANON, spec=OFF_SPEC).cls == CLEAN


def test_traversal_query_value():
    for v in ("../../etc/passwd", "..%2f..%2fetc", "....//....//etc", "..\\..\\x"):
        assert traversal_in_value(v), v
    for v in ("manual.v1.2.pdf", "a..b", "O'Brien", "..."):
        assert not traversal_in_value(v), v
    r = c("GET", "/anything", "file=..%2F..%2Fetc%2Fpasswd", who=ANON, spec=OFF_SPEC)
    assert "traversal:query.file" in r.reasons


def test_catchall_template():
    from gateway.spec import match_template, split_template
    segs = split_template("/public/plugins/{pluginId}/{path*}")
    assert match_template(segs, "/public/plugins/alertlist/img/a.svg") == {"pluginId": "alertlist", "path": "img/a.svg"}
    assert match_template(segs, "/public/plugins/alertlist") is None
    spec = Spec({"paths": {"/public/plugins/{pluginId}/{path*}": {"get": {"parameters": [
        {"name": "pluginId", "in": "path", "schema": {"type": "string"}},
        {"name": "path", "in": "path", "schema": {"type": "string"}}]}}}})
    assert c("GET", "/public/plugins/alertlist/img/a.svg", who=ANON, spec=spec).cls == CLEAN   # '/' allowed
    r = c("GET", "/public/plugins/alertlist/../../etc/passwd", who=ANON, spec=spec)
    assert r.cls == SUSPECT and "traversal:path" in r.reasons
