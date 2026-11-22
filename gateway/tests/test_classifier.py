import json, os

import pytest

from gateway.classifier import (CLEAN, EVIDENCE, SUSPECT, EnumTracker, Manifest, Rule, View, Who, classify,
                                redact_json, redact_multipart, redact_path, redact_query)
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
    with pytest.raises(ValueError):
        Rule({"id": "x", "method": "GET", "route": "/a", "scope": "param_present", "param": None})
    # a grammar violation, or a rule on the whole route, denies when the clone is inconclusive
    assert r.rule_strict == ["r"]
    assert c("GET", "/api/orders/3", who=TRUSTED, rules=[allr]).rule_strict == ["a"]


def test_param_present_rule():
    """Every request that carries the parameter is suspect; the grammar only marks the strict ones."""
    rule = Rule({"id": "p", "method": "GET", "route": "/api/products", "param": {"in": "query", "name": "q"},
                 "scope": "param_present"})
    assert rule.ttl_s is None and rule.to_dict()["expires_in"] is None
    r = c("GET", "/api/products", "q=usb", who=TRUSTED, rules=[rule])
    assert r.cls == SUSPECT and r.rule_hit == ["p"] and r.rule_strict == []
    # letters, digits and spaces only: clean for the base classifier, still detonated by the rule
    r = c("GET", "/api/products", "q=1%20UNION%20SELECT%20email%20FROM%20users", who=TRUSTED, rules=[rule])
    assert r.rule_hit == ["p"] and r.rule_strict == []
    r = c("GET", "/api/products", "q=a%27--", who=TRUSTED, rules=[rule])
    assert r.rule_hit == ["p"] and r.rule_strict == ["p"]
    assert c("GET", "/api/products", "", who=TRUSTED, rules=[rule]).rule_hit == []      # parameter absent
    assert c("GET", "/api/products", "q=", who=TRUSTED, rules=[rule]).rule_hit == ["p"]  # present, empty
    jr = Rule({"id": "j", "method": "POST", "route": "/api/login", "param": {"in": "json", "name": "email"},
               "scope": "param_present"})
    body = json.dumps({"email": "ana@tienda.example", "password": "x"}).encode()
    assert c("POST", "/api/login", body=body, ctype="application/json", rules=[jr]).rule_hit == ["j"]
    assert c("POST", "/api/login", body=b'{"password":"x"}', ctype="application/json", rules=[jr]).rule_hit == []


def test_identity_untrusted_rule_spares_authenticated_callers():
    """Missing-auth containment (CWE-306): a scope=all rule detonates anonymous/untrusted callers only."""
    rule = Rule({"id": "a", "method": "GET", "route": "/api/products", "scope": "all", "identity": "untrusted"})
    assert c("GET", "/api/products", who=ANON, rules=[rule]).rule_hit == ["a"]
    assert c("GET", "/api/products", who=UNTRUSTED, rules=[rule]).rule_hit == ["a"]
    assert c("GET", "/api/products", who=TRUSTED, rules=[rule]).rule_hit == []   # authenticated traffic untouched
    # without the qualifier the same rule hits every identity
    plain = Rule({"id": "b", "method": "GET", "route": "/api/products", "scope": "all"})
    assert c("GET", "/api/products", who=TRUSTED, rules=[plain]).rule_hit == ["b"]


def test_rule_without_ttl_never_expires_and_restores_its_clock():
    forever = Rule({"id": "f", "method": "GET", "route": "/a", "scope": "all"}, now=100.0)
    assert forever.expires == float("inf") and forever.to_store() == {"rule": forever.raw, "expires": None}
    timed = Rule({"id": "t", "method": "GET", "route": "/a", "scope": "all", "ttl_s": 60}, now=100.0)
    assert timed.expires == 160.0
    back = Rule(timed.to_store()["rule"], now=150.0, expires=timed.to_store()["expires"])
    assert back.expires == 160.0     # a restart does not extend a ttl


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


def test_group_route_ownership_uses_membership():
    from gateway.classifier import _is_owner
    m = Manifest.from_dict({"seed_max_uid": 60, "canaries": {"team_id": [900]},
                            "groups": {"teams": {"1": [3, 5], "900": [61]}}, "group_routes": {"team_id": "teams"},
                            "ownership": {"teams": {"1": 99}}})
    assert _is_owner(m, "team_id", "1", 3) and _is_owner(m, "team_id", "1", 5)
    assert not _is_owner(m, "team_id", "1", 4) and not _is_owner(m, "team_id", "1", None)
    assert _is_owner(m, "team_id", "900", 61) and not _is_owner(m, "team_id", "900", 3)
    # no declared relation: the one-owner lookup is unchanged
    assert _is_owner(MAN, "order_id", "12", 7) and not _is_owner(MAN, "order_id", "12", 3)
    assert Manifest.from_dict({"group_routes": {"team_id": "missing"}}).group_routes == {}


# ---- encoded slashes: the gateway matches on the path the upstream routes on (uvicorn decodes, then starlette splits)
@pytest.mark.parametrize("path", ["/api%2Fproducts", "/api%2fproducts", "%2Fapi%2Fproducts", "/api/products%2F"])
def test_encoded_slash_cannot_hide_a_route_from_the_classifier(path):
    from gateway.spec import match_template, split_template
    assert match_template(split_template("/api/products"), path) == {}
    r = c("GET", path, "q=x%27%20OR%20%271%27%3D%271")
    assert r.cls == SUSPECT and "grammar:query.q" in r.reasons
    assert c("GET", "/api%2Fproducts%2F1%27").reasons.count("schema:path.product_id:type") == 1


def test_encoded_slash_cannot_hide_a_route_from_a_rule():
    rule = Rule({"id": "r", "method": "GET", "route": "/api/products", "param": {"in": "query", "name": "q"},
                 "grammar": r"[a-z]{1,10}", "scope": "param", "ttl_s": 60})
    allr = Rule({"id": "a", "method": "GET", "route": "/api/orders/{order_id}", "scope": "all", "ttl_s": 60})
    for path in ("/api%2Fproducts", "/api%2fproducts"):
        assert c("GET", path, "q=a'b", rules=[rule]).rule_hit == ["r"]
        assert c("GET", path, "q=usb", rules=[rule]).rule_hit == []
    assert c("GET", "/api%2Forders%2F3", rules=[allr]).rule_hit == ["a"]
    assert allr.applies("GET", "/api%2Forders%2F3") == {"order_id": "3"}
    # a rule on an off-spec route is hit as well
    off = Rule({"id": "o", "method": "GET", "route": "/internal/debug", "scope": "all", "ttl_s": 60})
    assert c("GET", "/internal%2Fdebug", rules=[off], spec=OFF_SPEC).rule_hit == ["o"]


def test_encoded_slash_readings_follow_the_upstream():
    from gateway.spec import match_template, path_readings, split_template
    prod, order = split_template("/api/products"), split_template("/api/orders/{order_id}")
    # one decode only, as uvicorn does: '%252F' is the text '%2F', and '%5C' is a backslash, not a separator
    assert match_template(prod, "/api%252Fproducts") is None and match_template(prod, "/api%5Cproducts") is None
    assert c("GET", "/api%252Fproducts", "q=a'b").cls == CLEAN            # off-spec for the app too (404 there)
    assert path_readings("/api/orders/3") == [["api", "orders", "3"]]     # no encoded slash: a single reading
    # starlette splits '1%2F2' in two segments (404); a server that routes on the raw path serves order '1/2':
    # the rule applies under either reading and the classifier checks the parameter of the one that matches
    assert match_template(order, "/api/orders/1%2F2") == {"order_id": "1/2"}
    r = c("GET", "/api/orders/1%2F2")
    assert r.cls == SUSPECT and {"path:encoded_slash", "schema:path.order_id:type"} <= set(r.reasons)
    assert "path:encoded_slash" in c("GET", "/api%2Fproducts", "q=usb").reasons
    # inside a catch-all parameter an encoded slash changes nothing for anyone: same route, same value, clean
    spec = Spec({"paths": {"/files/{path*}": {"get": {"parameters": [
        {"name": "path", "in": "path", "schema": {"type": "string"}}]}}}})
    assert spec.match("GET", "/files/img%2Fa.svg")[1] == spec.match("GET", "/files/img/a.svg")[1] == {"path": "img/a.svg"}
    assert c("GET", "/files/img%2Fa.svg", who=ANON, spec=spec).cls == CLEAN
    assert c("GET", "/a%2Fb", who=ANON, spec=OFF_SPEC).cls == CLEAN        # unknown under every reading


# ---- owner-scoped routes and seeded identities: the manifest knows who owns what
def test_seeded_user_on_someone_elses_object_is_suspect():
    r = c("GET", "/api/orders/12", who=Who(uid=3, role="user", trusted=True))
    assert "owner_scoped:mismatch:order_id" in r.reasons                    # order 12 belongs to uid 7 (a canary too)
    man = Manifest.from_dict({"seed_max_uid": 60, "ownership": {"orders": {"5": 3, "6": 4}}})

    def cls(path, who):
        return classify(View("GET", path, "", {}, b""), VICTIM, who, man, [], "s")
    other = cls("/api/orders/6", TRUSTED)
    assert other.cls == SUSPECT and other.reasons == ["owner_scoped:mismatch:order_id"]
    assert cls("/api/orders/6/invoice", TRUSTED).cls == SUSPECT
    assert cls("/api/users/4/profile", TRUSTED).reasons == ["owner_scoped:mismatch:user_id"]
    # their own objects, an object the manifest does not know (created after the seed) and admins stay clean
    assert cls("/api/orders/5", TRUSTED).cls == CLEAN and cls("/api/orders/5/invoice", TRUSTED).cls == CLEAN
    assert cls("/api/users/3/profile", TRUSTED).cls == CLEAN
    assert cls("/api/orders/777", TRUSTED).cls == CLEAN
    assert cls("/api/orders/6", ADMIN).cls == CLEAN
    assert cls("/api/products/6", TRUSTED).cls == CLEAN                     # not owner-scoped
    # untrusted identities keep their own reason
    assert cls("/api/orders/6", UNTRUSTED).reasons == ["owner_scoped:untrusted"]


def test_seeded_member_of_a_group_route():
    spec = Spec({"paths": {"/teams/{team_id}/notes": {"get": {"x-owner-scoped": True, "parameters": [
        {"name": "team_id", "in": "path", "schema": {"type": "integer"}}]}}}})
    man = Manifest.from_dict({"seed_max_uid": 60, "groups": {"teams": {"1": [3, 5]}}, "group_routes": {"team_id": "teams"}})

    def cls(path, uid):
        return classify(View("GET", path, "", {}, b""), spec, Who(uid=uid, role="user", trusted=True), man, [], "s")
    assert cls("/teams/1/notes", 3).cls == CLEAN and cls("/teams/1/notes", 5).cls == CLEAN
    assert cls("/teams/1/notes", 4).reasons == ["owner_scoped:mismatch:team_id"]
    assert cls("/teams/2/notes", 4).cls == CLEAN                            # a team the manifest does not know


def test_redact_path_replaces_only_the_sensitive_segment():
    assert redact_path("/api/reset/s3cr%65t/confirm", {"s3cret"}) == "/api/reset/<redacted>/confirm"
    assert redact_path("/api/reset/other", {"s3cret"}) == "/api/reset/other"
    assert redact_path("/api/x", set()) == "/api/x"


def test_redact_multipart_replaces_the_named_part_and_keeps_the_rest():
    ct = "multipart/form-data; boundary=XyZ"
    body = (b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n"
            b"--XyZ\r\nContent-Disposition: form-data; name=\"pw\"\r\n\r\ntopsecret\r\n--XyZ--\r\n")
    out = redact_multipart(body, ct, {"pw"})
    assert b"topsecret" not in out and b"hello" in out and b"<redacted>" in out
    assert out.count(b"--XyZ") == 3
    assert redact_multipart(body, ct, set()) == body
    assert redact_multipart(body, "multipart/form-data", {"pw"}) == b"<redacted>"
