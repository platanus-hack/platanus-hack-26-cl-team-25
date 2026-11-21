import base64
import json
import os

import jsonschema
import pytest

from immune_contracts import grammar as G
from patcher import derive_rule

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMA = json.load(open(os.path.join(REPO, "contracts", "schemas", "rule.schema.json")))


def _valid(rule):
    jsonschema.validate(rule, SCHEMA)
    assert rule["ttl_s"] == 3600
    assert rule["id"].startswith("rule-")


def test_sqli_rule(incidents, openapi):
    inc = incidents["sql"]
    r = derive_rule(inc, openapi)
    _valid(r)
    assert r["id"] == "rule-fx-sqli"
    assert (r["method"], r["route"], r["scope"]) == ("GET", "/api/products", "param")
    assert r["param"] == {"in": "query", "name": "q"}
    g = r["grammar"]
    assert not G.matches(g, "zzzzzz' OR '1'='1")
    for ok in ["usb", "usb hub", "cable-3m", "O'Brien", "Conan O'Brien", "audio", "SSD 1TB", "x" * 80, ""]:
        assert G.matches(g, ok), ok
    for bad in ["x" * 81, "a'--", "a' OR 1=1", "x'or'x", "a' --", "' OR ''='", "O'Brien'", "a;b", "a/b", "a%b",
                "'a", "a'", "a''b", "a'b'c", "a) OR (1", "a/**/b", "a--b"]:
        assert not G.matches(g, bad), bad


def test_traversal_rule(incidents, openapi):
    inc = incidents["file"]
    r = derive_rule(inc, openapi)
    _valid(r)
    assert (r["route"], r["scope"], r["param"]) == ("/api/files/download", "param", {"in": "query", "name": "name"})
    g = r["grammar"]
    assert not G.matches(g, "../../../../../../../../etc/hostname")
    for ok in ["usb-hub.v2.txt", "audifonos.pro.guia.txt", "garantia.txt", "guia-cables.txt"]:
        assert G.matches(g, ok)
    for bad in ["/etc/passwd", "..", "a/../b", "..\\x", "x" * 81, "%2e%2e", "a\x00b"]:
        assert not G.matches(g, bad), bad


def test_idor_rule_is_scope_all(incidents, openapi):
    r = derive_rule(incidents["owner"], openapi)
    _valid(r)
    assert (r["method"], r["route"], r["scope"], r["grammar"], r["param"]) == ("GET", "/api/orders/{order_id}", "all", None, None)


def test_json_param_rule(openapi):
    body = json.dumps({"email": "admin@tienda.example' --", "password": "x"}).encode()
    inc = {"incident": "i9", "vuln_class": "sqli", "method": "POST", "route": "/api/login",
           "param": {"in": "json", "name": "email"},
           "request": {"method": "POST", "path": "/api/login", "query": "", "body_b64": base64.b64encode(body).decode()}}
    r = derive_rule(inc, openapi)
    _valid(r)
    assert r["scope"] == "param" and r["param"] == {"in": "json", "name": "email"}
    assert not G.matches(r["grammar"], "admin@tienda.example' --")
    assert G.matches(r["grammar"], "o'neil@example.com") and G.matches(r["grammar"], "ana.perez+1@mail.example")


@pytest.mark.parametrize("inc", [
    {"incident": "a", "vuln_class": "sqli", "method": "POST", "route": "/api/login", "param": {"in": "json", "name": "password"},
     "request": {"body_b64": base64.b64encode(b'{"password":"x\' OR 1=1 --"}').decode()}},   # x-sensitive
    {"incident": "b", "vuln_class": "sqli", "method": "GET", "route": "/api/products", "param": None, "request": {}},
    {"incident": "c", "vuln_class": "other", "method": "GET", "route": "/api/products", "param": {"in": "query", "name": "q"},
     "request": {"query": "q=x"}},
    {"incident": "d", "vuln_class": "traversal", "method": "GET", "route": "/api/files/download",
     "param": {"in": "query", "name": "name"}, "request": {"query": "name=garantia.txt"}},  # captured value is benign
])
def test_scope_all_fallbacks(inc, openapi):
    r = derive_rule(inc, openapi)
    _valid(r)
    assert r["scope"] == "all" and r["grammar"] is None
