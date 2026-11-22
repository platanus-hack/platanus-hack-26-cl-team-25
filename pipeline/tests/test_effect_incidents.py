"""Incidents of the input -> effect classes: class, input, PoC variants, self-audit and the gateway rule."""
import base64

import pytest

from immune_contracts import classes, payloads
from patcher.rule import derive_rule
from pipeline import audit, incident, poc, rules

SPEC = {"openapi": "3.0.3", "paths": {
    "/fetch": {"get": {"parameters": [{"name": "url", "in": "query", "schema": {"type": "string"}}],
                       "responses": {"200": {"description": "ok"}}}},
    "/run": {"post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
        "cfg": {"type": "object", "properties": {"host": {"type": "string"}}}}}}}}, "responses": {"200": {"description": "ok"}}}},
    "/import": {"post": {"responses": {"200": {"description": "ok"}}}},
    "/n": {"get": {"parameters": [{"name": "id", "in": "query", "schema": {"type": "integer"}}], "responses": {"200": {"description": "ok"}}}},
}}


def fired(oracle, detail, path="/fetch", query="", method="GET", body=b"", headers=None, uid=None):
    return {"type": "oracle.fired", "ts": 1.0, "rid": "r1", "data": {
        "rid": "r1", "uid": uid, "role": None, "status": 200, "mode": "L1",
        "events": [{"oracle": oracle, "detail": detail, "stack": [{"file": "app/x.py", "line": 7, "func": "go"}]}],
        "request": {"method": method, "path": path, "query": query, "headers": headers or {},
                    "body_b64": base64.b64encode(body).decode()}}}


CASES = [
    ("ssrf", {"address": "169.254.169.254", "port": 80, "input": "http://169.254.169.254/", "param": "url", "location": "query"},
     dict(query="url=http%3A%2F%2F169.254.169.254%2F"), {"in": "query", "name": "url"}),
    ("cmdi", {"argv": ["sh", "-c", "x; id"], "input": "x; id", "param": "cfg.host", "location": "json"},
     dict(path="/run", method="POST", body=b'{"cfg":{"host":"x; id"}}', headers={"content-type": "application/json"}),
     {"in": "json", "name": "cfg.host"}),
    ("ssti", {"expression": "{{ 91*91 }}", "evaluated": "8281", "input": "{{ 91*91 }}", "param": "url", "location": "query"},
     dict(query="url=%7B%7B%2091*91%20%7D%7D"), {"in": "query", "name": "url"}),
    ("deser", {"argv": ["sh"], "format": "pickle", "input": "gASV", "param": "session", "location": "cookie"},
     dict(headers={"cookie": "session=gASVxxxxxxxx"}), {"in": "cookie", "name": "session"}),
    ("xxe", {"entity": "file:///etc/passwd", "input": "<doc>", "param": "body", "location": "body"},
     dict(path="/import", method="POST", body=b"<doc/>", headers={"content-type": "application/xml"}),
     {"in": "body", "name": "body"}),
    ("redirect", {"target": "https://evil.example/", "host": "evil.example", "status": 302, "input": "https://evil.example/",
                  "param": "url", "location": "query"}, dict(query="url=https%3A%2F%2Fevil.example%2F"), {"in": "query", "name": "url"}),
]


@pytest.mark.parametrize("oracle,detail,req,param", CASES, ids=[c[0] for c in CASES])
def test_incident_class_and_input(oracle, detail, req, param):
    inc = incident.build(fired(oracle, detail, **req), SPEC)
    assert inc["vuln_class"] == oracle and inc["oracle"] == oracle
    assert inc["param"] == param
    assert inc["sink"] == {"file": "app/x.py", "line": 7}
    assert inc["key"].startswith(oracle + "|")


def test_an_unnamed_path_segment_is_not_an_addressable_input():
    ev = fired("ssrf", {"address": "10.0.0.1", "port": 80, "input": "10.0.0.1", "param": "path[2]", "location": "path"})
    assert incident.build(ev, SPEC)["param"] is None


def test_the_class_beats_the_side_effects_that_came_with_it():
    ev = fired("file", {"path": "/etc/passwd", "realpath": "/etc/passwd"})
    ev["data"]["events"] = [
        {"oracle": "file", "detail": {"path": "/etc/passwd", "realpath": "/etc/passwd"}, "stack": []},   # the spawned `id` read it
        {"oracle": "proc", "detail": {"argv": ["id"]}, "stack": []},
        {"oracle": "cmdi", "detail": {"param": "host", "location": "query", "input": "x; id"}, "stack": []}]
    assert incident.build(ev, SPEC)["vuln_class"] == "cmdi"
    older = fired("sql", {"statement": "SELECT 1", "param": "q", "location": "query"})
    older["data"]["events"].append({"oracle": "file", "detail": {"path": "/x", "realpath": "/x"}, "stack": []})
    assert incident.build(older, SPEC)["vuln_class"] == "sqli"                   # the older order is untouched


# ------------------------------------------------------------------ multi-step (stored) taint attribution
def _stored_xss_event():
    """A stored-XSS oracle.fired: the firing request (GET /wall) rendered a value an earlier POST /n planted."""
    payload = "<script>alert(91)</script>"
    origin_req = {"method": "POST", "path": "/n", "query": "", "headers": {"content-type": "application/json"},
                  "body_b64": base64.b64encode(b'{"body":"%s"}' % payload.encode()).decode()}
    ev = {"type": "oracle.fired", "ts": 1.0, "rid": "fire", "data": {
        "rid": "fire", "uid": 1, "role": "user", "status": 200, "mode": "L1",
        "events": [{"oracle": "xss", "detail": {"input": payload, "param": "body", "location": "json", "stored": True,
                                                "origin_rid": "plant"},
                    "stack": [{"file": "app/x.py", "line": 7, "func": "wall"}],
                    "origin": {"rid": "plant", "request": origin_req}}],
        "request": {"method": "GET", "path": "/wall", "query": "", "headers": {}, "body_b64": ""}}}
    return ev, payload, origin_req


def test_stored_incident_is_attributed_to_the_request_that_planted_the_value():
    ev, payload, origin_req = _stored_xss_event()
    inc = incident.build(ev, SPEC)
    assert inc["vuln_class"] == "xss" and inc["oracle"] == "xss"
    # the replayable request and the parameter are the planting request's, not the firing one's
    assert inc["request"]["method"] == "POST" and inc["request"]["path"] == "/n"
    assert inc["param"] == {"in": "json", "name": "body"}
    # the sink stays the firing request's render point
    assert inc["sink"] == {"file": "app/x.py", "line": 7}
    # both steps are recorded, plant first then trigger
    assert [s["path"] for s in inc["steps"]] == ["/n", "/wall"]
    assert payload.encode() in base64.b64decode(inc["steps"][0]["body_b64"])


def test_stored_poc_replays_both_steps():
    ev, payload, _ = _stored_xss_event()
    inc = incident.build(ev, SPEC)
    inc["incident"] = "inc-x"
    p = poc.build(inc, "t0")
    assert [r["path"] for r in p["requests"]] == ["/n", "/wall"]
    # the mutators target the planting step (where the parameter lives)
    muts = poc.mutate(inc, p)
    assert muts and all(m[1]["path"] == "/n" for m in muts)


# ------------------------------------------------------------------ PoC variants
@pytest.mark.parametrize("oracle,detail,req,param", [c for c in CASES if c[0] not in ("deser", "xxe")], ids=lambda x: x if isinstance(x, str) else None)
def test_builtin_mutators_use_the_classs_battery(oracle, detail, req, param):
    inc = incident.build(fired(oracle, detail, **req), SPEC)
    p = {"requests": [inc["request"] | {"headers": req.get("headers", {}), "uid": None, "role": None}], "expect": {"oracle": oracle}}
    muts = poc.mutate(inc, p)
    assert muts and len(muts) <= 8
    assert all(name.startswith("m") for name, _r in muts)


def test_patcher_variants_for_the_class_are_the_batteries():
    from patcher.variants import variants
    ev = {"events": [{"oracle": "cmdi", "detail": {"param": "host", "location": "query", "input": "x; id"}, "stack": []}],
          "request": {"method": "GET", "path": "/lookup", "query": "host=x%3B%20id", "headers": {}, "body_b64": ""}}
    got = variants({"requests": [ev["request"]], "expect": {"oracle": "cmdi"}}, ev)
    assert len({v["query"] for v in got}) >= len(payloads.CMDI) - 1


# ------------------------------------------------------------------ self-audit
def test_audit_probes_string_parameters_with_the_class_battery():
    cands = audit.candidates(SPEC, "ssrf")
    labels = {c.label for c in cands}
    assert "GET /fetch query:url" in labels and "POST /run json:cfg.host" in labels
    assert "GET /n query:id" not in labels                     # an integer cannot carry a URL
    assert audit.battery("cmdi", cands[0], None) == payloads.CMDI
    assert audit.ORACLE_OF["ssrf"] == "ssrf" and audit.ORACLE_OF["sqli"] == "sql"


def test_audit_skips_the_class_whose_input_is_the_whole_body():
    assert audit.candidates(SPEC, "xxe") == []
    assert "xxe" not in classes.STRING_CLASSES and "xxe" not in classes.AUDITABLE


# ------------------------------------------------------------------ the gateway rule
@pytest.mark.parametrize("cls", ["ssrf", "cmdi", "ssti", "deser", "redirect"])
def test_rule_for_an_addressable_input_is_param_present_with_a_grammar(cls):
    r = derive_rule({"incident": "inc-1", "vuln_class": cls, "method": "GET", "route": "/fetch",
                     "param": {"in": "query", "name": "url"}}, SPEC)
    assert r["scope"] == "param_present" and r["param"] == {"in": "query", "name": "url"} and r["grammar"]
    assert r["ttl_s"] is None


@pytest.mark.parametrize("param", [{"in": "body", "name": "body"}, {"in": "cookie", "name": "session"}])
def test_rule_for_an_input_the_gateway_cannot_address_covers_the_route(param):
    r = derive_rule({"incident": "inc-1", "vuln_class": "xxe", "method": "POST", "route": "/import", "param": param}, SPEC)
    assert r["scope"] == "all" and r["param"] is None


def test_pipeline_default_rule_agrees():
    inc = incident.build(fired(*CASES[0][:2], **CASES[0][2]), SPEC)
    inc["incident"] = "inc-1"
    r = rules.default_rule(inc, SPEC)
    assert r["scope"] == "param_present" and r["param"]["name"] == "url"


# ------------------------------------------------------------------ the contracts accept the new kinds
@pytest.mark.parametrize("kind", classes.EFFECT_CLASSES)
def test_evidence_and_poc_schemas_accept_the_new_oracle_kinds(kind):
    ev = {"clone": "c1", "rid": "r1", "mode": "L1", "release": "t0", "verdict": "oracle", "uid": None, "role": None,
          "request": {"method": "GET", "path": "/fetch", "query": "url=x", "headers": {}, "body_b64": ""}, "status": 200,
          "events": [{"oracle": kind, "detail": {"input": "x", "param": "url", "location": "query"}, "stack": []}],
          "pre_state_b64": None}
    poc.validate(ev, "evidence.schema.json")
    poc.validate({"incident": "inc-1", "release": "t0", "state_b64": None, "requests": [ev["request"] | {"uid": None, "role": None}],
                  "expect": {"oracle": kind}}, "poc.schema.json")
    bad = dict(ev, events=[{"oracle": "not-an-oracle", "detail": {}, "stack": []}])
    with pytest.raises(Exception):
        poc.validate(bad, "evidence.schema.json")
