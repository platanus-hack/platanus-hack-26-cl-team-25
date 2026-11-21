"""Gateway rule for a confirmed-vulnerable point (contracts/schemas/rule.schema.json).

sqli / traversal with a parameter -> scope "param": the grammar is the gateway's safe
default, widened only where legitimate values need it and the attack shape does not:
  * sqli: one apostrophe between two letters (O'Brien, o'neil@mail) is allowed, a
    comment marker "--" never is;
  * length capped by the OpenAPI maxLength of the parameter (else 128).
The captured value must NOT match the grammar (checked); if it would, or the parameter
is x-sensitive / unknown, the rule falls back to scope "all".
idor / other / no parameter -> scope "all".
"""
from __future__ import annotations

import base64
import json
from urllib.parse import parse_qsl

from immune_contracts import grammar as G

TTL_S = 3600
_SAFE_CHARS = r"A-Za-z0-9 _.,@:+\-"  # same set as grammar.SAFE_DEFAULT


def _op(openapi: dict, method: str, route: str) -> dict:
    return (((openapi or {}).get("paths") or {}).get(route) or {}).get((method or "").lower()) or {}


def param_schema(openapi: dict, method: str, route: str, param: dict) -> dict | None:
    op = _op(openapi, method, route)
    where, name = param.get("in"), param.get("name")
    if where in ("query", "path", "header"):
        for p in op.get("parameters") or []:
            if p.get("in") == where and p.get("name") == name:
                s = dict(p.get("schema") or {})
                if p.get("x-sensitive"):
                    s["x-sensitive"] = True
                return s
        return None
    if where in ("json", "form"):
        content = ((op.get("requestBody") or {}).get("content") or {})
        schema = (content.get("application/json") or content.get("application/x-www-form-urlencoded") or {}).get("schema") or {}
        for part in str(name).split("."):
            schema = ((schema or {}).get("properties") or {}).get(part)
            if schema is None:
                return None
        return schema
    return None


def captured_value(incident: dict) -> str | None:
    param = incident.get("param") or {}
    where, name = param.get("in"), param.get("name")
    req = incident.get("request") or (incident.get("evidence") or {}).get("request") or {}
    if where == "query":
        vals = [v for k, v in parse_qsl(req.get("query") or "", keep_blank_values=True) if k == name]
        if vals:
            return vals[-1]
    elif where in ("json", "form"):
        raw = base64.b64decode(req.get("body_b64") or "")
        try:
            obj = json.loads(raw) if where == "json" else dict(parse_qsl(raw.decode(), keep_blank_values=True))
            for part in str(name).split(".") if where == "json" else [name]:
                obj = obj[part]
            if isinstance(obj, str):
                return obj
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            pass
    for e in (incident.get("evidence") or {}).get("events") or []:
        d = e.get("detail") or {}
        if d.get("param") == name and isinstance(d.get("input"), str):
            return d["input"]
    return None


def build_grammar(vuln_class: str, max_len: int) -> str:
    n = max(1, min(int(max_len), 128))
    if vuln_class == "sqli":
        word = f"[{_SAFE_CHARS}]*"
        return rf"(?!.*--)(?=.{{0,{n}}}\Z)(?:{word}[A-Za-z]'(?=[A-Za-z]))?{word}"
    return rf"[{_SAFE_CHARS}]{{0,{n}}}"


def derive_rule(incident: dict, openapi: dict) -> dict:
    inc_id = str(incident.get("incident") or "unknown")
    method = (incident.get("method") or "GET").upper()
    route = incident.get("route") or "/"
    vuln_class = incident.get("vuln_class") or "other"
    param = incident.get("param") or None
    rule = {"id": f"rule-{inc_id}", "incident": inc_id, "method": method, "route": route,
            "param": None, "grammar": None, "scope": "all", "ttl_s": TTL_S}
    if vuln_class not in ("sqli", "traversal") or not param or not param.get("name") or not param.get("in"):
        return rule
    schema = param_schema(openapi, method, route, param)
    if schema is not None and schema.get("x-sensitive"):
        return rule  # never grammar-checked by the gateway: block the whole route
    value = captured_value(incident)
    max_len = (schema or {}).get("maxLength") or 128
    g = build_grammar(vuln_class, max_len)
    if value is None or G.matches(g, value):
        g = G.SAFE_DEFAULT
        if value is None or G.matches(g, value):
            return rule
    assert not G.matches(g, value)
    rule.update(param={"in": param["in"], "name": param["name"]}, grammar=g, scope="param")
    return rule
