"""Gateway rule for an incident: patcher.derive_rule, schema-checked, with a built-in fallback."""
from __future__ import annotations

from immune_contracts import grammar

from . import openapi, poc as pocmod

RULE_PARAM_IN = ("query", "path", "json", "form", "header")


def _param_schema(spec: dict, method: str, route: str, param: dict) -> dict:
    for m, tpl, op in openapi.operations(spec):
        if m == method and tpl == route:
            for p in op.get("parameters") or []:
                if p.get("name") == param.get("name") and p.get("in") == param.get("in"):
                    return p.get("schema") or {}
    return {}


def default_rule(inc: dict, spec: dict, ttl_s: int = 3600) -> dict:
    """Containment for a confirmed-vulnerable point. IDOR (values are well-formed ids) -> scope all."""
    param = inc.get("param")
    rule = {"id": "rule-%s" % inc["incident"], "incident": inc["incident"], "method": inc["method"],
            "route": inc["route"], "ttl_s": int(ttl_s)}
    if inc.get("vuln_class") == "idor" or not param or param.get("in") not in RULE_PARAM_IN:
        rule.update(scope="all", param=None, grammar=None)
        return rule
    sch = _param_schema(spec, inc["method"], inc["route"], param)
    g = grammar.SAFE_DEFAULT
    if param["in"] == "path" and param["name"] in openapi.catchall_params(inc["route"]):
        g = grammar.PATH_SAFE
    elif sch.get("type") == "integer":
        g = r"[0-9]{1,9}"
    rule.update(scope="param", param={"in": param["in"], "name": param["name"]}, grammar=g)
    return rule


def finalize(rule: dict, inc: dict, spec: dict, ttl_s: int) -> tuple:
    """-> (rule, note). Forces id/incident, validates against rule.schema.json, falls back if invalid."""
    note = ""
    try:
        if not isinstance(rule, dict):
            raise ValueError("not an object")
        rule = dict(rule)
        rule.setdefault("id", "rule-%s" % inc["incident"])
        rule["incident"] = inc["incident"]
        rule.setdefault("ttl_s", int(ttl_s))
        if rule.get("route") != inc["route"] or str(rule.get("method", "")).upper() != inc["method"]:
            raise ValueError("rule targets %s %s, incident is %s %s" % (rule.get("method"), rule.get("route"),
                                                                        inc["method"], inc["route"]))
        pocmod.validate(rule, "rule.schema.json")
        if rule.get("grammar"):
            import re
            re.compile(rule["grammar"])
        return rule, note
    except Exception as e:  # noqa: BLE001
        note = "patcher rule rejected (%s); using the built-in rule" % e
        r = default_rule(inc, spec, ttl_s)
        pocmod.validate(r, "rule.schema.json")
        return r, note
