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


def default_rule(inc: dict, spec: dict, ttl_s: int | None = None) -> dict:
    """Containment for a confirmed-vulnerable point: detonate every request that carries the parameter
    (the grammar only decides an inconclusive clone). IDOR or no addressable parameter -> the whole route.
    ttl_s None: the rule lives until the patch is verified."""
    param = inc.get("param")
    rule = {"id": "rule-%s" % inc["incident"], "incident": inc["incident"], "method": inc["method"],
            "route": inc["route"], "ttl_s": int(ttl_s) if ttl_s else None}
    if inc.get("vuln_class") == "idor" or not param or param.get("in") not in RULE_PARAM_IN:
        rule.update(scope="all", param=None, grammar=None)
        # missing-authentication (CWE-306): contain anonymous callers only, so authenticated traffic is untouched.
        if inc.get("anon"):
            rule["identity"] = "untrusted"
        return rule
    sch = _param_schema(spec, inc["method"], inc["route"], param)
    g = grammar.SAFE_DEFAULT
    if param["in"] == "path" and param["name"] in openapi.catchall_params(inc["route"]):
        g = grammar.PATH_SAFE
    elif sch.get("type") == "integer":
        g = r"[0-9]{1,9}"
    rule.update(scope="param_present", param={"in": param["in"], "name": param["name"]}, grammar=g)
    return rule


def finalize(rule: dict, inc: dict, spec: dict, ttl_s: int | None) -> tuple:
    """-> (rule, note). Forces `incident`, defaults `id`, gives `ttl_s` to a rule that has none, requires the incident's method and route,
    validates against rule.schema.json, falls back to default_rule if invalid."""
    note = ""
    try:
        if not isinstance(rule, dict):
            raise ValueError("not an object")
        rule = dict(rule)
        rule.setdefault("id", "rule-%s" % inc["incident"])
        rule["incident"] = inc["incident"]
        if rule.get("ttl_s") is None:      # the operator's PIPELINE_RULE_TTL_S applies to every rule without its own
            rule["ttl_s"] = int(ttl_s) if ttl_s else None
        if rule.get("route") != inc["route"] or str(rule.get("method", "")).upper() != inc["method"]:
            raise ValueError("rule targets %s %s, incident is %s %s" % (rule.get("method"), rule.get("route"),
                                                                        inc["method"], inc["route"]))
        # missing-authentication (CWE-306): a whole-route rule should contain anonymous callers only, so
        # authenticated traffic to a legitimately public-but-must-authenticate endpoint keeps flowing.
        if inc.get("anon") and rule.get("scope") == "all" and not rule.get("identity"):
            rule["identity"] = "untrusted"
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
