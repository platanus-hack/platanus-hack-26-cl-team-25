"""Gateway rule for a confirmed-vulnerable point (contracts/schemas/rule.schema.json).

sqli / traversal with a parameter -> scope "param_present": every request that carries
the parameter is detonated in the shadow, whatever the value looks like. The oracle is
the detector; a character whitelist is not (an injection into an unquoted context needs
only letters, digits and spaces: `1 UNION SELECT user,pass FROM users`).
The grammar only breaks the tie when the clone is inconclusive (401/404/5xx, no oracle):
a value inside it goes on to prod, a value outside it is denied. It is the gateway's safe
default, widened only where legitimate values need it:
  * sqli: one apostrophe between two letters (O'Brien, o'neil@mail) is allowed, a
    comment marker "--" never is;
  * length capped by the OpenAPI maxLength of the parameter (else 128).
An x-sensitive parameter is never read by the gateway -> scope "all".
idor / other / no parameter -> scope "all".
No ttl: the rule lives until the patch is deployed and verified, or it is deleted by hand.
"""
from __future__ import annotations

TTL_S = None  # no expiry
RULE_PARAM_IN = ("query", "path", "json", "form", "header")
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
    if param["in"] not in RULE_PARAM_IN:
        return rule  # a location the gateway cannot address (cookie, raw body): cover the whole route
    max_len = (schema or {}).get("maxLength") or 128
    rule.update(param={"in": param["in"], "name": param["name"]}, grammar=build_grammar(vuln_class, max_len),
                scope="param_present")
    return rule
