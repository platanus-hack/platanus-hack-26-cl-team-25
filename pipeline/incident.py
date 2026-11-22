"""oracle.fired evidence -> incident (class, route template, parameter, sink, dedupe key)."""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, quote, unquote

from . import openapi, reqs

CLASS_OF = {"sql": "sqli", "file": "traversal", "owner": "idor"}
PREFERENCE = ("sql", "file", "owner")   # when several oracles fired
ROUTE_MAX, NAME_MAX = 200, 100


def safe_route(path: str) -> str:
    """The route of a request no OpenAPI template matches: its path, made safe to show. It is attacker-chosen
    text that reaches the patch prompt, the pull-request title and the commit message outside any fence, so
    everything but unreserved URL characters is percent-encoded (no control character, newline, space,
    backtick or `{}` placeholder survives) and the result is capped at ROUTE_MAX characters. An ordinary
    path is returned unchanged."""
    out = quote(str(path), safe="/%-._~!$&'()*+,;=:@")
    return out[:ROUTE_MAX] or "/"


def safe_name(name: str) -> str:
    """A parameter name taken from the request (query key, JSON path): control characters dropped, capped."""
    return "".join(ch for ch in str(name) if ch.isprintable())[:NAME_MAX]


def primary_event(evidence: dict) -> dict | None:
    evs = [e for e in (evidence.get("events") or []) if isinstance(e, dict)]
    for kind in PREFERENCE:
        for e in evs:
            if e.get("oracle") == kind:
                return e
    return evs[0] if evs else None


def _inputs(req: dict, template: str | None):
    """[(location, name, decoded value)] like the shadow input extractor (no headers)."""
    out = []
    for k, v in parse_qsl(req.get("query") or "", keep_blank_values=True):
        out.append(("query", k, v))
    if template:
        for k, v in (openapi.match(template, req.get("path") or "") or {}).items():
            out.append(("path", k, v))
    body = reqs.body_of(req)
    if body:
        try:
            doc = json.loads(body)
            stack = [("", doc)]
            while stack:
                pre, node = stack.pop()
                if isinstance(node, dict):
                    stack += [((pre + "." if pre else "") + str(k), v) for k, v in node.items()]
                elif isinstance(node, list):
                    stack += [("%s[%d]" % (pre, i), v) for i, v in enumerate(node)]
                elif isinstance(node, str):
                    out.append(("json", pre, node))
        except Exception:
            for k, v in parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True):
                out.append(("form", k, v))
    return out


def derive_param(kind: str, event: dict, req: dict, template: str | None, manifest: dict | None) -> dict | None:
    detail = event.get("detail") or {}
    if kind == "sql" and detail.get("param"):
        loc = detail.get("location") or "query"
        return {"in": loc, "name": str(detail["param"])}
    if kind == "file":
        target = str(detail.get("path") or "")
        best = None
        for loc, name, val in _inputs(req, template):
            if len(val) >= 2 and (val in target or unquote(val) in target):
                if best is None or len(val) > len(best[2]):
                    best = (loc, name, val)
        if best is None:
            # the app may normalise before opening (Node's path.join turns ../../etc/hostname into
            # /etc/hostname): match the input with its leading ./ ../ / stripped as a suffix of the opened path
            for loc, name, val in _inputs(req, template):
                tail = re.sub(r"^(?:\.{1,2}[/\\]+|[/\\]+)+", "", unquote(val)).replace("\\", "/")
                if len(tail) >= 2 and tail != unquote(val) and (target == "/" + tail or target.endswith("/" + tail)):
                    if best is None or len(tail) > len(best[2]):
                        best = (loc, name, tail)
        if best:
            return {"in": best[0], "name": best[1]}
    if kind in ("owner", "file", "sql"):
        pps = openapi.path_params(template or "")
        if pps:
            canaries = (manifest or {}).get("canaries") or {}
            pick = [p for p in pps if p in canaries] or pps
            return {"in": "path", "name": pick[-1]}
        for loc, name, val in _inputs(req, template):
            if loc == "query" and val.isdigit():
                return {"in": "query", "name": name}
    return None


def dedupe_key(kind: str, method: str, route: str, param: dict | None) -> str:
    p = "%s:%s" % (param.get("in"), param.get("name")) if param else "-"
    return "|".join([kind, method.upper(), route, p])


def build(event: dict, spec: dict, manifest: dict | None = None) -> dict:
    """Incident skeleton (without id/poc) from one oracle.fired bus event."""
    ev = event.get("data") or {}
    prim = primary_event(ev)
    if prim is None:
        raise ValueError("evidence without oracle events")
    kind = prim.get("oracle")
    rq = ev.get("request") or {}
    method = re.sub(r"[^A-Z-]", "", str(rq.get("method") or "GET").upper())[:16] or "GET"
    path = str(rq.get("path") or "/")
    template, _op, _pp = openapi.find(spec, method, path)
    route = template or safe_route(path)
    req = {"method": method, "path": path, "query": rq.get("query") or "", "body_b64": rq.get("body_b64") or "",
           "headers": rq.get("headers") or {}}
    param = derive_param(kind, prim, req, template, manifest)
    if param:
        param["name"] = safe_name(param["name"])
    stack = prim.get("stack") or []
    sink = {"file": stack[-1]["file"], "line": int(stack[-1]["line"])} if stack else {"file": "", "line": 0}
    return {
        "vuln_class": CLASS_OF.get(kind, "other"),
        "oracle": kind,
        # missing-authentication (CWE-306): the owner oracle fired for a caller with no established identity.
        # Distinct from classic IDOR, where the attacker is authenticated but reaches another owner's resource.
        "anon": kind == "owner" and ev.get("uid") is None,
        "method": method,
        "route": route,
        "param": param,
        "sink": sink,
        "evidence_rid": ev.get("rid") or event.get("rid"),
        "request": {"method": method, "path": path, "query": req["query"], "body_b64": req["body_b64"]},
        "evidence": ev,
        "key": dedupe_key(kind, method, route, param),
        "first_seen": float(event.get("ts") or 0) or None,
    }


def public(inc: dict) -> dict:
    """The incident dict handed to the patcher (contracts/interfaces.md)."""
    keys = ("incident", "vuln_class", "anon", "method", "route", "param", "sink", "evidence_rid", "request", "evidence", "poc")
    return {k: inc.get(k) for k in keys}
