"""Regression case (contracts/schemas/poc.schema.json) and its variants."""
from __future__ import annotations

import json
import os
import re

import jsonschema

from immune_contracts import payloads

from . import reqs
from .config import REPO_ROOT

_SCHEMAS = {}


def schema(name: str) -> dict:
    if name not in _SCHEMAS:
        with open(os.path.join(REPO_ROOT, "contracts", "schemas", name)) as f:
            _SCHEMAS[name] = json.load(f)
    return _SCHEMAS[name]


def validate(obj: dict, name: str) -> None:
    jsonschema.validate(obj, schema(name))


def build(inc: dict, release: str) -> dict:
    ev = inc["evidence"]
    uid = ev.get("uid")
    role = ev.get("role") if uid is not None else None

    def _req(rq):
        return {"method": rq.get("method", "GET"), "path": rq.get("path", "/"), "query": rq.get("query") or "",
                "headers": reqs.clean_headers(rq.get("headers") or {}, drop_auth=uid is not None),
                "body_b64": rq.get("body_b64") or "", "uid": uid, "role": role}

    # multi-step (stored) taint: replay both steps — plant the value, then trigger it. The single-request case
    # (every channel oracle and the reflected effect classes) keeps its one captured request.
    steps = inc.get("steps")
    requests = [_req(s) for s in steps] if steps else [_req(ev.get("request") or {})]
    poc = {"incident": inc["incident"], "release": release, "state_b64": ev.get("pre_state_b64"),
           "requests": requests, "expect": {"oracle": inc["oracle"], "sink": dict(inc["sink"])}}
    validate(poc, "poc.schema.json")
    return poc


# ------------------------------------------------------------------ built-in mutators
def _target(value: str) -> str:
    t = value
    while True:
        t2 = re.sub(r"^(\.{1,}[/\\]+)+", "", t)
        t2 = t2.lstrip("/\\")
        if t2 == t:
            return t
        t = t2


def mutate(inc: dict, poc: dict, manifest: dict | None = None) -> list:
    """[(name, request)] derived from the captured request (same shape as poc.requests items)."""
    param, tpl = inc.get("param"), inc.get("route")
    if not param:
        return []
    # the parameter lives in the planting step for a stored attack, in the only request otherwise
    base = next((r for r in poc["requests"] if reqs.get_value(r, param, tpl) is not None), poc["requests"][-1])
    val = reqs.get_value(base, param, tpl)
    if val is None:
        return []
    val = str(val)
    out = []
    cls = inc.get("vuln_class")
    if cls == "sqli":
        cands = [val + " --", "' OR 1=1 --", "x' OR 'a'='a", "') OR ('a'='a", "%' OR '1'='1",
                 val.replace("'", "\""), val.upper(), "zz' UNION SELECT NULL --"]
    elif cls == "traversal":
        t = _target(val) or "etc/hostname"
        cands = ["/" + t, "../" * 12 + t, "..//" * 8 + t, "./" + val, val.replace("/", "//"),
                 "/etc/passwd", "../" * 12 + "etc/passwd", "....//" * 8 + t]
    elif cls in payloads.BATTERY:                   # input -> effect classes: the same battery the gate replays
        cands = list(payloads.BATTERY[cls])[:8]
    elif cls == "idor":
        cands = []
        for c in (manifest or {}).get("canaries", {}).get(param.get("name"), []):
            cands.append(str(c))
        if val.isdigit():
            cands += [str(int(val) + 1), str(max(1, int(val) - 1))]
    else:
        cands = []
    seen = {val}
    for i, c in enumerate(cands):
        if c in seen:
            continue
        seen.add(c)
        try:
            out.append(("m%d:%s" % (i, c[:40]), reqs.set_value(base, param, c, tpl)))
        except Exception:
            continue
    return out


def normalise_variant(v: dict, base: dict) -> dict | None:
    if not isinstance(v, dict) or not v.get("path"):
        return None
    r = {"method": str(v.get("method") or base["method"]), "path": str(v["path"]), "query": str(v.get("query") or ""),
         "headers": reqs.clean_headers(v.get("headers") or {}, drop_auth=v.get("uid", base.get("uid")) is not None),
         "body_b64": str(v.get("body_b64") or ""), "uid": v.get("uid", base.get("uid")),
         "role": v.get("role", base.get("role"))}
    return r
