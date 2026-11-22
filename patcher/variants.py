"""Deterministic regression requests derived from the captured request (no LLM).

Each variant exercises the SAME parameter as the PoC with another payload, encoding or
form typical of the class, so a fix that only handles the exact captured value is caught.
Validation counts only the variants that fire the oracle on the unpatched code, so
including a few that do not is harmless. Every variant differs from the captured request and
from every other variant; a request with no parameter to mutate yields no variants (there is
no minimum: copies of the PoC would be counted as if they were distinct cases).
"""
from __future__ import annotations

import base64
import copy
import json
import re
from urllib.parse import parse_qsl, quote, unquote

from immune_contracts import classes as _classes
from immune_contracts import payloads as _payloads

MAX_VARIANTS = 40

_ORACLE_CLASS = _classes.CLASS_OF


# ---------------------------------------------------------------- locating the parameter
def _base_request(poc: dict, evidence: dict) -> dict:
    reqs = (poc or {}).get("requests") or []
    if reqs:
        return copy.deepcopy(reqs[-1])
    r = copy.deepcopy((evidence or {}).get("request") or {})
    r.setdefault("uid", (evidence or {}).get("uid"))
    r.setdefault("role", (evidence or {}).get("role"))
    return r


def _oracle(poc: dict, evidence: dict) -> str:
    o = ((poc or {}).get("expect") or {}).get("oracle")
    if o:
        return o
    evs = (evidence or {}).get("events") or []
    return evs[0].get("oracle", "") if evs else ""


def _qs_pairs(query: str) -> list[tuple[str, str]]:
    return parse_qsl(query or "", keep_blank_values=True)


def _body_json(req: dict):
    raw = base64.b64decode(req.get("body_b64") or "")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _json_get(obj, dotted: str):
    for part in dotted.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return None
        obj = obj[part]
    return obj


def _json_leaves(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _json_leaves(v, f"{prefix}{k}" if not prefix else f"{prefix}.{k}")
    elif isinstance(obj, str):
        yield prefix, obj


def locate(poc: dict, evidence: dict) -> tuple[str, str, str]:
    """-> (location, name, captured value). location in query|json|path."""
    req = _base_request(poc, evidence)
    events = (evidence or {}).get("events") or []
    pairs = _qs_pairs(req.get("query", ""))
    body = _body_json(req)
    for e in events:
        d = e.get("detail") or {}
        if e.get("oracle") == "sql" and d.get("param"):
            loc, name = d.get("location") or "query", d["param"]
            if loc == "query":
                vals = [v for k, v in pairs if k == name]
                if vals:
                    return "query", name, vals[-1]
            if loc == "json" and body is not None:
                v = _json_get(body, name)
                if isinstance(v, str):
                    return "json", name, v
            if d.get("input"):
                return loc, name, d["input"]
    for e in events:
        d = e.get("detail") or {}
        if e.get("oracle") == "file":
            target = d.get("path") or d.get("realpath") or ""
            cands = [(k, v) for k, v in pairs if v and target.endswith(v)]
            if cands:
                k, v = max(cands, key=lambda kv: len(kv[1]))
                return "query", k, v
            if body is not None:
                for k, v in _json_leaves(body):
                    if v and target.endswith(v):
                        return "json", k, v
    # input -> effect classes (shadow/effects.py): the oracle names the input that reached the effect
    for e in events:
        d = e.get("detail") or {}
        if e.get("oracle") in _classes.EFFECT_CLASSES and d.get("param"):
            loc, name = d.get("location") or "query", d["param"]
            if loc == "query":
                vals = [v for k, v in pairs if k == name]
                if vals:
                    return "query", name, vals[-1]
            if loc == "json" and body is not None:
                v = _json_get(body, name)
                if isinstance(v, str):
                    return "json", name, v
    # owner / fallback: last numeric path segment
    segs = req.get("path", "").split("/")
    for i in range(len(segs) - 1, -1, -1):
        if segs[i].isdigit():
            return "path", str(i), segs[i]
    if pairs:
        return "query", pairs[-1][0], pairs[-1][1]
    return "path", "", ""


# ---------------------------------------------------------------- building requests
def _with_query_value(req: dict, name: str, raw_value: str, extra_before: str | None = None) -> dict:
    """raw_value is already wire-encoded."""
    out = copy.deepcopy(req)
    parts, done = [], False
    for piece in (req.get("query") or "").split("&"):
        if not piece:
            continue
        k = unquote(piece.split("=", 1)[0].replace("+", " "))
        if k == name and not done:
            if extra_before is not None:
                parts.append(f"{quote(name, safe='')}={extra_before}")
            parts.append(f"{quote(name, safe='')}={raw_value}")
            done = True
        elif k != name:
            parts.append(piece)
    if not done:
        parts.append(f"{quote(name, safe='')}={raw_value}")
    out["query"] = "&".join(parts)
    return out


def _with_json_value(req: dict, dotted: str, value: str, ascii_escape: bool = False) -> dict:
    out = copy.deepcopy(req)
    body = _body_json(req) or {}
    obj = body
    keys = dotted.split(".")
    for k in keys[:-1]:
        obj = obj.setdefault(k, {})
    obj[keys[-1]] = value
    text = json.dumps(body, ensure_ascii=True)
    if ascii_escape:
        text = text.replace("'", "\\u0027").replace("/", "\\/")
    raw = text.encode()
    out["body_b64"] = base64.b64encode(raw).decode()
    hdrs = dict(out.get("headers") or {})
    for h in list(hdrs):
        if h.lower() == "content-length":
            hdrs[h] = str(len(raw))
    out["headers"] = hdrs
    return out


def _with_path_segment(req: dict, index: int, value: str) -> dict:
    out = copy.deepcopy(req)
    segs = req["path"].split("/")
    segs[index] = value
    out["path"] = "/".join(segs)
    return out


# ---------------------------------------------------------------- payload families
def _sqli_payloads(v: str) -> list[str]:
    prefix = v.split("'", 1)[0] if "'" in v else v
    prefix = prefix[:40] or "a"
    p = [
        v.replace(" OR ", " or ").replace(" AND ", " and "),
        v.replace(" ", "  "),
        v.replace(" ", "/**/"),
        v.replace(" ", "\t"),
        v.replace(" ", "\n"),
        v.upper(),
        f"{prefix}' OR 'x'='x",
        f"{prefix}' OR 1=1 OR '",
        f"{prefix}' OR 2>1 OR '",
        f"{prefix}'OR'1'='1",
        f"{prefix}'||'",
        f"{prefix}' AND 1=1 AND 'a'='a",
        f"{prefix}' --",
        f"{prefix}'--",
        f"{prefix}' -- x",
        f"{prefix}'/*",
        f"{prefix}') OR ('1'='1",
        f"{prefix}' OR 1=1) --",
        "' OR ''='",
        "' OR 1=1 --",
        "x' OR 'x'='x",
        "nothing' OR 'b'='b",
        f"{prefix}' UNION SELECT 1 --",
        f"{prefix}' OR role='admin' --",
        "%' OR 1=1 OR '%'='",
        f"{prefix}\" OR \"1\"=\"1",
    ]
    return p


def _traversal_payloads(v: str) -> list[str]:
    target = v.replace("\\", "/").lstrip("./")
    m = re.search(r"((?:\.\./)+)(.*)$", v)
    if m:
        target = m.group(2)
    target = target or "etc/hostname"
    p = []
    for depth in (3, 4, 5, 6, 7, 9, 12):
        p.append("../" * depth + target)
    for t in ("etc/passwd", "etc/hosts", "etc/os-release"):
        p.append("../" * 8 + t)
    p += [
        "/" + target,
        "//" + target,
        "/./" + target,
        "/" + target.replace("/", "//"),
        "./" + "../" * 8 + target,
        "../manuals/" + "../" * 8 + target,
        "../images/" + "../" * 8 + target,
        "x/../" + "../" * 8 + target,
        ".././" * 8 + target,
        "../" * 8 + "./" + target,
    ]
    return p


def _traversal_encodings(v: str) -> list[str]:
    """Wire encodings of the captured value (query string)."""
    return [
        quote(v, safe=""),
        v.replace("/", "%2f"),
        v.replace("/", "%2F"),
        v.replace(".", "%2e"),
        v.replace("../", "%2e%2e%2f"),
        v.replace("../", "..%2f"),
    ]


def _sqli_encodings(v: str) -> list[str]:
    return [
        quote(v, safe=""),
        quote(v, safe="").replace("%20", "+"),
        v.replace("'", "%27").replace(" ", "%20"),
        quote(v, safe="'=").replace("%20", "+"),
    ]


def _key(r: dict) -> str:
    return json.dumps([r.get("method"), r.get("path"), r.get("query"), r.get("body_b64"), r.get("uid"), r.get("role")],
                      sort_keys=True)


def _dedupe(reqs: list[dict], seen: set | None = None) -> list[dict]:
    """Distinct requests, in order; `seen`: keys that are already taken (the captured request)."""
    seen, out = set(seen or ()), []
    for r in reqs:
        if _key(r) not in seen:
            seen.add(_key(r))
            out.append(r)
    return out


def variants(poc: dict, evidence: dict) -> list[dict]:
    base = _base_request(poc, evidence)
    base.setdefault("headers", {})
    base.setdefault("body_b64", "")
    base.setdefault("query", "")
    oracle = _oracle(poc, evidence)
    loc, name, value = locate(poc, evidence)
    out: list[dict] = []

    if oracle in ("sql", "file") and name and loc in ("query", "json"):
        payloads = _sqli_payloads(value) if oracle == "sql" else _traversal_payloads(value)
        if loc == "query":
            out += [_with_query_value(base, name, quote(p, safe="")) for p in payloads]
            encs = _sqli_encodings(value) if oracle == "sql" else _traversal_encodings(value)
            out += [_with_query_value(base, name, e) for e in encs]
            # duplicated parameter: benign value first, payload last (frameworks take the last)
            out.append(_with_query_value(base, name, quote(value, safe=""), extra_before="usb"))
        else:
            out += [_with_json_value(base, name, p) for p in payloads]
            out += [_with_json_value(base, name, value, ascii_escape=True),
                    _with_json_value(base, name, payloads[0], ascii_escape=True)]
    elif oracle in _classes.EFFECT_CLASSES and name and loc in ("query", "json"):
        battery = _payloads.BATTERY[oracle]
        if loc == "query":
            out += [_with_query_value(base, name, quote(p, safe="")) for p in battery]
            out.append(_with_query_value(base, name, quote(value, safe=""), extra_before=_payloads.BENIGN[oracle]))
        else:
            out += [_with_json_value(base, name, p) for p in battery]
            out.append(_with_json_value(base, name, battery[0], ascii_escape=True))
    elif oracle == "sql" and loc == "path" and name.isdigit():
        out += [_with_path_segment(base, int(name), quote(p, safe="")) for p in _sqli_payloads(value)]
    else:
        # idor / owner / other: same route, other object ids, other id spellings, other requesters
        if loc == "path" and name.isdigit():
            idx, cur = int(name), int(value)
            ids = [i for i in range(1, 25) if i != cur][:18] + [cur + 1, cur + 7, cur * 2 + 1]
            out += [_with_path_segment(base, idx, str(i)) for i in ids]
            out += [_with_path_segment(base, idx, s) for s in ("0" + value, "00" + value, "+" + value)]
            uid = base.get("uid")
            for other in ([uid + 1, uid + 2, uid + 40] if isinstance(uid, int) else []) + [2, 3]:
                r = copy.deepcopy(base)
                r["uid"] = other
                r["role"] = "user"
                for h in list(r["headers"]):
                    if h.lower() == "authorization":
                        del r["headers"][h]  # the runner mints a token for `uid`
                out.append(r)

    return _dedupe(out, {_key(base)})[:MAX_VARIANTS]
