"""Request dicts (poc.schema.json `requests` items) and parameter substitution."""
from __future__ import annotations

import base64
import copy
import json
import re
from urllib.parse import parse_qsl, quote, urlencode

from . import openapi

DROP_HEADERS = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "expect", "cookie"}


def body_of(req: dict) -> bytes:
    try:
        return base64.b64decode(req.get("body_b64") or "")
    except Exception:
        return b""


def with_body(req: dict, body: bytes) -> dict:
    r = dict(req)
    r["body_b64"] = base64.b64encode(body).decode()
    return r


def clean_headers(headers: dict, drop_auth: bool = False) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        lk = str(k).lower()
        if lk in DROP_HEADERS or lk.startswith("x-imm-"):
            continue
        if drop_auth and lk == "authorization":
            continue
        out[lk] = str(v)
    return out


def encode_query(pairs) -> str:
    return urlencode(list(pairs), quote_via=quote, safe="")


def _json_path(path: str) -> list:
    keys = []
    for part in path.split("."):
        for m in re.finditer(r"([^\[\]]+)|\[(\d+)\]", part):
            keys.append(m.group(1) if m.group(1) is not None else int(m.group(2)))
    return keys


def get_value(req: dict, param: dict | None, template: str | None = None):
    if not param:
        return None
    loc, name = param.get("in"), param.get("name")
    if loc == "query":
        for k, v in parse_qsl(req.get("query") or "", keep_blank_values=True):
            if k == name:
                return v
        return None
    if loc == "path":
        pp = openapi.match(template, req.get("path") or "") if template else None
        return (pp or {}).get(name)
    if loc == "json":
        try:
            cur = json.loads(body_of(req) or b"null")
            for k in _json_path(name):
                cur = cur[k]
            return cur
        except Exception:
            return None
    if loc == "form":
        for k, v in parse_qsl(body_of(req).decode("utf-8", "replace"), keep_blank_values=True):
            if k == name:
                return v
        return None
    if loc in ("header", "cookie"):
        return {k.lower(): v for k, v in (req.get("headers") or {}).items()}.get(name.lower())
    return None


def set_value(req: dict, param: dict, value, template: str | None = None) -> dict:
    """Copy of `req` with the parameter replaced by `value` (added when absent)."""
    r = copy.deepcopy(req)
    loc, name = param.get("in"), param.get("name")
    sval = value if isinstance(value, str) else str(value)
    if loc == "query":
        pairs = parse_qsl(r.get("query") or "", keep_blank_values=True)
        out, done = [], False
        for k, v in pairs:
            if k == name:
                if not done:
                    out.append((k, sval))
                    done = True
                continue
            out.append((k, v))
        if not done:
            out.append((name, sval))
        r["query"] = encode_query(out)
    elif loc == "path":
        if not template:
            raise ValueError("path parameter needs the route template")
        pp = openapi.match(template, r.get("path") or "") or {}
        pp = {k: quote(v, safe="") for k, v in pp.items()}
        pp[name] = quote(sval, safe="")
        r["path"] = openapi.fill(template, pp)
    elif loc == "json":
        try:
            doc = json.loads(body_of(r) or b"{}")
        except Exception:
            doc = {}
        keys = _json_path(name)
        cur = doc
        for k in keys[:-1]:
            cur = cur[k]
        cur[keys[-1]] = value
        r = with_body(r, json.dumps(doc).encode())
        r.setdefault("headers", {})["content-type"] = "application/json"
    elif loc == "form":
        pairs = parse_qsl(body_of(r).decode("utf-8", "replace"), keep_blank_values=True)
        pairs = [(k, v) for k, v in pairs if k != name] + [(name, sval)]
        r = with_body(r, encode_query(pairs).encode())
        r.setdefault("headers", {})["content-type"] = "application/x-www-form-urlencoded"
    elif loc in ("header", "cookie"):
        r.setdefault("headers", {})[name.lower()] = sval
    else:
        raise ValueError("unsupported parameter location %r" % loc)
    return r
