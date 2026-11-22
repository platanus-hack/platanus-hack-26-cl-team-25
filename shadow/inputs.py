"""Extract the attacker-controlled input values of one request."""
from __future__ import annotations

import json
from email.parser import BytesParser
from email.policy import HTTP
from urllib.parse import parse_qsl, unquote

MIN_LEN = 2
# Header values the client does not meaningfully control or that are pure transport noise.
_SKIP_HEADERS = {"host", "content-length", "connection", "accept-encoding", "content-type", "accept",
                 "transfer-encoding", "expect"}


def _ok(v) -> bool:
    return isinstance(v, str) and len(v) >= MIN_LEN and v.strip() != ""


def _json_leaves(obj, prefix, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            _json_leaves(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _json_leaves(v, f"{prefix}[{i}]", out)
    elif isinstance(obj, str):
        out.append(("json", prefix or "body", obj))


def extract(path: str, query: str, headers: dict, body: bytes, path_params: dict | None = None) -> list:
    """[(location, param, value)], de-duplicated, values of length >= 2."""
    out = []
    for k, v in parse_qsl(query or "", keep_blank_values=True):
        out.append(("query", k, v))
        out.append(("query", k, k))  # parameter names can be injected too (e.g. dynamic columns)
    # path segments, named after the route parameter when the router told us
    by_value = {}
    for name, val in (path_params or {}).items():
        by_value.setdefault(str(val), name)
    for i, seg in enumerate(p for p in (path or "").split("/") if p):
        seg = unquote(seg) if "%" in seg else seg
        out.append(("path", by_value.get(seg, f"path[{i}]"), seg))
    for name, val in (path_params or {}).items():
        if isinstance(val, str):
            out.append(("path", name, val))
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    ctype_raw = lower.get("content-type", "")   # as sent: the multipart boundary is case-sensitive
    ctype = ctype_raw.lower()                   # for the type tests only
    if body:
        if "json" in ctype or (not ctype and body[:1] in (b"{", b"[")):
            try:
                _json_leaves(json.loads(body), "", out)
            except Exception:
                out.append(("body", "body", body.decode("utf-8", "replace")))
        elif "x-www-form-urlencoded" in ctype:
            for k, v in parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True):
                out.append(("form", k, v))
        elif "multipart/form-data" in ctype:
            try:
                msg = BytesParser(policy=HTTP).parsebytes(b"content-type: " + ctype_raw.encode() + b"\r\n\r\n" + body)
                for part in msg.iter_parts():
                    name = part.get_param("name", header="content-disposition") or "part"
                    if part.get_filename():
                        out.append(("form", name, part.get_filename()))
                    payload = part.get_payload(decode=True) or b""
                    if len(payload) < 4096:
                        out.append(("form", name, payload.decode("utf-8", "replace")))
            except Exception:
                pass
        else:
            text = body.decode("utf-8", "replace")
            if len(text) < 4096:
                out.append(("body", "body", text))
    for k, v in lower.items():
        if k in _SKIP_HEADERS or k.startswith("x-imm-"):
            continue
        if k == "authorization" and v.lower().startswith("bearer "):
            v = v[7:]
        if k == "cookie":
            for part in v.split(";"):
                if "=" in part:
                    ck, cv = part.split("=", 1)
                    out.append(("cookie", ck.strip(), cv.strip()))
            continue
        out.append(("header", k, v))
    seen = set()
    result = []
    for loc, param, val in out:
        if not _ok(val) or (loc, param, val) in seen:
            continue
        seen.add((loc, param, val))
        result.append((loc, param, val))
    return result
