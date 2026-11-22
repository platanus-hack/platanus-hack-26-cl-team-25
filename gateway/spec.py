"""OpenAPI loading, operation matching and per-value schema checks.

Only the subset of OpenAPI 3.0 the project uses: local `$ref`, path templates,
query/path/header parameters, JSON and form request bodies, `x-owner-scoped`
and `x-sensitive`.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

import yaml

METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def _resolve(node, root, seen=()):
    """Inline local $refs (cycle-safe)."""
    if isinstance(node, dict):
        if "$ref" in node and isinstance(node["$ref"], str) and node["$ref"].startswith("#/"):
            ref = node["$ref"]
            if ref in seen:
                return {}
            target = root
            for part in ref[2:].split("/"):
                target = target.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(target, dict) else {}
            merged = dict(_resolve(target, root, seen + (ref,)))
            for k, v in node.items():
                if k != "$ref":
                    merged[k] = _resolve(v, root, seen)
            return merged
        return {k: _resolve(v, root, seen) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve(v, root, seen) for v in node]
    return node


def split_template(template: str) -> list:
    """'/a/{x}/b' -> ['a', ('x',), 'b'] (tuples are parameters)."""
    out = []
    for seg in template.strip("/").split("/") if template.strip("/") else []:
        m = re.fullmatch(r"\{([^}*]+)(\*?)\}", seg)
        out.append(((m.group(1), "*") if m.group(2) else (m.group(1),)) if m else seg)
    return out


def is_catchall(seg) -> bool:
    return isinstance(seg, tuple) and len(seg) > 1


def _match_parts(segments: list, parts: list) -> dict | None:
    """Match already-decoded path segments against template segments."""
    if segments and is_catchall(segments[-1]):          # {name*}: one or more trailing segments
        n = len(segments) - 1
        if len(parts) <= n:
            return None
        rest = parts[n:]
        if any(p == "" for p in rest):
            return None
        parts = parts[:n] + ["/".join(rest)]
    if len(parts) != len(segments):
        return None
    params = {}
    for seg, part in zip(segments, parts):
        if isinstance(seg, tuple):
            if part == "":
                return None
            params[seg[0]] = part
        elif part != seg:
            return None
    return params


def _split(path: str) -> list:
    return path.strip("/").split("/") if path.strip("/") else []


def path_readings(raw_path: str) -> list:
    """The segment lists an upstream server may route a raw (percent-encoded) path on.

    First the reference one: decode once, then split (uvicorn unquotes the whole path before starlette
    routes, so '%2F' IS a separator and '%252F' is the literal text '%2F'). Then, only when it differs,
    split first and decode each segment (servers that route on the raw path, e.g. Express, where '%2F'
    stays inside one parameter). They differ only when the path carries an encoded slash.
    """
    decoded = _split(unquote(raw_path))
    raw = [unquote(p) for p in _split(raw_path)]
    return [decoded] if raw == decoded else [decoded, raw]


def match_template(segments: list, raw_path: str) -> dict | None:
    """Match a raw (percent-encoded) path against template segments. Returns decoded path params.

    A path matches if ANY reading an upstream may route on matches (see path_readings), the reference
    reading first: a gateway that splits before decoding lets '/api%2Fproducts' pass as an unknown route
    while the app serves '/api/products'.
    """
    for parts in path_readings(raw_path):
        params = _match_parts(segments, parts)
        if params is not None:
            return params
    return None


@dataclass
class Operation:
    method: str
    template: str
    segments: list
    params: dict = field(default_factory=dict)   # (in, name) -> parameter dict (schema resolved)
    json_schema: dict | None = None
    form_schema: dict | None = None
    owner_scoped: bool = False
    high_risk: bool = False      # x-high-risk: always verify in the shadow (e.g. a process/script execution endpoint)

    @property
    def literal_count(self) -> int:
        return sum(1 for s in self.segments if not isinstance(s, tuple))


class Spec:
    def __init__(self, doc: dict | None):
        doc = _resolve(doc or {}, doc or {})
        self.ops: list[Operation] = []
        for template, item in (doc.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            common = item.get("parameters") or []
            for method in METHODS:
                op = item.get(method)
                if not isinstance(op, dict):
                    continue
                o = Operation(method=method.upper(), template=template, segments=split_template(template),
                              owner_scoped=bool(op.get("x-owner-scoped")), high_risk=bool(op.get("x-high-risk")))
                for p in list(common) + list(op.get("parameters") or []):
                    if isinstance(p, dict) and "name" in p and "in" in p:
                        o.params[(p["in"], p["name"])] = p
                content = ((op.get("requestBody") or {}).get("content") or {})
                for ctype, media in content.items():
                    schema = (media or {}).get("schema") or {}
                    if "json" in ctype:
                        o.json_schema = schema
                    elif "form" in ctype:
                        o.form_schema = schema
                self.ops.append(o)
        # most specific first: more literal segments win over templates
        self.ops.sort(key=lambda o: -o.literal_count)

    @classmethod
    def load(cls, path: str | None) -> "Spec":
        if not path:
            return cls(None)
        try:
            with open(path) as f:
                return cls(yaml.safe_load(f))
        except FileNotFoundError:
            return cls(None)

    def match(self, method: str, raw_path: str) -> tuple[Operation | None, dict]:
        return next((m for m in self.match_readings(method, raw_path) if m is not None), (None, {}))

    def match_readings(self, method: str, raw_path: str) -> list:
        """One entry per reading of the path (see path_readings), the reference reading first: the
        (operation, params) it routes to, or None. Entries that differ mean gateway and upstream could
        disagree on the route; the classifier flags that."""
        method = "GET" if method.upper() == "HEAD" else method.upper()
        out = []
        for parts in path_readings(raw_path):
            hit = None
            for op in self.ops:
                if op.method == method:
                    params = _match_parts(op.segments, parts)
                    if params is not None:
                        hit = (op, params)
                        break
            out.append(hit)
        return out


# ---------------------------------------------------------------- value checks

INT_RE = re.compile(r"[+-]?\d{1,18}")


def _bounds(num: float, schema: dict) -> bool:
    if "minimum" in schema and num < schema["minimum"]:
        return False
    if "maximum" in schema and num > schema["maximum"]:
        return False
    if schema.get("exclusiveMinimum") is True and "minimum" in schema and num <= schema["minimum"]:
        return False
    if schema.get("exclusiveMaximum") is True and "maximum" in schema and num >= schema["maximum"]:
        return False
    return True


def check_string_value(value: str, schema: dict | None) -> str | None:
    """Check a decoded textual value (query/path/form/header) against its schema.

    Returns None if valid, else a short failure kind ('type', 'enum', 'bounds', 'length', 'pattern').
    The safe-default grammar is applied separately by the classifier.
    """
    schema = schema or {}
    typ = schema.get("type")
    if typ == "array":
        return check_string_value(value, schema.get("items") or {})
    if "enum" in schema and value not in [str(e) if not isinstance(e, bool) else str(e).lower() for e in schema["enum"]]:
        return "enum"
    if typ == "integer":
        if not INT_RE.fullmatch(value):
            return "type"
        return None if _bounds(int(value), schema) else "bounds"
    if typ == "number":
        try:
            num = float(value)
        except ValueError:
            return "type"
        if not math.isfinite(num):
            return "type"
        return None if _bounds(num, schema) else "bounds"
    if typ == "boolean":
        return None if value in ("true", "false") else "type"
    if "maxLength" in schema and len(value) > schema["maxLength"]:
        return "length"
    if "minLength" in schema and len(value) < schema["minLength"]:
        return "length"
    if "pattern" in schema:
        try:
            if not re.search(schema["pattern"], value):
                return "pattern"
        except re.error:
            pass
    return None


def check_json_value(value, schema: dict | None) -> str | None:
    """Check a typed JSON scalar against its schema (no grammar)."""
    schema = schema or {}
    typ = schema.get("type")
    if "enum" in schema and value not in schema["enum"]:
        return "enum"
    if isinstance(value, bool):
        return "type" if typ in ("integer", "number", "string", "object", "array") else None
    if isinstance(value, int):
        if typ in ("string", "boolean", "object", "array"):
            return "type"
        return None if _bounds(value, schema) else "bounds"
    if isinstance(value, float):
        if typ in ("integer", "string", "boolean", "object", "array") or not math.isfinite(value):
            return "type"
        return None if _bounds(value, schema) else "bounds"
    if isinstance(value, str):
        if typ in ("integer", "number", "boolean", "object", "array"):
            return "type"
        return check_string_value(value, {k: v for k, v in schema.items() if k != "enum"})
    return None  # null is accepted: the app validates required-ness, nothing to inject
