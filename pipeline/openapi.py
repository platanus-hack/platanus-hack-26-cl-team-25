"""Minimal OpenAPI helpers: load, resolve $ref, match a concrete path to its template."""
from __future__ import annotations

import re
from urllib.parse import unquote

import yaml

METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def load(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def resolve(spec: dict, node):
    """Recursively inline local $ref pointers (cycles are cut)."""
    def deref(ref: str):
        cur = spec
        for part in ref.lstrip("#/").split("/"):
            cur = cur.get(part, {}) if isinstance(cur, dict) else {}
        return cur

    def walk(n, depth=0):
        if depth > 20:
            return n
        if isinstance(n, dict):
            if "$ref" in n and isinstance(n["$ref"], str) and n["$ref"].startswith("#/"):
                base = dict(deref(n["$ref"]))
                base.update({k: v for k, v in n.items() if k != "$ref"})
                return walk(base, depth + 1)
            return {k: walk(v, depth + 1) for k, v in n.items()}
        if isinstance(n, list):
            return [walk(v, depth + 1) for v in n]
        return n
    return walk(node)


def segments(template: str) -> list:
    return [s for s in template.split("/") if s != ""]


def match(template: str, path: str) -> dict | None:
    """{param: value} if the concrete `path` matches `template`, else None."""
    ts, ps = segments(template), [unquote(s) for s in path.split("?")[0].split("/") if s != ""]
    if len(ts) != len(ps):
        return None
    out = {}
    for t, p in zip(ts, ps):
        m = re.fullmatch(r"\{([^}]+)\}", t)
        if m:
            out[m.group(1)] = p
        elif t != p:
            return None
    return out


def operations(spec: dict):
    """Yield (METHOD, template, operation dict with resolved parameters)."""
    for tpl, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        common = item.get("parameters") or []
        for m in METHODS:
            op = item.get(m)
            if isinstance(op, dict):
                op = resolve(spec, op)
                op["parameters"] = resolve(spec, common) + (op.get("parameters") or [])
                yield m.upper(), tpl, op


def find(spec: dict, method: str, path: str):
    """(template, op, path_params) for a concrete request; static templates win over parametrised ones."""
    best = None
    for m, tpl, op in operations(spec):
        if m != method.upper():
            continue
        pp = match(tpl, path)
        if pp is None:
            continue
        score = sum(1 for s in segments(tpl) if not s.startswith("{"))
        if best is None or score > best[0]:
            best = (score, tpl, op, pp)
    if best is None:
        return None, None, {}
    return best[1], best[2], best[3]


def path_params(template: str) -> list:
    return re.findall(r"\{([^}]+)\}", template)


def fill(template: str, values: dict) -> str:
    return re.sub(r"\{([^}]+)\}", lambda m: str(values.get(m.group(1), m.group(0))), template)


def route_matches(template: str, method: str, step_method: str, step_path: str) -> bool:
    return step_method.upper() == method.upper() and match(template, step_path or "") is not None
