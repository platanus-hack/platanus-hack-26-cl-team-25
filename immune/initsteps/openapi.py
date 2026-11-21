"""Step 2 (OpenAPI dump) and the mechanical half of step 6 (applying x-owner-scoped / x-sensitive)."""
from __future__ import annotations

import copy
import json
import os
import re

import yaml

from . import docker, sandbox
from .detect import walk

METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
SPEC_NAMES = ("openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.json")


def _dummy_env(det: dict, db: str) -> dict:
    env = {}
    if det.get("db_env"):
        env[det["db_env"]] = db
    for s in det.get("secret_envs") or []:
        env[s] = "immune-init-dummy"
    return env


def dump(project: str, det: dict) -> tuple[dict | None, str]:
    """(openapi document, how it was obtained). FastAPI: imported in a --network none container
    (falls back to a clean host subprocess when Docker is unavailable); otherwise a spec file."""
    project = os.path.realpath(project)
    errors = []
    if det.get("framework") == "fastapi" and det.get("asgi"):
        ok, why = docker.available()
        job = json.dumps({"op": "openapi", "asgi": det["asgi"]})
        if ok:
            env = dict(_dummy_env(det, "/tmp/immune-init.db"), PYTHONDONTWRITEBYTECODE="1")
            rc, out, err = docker.run([(project, "/app", "ro"), docker.HOME_MOUNT],
                                      docker.boot("immune.initsteps.probe", ["/app", "/app/.immune", "/opt/immune"]),
                                      env=env, stdin=job, timeout=180)
            res = docker.last_json(out)
            if res and res.get("ok"):
                return res["openapi"], "app.openapi() of %s in a --network none container" % det["asgi"]
            errors.append("container: %s" % ((res or {}).get("error") or (err or out)[-400:]))
        else:
            errors.append("docker: %s" % why)
        env = sandbox.base_env(_dummy_env(det, os.path.join(project, ".immune", "tmp-openapi.db")))
        res = sandbox.run_module("immune.initsteps.probe", {"op": "openapi", "asgi": det["asgi"]},
                                 sandbox.roots_for(project), env)
        try:
            os.remove(os.path.join(project, ".immune", "tmp-openapi.db"))
        except OSError:
            pass
        if res.get("ok"):
            return res["openapi"], "app.openapi() of %s in a host subprocess (%s)" % (det["asgi"], "; ".join(errors))
        errors.append("subprocess: %s" % res.get("error"))
    for path in walk(project, exts=(".yaml", ".yml", ".json")):
        if os.path.basename(path).lower() in SPEC_NAMES:
            try:
                with open(path) as f:
                    doc = yaml.safe_load(f)
                if isinstance(doc, dict) and (doc.get("openapi") or doc.get("swagger")) and doc.get("paths"):
                    return doc, "spec file %s" % os.path.relpath(path, project)
            except Exception as e:  # noqa: BLE001
                errors.append("%s: %s" % (path, e))
    return None, "; ".join(errors) or "no OpenAPI source found"


def operations(doc: dict) -> list[dict]:
    out = []
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        common = item.get("parameters") or []
        for m in METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            params = [p for p in list(common) + list(op.get("parameters") or []) if isinstance(p, dict)]
            out.append({"key": "%s %s" % (m.upper(), path), "method": m.upper(), "path": path, "op": op,
                        "params": params, "path_params": re.findall(r"\{([^}]+)\}", path)})
    return out


def body_properties(doc: dict, op: dict) -> dict:
    """{property name: (schema dict to mark, where)} of the JSON/form body (one level, $ref resolved)."""
    out = {}
    content = ((op.get("requestBody") or {}).get("content") or {})
    for ctype, media in content.items():
        schema = (media or {}).get("schema") or {}
        schema = _deref(doc, schema)
        for name, prop in (schema.get("properties") or {}).items():
            out[name] = prop
    return out


def _deref(doc, node, depth=0):
    while isinstance(node, dict) and "$ref" in node and depth < 10:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return {}
        t = doc
        for part in ref[2:].split("/"):
            t = t.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(t, dict) else {}
        node, depth = t, depth + 1
    return node if isinstance(node, dict) else {}


def validate_marks(marks, doc: dict) -> list[str]:
    errs = []
    if not isinstance(marks, dict):
        return ["marks.yaml: top level must be a mapping with owner_scoped and sensitive lists"]
    ops = {o["key"]: o for o in operations(doc)}
    for i, e in enumerate(marks.get("owner_scoped") or []):
        key = e.get("op") if isinstance(e, dict) else e
        if key not in ops:
            errs.append("owner_scoped[%d]: operation %r is not in the OpenAPI (operations look like 'GET /path/{id}')"
                        % (i, key))
    for i, e in enumerate(marks.get("sensitive") or []):
        if not isinstance(e, dict):
            errs.append("sensitive[%d]: must be a mapping {op, in, name, why}" % i)
            continue
        key, where, name = e.get("op"), e.get("in"), e.get("name")
        if key not in ops:
            errs.append("sensitive[%d]: operation %r is not in the OpenAPI" % (i, key))
            continue
        if where == "body":
            if name not in body_properties(doc, ops[key]["op"]):
                errs.append("sensitive[%d]: %s has no body property %r" % (i, key, name))
        elif where in ("query", "path", "header", "cookie"):
            if not any(p.get("name") == name and p.get("in") == where for p in ops[key]["params"]):
                errs.append("sensitive[%d]: %s has no %s parameter %r" % (i, key, where, name))
        else:
            errs.append("sensitive[%d]: 'in' must be one of query|path|header|cookie|body (got %r)" % (i, where))
    return errs


def apply_marks(doc: dict, marks: dict) -> dict:
    """Return a copy of ``doc`` with x-owner-scoped on operations and x-sensitive on params/properties."""
    doc = copy.deepcopy(doc)
    ops = {o["key"]: o for o in operations(doc)}
    for e in marks.get("owner_scoped") or []:
        key = e.get("op") if isinstance(e, dict) else e
        if key in ops:
            ops[key]["op"]["x-owner-scoped"] = True
    for e in marks.get("sensitive") or []:
        key, where, name = e.get("op"), e.get("in"), e.get("name")
        if key not in ops:
            continue
        if where == "body":
            prop = body_properties(doc, ops[key]["op"]).get(name)
            if isinstance(prop, dict):
                prop["x-sensitive"] = True
        else:
            for p in ops[key]["params"]:
                if p.get("name") == name and p.get("in") == where:
                    p["x-sensitive"] = True
    return doc


def param_free_gets(doc: dict) -> list[str]:
    return [o["path"] for o in operations(doc) if o["method"] == "GET" and not o["path_params"]
            and not any(p.get("required") and p.get("in") in ("query", "header") for p in o["params"])]


def health_route(doc: dict) -> str | None:
    paths = param_free_gets(doc)
    for cand in ("/health", "/healthz", "/api/health", "/_health", "/status", "/ping", "/api/status"):
        if cand in paths:
            return cand
    for p in paths:
        if "health" in p:
            return p
    return None


def summary(doc: dict) -> str:
    """Compact text listing of the operations (for the LLM context)."""
    lines = []
    for o in operations(doc):
        ps = ["%s:%s%s" % (p.get("in"), p.get("name"), "*" if p.get("required") else "") for p in o["params"]]
        props = list(body_properties(doc, o["op"]))
        lines.append("%-7s %s  params=[%s]%s" % (o["method"], o["path"], ", ".join(ps),
                                                ("  body=[%s]" % ", ".join(props)) if props else ""))
    return "\n".join(lines)


def write(doc: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("# Generated by `immune init` (app.openapi() + x-owner-scoped / x-sensitive marks).\n")
        yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True, width=120)
