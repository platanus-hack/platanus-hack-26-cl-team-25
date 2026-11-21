"""Runtime of the generated legitimate journeys (`<project>/.immune/scenarios.py`, written by `immune init`).

The generated module holds only data (PLAN) and calls ``scenarios_from(PLAN)``; this module turns it into
``SCENARIOS`` (contracts/README.md §9: deterministic callables ``(client, manifest) -> steps``), run by the
pipeline's `legit` gate against a TestClient on a fresh prod-like seed with a frozen clock.

Journeys are legitimate by construction: an existing seeded user (the manifest's ``legit_users``) reads
**its own** resources on every GET route of the OpenAPI: resources it owns (manifest ``ownership``),
groups it belongs to (manifest ``groups``), itself; parameter-free routes are also read by the admin.
Credentials come from the shadow profile's ``mint_token``. Values never contain SQL or path
metacharacters, so the unpatched and the patched release must answer them identically.

PLAN = {"profile": "profile", "users_table": "users",
        "ops": [{"path": "/notes/{note_id}", "path_params": {"note_id": {"own": "notes"}},
                 "query": [{"name": "sort", "values": ["created", "title"], "required": false}], "admin": false}]}
path param sources: {"own": table} | {"group": table} | {"self": true}
query values: a literal list, or "files" (relative names of the files under the profile's allowed roots).
"""
from __future__ import annotations

import hashlib
import importlib
import os
import re
from urllib.parse import quote

MAX_USERS = 2
MAX_RESOURCES = 2
MAX_FILES = 6
TOKEN_KEYS = re.compile(r"(^|_)(token|access_token|refresh_token|session|csrf)$", re.I)


def _norm(r):
    ctype = r.headers.get("content-type", "")
    if "json" in ctype:
        try:
            body = r.json()
        except ValueError:
            body = r.text
    elif ctype.startswith("text/"):
        body = r.text
    else:
        body = "sha256:" + hashlib.sha256(r.content).hexdigest()

    def scrub(x):
        if isinstance(x, dict):
            return {k: ("<token>" if TOKEN_KEYS.search(str(k)) else scrub(v)) for k, v in x.items()}
        if isinstance(x, list):
            return [scrub(v) for v in x]
        return x
    return scrub(body)


def _profile(plan):
    return importlib.import_module(plan.get("profile") or "profile")


def _auth(plan, uid, role):
    tok = _profile(plan).mint_token(dict(os.environ), int(uid), role or "user")
    return {"authorization": "Bearer " + tok}


def _files(plan) -> list:
    out = []
    try:
        roots = _profile(plan).allowed_file_roots(dict(os.environ)) or []
    except Exception:  # noqa: BLE001
        return out
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for d, dirs, files in sorted(os.walk(root)):
            dirs.sort()
            for fn in sorted(files):
                out.append(os.path.relpath(os.path.join(d, fn), root).replace(os.sep, "/"))
    out.sort(key=lambda n: (-n.count("."), n))       # dotted names first: they are the fragile ones
    return out[:MAX_FILES]


def _owned(manifest, table, uid) -> list:
    own = (manifest.get("ownership") or {}).get(table) or {}
    ids = [k for k, o in own.items() if str(o) == str(uid)]
    return sorted(ids, key=lambda k: (len(k), k))[:MAX_RESOURCES]


def _member_of(manifest, table, uid) -> list:
    gs = (manifest.get("groups") or {}).get(table) or {}
    ids = [g for g, ms in gs.items() if uid in ms or str(uid) in [str(m) for m in ms]]
    return sorted(ids, key=lambda k: (len(k), k))[:MAX_RESOURCES]


def _values(manifest, src, uid) -> list:
    if src.get("own"):
        return _owned(manifest, src["own"], uid)
    if src.get("group"):
        return _member_of(manifest, src["group"], uid)
    if src.get("self"):
        return [str(uid)]
    return []


def _bindings(manifest, op, uid) -> list:
    """Every combination of path values the user legitimately addresses (at most MAX_RESOURCES per param)."""
    combos = [{}]
    for name, src in (op.get("path_params") or {}).items():
        vals = _values(manifest, src, uid)
        if not vals:
            return []
        combos = [dict(c, **{name: v}) for c in combos for v in vals][:MAX_RESOURCES * 2]
    return combos


def _queries(plan, op) -> list:
    """Query strings: one with only the required parameters, then one per listed value of each parameter."""
    req, extra = [], []
    files = None
    for q in op.get("query") or []:
        vals = q.get("values")
        if vals == "files":
            files = _files(plan) if files is None else files
            vals = files
        vals = [str(v) for v in (vals or [])]
        if q.get("required"):
            if not vals:
                return []
            req.append((q["name"], vals))
        else:
            extra += [(q["name"], v) for v in vals]
    if req:
        # vary the first required parameter over its values, the others fixed to their first value
        n0, vs0 = req[0]
        rest = [(n, vs[0]) for n, vs in req[1:]]
        out = [[(n0, v)] + rest for v in vs0]
    else:
        out = [[]]
    for n, v in extra:
        out.append(list(out[0]) + [(n, v)])
    return ["&".join("%s=%s" % (quote(n, safe=""), quote(v, safe="")) for n, v in qs) for qs in out]


def _users(manifest) -> list:
    return [u for u in manifest.get("legit_users") or [] if u.get("id") is not None]


def _scenario(plan, op, idx):
    def run(client, manifest):
        steps = []
        users = _users(manifest)
        picked = []
        for u in users:
            if _bindings(manifest, op, u["id"]):
                picked.append(u)
            if len(picked) >= MAX_USERS:
                break
        identities = [(u["id"], u.get("role") or "user", "user") for u in picked]
        if op.get("admin") and (manifest.get("admin") or {}).get("id") is not None:
            a = manifest["admin"]
            identities.append((a["id"], a.get("role") or "admin", "admin"))
        queries = _queries(plan, op)
        for uid, role, who in identities:
            hdrs = _auth(plan, uid, role)
            for b in _bindings(manifest, op, uid):
                path = op["path"]
                for k, v in b.items():
                    path = path.replace("{%s}" % k, quote(str(v), safe=""))
                for q in queries:
                    r = client.request("GET", path + ("?" + q if q else ""), headers=hdrs)
                    steps.append({"step": "%s %s reads %s" % (who, uid, op["path"]), "method": "GET", "path": path,
                                  "query": q, "status": r.status_code, "body": _norm(r)})
        return steps
    run.__name__ = "get_%d_%s" % (idx, re.sub(r"[^a-z0-9]+", "_", op["path"].lower()).strip("_") or "root")
    return run


def scenarios_from(plan: dict) -> list:
    return [_scenario(plan, op, i) for i, op in enumerate(plan.get("ops") or [])]
