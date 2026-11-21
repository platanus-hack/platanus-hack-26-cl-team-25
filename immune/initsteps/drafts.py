"""Heuristic first drafts of the three LLM-owned artefacts.

These are what `--no-llm` writes (with TODO markers) and what the LLM steps start from:
    .immune/shadow/columns.yaml   (step 4)    columns_draft(schema, doc)
    .immune/profile.py            (step 5)    profile_draft(det, schema, cols, doc)
    .immune/shadow/auth.yaml      (step 5)    auth_draft(det, schema, cols, doc)
    .immune/shadow/marks.yaml     (step 6)    marks_draft(doc, cols)
"""
from __future__ import annotations

import os
import re

import yaml

from . import openapi as oa

USER_TABLES = ("users", "user", "accounts", "account", "members", "member", "customers", "customer", "usuarios",
               "people", "profiles")
OWNER_COLS = ("user_id", "owner_id", "author_id", "created_by", "customer_id", "member_id", "account_id", "uid",
              "usuario_id", "owner")
SECRET_RE = re.compile(r"(pass(word|wd)?|_hash$|^hash|secret|token|salt|api_?key|otp|totp|private_key|refresh)", re.I)
NONPRIVATE_RE = re.compile(r"(^id$|_id$|^role$|^roles$|status|^type$|_type$|^kind$|created|updated|deleted|_at$|"
                           r"^is_|^has_|count|^qty$|quantity|price|total|amount|currency|^lang|locale|timezone|"
                           r"^version$|^position$|^sort|^order$|^priority$|^category$|^slug$)", re.I)
PERSONAL_RE = re.compile(r"(email|mail|name|nombre|phone|tel|address|direcc|street|city|zip|postal|birth|ssn|dni|"
                         r"rut|note|nota|body|text|comment|message|content|title|descr|bio|avatar|ip)", re.I)
SENSITIVE_RE = re.compile(r"(pass(word|wd)?|secret|token|api_?key|otp|card|cvv|iban)", re.I)
TODO = "TODO(immune)"


# --------------------------------------------------------------------------------------- columns
def users_table(schema: dict) -> str | None:
    tables = schema["tables"]
    for t in USER_TABLES:
        if t in tables:
            return t
    for t, info in tables.items():
        names = [c["name"].lower() for c in info["columns"]]
        if any("email" in n for n in names) and any(SECRET_RE.search(n) for n in names):
            return t
    return None


def _pkcol(info):
    return info["rowid_alias"] or (info["pk"][0] if info["pk"] else "id")


def columns_draft(schema: dict, doc: dict | None) -> dict:
    tables = schema["tables"]
    ut = users_table(schema)
    out = {"users_table": ut or TODO, "user_id_column": _pkcol(tables[ut]) if ut else "id"}
    why = {}
    if ut:
        names = [c["name"] for c in tables[ut]["columns"]]
        role = next((n for n in names if n.lower() in ("role", "roles", "user_type", "rol")), None)
        if role:
            out["role_column"] = role
        login = next((n for n in names if n.lower() in ("email", "username", "login", "user_name", "correo")), None)
        if login:
            out["login_column"] = login
        sec = next((n for n in names if re.search(r"pass(word|wd)?", n, re.I)), None)
        if sec:
            out["secret_column"] = sec
    cls = {}
    for t, info in tables.items():
        keys = set(info["pk"]) | {f["from"] for f in info["fks"]}
        referenced = any(f["table"] == t for i in tables.values() for f in i["fks"])
        owner = None
        if t == ut:
            owner = out["user_id_column"]
        else:
            for f in info["fks"]:
                if f["table"] == ut:
                    owner = f["from"]
                    break
            if owner is None:
                owner = next((c["name"] for c in info["columns"] if c["name"].lower() in OWNER_COLS), None)
            if owner is None:   # owner through a foreign key to an owned table
                for f in info["fks"]:
                    pi = tables.get(f["table"])
                    if pi and any(fk["table"] == ut for fk in pi["fks"]) or \
                            (pi and any(c["name"].lower() in OWNER_COLS for c in pi["columns"])):
                        owner = {"via": f["from"], "table": f["table"]}
                        break
        private, secret = [], []
        for c in info["columns"]:
            n = c["name"]
            text = c["type"] in ("TEXT", "", "BLOB") or "CHAR" in c["type"] or "CLOB" in c["type"]
            if n == owner or (isinstance(owner, dict) and n == owner["via"]):
                continue
            if SECRET_RE.search(n) and text:
                if n in keys and (referenced or n != (info["pk"][:1] or [None])[0]):
                    continue
                secret.append(n)
            elif n in keys:
                continue
            elif text and (owner is not None) and not NONPRIVATE_RE.search(n):
                private.append(n)
            elif text and owner is None and PERSONAL_RE.search(n) and re.search(r"(email|phone|address|birth|ssn)", n, re.I):
                private.append(n)
        if owner is None and not private and not secret:
            cls[t] = {"public": True}
            why[t] = "heuristic: no owner column and no personal/secret-looking column"
        else:
            spec = {}
            if owner is not None:
                spec["owner"] = owner
            if private:
                spec["private"] = private
            if secret:
                spec["secret"] = secret
            cls[t] = spec
            why[t] = "heuristic: owner=%s, private by column name/type, secret by name" % (owner,)
    out["tables"] = cls
    out["routes"] = routes_draft(schema, doc, ut)
    out["why"] = why
    return out


def routes_draft(schema: dict, doc: dict | None, ut: str | None) -> dict:
    routes = {}
    tables = schema["tables"]
    for o in oa.operations(doc or {}):
        segs = o["path"].strip("/").split("/")
        for i, s in enumerate(segs):
            m = re.fullmatch(r"\{([^}]+)\}", s)
            if not m:
                continue
            p = m.group(1)
            if p in routes:
                continue
            base = p[:-3] if p.endswith("_id") else (segs[i - 1] if i and p == "id" else p)
            for cand in (base, base + "s", base + "es", base.rstrip("s"), (segs[i - 1] if i else "")):
                if cand in tables:
                    routes[p] = {"table": cand, "column": _pkcol(tables[cand])}
                    break
    return routes


# --------------------------------------------------------------------------------------- auth / profile
def _q(n):
    return '"%s"' % n.replace('"', '""')


def _code_uses(project: str, det: dict, needle: str) -> bool:
    from .detect import walk
    for d in det.get("source_dirs") or []:
        root = os.path.join(project, d)
        for path in ([root] if os.path.isfile(root) else walk(root)):
            try:
                if needle in open(path, encoding="utf-8", errors="replace").read():
                    return True
            except OSError:
                pass
    return False


def session_table(schema: dict, ut: str | None) -> tuple[str, str, str] | None:
    """(table, token column, user column) of a table that stores opaque session tokens."""
    for t, info in schema["tables"].items():
        names = [c["name"] for c in info["columns"]]
        tok = next((n for n in names if re.search(r"token|session_id|sid$", n, re.I)), None)
        usr = next((n for n in names if n.lower() in OWNER_COLS), None)
        if tok and usr and (re.search(r"session|token", t, re.I)):
            return t, tok, usr
    return None


def me_route(doc: dict | None) -> str | None:
    gets = oa.param_free_gets(doc or {})
    for p in gets:
        if re.search(r"/(me|whoami|current[_-]?user|profile|session)$", p):
            return p
    return None


def auth_draft(project: str, det: dict, schema: dict, cols: dict, doc: dict | None) -> dict:
    ut = cols.get("users_table")
    if _code_uses(project, det, "immune_contracts") and _code_uses(project, det, "authtoken"):
        return {"auth": {"kind": "immune-token", "admin_values": ["admin"]},
                "why": "heuristic: the app uses immune_contracts.authtoken"}
    st = session_table(schema, ut)
    me = me_route(doc)
    if st and me:
        return {"auth": {"kind": "introspect", "path": me, "uid_field": "id", "role_field": "role",
                         "admin_values": ["admin"], "cache_s": 30},
                "why": "heuristic: sessions are stored in table %s (opaque tokens); %s returns the caller" % (st[0], me)}
    return {"auth": {"kind": TODO, "admin_values": ["admin"]}, "why": TODO + ": could not tell how the app authenticates"}


def _fill_value(col: dict, uid_expr: str, role_col: str | None):
    n, t = col["name"], col["type"]
    if role_col and n == role_col:
        return "role"
    if "INT" in t or t in ("NUMERIC", "BOOLEAN"):
        return "0"
    if "REAL" in t or "FLOA" in t or "DOUB" in t:
        return "0.0"
    if re.search(r"mail", n, re.I):
        return '"user%%d@shadow.invalid" %% %s' % uid_expr
    if re.search(r"_at$|date|time", n, re.I):
        return '"2025-01-01T00:00:00Z"'
    return '"shadow %s %%d" %% %s' % (n, uid_expr)


def ensure_user_code(schema: dict, cols: dict) -> str:
    ut = cols.get("users_table")
    if not ut or ut not in schema["tables"]:
        return ("def ensure_user(conn, uid, role):\n    # %s: insert a synthetic user row with id=uid and the given role\n"
                "    raise NotImplementedError('ensure_user')\n" % TODO)
    info = schema["tables"][ut]
    uc = cols.get("user_id_column") or "id"
    role = cols.get("role_column")
    need = [c for c in info["columns"] if c["name"] == uc or c["name"] == role or
            (c["notnull"] and not c["pk"] and _no_default(info, c["name"]))]
    names = ", ".join(_q(c["name"]) for c in need)
    vals = ", ".join("uid" if c["name"] == uc else _fill_value(c, "uid", role) for c in need)
    return ("def ensure_user(conn, uid, role):\n"
            "    if conn.execute('SELECT 1 FROM %s WHERE %s = ?', (uid,)).fetchone():\n"
            "        return\n"
            "    conn.execute('INSERT INTO %s (%s) VALUES (%s)',\n"
            "                 (%s,))\n"
            "    conn.commit()\n" % (_q(ut), _q(uc), _q(ut), names, ", ".join("?" * len(need)), vals))


def _no_default(info, col):
    m = re.search(r"%s\b[^,]*" % re.escape(col), info.get("sql") or "")
    return not (m and re.search(r"\bDEFAULT\b", m.group(0), re.I))


def profile_draft(project: str, det: dict, schema: dict, cols: dict, auth: dict, doc: dict | None,
                  static_dirs: list[str]) -> str:
    kind = (auth.get("auth") or {}).get("kind")
    db_env = det.get("db_env") or "APP_DB"
    secret_env = (det.get("secret_envs") or ["APP_SECRET"])[0]
    roots = ", ".join("os.path.join(_RELEASE, %r)" % d for d in static_dirs) or ""
    header = ('"""Shadow profile of %s (generated by `immune init`; contract: contracts/README.md section 4).\n\n'
              'Review before deploying. Lines marked %s need a human or the LLM step.\n"""\n'
              % (det.get("name") or "the app", TODO))
    imports = "import json\nimport os\nimport secrets\nimport sqlite3\nimport time\n"
    if kind == "immune-token":
        imports += "\nfrom immune_contracts import authtoken\n"
    body = ['APP = %r' % det.get("asgi"), 'DB_ENV = %r' % db_env,
            '_RELEASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # release root (.immune/..)', "",
            "",
            "def allowed_file_roots(env):",
            "    # directories the app legitimately serves files from (%s: check)" % TODO,
            "    return [%s]" % roots, "", "",
            ensure_user_code(schema, cols), ""]
    if kind == "immune-token":
        body += ["def mint_token(env, uid, role):",
                 "    now = float(env[%r]) if env.get(%r) else None" % (det.get("time_env") or "APP_NOW",
                                                                        det.get("time_env") or "APP_NOW"),
                 "    return authtoken.mint(env[%r], uid, role, now=now)" % secret_env, ""]
    else:
        st = session_table(schema, cols.get("users_table"))
        if kind == "introspect" and st:
            t, tok, usr = st
            info = schema["tables"][t]
            others = [c for c in info["columns"] if c["name"] not in (tok, usr) and c["notnull"] and not c["pk"]
                      and _no_default(info, c["name"])]
            names = ", ".join(_q(c) for c in [tok, usr] + [c["name"] for c in others])
            vals = ", ".join(["token", "uid"] + [("int(time.time())" if "INT" in c["type"] else '"shadow"')
                                                 for c in others])
            body += ["def mint_token(env, uid, role):",
                     "    # opaque session token stored in %s" % t,
                     "    token = secrets.token_hex(24)",
                     "    conn = sqlite3.connect(env[DB_ENV])",
                     "    try:",
                     "        conn.execute('INSERT INTO %s (%s) VALUES (%s)', (%s,))" % (
                         _q(t), names, ", ".join("?" * (2 + len(others))), vals),
                     "        conn.commit()",
                     "    finally:",
                     "        conn.close()",
                     "    return token", ""]
        else:
            body += ["def mint_token(env, uid, role):",
                     "    # %s: return a credential (sent as 'Authorization: Bearer <token>') that the app" % TODO,
                     "    # accepts for user uid with the given role",
                     "    raise NotImplementedError('mint_token')", ""]
    body += ["", "def load_markers(env):",
             "    with open(env[\"MARKERS_PATH\"]) as f:",
             "        return json.load(f)", "", "",
             "def public_paths():",
             "    # path prefixes whose responses are never owner-checked: health, login/register, public catalogue",
             "    # (%s: check)" % TODO,
             "    return %r" % public_paths_draft(doc), ""]
    return header + "\n" + imports + "\n" + "\n".join(body)


def public_paths_draft(doc: dict | None) -> list[str]:
    out = []
    for o in oa.operations(doc or {}):
        p = o["path"]
        if re.search(r"(health|login|register|signup|sign-up|token)$", p) and p not in out:
            out.append(p)
    return out or ["/health"]


# --------------------------------------------------------------------------------------- marks
def marks_draft(doc: dict | None, cols: dict) -> dict:
    owned = {t for t, s in (cols.get("tables") or {}).items() if isinstance(s, dict) and s.get("owner")}
    routes = cols.get("routes") or {}
    owner_scoped, sensitive = [], []
    for o in oa.operations(doc or {}):
        if any((routes.get(p) or {}).get("table") in owned for p in o["path_params"]):
            owner_scoped.append({"op": o["key"], "why": "heuristic: path parameter maps to an owner-scoped table"})
        for p in o["params"]:
            if SENSITIVE_RE.search(p.get("name", "")) and p.get("in") != "header":
                sensitive.append({"op": o["key"], "in": p.get("in"), "name": p["name"], "why": "heuristic: name"})
        for name in oa.body_properties(doc, o["op"]):
            if SENSITIVE_RE.search(name):
                sensitive.append({"op": o["key"], "in": "body", "name": name, "why": "heuristic: name"})
    return {"owner_scoped": owner_scoped, "sensitive": sensitive}


def dump_yaml(obj, header: str = "") -> str:
    return header + yaml.safe_dump(obj, sort_keys=False, allow_unicode=True, width=120)
