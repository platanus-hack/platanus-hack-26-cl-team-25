"""Mechanical validation of the LLM-owned artefacts. Each function returns a list of error strings ([] = valid).

columns.yaml  YAML; every table classified; referenced tables/columns exist; keys never rewritten
profile.py    static AST policy (imports, no exec/eval/subprocess/network/writes) + import in a clean subprocess:
              APP importable and callable, the five functions exist with the right arity,
              public_paths() a list of '/...' prefixes (not '/'), allowed_file_roots(env) absolute dirs, not system dirs
auth.yaml     auth.kind and its fields; introspect path is a parameter-free GET of the OpenAPI
marks.yaml    every operation / parameter / body property exists in the OpenAPI
"""
from __future__ import annotations

import ast
import os

import yaml

from immune import shadowdata
from . import openapi as oa
from . import sandbox

AUTH_KINDS = ("immune-token", "jwt-hs256", "introspect", "none")
ALLOWED_IMPORTS = {"json", "os", "os.path", "sqlite3", "secrets", "hashlib", "hmac", "base64", "time", "datetime",
                   "uuid", "string", "random", "re", "binascii", "typing", "__future__", "immune_contracts",
                   "immune_contracts.authtoken", "functools", "math"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "breakpoint", "input"}
FORBIDDEN_ATTRS = {"system", "popen", "spawnl", "spawnv", "execv", "execl", "fork", "remove", "unlink", "rmdir",
                   "removedirs", "rename", "replace", "chmod", "chown", "kill", "putenv", "symlink", "link",
                   "truncate", "makedirs", "mkdir"}
SYSTEM_DIRS = {"/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/root", "/home",
               "/var", "/tmp", "/opt", "/srv", "/boot", "/run"}
REQUIRED = {"allowed_file_roots": 1, "ensure_user": 3, "mint_token": 3, "load_markers": 1, "public_paths": 0}


def yaml_file(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f), None
    except FileNotFoundError:
        return None, "%s does not exist" % os.path.basename(path)
    except yaml.YAMLError as e:
        return None, "%s: invalid YAML: %s" % (os.path.basename(path), str(e).replace("\n", " ")[:300])


def columns(path: str, schema: dict) -> list[str]:
    doc, err = yaml_file(path)
    if err:
        return [err]
    errs = shadowdata.validate_columns(doc, schema)
    if isinstance(doc, dict) and "TODO" in yaml.safe_dump(doc):
        errs.append("columns.yaml still contains TODO markers")
    return errs


def profile_static(source: str, app_package: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return ["profile.py: syntax error line %s: %s" % (e.lineno, e.msg)]
    errs = []
    allowed = ALLOWED_IMPORTS | {app_package}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name not in allowed and a.name.split(".")[0] not in (app_package,):
                    errs.append("profile.py line %d: import %s is not allowed (allowed: stdlib %s, %s.*)"
                                % (node.lineno, a.name, ", ".join(sorted(ALLOWED_IMPORTS - {"__future__"})), app_package))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if node.level:
                errs.append("profile.py line %d: relative imports are not allowed" % node.lineno)
            elif mod not in allowed and mod.split(".")[0] != app_package:
                errs.append("profile.py line %d: from %s import ... is not allowed" % (node.lineno, mod))
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in FORBIDDEN_CALLS:
                errs.append("profile.py line %d: %s() is not allowed" % (node.lineno, f.id))
            if isinstance(f, ast.Attribute) and f.attr in FORBIDDEN_ATTRS:
                errs.append("profile.py line %d: .%s() is not allowed" % (node.lineno, f.attr))
            if isinstance(f, ast.Name) and f.id == "open":
                mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
                if mode is not None and not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)
                                             and not set(mode.value) & set("wax+")):
                    errs.append("profile.py line %d: open() may only read files" % node.lineno)
    if "TODO(immune)" in source and "raise NotImplementedError" in source:
        errs.append("profile.py still has unimplemented TODO(immune) functions")
    return errs


def profile(cfg, root: str | None = None) -> tuple[list[str], dict]:
    """Static policy + import in a clean subprocess. -> (errors, inspect result)."""
    path = os.path.join(root or cfg.project_dir, ".immune", cfg.shadow.profile.replace(".", "/") + ".py")
    if not os.path.isfile(path):
        return ["%s does not exist" % path], {}
    with open(path, encoding="utf-8") as f:
        src = f.read()
    errs = profile_static(src, cfg.app.package)
    if errs:
        return errs, {}
    info = sandbox.profile_job(cfg, "inspect", root=root)
    if not info.get("ok"):
        return ["profile.py does not import: %s" % info.get("error")], info
    if info.get("file") and os.path.realpath(info["file"]) != os.path.realpath(path):
        errs.append("module %r resolves to %s, not %s (name clash)" % (cfg.shadow.profile, info["file"], path))
    for name in info.get("missing") or []:
        errs.append("profile.py: function %s is missing" % name)
    for fn, n in REQUIRED.items():
        got = (info.get("arity") or {}).get(fn)
        if got is not None and got != n:
            errs.append("profile.py: %s must take %d argument(s), takes %d" % (fn, n, got))
    if info.get("app") != cfg.app.asgi:
        errs.append("profile.py: APP is %r but app.asgi is %r" % (info.get("app"), cfg.app.asgi))
    if not info.get("app_ok"):
        errs.append("profile.py: %s" % info.get("app_error"))
    errs += ["profile.py: %s" % e for e in info.get("errors") or []]
    pub = info.get("public_paths")
    if isinstance(pub, list):
        for p in pub:
            if not isinstance(p, str) or not p.startswith("/"):
                errs.append("public_paths(): %r is not a path prefix starting with /" % (p,))
            elif p.rstrip("/") == "":
                errs.append("public_paths(): '/' would make every path public and disable the owner oracle")
    roots = info.get("allowed_file_roots")
    if isinstance(roots, list):
        for r in roots:
            if not os.path.isabs(r):
                errs.append("allowed_file_roots(env): %r is not an absolute path" % r)
            elif os.path.realpath(r).rstrip("/") in SYSTEM_DIRS or os.path.realpath(r) == "/":
                errs.append("allowed_file_roots(env): %r is a system directory; the file oracle would be blind" % r)
            elif not os.path.isdir(r):
                errs.append("allowed_file_roots(env): %r does not exist" % r)
    return errs, info


def auth(path: str, doc: dict) -> tuple[list[str], dict]:
    d, err = yaml_file(path)
    if err:
        return [err], {}
    if not isinstance(d, dict) or not isinstance(d.get("auth"), dict):
        return ["auth.yaml: must contain a mapping 'auth:'"], {}
    a = d["auth"]
    errs = []
    kind = a.get("kind")
    if kind not in AUTH_KINDS:
        errs.append("auth.kind must be one of %s (got %r)" % ("|".join(AUTH_KINDS), kind))
    if kind == "introspect":
        p = a.get("path")
        if p not in oa.param_free_gets(doc):
            errs.append("auth.path %r is not a parameter-free GET operation of the OpenAPI" % (p,))
        for k in ("uid_field",):
            if not isinstance(a.get(k), str) or not a.get(k):
                errs.append("auth.%s is required for introspect" % k)
    if kind == "jwt-hs256" and not a.get("secret_env"):
        errs.append("auth.secret_env is required for jwt-hs256")
    av = a.get("admin_values", ["admin"])
    if not isinstance(av, list) or not all(isinstance(x, (str, int)) for x in av):
        errs.append("auth.admin_values must be a list")
    allowed = {"kind", "secret_env", "uid_claim", "role_claim", "admin_values", "path", "uid_field", "role_field",
               "cache_s"}
    extra = set(a) - allowed
    if extra:
        errs.append("auth: unknown keys %s" % sorted(extra))
    return errs, a


def marks(path: str, doc: dict) -> tuple[list[str], dict]:
    d, err = yaml_file(path)
    if err:
        return [err], {}
    return oa.validate_marks(d, doc), d or {}
