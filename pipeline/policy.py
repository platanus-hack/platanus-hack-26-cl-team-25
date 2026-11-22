"""Gate 1 — mechanical policy on the diff (docs/plan-construccion.md §4.1).

Compares the before/after ASTs of every changed file (never regexes over the diff):
only existing Python files under the project's `app.source_dirs`; no new imports (or dynamic import/exec/env access);
no new reads of request attributes (new handler parameters, Request/Header/Cookie
objects, .headers/.cookies/...); no comparisons against literals the app did not
already compare against; no removed authentication checks; no high-entropy strings;
bounded size.
"""
from __future__ import annotations

import ast
import math
import os
import re
from collections import Counter

from . import diffs



def source_dirs(dirs=None) -> list:
    """Allowed edit area: app.source_dirs of .immune/config.yaml (release-relative, no trailing slash)."""
    if dirs is None:
        from immune import config as icfg
        dirs = icfg.current().app.source_dirs
    return [d.strip("/") for d in dirs if d and d.strip("/")]


def _allowed(path: str, dirs: list) -> bool:
    return any(path.startswith(d + "/") for d in dirs)
REQ_ATTRS = {"headers", "cookies", "query_params", "path_params", "client", "url", "base_url", "scope", "state",
             "form", "body", "stream", "receive", "json"}
REQ_NAMES = {"Request", "Header", "Cookie", "Query", "Body", "Form", "File", "UploadFile", "Depends", "Security",
             "HTTPConnection", "WebSocket"}
DANGEROUS = {"__import__", "exec", "eval", "compile", "importlib", "globals", "locals", "vars", "__builtins__",
             "setattr", "delattr", "environ", "getenv", "putenv", "system", "popen", "subprocess", "socket",
             "pickle", "marshal", "ctypes", "__subclasses__", "__globals__"}
CMP_METHODS = {"startswith", "endswith", "find", "rfind", "index", "rindex", "count", "__eq__", "__ne__",
               "__contains__", "removeprefix", "removesuffix"}
ROUTE_DECOS = {"get", "post", "put", "patch", "delete", "head", "options", "api_route", "route", "websocket"}
TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
IGNORED_LITERALS = {("NoneType", "None"), ("bool", "True"), ("bool", "False")}


def _lit(v) -> tuple:
    return (type(v).__name__, repr(v))


def _consts(node) -> list:
    """Literal values inside an operand (constants, and constants inside tuple/list/set/dict displays)."""
    if isinstance(node, ast.Constant):
        return [node.value]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [v for e in node.elts for v in _consts(e)]
    if isinstance(node, ast.Dict):
        return [v for e in node.keys if e is not None for v in _consts(e)]
    if isinstance(node, ast.UnaryOp) and isinstance(node.operand, ast.Constant):
        try:
            return [ast.literal_eval(node)]
        except ValueError:
            return []
    return []


def compared_literals(tree) -> list:
    """[(literal key, lineno)] of literals used in comparisons."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Compare):
            for operand in [n.left] + list(n.comparators):
                out += [(_lit(v), n.lineno) for v in _consts(operand)]
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in CMP_METHODS:
            for a in n.args:
                out += [(_lit(v), n.lineno) for v in _consts(a)]
            if isinstance(n.func.value, ast.Constant):        # "'" .__contains__(x) / "x".count(...)
                out.append((_lit(n.func.value.value), n.lineno))
        elif isinstance(n, ast.MatchValue):
            out += [(_lit(v), getattr(n, "lineno", 0)) for v in _consts(n.value)]
        elif isinstance(n, ast.MatchSingleton):
            out.append((_lit(n.value), getattr(n, "lineno", 0)))
    return out


def string_constants(tree) -> set:
    return {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes))}


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values()) if s else 0.0


def high_entropy_tokens(value) -> list:
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    out = []
    for tok in TOKEN_RE.findall(value):
        has_digit = any(ch.isdigit() for ch in tok)
        has_alpha = any(ch.isalpha() for ch in tok)
        if has_digit and has_alpha and entropy(tok) >= 3.5:
            out.append(tok)
    return out


def imports(tree) -> set:
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out |= {("import", a.name, a.asname) for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            out |= {("from", "." * n.level + (n.module or ""), a.name, a.asname) for a in n.names}
    return out


def name_uses(tree, names: set, attrs: set | None = None) -> Counter:
    """Count Name loads in `names` and attribute accesses in `names | attrs`."""
    attrs = names | (attrs or set())
    c = Counter()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and n.id in names:
            c[n.id] += 1
        elif isinstance(n, ast.Attribute) and n.attr in attrs:
            c[n.attr] += 1
    return c


def functions(tree) -> dict:
    """qualname -> FunctionDef (nested names joined with '.')."""
    out = {}

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = prefix + ch.name
                out[q] = ch
                walk(ch, q + ".")
            elif isinstance(ch, ast.ClassDef):
                walk(ch, prefix + ch.name + ".")
            else:
                walk(ch, prefix)
    walk(tree, "")
    return out


def route_of(fn) -> str | None:
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_DECOS:
            path = d.args[0].value if d.args and isinstance(d.args[0], ast.Constant) else "?"
            return "%s %s" % (d.func.attr.upper(), path)
    return None


def _status(call: ast.Call):
    for a in call.args[:1]:
        if isinstance(a, ast.Constant) and isinstance(a.value, int):
            return a.value
    for k in call.keywords:
        if k.arg == "status_code" and isinstance(k.value, ast.Constant):
            return k.value.value
    return None


def _auth_raises(fn) -> int:
    n = 0
    for node in ast.walk(fn):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and _status(node.exc) in (401, 403):
            n += 1
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Call) and _status(node.value) in (401, 403):
            n += 1
    return n


def guard_names(trees: list) -> set:
    """Functions of the app that reject with 401/403: calling one of them is an authentication check."""
    names = set()
    for t in trees:
        for q, fn in functions(t).items():
            if _auth_raises(fn):
                names.add(q.split(".")[-1])
    return names


def auth_checks(fn, guards: set) -> int:
    n = _auth_raises(fn)
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name in guards:
                n += 1
    return n


def _params(fn) -> set:
    a = fn.args
    return {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs} | ({a.vararg.arg} if a.vararg else set()) | \
           ({a.kwarg.arg} if a.kwarg else set())


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None


def package_trees(release_dir: str, dirs=None) -> dict:
    out = {}
    for sd in source_dirs(dirs):
        root = os.path.join(release_dir, sd)
        for d, _ds, fs in os.walk(root):
            for f in fs:
                if f.endswith(".py"):
                    p = os.path.join(d, f)
                    rel = os.path.relpath(p, release_dir).replace(os.sep, "/")
                    if rel in out:
                        continue
                    try:
                        out[rel] = ast.parse(_read(p) or "", p)
                    except SyntaxError:
                        pass
    return out


def check(diff: str, base_dir: str, patched_dir: str, max_lines: int = 120, max_files: int = 4, dirs=None):
    """-> (ok: bool, detail: str, violations: list[str]). dirs: allowed edit area (default app.source_dirs)."""
    dirs = source_dirs(dirs)
    area = ", ".join(d + "/" for d in dirs) or "(no app.source_dirs configured)"
    v = []
    try:
        changes = diffs.parse(diff)
    except diffs.DiffError as e:
        return False, "REJECTED: %s" % e, [str(e)]
    files = []
    for ch in changes:
        if ch.flags:
            v.append("%s: %s changes are not allowed" % (ch.path or "?", ", ".join(ch.flags)))
        if ch.old is None or ch.new is None:
            v.append("%s: creating or deleting files is not allowed" % (ch.path or "?"))
            continue
        if ch.old != ch.new:
            v.append("%s -> %s: renames are not allowed" % (ch.old, ch.new))
        p = ch.new
        norm = os.path.normpath(p).replace(os.sep, "/")
        if p.startswith("/") or ".." in p.split("/") or norm != p or not _allowed(norm, dirs):
            v.append("%s: only files under %s may change" % (p, area))
        elif not p.endswith(".py"):
            v.append("%s: only Python sources may change" % p)
        elif os.path.islink(os.path.join(base_dir, p)) or os.path.islink(os.path.join(patched_dir, p)):
            v.append("%s: symlinks are not allowed" % p)
        else:
            files.append(p)
    lines = sum(c.added + c.removed for c in changes)
    if lines > max_lines:
        v.append("diff too large: %d changed lines (max %d)" % (lines, max_lines))
    if len(changes) > max_files:
        v.append("too many files: %d (max %d)" % (len(changes), max_files))

    base_trees = package_trees(base_dir, dirs)
    base_lits = {k for t in base_trees.values() for k, _ in compared_literals(t)} | IGNORED_LITERALS
    base_strs = {s for t in base_trees.values() for s in string_constants(t)}
    guards = guard_names(list(base_trees.values()))
    summary = []
    for p in sorted(set(files)):
        before_src, after_src = _read(os.path.join(base_dir, p)), _read(os.path.join(patched_dir, p))
        if before_src is None or after_src is None:
            v.append("%s: file missing before or after the patch" % p)
            continue
        try:
            before = ast.parse(before_src, p)
        except SyntaxError:
            before = ast.parse("", p)
        try:
            after = ast.parse(after_src, p)
        except SyntaxError as e:
            v.append("%s: syntax error after the patch (line %s: %s)" % (p, e.lineno, e.msg))
            continue
        new_imp = imports(after) - imports(before)
        if new_imp:
            v.append("%s: new import(s) %s" % (p, ", ".join(sorted(_fmt_import(i) for i in new_imp))))
        dang = name_uses(after, DANGEROUS) - name_uses(before, DANGEROUS)
        if dang:
            v.append("%s: new use of %s (dynamic code, process, network or environment access)" % (p, ", ".join(sorted(dang))))
        req = name_uses(after, REQ_NAMES, REQ_ATTRS) - name_uses(before, REQ_NAMES, REQ_ATTRS)
        if req:
            v.append("%s: new read(s) of request data via %s" % (p, ", ".join(sorted(req))))
        fb, fa = functions(before), functions(after)
        for q, fn in fa.items():
            r = route_of(fn)
            if r and q not in fb:
                v.append("%s: new route handler %s (%s)" % (p, q, r))
            elif r and q in fb:
                extra = _params(fn) - _params(fb[q])
                if extra:
                    v.append("%s: handler %s reads new request input(s): %s" % (p, q, ", ".join(sorted(extra))))
        for q, fn in fb.items():
            n_before = auth_checks(fn, guards)
            if not n_before:
                continue
            n_after = auth_checks(fa[q], guards) if q in fa else 0
            if n_after < n_before:
                v.append("%s: authentication check removed from %s (%d -> %d)" % (p, q, n_before, n_after))
        new_lits = {}
        for k, line in compared_literals(after):
            if k not in base_lits:
                new_lits.setdefault(k, line)
        if new_lits:
            shown = ", ".join("%s (line %d)" % (val[:40], ln) for (_t, val), ln in sorted(new_lits.items(), key=lambda x: x[1]))
            v.append("%s: comparison against new literal(s) %s" % (p, shown))
        for s in string_constants(after) - string_constants(before) - base_strs:
            toks = high_entropy_tokens(s)
            if toks:
                v.append("%s: high-entropy string constant %r" % (p, toks[0][:12] + "..."))
        summary.append(p)
    if v:
        return False, "REJECTED: " + "; ".join(v), v
    added = sum(c.added for c in changes)
    removed = sum(c.removed for c in changes)
    return True, ("OK: %d file(s) (%s), +%d/-%d lines; no new imports, request reads, literal comparisons, "
                  "removed auth checks or secrets" % (len(summary), ", ".join(summary), added, removed)), []


def _fmt_import(i) -> str:
    if i[0] == "import":
        return "import %s" % i[1]
    return "from %s import %s" % (i[1], i[2])


def changed_routes(base_dir: str, patched_dir: str, files: list) -> list:
    """['GET /api/x', ...] of route handlers whose body changed."""
    out = []
    for p in files:
        try:
            fb = functions(ast.parse(_read(os.path.join(base_dir, p)) or ""))
            fa = functions(ast.parse(_read(os.path.join(patched_dir, p)) or ""))
        except SyntaxError:
            continue
        for q, fn in fa.items():
            r = route_of(fn)
            if r and (q not in fb or ast.dump(fn) != ast.dump(fb[q])):
                out.append(r)
    return out
