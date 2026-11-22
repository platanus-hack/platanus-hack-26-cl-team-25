"""Gate 1 — mechanical policy on the diff (docs/validaciones.md).

Compares the before/after ASTs of every changed file (never regexes over the diff):
only existing Python files under the project's `app.source_dirs`; no new imports; no new dynamic
code, attribute, process, network or environment access (`__import__`, `importlib`, `eval`, `exec`,
`compile`, `globals`, `vars`, `os.environ`, `__dict__`, `getattr` with a computed, private or dangerous
name, ...); no new file access with a literal absolute path
(`open("/etc/...")`, `Path("/...")`) and no new string constant naming a system directory; no new reads
of request attributes (new handler parameters, Request/Header/Cookie objects, .headers/.cookies/...);
no test of a value against a literal the app did not already test against (comparisons, `in`,
lookups in dict/set/list literals such as `{12: True}.get(x)`, `match` cases, arithmetic on a constant
inside a comparison or condition, and names the patch binds to such literals); no removed
authentication checks; no high-entropy strings; bounded size.

This is a heuristic over syntax, not a proof. It does not follow data flow: a literal passed as an
argument to a helper that compares it, unpacked from a tuple, returned by a function, built by string
formatting at run time, or a test that needs no literal at all (e.g. `len(x) == len(y)`, a hash of the
value) is not seen, and neither is a semantic backdoor that needs no new literal, import or request
read. The other four gates judge behaviour.
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
             "pickle", "marshal", "ctypes", "__subclasses__", "__globals__",
             # interpreter internals that reach any attribute by name: `os.__dict__[...]` (getattr: `risky_getattr`)
             "__getattribute__", "__dict__", "__class__", "__mro__", "__bases__", "__code__", "__closure__",
             "__loader__", "__spec__", "builtins", "attrgetter", "methodcaller", "modules", "breakpoint",
             "environb", "getenvb", "execv", "execve", "execl", "execvp", "fork", "unlink", "rmtree", "symlink"}
CMP_METHODS = {"startswith", "endswith", "find", "rfind", "index", "rindex", "count", "__eq__", "__ne__",
               "__contains__", "removeprefix", "removesuffix"}
# lookups that test their receiver's literal elements against a value: `{12: True}.get(x)`, `BAD.pop(x)`
LOOKUP_METHODS = {"get", "pop", "setdefault", "__getitem__", "keys", "values", "items"}
SET_METHODS = {"issubset", "issuperset", "isdisjoint", "intersection", "difference", "union", "symmetric_difference"}
# builtins that only convert or combine their arguments: `x == int("12")`, `x in set([12])`
PURE_CALLS = {"int", "str", "float", "bool", "bytes", "bytearray", "chr", "ord", "repr", "hex", "oct", "bin", "abs",
              "round", "len", "min", "max", "sum", "tuple", "list", "set", "frozenset", "dict", "range", "sorted",
              "reversed", "complex"}
FILE_CALLS = {"open", "Path", "PurePath", "PosixPath", "PurePosixPath", "FileResponse", "listdir", "scandir", "walk",
              "readlink", "read_text", "read_bytes", "stat", "lstat", "glob", "iglob"}
PATH_JOINS = {"join", "joinpath", "Path", "PurePath", "PosixPath", "PurePosixPath", "abspath", "realpath", "normpath",
              "expanduser", "fspath"}
SYSTEM_PATH_RE = re.compile(r"^(?:~|/(?:etc|proc|sys|dev|root|home|var|run|tmp|usr|bin|sbin|opt|srv|boot|lib|lib64|mnt|"
                            r"media|app)(?:/|$))")
ROUTE_DECOS = {"get", "post", "put", "patch", "delete", "head", "options", "api_route", "route", "websocket"}
TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
IGNORED_LITERALS = {("NoneType", "None"), ("bool", "True"), ("bool", "False")}


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _consts(node, binds=None) -> list:
    """Literal values an operand is built from: constants; elements, keys and values of tuple/list/set/dict
    displays; operands of arithmetic, boolean and conditional expressions; f-string parts; arguments of pure
    builtins (`int("12")`, `set([12])`, `dict(k=1)`). With `binds` ({name: literals}, see `bindings`), a name
    or attribute bound to such an expression counts as the expression."""
    if isinstance(node, ast.Constant):
        return [node.value]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [v for e in node.elts for v in _consts(e, binds)]
    if isinstance(node, ast.Dict):
        return [v for e in list(node.keys) + list(node.values) if e is not None for v in _consts(e, binds)]
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.operand, ast.Constant):
            try:
                return [ast.literal_eval(node)]
            except ValueError:
                return []
        return _consts(node.operand, binds)
    if isinstance(node, ast.BinOp):
        return _consts(node.left, binds) + _consts(node.right, binds)
    if isinstance(node, ast.BoolOp):
        return [v for e in node.values for v in _consts(e, binds)]
    if isinstance(node, ast.IfExp):
        return _consts(node.body, binds) + _consts(node.orelse, binds)
    if isinstance(node, ast.JoinedStr):
        return [v for e in node.values for v in _consts(e, binds)]
    if isinstance(node, (ast.FormattedValue, ast.Starred, ast.NamedExpr)):
        return _consts(node.value, binds)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in PURE_CALLS:
        out = [v for e in node.args for v in _consts(e, binds)]
        for k in node.keywords:
            out += _consts(k.value, binds) + ([k.arg] if k.arg and node.func.id == "dict" else [])
        return out
    if binds and _name(node) in binds:
        return list(binds[_name(node)])
    return []


def _pure(node) -> bool:
    """A constant expression: `_consts` saw all of it (no name, attribute or other call inside)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_pure(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(e is not None and _pure(e) for e in list(node.keys) + list(node.values))
    if isinstance(node, ast.UnaryOp):
        return _pure(node.operand)
    if isinstance(node, ast.BinOp):
        return _pure(node.left) and _pure(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in PURE_CALLS:
        return all(_pure(e) for e in node.args) and all(_pure(k.value) for k in node.keywords)
    return False


def bindings(tree) -> dict:
    """{name: (literal keys)} for names (and attributes, by their last part) bound to a constant expression:
    `BAD = {12}`, `self.key = "letmein"`, `(n := 12)`, `for b in (12, 31)`, `[... for b in [12]]`,
    `def f(x, bad=12)`. Scopes are not tracked."""
    out = {}

    def bind(name, value):
        if name and value is not None and _pure(value):
            lits = {_lit(v) for v in _consts(value)}
            if lits:
                out[name] = tuple(sorted(set(out.get(name, ())) | lits))

    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                bind(_name(t), n.value)
        elif isinstance(n, (ast.AnnAssign, ast.NamedExpr)):
            bind(_name(n.target), n.value)
        elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
            bind(_name(n.target), n.iter)
        elif isinstance(n, ast.arguments):
            pos = n.posonlyargs + n.args
            for a, d in list(zip(pos[len(pos) - len(n.defaults):], n.defaults)) + list(zip(n.kwonlyargs, n.kw_defaults)):
                bind(a.arg, d)
    return out


def new_bindings(before: dict, after: dict) -> dict:
    """{name: [values]} for the literals a patch newly binds to a name (shape of `_consts`' `binds`)."""
    out = {}
    for name, lits in after.items():
        fresh = [k for k in lits if k not in before.get(name, ())]
        if fresh:
            out[name] = [_Key(k) for k in fresh]
    return out


class _Key:
    """A literal already reduced to its key (type name, repr), passed through `_consts` unchanged."""

    def __init__(self, key):
        self.key = key


def _lit(v) -> tuple:
    return v.key if isinstance(v, _Key) else (type(v).__name__, repr(v))


def _test_leaves(node):
    if isinstance(node, ast.BoolOp):
        for v in node.values:
            yield from _test_leaves(v)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        yield from _test_leaves(node.operand)
    else:
        yield node


def compared_literals(tree, binds=None) -> list:
    """[(literal key, lineno)] of literals a value is tested against: comparisons and `in`, string/sequence
    predicates (`x.startswith("..")`), lookups in literal containers (`{12: True}.get(x)`, `{12: 1}[x]`,
    `{x} & {12}`), `match` cases, and arithmetic on a constant used as a condition (`if x - 12:`).
    `binds`: names the patch binds to literals, resolved as those literals."""
    out = []

    def add(node, line):
        out.extend((_lit(v), line) for v in _consts(node, binds))

    for n in ast.walk(tree):
        line = getattr(n, "lineno", 0)
        if isinstance(n, ast.Compare):
            for operand in [n.left] + list(n.comparators):
                add(operand, line)
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            attr, recv = n.func.attr, n.func.value
            if attr in CMP_METHODS or attr in SET_METHODS:
                for a in n.args:
                    add(a, line)
                add(recv, line)                      # "'".__contains__(x), [12].count(x), BAD.issubset(...)
            elif attr in LOOKUP_METHODS:
                add(recv, line)                      # {12: True}.get(x): the keys are the tested literals
        elif isinstance(n, ast.Subscript) and not isinstance(n.value, ast.Constant):
            add(n.value, line)                       # {12: True}[x], BAD[x]
        elif isinstance(n, ast.MatchValue):
            add(n.value, line)
        elif isinstance(n, ast.MatchSingleton):
            out.append((_lit(n.value), line))
        elif isinstance(n, ast.MatchMapping):
            for k in n.keys:
                add(k, line)
        tests = []
        if isinstance(n, (ast.If, ast.While, ast.IfExp, ast.Assert)):
            tests.append(n.test)
        elif isinstance(n, ast.comprehension):
            tests += n.ifs
        elif isinstance(n, ast.match_case) and n.guard is not None:
            tests.append(n.guard)
        for t in tests:
            for leaf in _test_leaves(t):
                if isinstance(leaf, ast.BinOp) or (isinstance(leaf, ast.Call) and isinstance(leaf.func, ast.Name)
                                                   and leaf.func.id in PURE_CALLS):
                    add(leaf, getattr(leaf, "lineno", line))
    return out


def _leading_const(node):
    """The literal a path expression starts with (`"/etc" + x`, `os.path.join("/etc", x)`, f"/etc/{x}"), or None."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, (str, bytes)) else None
    if isinstance(node, ast.BinOp):
        return _leading_const(node.left)
    if isinstance(node, ast.JoinedStr) and node.values:
        return _leading_const(node.values[0])
    if isinstance(node, ast.Call) and _name(node.func) in PATH_JOINS and node.args:
        return _leading_const(node.args[0])
    return None


def _absolute(value) -> bool:
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    return len(value) > 1 and value.startswith(("/", "~"))


def absolute_file_access(tree) -> Counter:
    """Counter of "call(literal)" for file calls whose path argument starts with a literal absolute path."""
    c = Counter()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _name(n.func) in FILE_CALLS:
            for a in list(n.args) + [k.value for k in n.keywords]:
                lead = _leading_const(a)
                if lead is not None and _absolute(lead):
                    c["%s(%r)" % (_name(n.func), lead if isinstance(lead, str) else lead.decode("latin-1"))] += 1
    return c


def system_paths(tree) -> set:
    """String constants that name a system directory (`/etc/...`, `/proc/...`, `~`), wherever they are used."""
    out = set()
    for v in string_constants(tree):
        text = v.decode("latin-1") if isinstance(v, bytes) else v
        if SYSTEM_PATH_RE.match(text):
            out.add(text)
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


def risky_getattr(tree) -> int:
    """Uses of `getattr` other than reading a fixed, ordinary attribute (`getattr(ident, "role", None)`): a
    computed name (`getattr(os, "env" + "iron")`), a private/dunder or dangerous name, or `getattr` passed around."""
    uses = safe = 0
    for n in ast.walk(tree):
        if _name(n) == "getattr":
            uses += 1
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "getattr" and len(n.args) >= 2:
            a = n.args[1]
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and not a.value.startswith("_") \
                    and a.value not in DANGEROUS:
                safe += 1
    return uses - safe


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
    base_binds, after_binds = {}, {}
    for p, t in base_trees.items():
        for name, lits in bindings(t).items():
            base_binds[name] = tuple(set(base_binds.get(name, ())) | set(lits))
    for p in sorted(set(files)):
        try:
            for name, lits in bindings(ast.parse(_read(os.path.join(patched_dir, p)) or "", p)).items():
                after_binds[name] = tuple(set(after_binds.get(name, ())) | set(lits))
        except SyntaxError:
            pass
    binds = new_bindings(base_binds, after_binds)    # literals the patch binds to a name: `BAD = {12}`
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
            v.append("%s: new use of %s (dynamic code or attribute access, process, network or environment "
                     "access)" % (p, ", ".join(sorted(dang))))
        if risky_getattr(after) > risky_getattr(before):
            v.append("%s: new use of getattr with a computed, private or dangerous attribute name (dynamic "
                     "attribute access)" % p)
        files_new = absolute_file_access(after) - absolute_file_access(before)
        if files_new:
            v.append("%s: new file access with a literal absolute path: %s" % (p, ", ".join(sorted(files_new))))
        sys_new = system_paths(after) - system_paths(before) - {x for x in base_strs if isinstance(x, str)}
        if sys_new:
            v.append("%s: new string constant naming a system path: %s" % (p, ", ".join(repr(x[:60]) for x in sorted(sys_new))))
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
        for k, line in compared_literals(after, binds):
            if k not in base_lits:
                new_lits.setdefault(k, line)
        if new_lits:
            shown = ", ".join("%s (line %d)" % (val[:40], ln) for (_t, val), ln in sorted(new_lits.items(), key=lambda x: x[1]))
            v.append("%s: comparison or lookup against new literal(s) %s" % (p, shown))
        for s in string_constants(after) - string_constants(before) - base_strs:
            toks = high_entropy_tokens(s)
            if toks:
                v.append("%s: high-entropy string constant %r" % (p, toks[0][:12] + "..."))
        summary.append(p)
    if v:
        return False, "REJECTED: " + "; ".join(v), v
    added = sum(c.added for c in changes)
    removed = sum(c.removed for c in changes)
    return True, ("OK: %d file(s) (%s), +%d/-%d lines; no new imports, dynamic or absolute-path access, request "
                  "reads, literal comparisons or lookups, removed auth checks or secrets" % (len(summary), ", ".join(summary), added, removed)), []


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
