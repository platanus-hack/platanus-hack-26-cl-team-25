"""Process-wide instrumentation: sqlite3 wrapper + audit hook + FileResponse stack capture.

Installed once per process, BEFORE the app is imported. Everything here is inert
unless a request is in flight (``STATE.current`` is set) or warm-up is learning
(``STATE.learning``). The wrapper processes one request at a time per process, so
every event observed while ``STATE.current`` is set belongs to that request,
whichever thread (event loop or anyio worker) produced it.

Stack frames: only frames whose file is inside the release's app paths (``app.release_paths``
of .immune/config.yaml; default: the app's top-level package), with the path relative to the
release root (default: the directory that contains the package, e.g. ``victim/app/products.py``). Order: **outermost first, innermost (the sink)
last**, like a Python traceback.
"""
from __future__ import annotations

import importlib
import os
import sqlite3
import sys
import threading

from immune_contracts import wire

ORIG_CONNECT = sqlite3.connect

_IMPORTLIB_DIR = os.path.dirname(os.path.realpath(importlib.__file__)) + os.sep

FILE_EVENTS = {"open", "os.listdir", "os.scandir"}
PROC_EVENTS = {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork",
               "os.forkpty", "pty.spawn", "os.startfile"}
NET_EVENTS = {"socket.connect", "socket.sendto", "socket.sendmsg", "socket.getaddrinfo",
              "socket.gethostbyname", "socket.gethostbyname_ex", "socket.gethostbyaddr"}
_ALL_EVENTS = FILE_EVENTS | PROC_EVENTS | NET_EVENTS

# Opens performed by these stdlib modules are never attributed to the request.
_EXEMPT_FILES = ("linecache.py", "tokenize.py")


class RequestRecord:
    """Everything observed while one request runs."""

    def __init__(self):
        self.statements = []   # (sql, stack) executed successfully
        self.failed = []       # (sql, error) statements that raised
        self.events = []       # file/proc/net events, already final
        self._keys = set()
        self.file_stacks = {}  # realpath -> stack captured at FileResponse(...) construction

    def add(self, oracle, detail, stack):
        key = (oracle, repr(sorted(detail.items())))
        if key in self._keys:
            return
        self._keys.add(key)
        self.events.append({"oracle": oracle, "detail": detail, "stack": stack})


class _State:
    def __init__(self):
        self.installed = False
        self.current: RequestRecord | None = None
        self.learning = False
        self.app_roots = []        # realpaths of the app paths (dirs end with os.sep)
        self.release_root = None   # stack paths are relative to this dir
        self.allowed_roots = []    # realpaths
        self.allowlist = {"/dev/null", "/dev/urandom", "/dev/random"}
        self._rel_cache = {}


STATE = _State()
_tls = threading.local()


def configure(app_pkg_dir: str, allowed_roots: list[str], release_root: str | None = None,
              release_paths: list[str] | None = None) -> None:
    root = os.path.realpath(app_pkg_dir).rstrip(os.sep)
    STATE.release_root = os.path.realpath(release_root) if release_root else os.path.dirname(root)
    paths = [os.path.realpath(os.path.join(STATE.release_root, p)) for p in (release_paths or []) if p]
    STATE.app_roots = [p + os.sep if os.path.isdir(p) else p for p in (paths or [root])]
    STATE.allowed_roots = [os.path.realpath(r) for r in allowed_roots if r]
    STATE._rel_cache.clear()


def _rel(filename: str):
    cache = STATE._rel_cache
    if filename in cache:
        return cache[filename]
    rel = None
    if STATE.app_roots and not filename.startswith("<"):
        real = os.path.realpath(filename)
        if any(real == r or (r.endswith(os.sep) and real.startswith(r)) for r in STATE.app_roots):
            rel = os.path.relpath(real, STATE.release_root).replace(os.sep, "/")
    cache[filename] = rel
    return rel


def capture_stack(skip: int = 1) -> list[dict]:
    frames = []
    f = sys._getframe(skip)
    while f is not None:
        rel = _rel(f.f_code.co_filename)
        if rel is not None:
            frames.append({"file": rel, "line": f.f_lineno, "func": f.f_code.co_name})
        f = f.f_back
    frames.reverse()
    return frames


def path_allowed(real: str) -> bool:
    if real in STATE.allowlist:
        return True
    for root in STATE.allowed_roots:
        if real == root or real.startswith(root.rstrip(os.sep) + os.sep):
            return True
    return False


def _exempt_by_frames() -> bool:
    f = sys._getframe(2)
    while f is not None:
        fn = f.f_code.co_filename
        if fn.startswith("<frozen importlib") or fn.startswith(_IMPORTLIB_DIR) or fn.endswith(_EXEMPT_FILES):
            return True
        f = f.f_back
    return False


# ---------------------------------------------------------------- audit hook
def _hook(event, args):
    if event not in _ALL_EVENTS:
        return
    rec = STATE.current
    if rec is None and not STATE.learning:
        return
    if getattr(_tls, "busy", False):
        return
    _tls.busy = True
    try:
        if event in FILE_EVENTS:
            _on_file(rec, event, args)
        elif rec is not None and not STATE.learning:
            if event in PROC_EVENTS:
                detail = {"event": event, "args": _short(args[:2] if event != "os.system" else args)}
                argv = _argv(event, args)
                if argv:
                    detail["argv"] = argv      # structured, for the input -> effect correlation (shadow/effects.py)
                rec.add(wire.ORACLE_PROC, detail, capture_stack(1))
            else:
                addr = args[1] if event in ("socket.connect", "socket.sendto", "socket.sendmsg") and len(args) > 1 else args[:2]
                detail = {"event": event, "address": _short(addr)}
                detail.update(_hostport(addr))
                rec.add(wire.ORACLE_NET, detail, capture_stack(1))
    except Exception:  # never break the app because of the oracle
        pass
    finally:
        _tls.busy = False


def _argv(event, args) -> list:
    """The command line of a proc event as strings: Popen/exec/spawn carry an argv list, os.system a command."""
    try:
        if event == "os.system":
            return [os.fsdecode(args[0])]
        for a in args[:3]:
            if isinstance(a, (list, tuple)) and all(isinstance(x, (str, bytes, os.PathLike)) for x in a):
                return [os.fsdecode(x) for x in a][:40]
        return [os.fsdecode(args[0])] if args and isinstance(args[0], (str, bytes, os.PathLike)) else []
    except Exception:
        return []


def _hostport(addr) -> dict:
    """{"host": ..., "port": ...} of a socket address tuple ((host, port) / (host,)); {} for anything else."""
    try:
        if isinstance(addr, (tuple, list)) and addr and isinstance(addr[0], (str, bytes)):
            out = {"host": os.fsdecode(addr[0])}
            if len(addr) > 1 and isinstance(addr[1], int):
                out["port"] = addr[1]
            return out
    except Exception:
        pass
    return {}


def _short(obj, n=300):
    s = repr(obj)
    return s if len(s) <= n else s[:n] + "..."


def _on_file(rec, event, args):
    path = args[0] if args else None
    if path is None or isinstance(path, int):
        return
    try:
        path = os.fsdecode(os.fspath(path))
    except TypeError:
        return
    real = os.path.realpath(path)
    if STATE.learning:
        STATE.allowlist.add(real)
        return
    if path_allowed(real) or _exempt_by_frames():
        return
    stack = capture_stack(1)
    if not stack:
        stack = rec.file_stacks.get(real, [])
    detail = {"path": path, "realpath": real}
    if event != "open":
        detail["op"] = event
    rec.add(wire.ORACLE_FILE, detail, stack)


# ---------------------------------------------------------------- sqlite3
def _record(sql, ok, err=None):
    rec = STATE.current
    if rec is None or STATE.learning or not isinstance(sql, str):
        return
    if ok:
        rec.statements.append((sql, capture_stack(1)))
    else:
        rec.failed.append((sql, repr(err)))


class CursorMixin:
    def execute(self, sql, *a, **k):
        try:
            r = super().execute(sql, *a, **k)
        except Exception as e:
            _record(sql, False, e)
            raise
        _record(sql, True)
        return r

    def executemany(self, sql, *a, **k):
        try:
            r = super().executemany(sql, *a, **k)
        except Exception as e:
            _record(sql, False, e)
            raise
        _record(sql, True)
        return r

    def executescript(self, script, *a, **k):
        try:
            r = super().executescript(script, *a, **k)
        except Exception as e:
            _record(script, False, e)
            raise
        _record(script, True)
        return r


class Cursor(CursorMixin, sqlite3.Cursor):
    pass


_mixed = {}


def _mix(mixin, base, default):
    if base is None or base is default.__bases__[-1]:
        return default
    if issubclass(base, mixin):
        return base
    key = (mixin, base)
    if key not in _mixed:
        _mixed[key] = type("Instrumented" + base.__name__, (mixin, base), {})
    return _mixed[key]


class ConnectionMixin:
    def cursor(self, factory=None, *a, **k):
        return super().cursor(_mix(CursorMixin, factory, Cursor), *a, **k)

    def execute(self, sql, *a):
        return self.cursor().execute(sql, *a)

    def executemany(self, sql, *a):
        return self.cursor().executemany(sql, *a)

    def executescript(self, script):
        return self.cursor().executescript(script)


class Connection(ConnectionMixin, sqlite3.Connection):
    pass


def connect(*args, **kwargs):
    args = list(args)
    if len(args) > 5:
        kwargs["factory"] = args[5]
        args[5:6] = []
        if len(args) > 5:  # keep the remaining positionals as keywords
            for name, val in zip(("cached_statements", "uri", "autocommit"), args[5:]):
                kwargs[name] = val
            del args[5:]
    kwargs["factory"] = _mix(ConnectionMixin, kwargs.get("factory"), Connection)
    return ORIG_CONNECT(*args, **kwargs)


# ---------------------------------------------------------------- install
def _patch_file_response():
    try:
        from starlette import responses
    except Exception:
        return
    cls = responses.FileResponse
    if getattr(cls.__init__, "_shadow", False):
        return
    orig = cls.__init__

    def __init__(self, path, *a, **k):
        rec = STATE.current
        if rec is not None and not STATE.learning:
            try:
                rec.file_stacks[os.path.realpath(os.fspath(path))] = capture_stack(1)
            except Exception:
                pass
        return orig(self, path, *a, **k)

    __init__._shadow = True
    cls.__init__ = __init__


def install() -> None:
    """Idempotent. Must run before the app module is imported."""
    if STATE.installed:
        return
    sqlite3.connect = connect
    sqlite3.dbapi2.connect = connect
    _patch_file_response()
    sys.addaudithook(_hook)
    STATE.installed = True
