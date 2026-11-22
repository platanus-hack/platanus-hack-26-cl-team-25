"""Request windows and oracle evaluation (contracts/README.md §5, product.md §6).

Observations arrive from two sources: the strace reader thread (file / exec / fork / net) and the
pg proxy on the event loop (statements). Only those arriving while a request window is open are kept;
everything else is dropped (counted in ``outside``). During warm-up (``learning``) file and net
observations populate the allowlist instead.

Two file rules:
- allowlist (default): a successful open outside ``allowed_file_roots`` and the warm-up allowlist fires;
- protected (``protected`` globs given, e.g. the files that hold the shadow's planted secrets): only an open of a
  protected path fires, and a failed attempt counts. For apps that legitimately open files all over the disk.

``exec_allow`` / ``net_allow`` are globs (program path, ``address:port``) that never fire.
``learn_background``: what the app does on its own, with no request in flight and none just finished, is
remembered and does not fire later (scheduled jobs, periodic reopens).
"""
from __future__ import annotations

import fnmatch
import gzip
import json
import posixpath
import re
import threading
import time
import zlib

from shadow import inputs as shadow_inputs
from shadow import sqltaint

MARKER_RE = re.compile(rb"MK[A-Z0-9]{10}")
MAX_OWNER_EVENTS = 20
DEFAULT_ALLOW = {"/dev/null", "/dev/urandom", "/dev/random", "/dev/zero", "/dev/tty"}


class Record:
    def __init__(self):
        self.statements: list[str] = []     # executed successfully
        self.failed: list[tuple[str, str]] = []
        self.obs: list = []                 # strace observations
        self.times: list[float] = []        # arrival time of each observation (perf_counter)
        self.bound: list[tuple[str, list]] = []  # judge mode: (statement, bound params) of executed Executes


def _match(key: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(key, p) for p in patterns)


def obs_key(o) -> tuple:
    d = o.detail
    if o.kind == "file":
        return ("file", d["realpath"])
    if o.kind == "exec":
        return ("exec", d["path"])
    if o.kind == "net":
        return ("net",) + _net_key(d)
    return (o.kind,)


class Observer:
    def __init__(self, allowed_roots, dns_fires: bool = True, protected=(), exec_allow=(), net_allow=(),
                 learn_background: bool = False, quiet_s: float = 1.0):
        self.protected = [p for p in protected if p]
        self.exec_allow, self.net_globs = list(exec_allow or []), list(net_allow or [])
        self.learn_background, self.quiet_s = learn_background, quiet_s
        self.background: set[tuple] = set()
        self.background_sql: list[str] = []     # statements seen with no request in flight (structure baseline)
        self.last_end = 0.0
        self.paused = False                     # the app is starting (tracer re-attached): observe nothing
        self.lock = threading.Lock()
        self.current: Record | None = None
        self.learning = False
        self.allowed_roots = [posixpath.normpath(r) for r in allowed_roots if r]
        self.file_allow: set[str] = set(DEFAULT_ALLOW)
        self.net_allow: set[tuple] = set()
        self.dns_fires = dns_fires
        self.outside = 0

    # ---------------------------------------------------------------- feeding
    def on_obs(self, obs):
        with self.lock:
            if self.paused:
                return
            if self.learning:
                if obs.kind == "file":
                    self.file_allow.add(obs.detail["realpath"])
                elif obs.kind == "net":
                    self.net_allow.add(_net_key(obs.detail))
                return
            if self.current is None:
                self.outside += 1
                # not right after a request: a late line of that request must not become "normal"
                if self.learn_background and obs.kind != "fork" and time.time() - self.last_end > self.quiet_s:
                    self.background.add(obs_key(obs))
                return
            self.current.obs.append(obs)
            self.current.times.append(time.perf_counter())

    def on_statement(self, sql: str, ok: bool, error: str | None, via: str):
        with self.lock:
            rec = self.current
            if rec is None:
                if len(self.background_sql) < 5000:
                    self.background_sql.append(sql)
                return
            if ok:
                rec.statements.append(sql)
            else:
                rec.failed.append((sql, error or ""))

    def on_bound(self, sql: str, params: list):
        with self.lock:
            if self.current is not None:
                self.current.bound.append((sql, list(params or [])))

    def begin(self) -> Record:
        with self.lock:
            self.current = Record()
            return self.current

    def end(self) -> Record:
        with self.lock:
            rec, self.current = self.current, None
            self.last_end = time.time()
            return rec

    def take_background_sql(self) -> list[str]:
        with self.lock:
            out, self.background_sql = self.background_sql, []
            return out

    # ---------------------------------------------------------------- oracles
    def path_allowed(self, real: str) -> bool:
        if real in self.file_allow:
            return True
        if self.protected:
            return not _match(real, self.protected)
        for root in self.allowed_roots:
            if real == root or real.startswith(root.rstrip("/") + "/"):
                return True
        return False

    def system_events(self, rec: Record) -> list[dict]:
        events, seen = [], set()
        execed = {o.pid for o in rec.obs if o.kind == "exec"}

        def add(kind, detail):
            key = (kind, repr(sorted(detail.items())))
            if key not in seen:
                seen.add(key)
                events.append({"oracle": kind, "detail": detail, "stack": []})

        for o in rec.obs:
            d = o.detail
            if o.kind != "fork" and obs_key(o) in self.background:
                continue
            if o.kind == "file":
                if d.get("result") and not self.protected:
                    continue  # a failed open only matters for a protected path
                if not self.path_allowed(d["realpath"]):
                    add("file", {k: d[k] for k in ("path", "realpath", "result") if k in d})
            elif o.kind == "exec":
                if not _match(d["path"], self.exec_allow):
                    add("proc", {"path": d["path"], "argv": d["argv"]})
            elif o.kind == "fork":
                if d["child"] not in execed:  # fork without exec (exec'd children are reported by execve)
                    add("proc", {"syscall": d["syscall"], "child": d["child"]})
            elif o.kind == "net":
                if self.net_fires(d):
                    add("net", {"family": d["family"], "address": d["address"], "port": d["port"],
                                "syscall": d["syscall"]})
        return events

    def net_fires(self, d) -> bool:
        from .strace import is_loopback
        fam = d["family"]
        if self.net_globs and _match("%s:%s" % (d.get("address"), d.get("port")), self.net_globs):
            return False
        if fam in ("AF_INET", "AF_INET6"):
            if d["port"] == 53:
                return self.dns_fires  # a name lookup during a request (SSRF to a hostname)
            if is_loopback(d["address"]):
                return False  # the app talking to itself or to the sidecar's pg proxy
            return _net_key(d) not in self.net_allow
        if fam == "AF_UNIX":
            return _net_key(d) not in self.net_allow
        return fam not in ("AF_NETLINK",)


def _net_key(d):
    return (d.get("family"), d.get("address"), d.get("port"))


def sql_events(statements, ins, constants) -> list[dict]:
    """Taint check (shadow.sqltaint) of the request inputs against successfully executed statements.
    No stack frames are available from outside the process."""
    return sqltaint.check([(s, []) for s in statements], ins, constants)


def extract_inputs(path, query, headers, body):
    return shadow_inputs.extract(path, query, headers, body, None)


def decoded_body(headers: dict, body: bytes) -> bytes:
    enc = headers.get("content-encoding", "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body)
    except Exception:
        pass
    return body


def owner_events(markers: dict, public: list, path: str, headers: dict, body: bytes, uid, role,
                 other_fired: bool) -> list[dict]:
    """Same rule as shadow.core.Engine.owner_events."""
    if not markers or role == "admin":
        return []
    owners = set()
    for m in MARKER_RE.findall(decoded_body(headers, body)):
        o = markers.get(m.decode())
        if o is not None and o != uid:
            owners.add(o)
    if not owners:
        return []
    if is_public(public, path) and not (other_fired or len(owners) >= 2):
        return []
    return [{"oracle": "owner", "detail": {"marker_owner": o, "requester": uid}, "stack": []}
            for o in sorted(owners)[:MAX_OWNER_EVENTS]]


def is_public(public, path) -> bool:
    for p in public:
        if path == p or path.startswith(p if p.endswith("/") else p + "/"):
            return True
    return False


# ---------------------------------------------------------------- file markers (planted secrets)
def load_file_markers(path: str | None) -> dict:
    """Markers planted in files of the shadow: {marker: {"path": file it lives in, ...}}. The same JSON may also
    hold owner markers ({marker: uid}); those belong to the owner oracle (identity.Identity.markers)."""
    if not path:
        return {}
    try:
        with open(path) as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {}
    return {str(m): v for m, v in raw.items() if isinstance(v, dict) and v.get("path")}


def marker_events(file_markers: dict, headers: dict, body: bytes, system: list[dict]) -> list[dict]:
    """`file` events for markers found in the response, merged with the syscall events of the same file
    (detail ``observed``: response | response+syscall). Returns the full event list."""
    if not file_markers:
        return system
    text = decoded_body(headers, body)
    by_path = {}
    for m, info in file_markers.items():
        if m.encode() in text and info["path"] not in by_path:
            by_path[info["path"]] = {"oracle": "file", "stack": [],
                                     "detail": {"path": info["path"], "realpath": info["path"], "marker": m,
                                                "observed": "response"}}
    rest = []
    for e in system:
        hit = by_path.get(e["detail"].get("realpath")) if e["oracle"] == "file" else None
        if hit and not e["detail"].get("result"):
            hit["detail"]["observed"] = "response+syscall"
        else:
            rest.append(e)
    return list(by_path.values()) + rest


def from_config(cfg, file_markers: dict | None = None, extra_allow=()) -> "Observer":
    """The observer a config describes; paths of file markers are protected."""
    protected = list(cfg.protected_paths or [])
    protected += sorted({i["path"] for i in (file_markers or {}).values()} - set(protected))
    protected = [p for p in protected if p not in set(extra_allow)]
    return Observer(cfg.allowed_file_roots, protected=protected, exec_allow=cfg.exec_allow,
                    net_allow=cfg.net_allow, learn_background=cfg.learn_background)
