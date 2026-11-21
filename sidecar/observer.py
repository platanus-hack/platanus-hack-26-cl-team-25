"""Request windows and oracle evaluation (contracts/README.md §5, product.md §6).

Observations arrive from two sources: the strace reader thread (file / exec / fork / net) and the
pg proxy on the event loop (statements). Only those arriving while a request window is open are kept;
everything else is dropped (counted in ``outside``). During warm-up (``learning``) file and net
observations populate the allowlist instead.
"""
from __future__ import annotations

import gzip
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


class Observer:
    def __init__(self, allowed_roots, dns_fires: bool = True):
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
            if self.learning:
                if obs.kind == "file":
                    self.file_allow.add(obs.detail["realpath"])
                elif obs.kind == "net":
                    self.net_allow.add(_net_key(obs.detail))
                return
            if self.current is None:
                self.outside += 1
                return
            self.current.obs.append(obs)
            self.current.times.append(time.perf_counter())

    def on_statement(self, sql: str, ok: bool, error: str | None, via: str):
        with self.lock:
            rec = self.current
            if rec is None:
                return
            if ok:
                rec.statements.append(sql)
            else:
                rec.failed.append((sql, error or ""))

    def begin(self) -> Record:
        with self.lock:
            self.current = Record()
            return self.current

    def end(self) -> Record:
        with self.lock:
            rec, self.current = self.current, None
            return rec

    # ---------------------------------------------------------------- oracles
    def path_allowed(self, real: str) -> bool:
        if real in self.file_allow:
            return True
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
            if o.kind == "file":
                if not self.path_allowed(d["realpath"]):
                    add("file", {"path": d["path"], "realpath": d["realpath"]})
            elif o.kind == "exec":
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
