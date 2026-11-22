"""Syscall oracles: what the shadow app does, seen from outside its process (docs/plan-producto.md §6b).

A tracer container shares the app container's PID namespace and runs
`strace -f -e trace=open,openat,execve,execveat,connect -p 1`. Nothing is installed in the app image and
the app is not restarted. Three oracles come out of it:

  file  the process opened a protected path (failed opens count: the attempt is the signal);
  proc  the process, or a child, executed a program;
  net   the process connected to an IP address (AF_UNIX is ignored).

The sidecar handles one request at a time, so everything between "request sent" and "response received"
belongs to that request. What the app does on its own (no request in flight) is learnt as background and
ignored from then on. `Policy` holds the protected paths and the exec / connect allowlists.

Language independent: it only needs the app to be a Linux process. While the tracer is not attached
(start-up, shadow redeploy) the sidecar falls back to markers.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import posixpath
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field

log = logging.getLogger("sidecar.marker.syscalls")

HEAD = re.compile(r'^(?:\[pid\s+\d+\]\s+)?(\d+\.\d+) (open|openat|execve|execveat|connect)\((.*)$')
OPEN = re.compile(r'^(?:AT_FDCWD(?:<([^>]*)>)?, |\d+(?:<([^>]*)>)?, )?"((?:[^"\\]|\\.)*)"')
EXEC = re.compile(r'^(?:AT_FDCWD(?:<[^>]*>)?, |\d+(?:<[^>]*>)?, )?"((?:[^"\\]|\\.)*)", \[(.*?)\](?:, |\.\.\.)')
ARG = re.compile(r'"((?:[^"\\]|\\.)*)"')
INET = re.compile(r'sa_family=AF_INET, sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)')
INET6 = re.compile(r'sa_family=AF_INET6, sin6_port=htons\((\d+)\),.*?inet_pton\(AF_INET6, "([^"]+)"')
RESULT = re.compile(r'\) = (-?\d+)(?: (E[A-Z]+))?')
NOT_FAILED = {"ok", "?", "EINPROGRESS"}     # a non-blocking connect reports EINPROGRESS


def parse_line(line: str):
    """One strace line -> {"kind": file|proc|net, "ts", "key", "result", ...} or None.

    result: "ok", an errno name, or "?" (the call had not returned when the line was printed).
    key is what the policy matches: the normalised path, the program path, or "ip:port".
    """
    m = HEAD.match(line.strip())
    if not m:
        return None
    ts, call, rest = float(m.group(1)), m.group(2), m.group(3)
    r = RESULT.search(rest)
    result = "?" if not r else ("ok" if int(r.group(1)) >= 0 else (r.group(2) or "error"))
    if call in ("open", "openat"):
        o = OPEN.match(rest)
        if not o:
            return None
        cwd, dirfd, path = o.groups()
        real = posixpath.normpath(path if path.startswith("/") else posixpath.join(cwd or dirfd or "/", path))
        return {"kind": "file", "ts": ts, "key": real, "path": path, "realpath": real, "result": result}
    if call in ("execve", "execveat"):
        e = EXEC.match(rest)
        if not e:
            return None
        return {"kind": "proc", "ts": ts, "key": e.group(1), "args": [e.group(1)] + ARG.findall(e.group(2))[:8],
                "result": result}
    a = INET.search(rest) or INET6.search(rest)
    if not a:
        return None                         # AF_UNIX, AF_NETLINK ...
    addr = "%s:%s" % (a.group(2), a.group(1))
    return {"kind": "net", "ts": ts, "key": addr, "address": addr, "result": result}


def _match(key: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(key, p) for p in patterns)


@dataclass
class Policy:
    protected: list = field(default_factory=list)    # path globs: opening one is a `file` event
    exec_allow: list = field(default_factory=list)   # program path globs the app may execute
    net_allow: list = field(default_factory=list)    # "ip:port" globs the app may connect to
    prod_ignore: list = field(default_factory=list)  # protected paths prod opens in normal operation (prodwatch)

    @classmethod
    def load(cls, path: str = "", extra_protected=()) -> "Policy":
        raw = {}
        if path:
            with open(path) as f:
                raw = json.load(f)
        prot = sorted(set(raw.get("protected") or []) | {p for p in extra_protected if p})
        return cls(prot, list(raw.get("exec_allow") or []), list(raw.get("net_allow") or []),
                   list(raw.get("prod_ignore") or []))

    def relevant(self, ev: dict) -> bool:
        if ev["kind"] == "file":
            return _match(ev["key"], self.protected)
        if ev["kind"] == "proc":
            return not _match(ev["key"], self.exec_allow)
        return not _match(ev["key"], self.net_allow)


def tracer_cmd(container: str, image: str, name: str, label: str = "") -> list:
    cmd = ["docker", "run", "--rm", "--name", name, "--pid=container:" + container, "--network", "none",
           "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--cap-add", "KILL"]
    if label:
        cmd += ["--label", label]
    return cmd + [image, "strace", "-f", "-y", "-qq", "-ttt", "-s", "256",
                  "-e", "trace=open,openat,execve,execveat,connect", "-e", "signal=none", "-p", "1"]


class Collector:
    """Keeps the policy-relevant events and assigns them to request windows."""

    def __init__(self, policy: Policy, settle_s: float = 0.1):
        self.policy, self.settle_s = policy, settle_s
        self.pending = []                   # relevant events not yet assigned to a request
        self.background = set()             # (kind, key) the app does on its own
        self.last_ts = 0.0
        self.attached = False

    def feed(self, line: str) -> bool:
        ev = parse_line(line)
        if not ev:
            return False
        self.attached = True
        self.last_ts = max(self.last_ts, ev["ts"])
        if self.policy.relevant(ev):
            self.pending.append(ev)
            del self.pending[:-4096]
        return True

    def take(self, t0: float, t1: float) -> list:
        """Relevant events inside [t0, t1], one per (kind, key). Earlier ones were background."""
        hits, later = {}, []
        for ev in self.pending:
            k = (ev["kind"], ev["key"])
            if ev["ts"] < t0:
                if k not in self.background:
                    log.info("background %s %s: ignored from now on", *k)
                self.background.add(k)
            elif ev["ts"] <= t1:
                if k not in hits or (hits[k]["result"] not in NOT_FAILED and ev["result"] in NOT_FAILED):
                    hits[k] = ev            # Go retries exec/connect: keep the attempt that worked
            else:
                later.append(ev)
        self.pending = later
        return [ev for k, ev in hits.items() if k not in self.background]


class Tracer(Collector):
    """asyncio runner (the sidecar). Attaches again when the app container is replaced."""

    def __init__(self, cmd: list, policy: Policy, settle_s: float = 0.1, name: str = ""):
        super().__init__(policy, settle_s)
        self.cmd, self.name = cmd, name
        self._task = self._proc = None

    async def window(self, t0: float, t1: float) -> list:
        """Wait until the tracer has reported past t1 (or settle_s), then take()."""
        if not self.attached:
            return []
        deadline = time.time() + self.settle_s
        while self.last_ts <= t1 and time.time() < deadline:
            await asyncio.sleep(0.005)
        return self.take(t0 - 0.005, t1 + 0.005)

    async def start(self):
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        if self._task:
            self._task.cancel()
        await self._kill()

    async def _kill(self):
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
        if self.name:
            p = await asyncio.create_subprocess_exec("docker", "rm", "-f", self.name,
                                                     stdout=asyncio.subprocess.DEVNULL,
                                                     stderr=asyncio.subprocess.DEVNULL)
            await p.wait()

    async def _run(self):
        while True:
            try:
                await self._kill()
                self._proc = await asyncio.create_subprocess_exec(
                    *self.cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, limit=1 << 20)
                async for raw in self._proc.stdout:
                    line = raw.decode("utf-8", "replace")
                    if not self.feed(line) and not self.attached:
                        log.info("tracer: %s", line.strip()[:200])
                await self._proc.wait()
            except asyncio.CancelledError:
                raise
            except Exception as e:      # noqa: BLE001
                log.warning("tracer failed: %s", e)
            if self.attached:
                log.info("tracer detached; attaching again")
            self.attached = False
            await asyncio.sleep(1.0)


class SyncTracer(Collector):
    """Thread runner for synchronous callers (the CI `poc` gate). Use as a context manager."""

    def __init__(self, cmd: list, policy: Policy, settle_s: float = 0.15, name: str = ""):
        super().__init__(policy, settle_s)
        self.cmd, self.name = cmd, name
        self._proc = None
        self.output = []

    def _read(self):
        for line in self._proc.stdout:
            if not self.feed(line):
                self.output.append(line.strip()[:200])

    def __enter__(self):
        if self.name:
            subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        self._proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                      errors="replace")
        threading.Thread(target=self._read, daemon=True).start()
        return self

    def __exit__(self, *exc):
        if self._proc.poll() is None:
            self._proc.terminate()
        if self.name:
            subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)

    def wait_attached(self, probe, timeout_s: float = 15.0) -> bool:
        """probe() must make the app do any traced syscall (a legit request)."""
        deadline = time.time() + timeout_s
        while time.time() < deadline and self._proc.poll() is None:
            probe()
            time.sleep(0.2)
            if self.attached:
                time.sleep(0.3)
                self.take(time.time() + 1, time.time() + 1)     # whatever the warm-up did is background
                self.background.clear()
                return True
        return False

    def window(self, t0: float, t1: float) -> list:
        deadline = time.time() + self.settle_s
        while self.last_ts <= t1 and time.time() < deadline:
            time.sleep(0.005)
        return self.take(t0 - 0.005, t1 + 0.005)
