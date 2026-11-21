"""Syscall oracle: which files the shadow app opens, seen from outside its process (docs/plan-producto.md §6b).

A tracer container shares the app container's PID namespace and runs `strace -f -e trace=open,openat -p 1`.
Nothing is installed in the app image and the app is not restarted. The sidecar handles one request at a
time, so every open of a protected path between "request sent" and "response received" belongs to that
request. A protected path the app opens on its own (no request in flight) is learnt as background and ignored.

Language independent: it only needs the app to be a Linux process. Failed opens count too (the attempt is
the signal). While the tracer is not attached (start-up, shadow redeploy) the sidecar falls back to markers.
"""
from __future__ import annotations

import asyncio
import fnmatch
import logging
import posixpath
import re
import time
from collections import deque

log = logging.getLogger("sidecar.syscalls")

LINE = re.compile(r'^(?:\[pid\s+\d+\]\s+)?(\d+\.\d+) open(?:at)?\('
                  r'(?:AT_FDCWD(?:<([^>]*)>)?, |\d+(?:<([^>]*)>)?, )?"((?:[^"\\]|\\.)*)"(.*)$')
RESULT = re.compile(r'\) = (-?\d+)(?: (E[A-Z]+))?')


def parse_line(line: str):
    """One strace line -> {"ts", "path", "realpath", "result"} or None. result: "ok", an errno name, or "?"."""
    m = LINE.match(line.strip())
    if not m:
        return None
    ts, cwd, dirfd, path, rest = m.groups()
    base = cwd or dirfd or "/"
    real = posixpath.normpath(path if path.startswith("/") else posixpath.join(base, path))
    r = RESULT.search(rest)
    result = "?" if not r else ("ok" if int(r.group(1)) >= 0 else (r.group(2) or "error"))
    return {"ts": float(ts), "path": path, "realpath": real, "result": result}


def is_protected(realpath: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(realpath, p) for p in patterns)


def tracer_cmd(container: str, image: str, name: str, label: str = "") -> list:
    cmd = ["docker", "run", "--rm", "--name", name, "--pid=container:" + container, "--network", "none",
           "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--cap-add", "KILL"]
    if label:
        cmd += ["--label", label]
    return cmd + [image, "strace", "-f", "-y", "-qq", "-ttt", "-e", "trace=open,openat", "-e", "signal=none",
                  "-p", "1"]


class Tracer:
    def __init__(self, cmd: list, patterns, settle_s: float = 0.1, name: str = ""):
        self.cmd, self.patterns, self.settle_s, self.name = cmd, list(patterns), settle_s, name
        self.opens = deque(maxlen=4096)     # protected opens not yet assigned to a request
        self.background = set()             # protected paths the app opens on its own
        self.last_ts = 0.0
        self.attached = False
        self._task = self._proc = None

    def feed(self, line: str):
        ev = parse_line(line)
        if not ev:
            return
        self.attached = True
        self.last_ts = max(self.last_ts, ev["ts"])
        if is_protected(ev["realpath"], self.patterns):
            self.opens.append(ev)

    def take(self, t0: float, t1: float) -> list:
        """Protected opens inside [t0, t1], one per realpath. Earlier ones were background."""
        hits, later = {}, []
        for ev in self.opens:
            if ev["ts"] < t0:
                if ev["realpath"] not in self.background:
                    log.info("background open of %s: ignored from now on", ev["realpath"])
                self.background.add(ev["realpath"])
            elif ev["ts"] <= t1:
                hits.setdefault(ev["realpath"], ev)
            else:
                later.append(ev)
        self.opens = deque(later, maxlen=4096)
        return [ev for p, ev in hits.items() if p not in self.background]

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
        while True:     # the shadow container is replaced on every deploy: attach again
            try:
                await self._kill()
                self._proc = await asyncio.create_subprocess_exec(
                    *self.cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                async for raw in self._proc.stdout:
                    line = raw.decode("utf-8", "replace")
                    if not self.attached and not parse_line(line):
                        if "attached" not in line:
                            log.info("tracer: %s", line.strip()[:200])
                        if "attached" in line:
                            self.attached = True
                        continue
                    self.feed(line)
                await self._proc.wait()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("tracer failed: %s", e)
            if self.attached:
                log.info("tracer detached; attaching again")
            self.attached = False
            await asyncio.sleep(1.0)
