"""Out-of-process file oracle for any runtime.

It reads a syscall trace (``strace -f -ttt -e trace=openat,execve,connect``) instead of
instrumenting the application, so it works for a C server (Apache), not only Python. The
rule mirrors the in-process shadow oracle: during a single request in flight, a file
*successfully opened outside the directories the server is allowed to serve* — and never
opened during pre-warming — is the exploit firing.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

# Matches open / openat / openat2:
#   "<pid> <ts> open("/path", FLAGS) = <ret>"
#   "<pid> <ts> openat(AT_FDCWD, "/path", FLAGS) = <ret>"   (ret <0 / "-1 ENOENT" = failed)
# APR serves files with plain open(2); NSS/module loading uses openat(2) — we need both.
_OPENAT = re.compile(
    r'^(?P<pid>\d+)\s+(?P<ts>\d+\.\d+)\s+open(?:at2?)?\((?:[^,"]+,\s*)?"(?P<path>(?:[^"\\]|\\.)*)"[^)]*\)\s*=\s*(?P<ret>-?\d+)'
)
_EXEC = re.compile(r'^(?P<pid>\d+)\s+(?P<ts>\d+\.\d+)\s+execve\("(?P<path>(?:[^"\\]|\\.)*)"')


@dataclass
class Open:
    pid: str
    ts: float
    path: str
    ok: bool


def parse_opens(trace: str) -> list[Open]:
    out = []
    for line in trace.splitlines():
        m = _OPENAT.match(line.strip())
        if not m:
            continue
        ret = int(m.group("ret"))
        out.append(Open(m.group("pid"), float(m.group("ts")),
                        _unescape(m.group("path")), ret >= 0))
    return out


def parse_execs(trace: str) -> list[str]:
    return [_unescape(m.group("path")) for line in trace.splitlines()
            if (m := _EXEC.match(line.strip()))]


def _unescape(s: str) -> str:
    return s.encode().decode("unicode_escape")


def _under(path: str, roots: list[str]) -> bool:
    rp = os.path.normpath(path)
    return any(rp == r or rp.startswith(r.rstrip("/") + "/") for r in roots)


class FileEscapeOracle:
    """allowed_roots: absolute directories the server may legitimately read from."""

    def __init__(self, allowed_roots: list[str]):
        self.allowed_roots = [os.path.normpath(r) for r in allowed_roots]
        self.baseline: set[str] = set()

    def prewarm(self, trace: str) -> None:
        """Record every path opened during normal operation (startup + legit traffic)."""
        for o in parse_opens(trace):
            if o.ok and o.path.startswith("/"):
                self.baseline.add(os.path.normpath(o.path))

    def check(self, trace: str) -> list[dict]:
        """Return one event per file opened outside the roots that pre-warming never saw."""
        events, seen = [], set()
        for o in parse_opens(trace):
            p = os.path.normpath(o.path)
            if not (o.ok and p.startswith("/")):
                continue
            if _under(p, self.allowed_roots) or p in self.baseline or p in seen:
                continue
            seen.add(p)
            events.append({"oracle": "file", "detail": {"opened": p, "outside_roots": True},
                           "ts": o.ts})
        return events
