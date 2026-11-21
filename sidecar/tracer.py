"""Runs strace against the app and feeds parsed observations to a callback (from a reader thread).

Two modes:
- attach (default): the sidecar shares the app container's PID namespace (``--pid container:<app>``)
  and attaches with ``strace -p`` to every process of the app's mount namespace (so the sidecar's own
  processes - uvicorn, the pg proxy, the evidence push - are never traced). Needs CAP_SYS_PTRACE.
- launch: the sidecar starts the app itself as a traced child (``strace -f --seccomp-bpf -- cmd``),
  for when both run in one container (contracts/product.md §6). No extra capability needed; with
  seccomp-bpf only the traced syscalls stop the tracee.
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time

from . import strace

log = logging.getLogger("sidecar.trace")

SYSCALLS = "openat,openat2,open,creat,execve,execveat,connect,sendto,sendmsg,fork,vfork,clone,clone3"
BASE_ARGS = ["strace", "-f", "-y", "-qq", "-s", "4096", "-e", "signal=none", "-e", f"trace={SYSCALLS}"]


def mntns(pid) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/ns/mnt")
    except OSError:
        return None


def app_pids(anchor: int | None = None) -> list[int]:
    """Processes of the app: same mount namespace as ``anchor`` (default: PID 1 of the shared PID namespace)
    and different from ours."""
    mine = mntns("self")
    target = mntns(anchor or 1)
    if target is None or target == mine:
        return []
    out = []
    for d in os.listdir("/proc"):
        if d.isdigit() and mntns(d) == target:
            out.append(int(d))
    return sorted(out)


def traced(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    return int(line.split()[1]) != 0
    except OSError:
        return False
    return False


class Tracer:
    def __init__(self, on_obs, mode: str = "attach", command: list[str] | None = None, anchor: int | None = None,
                 seccomp: bool = True):
        self.on_obs = on_obs
        self.mode = mode
        self.command = command or []
        self.anchor = anchor
        self.seccomp = seccomp
        self.proc: subprocess.Popen | None = None
        self.thread: threading.Thread | None = None
        self.pids: list[int] = []
        self.lines = 0
        self.root_pid: int | None = None

    def cwd_of(self, pid: int) -> str | None:
        try:
            return os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            return None

    def app_pids_now(self) -> list[int]:
        """Current app processes (attach: same mount ns as the anchor; launch: strace's descendants)."""
        if self.mode == "attach":
            return app_pids(self.anchor) or self.pids
        out, todo = [], [self.proc.pid] if self.proc else []
        while todo:
            p = todo.pop()
            try:
                with open(f"/proc/{p}/task/{p}/children") as f:
                    kids = [int(x) for x in f.read().split()]
            except OSError:
                kids = []
            out += kids
            todo += kids
        return out

    def root_dir(self) -> str:
        """Path through which the sidecar sees the app's filesystem."""
        pid = self.root_pid or (self.pids[0] if self.pids else None)
        return f"/proc/{pid}/root" if pid and self.mode == "attach" else "/"

    def start(self, timeout: float = 30.0):
        rfd, wfd = os.pipe()
        out = f"/proc/self/fd/{wfd}"
        if self.mode == "attach":
            end = time.time() + timeout
            while not self.pids and time.time() < end:
                self.pids = app_pids(self.anchor)
                if not self.pids:
                    time.sleep(0.2)
            if not self.pids:
                raise RuntimeError("no app process found in the shared PID namespace (run with --pid container:<app>)")
            self.root_pid = self.pids[0]
            args = BASE_ARGS + ["-o", out] + [x for p in self.pids for x in ("-p", str(p))]
        else:
            args = BASE_ARGS + (["--seccomp-bpf"] if self.seccomp else []) + ["-o", out, "--"] + self.command
        log.info("starting tracer: %s", " ".join(args))
        self.proc = subprocess.Popen(args, pass_fds=(wfd,), stdin=subprocess.DEVNULL)
        os.close(wfd)
        self.thread = threading.Thread(target=self._read, args=(rfd,), daemon=True, name="strace-reader")
        self.thread.start()
        if self.mode == "attach":
            end = time.time() + timeout
            while time.time() < end and not all(traced(p) for p in self.pids if os.path.exists(f"/proc/{p}")):
                if self.proc.poll() is not None:
                    raise RuntimeError(f"strace exited with {self.proc.returncode} (missing CAP_SYS_PTRACE?)")
                time.sleep(0.05)
            log.info("attached to pids %s", self.pids)
        else:
            self.root_pid = self.proc.pid  # the strace process; the app is its child
            self.pids = [self.proc.pid]

    def _read(self, rfd):
        parser = strace.Parser(default_pid=self.pids[0] if self.pids else 0)
        with os.fdopen(rfd, "r", encoding="utf-8", errors="surrogateescape", buffering=1) as f:
            for line in f:
                self.lines += 1
                try:
                    sc = parser.feed(line)
                    if sc is None:
                        continue
                    obs = strace.observe(sc, self.cwd_of)
                    if obs is not None:
                        self.on_obs(obs)
                except Exception:  # never let one odd line kill the reader
                    log.exception("unparsable strace line: %r", line[:300])
        log.warning("strace output closed")

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()  # strace detaches cleanly on SIGTERM (attach) / kills the child (launch)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
