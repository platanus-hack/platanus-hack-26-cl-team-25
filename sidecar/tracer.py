"""Runs strace against the app and feeds parsed observations to a callback (from a reader thread).

Two modes:
- attach (default): the sidecar shares the app container's PID namespace (``--pid container:<app>``)
  and attaches with ``strace -p`` to every process of the app's mount namespace (so the sidecar's own
  processes - uvicorn, the pg proxy, the evidence push - are never traced). Needs CAP_SYS_PTRACE.
- launch: the sidecar starts the app itself as a traced child (``strace -f --seccomp-bpf -- cmd``),
  for when both run in one container (sidecar/README.md, "Tracer"). No extra capability needed; with
  seccomp-bpf only the traced syscalls stop the tracee.
- docker: the sidecar runs outside (on the host, next to the gateway) and starts a tracer container that shares
  the app container's PID namespace: ``docker run --pid=container:<app> … strace -f -p 1``. Nothing is installed
  in the app image and the sidecar needs no capability; the tracer container has no network and only
  SYS_PTRACE + KILL. When the app container is replaced (a redeploy of the shadow) the tracer attaches again
  and ``on_attach`` is called; until then ``alive()`` is false and the sidecar fails closed.
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


def base_args(stack: int = 0) -> list:
    """strace arguments; ``stack`` > 0 adds the native call stack of every traced syscall (-k), at most that many
    frames (sidecar/nativestack.py turns them into the evidence ``stack``)."""
    return BASE_ARGS + (["-k", f"--stack-trace-frame-limit={int(stack)}"] if stack else [])


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


def docker_cmd(container: str, image: str, name: str, label: str = "", stack: int = 0) -> list:
    cmd = ["docker", "run", "--rm", "--name", name, "--pid=container:" + container, "--network", "none",
           "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--cap-add", "KILL"]
    if label:
        cmd += ["--label", label]
    # no -qq: the "attached" message is how we know the tracer is in place
    return cmd + [image] + [a for a in base_args(stack) if a != "-qq"] + ["-p", "1"]


class Tracer:
    def __init__(self, on_obs, mode: str = "attach", command: list[str] | None = None, anchor: int | None = None,
                 seccomp: bool = True, container: str = "", image: str = "immune-strace:1", label: str = "",
                 attempts: bool = False, on_attach=None, stack: int = 0):
        self.on_obs = on_obs
        self.stack = stack                  # > 0: strace -k with this frame limit (native stacks for the evidence)
        self.container, self.image, self.label = container, image, label
        self.name = container + "-strace"
        self.attempts = attempts            # failed opens are observations too (protected-path rule)
        self.on_attach = on_attach          # docker mode: called after every re-attach (not the first)
        self.attached = threading.Event()
        self.stopped = False
        self.output: list[str] = []         # docker mode: last lines that were not syscalls (diagnostics)
        self.mode = mode
        self.command = command or []
        self.anchor = anchor
        self.seccomp = seccomp
        self.proc: subprocess.Popen | None = None
        self.thread: threading.Thread | None = None
        self.pids: list[int] = []
        self.lines = 0
        self.dropped = 0  # strace lines that produced no Syscall: unparsable, or failed in observe (logged per request)
        self.root_pid: int | None = None

    def cwd_of(self, pid: int) -> str | None:
        try:
            return os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            return None

    def app_pids_now(self) -> list[int]:
        """Current app processes (attach: same mount ns as the anchor; launch: strace's descendants)."""
        if self.mode == "docker":
            return []
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

    # ------------------------------------------------------------------ docker mode
    def _spawn_docker(self):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        self.attached.clear()
        self.proc = subprocess.Popen(docker_cmd(self.container, self.image, self.name, self.label, self.stack),
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, encoding="utf-8", errors="surrogateescape")

    def _run_docker(self):
        first = True
        while not self.stopped:
            parser = strace.Parser(default_pid=1)
            for line in self.proc.stdout:
                if line.startswith(("strace:", "+++", "---")) or " +++ " in line:
                    if "attached" in line and not self.attached.is_set():
                        self.attached.set()
                        log.info("tracer attached to container %s", self.container)
                        if not first and self.on_attach:
                            self.on_attach()
                    elif not self.attached.is_set():
                        self.output = (self.output + [line.strip()[:200]])[-5:]
                    continue
                self._line(parser, line)
            self.proc.wait()
            self.attached.clear()
            if self.stopped:
                return
            first = False
            log.info("tracer left container %s; attaching again", self.container)
            time.sleep(1.0)
            if not self.stopped:
                self._spawn_docker()

    def _line(self, parser, line):
        self.lines += 1
        seen = parser.dropped
        try:
            sc = parser.feed(line)
            if sc is None:
                if parser.dropped != seen:
                    self.dropped += 1
                    log.debug("strace line dropped: %r", line[:300])
                return
            obs = strace.observe(sc, None if self.mode == "docker" else self.cwd_of, attempts=self.attempts)
            if obs is not None:
                self.on_obs(obs)
        except Exception:  # never let one odd line kill the reader
            self.dropped += 1
            log.exception("unparsable strace line: %r", line[:300])

    def start(self, timeout: float = 30.0):
        if self.mode == "docker":
            self._spawn_docker()
            self.thread = threading.Thread(target=self._run_docker, daemon=True, name="strace-reader")
            self.thread.start()
            if not self.attached.wait(timeout):
                self.stop()
                raise RuntimeError("tracer did not attach to container %s: %s"
                                   % (self.container, " | ".join(self.output) or "no output"))
            return
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
            args = base_args(self.stack) + ["-o", out] + [x for p in self.pids for x in ("-p", str(p))]
        else:
            args = base_args(self.stack) + (["--seccomp-bpf"] if self.seccomp else []) + ["-o", out, "--"] + self.command
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
                self._line(parser, line)
        log.warning("strace output closed")

    def alive(self) -> bool:
        if self.mode == "docker" and not self.attached.is_set():
            return False
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        self.stopped = True
        if self.mode == "docker":
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
            subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
            return
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()  # strace detaches cleanly on SIGTERM (attach) / kills the child (launch)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
