"""python -m immune.supervise <spec.json> — keep one host process (fleet, pipeline) alive.

`immune up` writes the spec (0600: it carries the stack secrets) and starts this supervisor outside the caller's
session: as a transient systemd user unit when there is a user manager, detached otherwise. A process started
from a terminal or an SSH session is killed with that session; the stack must not be.

spec: {"name", "argv", "cwd", "env", "log", "pidfile"}

The child is restarted when it exits, with backoff (1 s doubling to 30 s, back to 1 s after a minute of uptime).
SIGTERM/SIGINT stop the child (SIGKILL after 10 s) and then the supervisor. The pidfile holds the supervisor's
pid; "<pidfile>.child" the current child's.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

BACKOFF_MAX = 30.0
STABLE_AFTER = 60.0
STOP_GRACE = 10.0


def _log(fh, name: str, msg: str) -> None:
    fh.write(("%s supervisor[%s] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), name, msg)).encode())
    fh.flush()


def _write(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def run(spec: dict, sleep=time.sleep, max_starts: int | None = None) -> int:
    name, pidfile = spec["name"], spec["pidfile"]
    os.makedirs(os.path.dirname(spec["log"]), exist_ok=True)
    log = open(spec["log"], "ab")
    stopping = {"flag": False}
    child: dict = {"p": None}

    def on_stop(*_):
        stopping["flag"] = True
        p = child["p"]
        if p is not None and p.poll() is None:
            try:
                p.terminate()
            except OSError:
                pass

    signal.signal(signal.SIGTERM, on_stop)
    signal.signal(signal.SIGINT, on_stop)
    _write(pidfile, str(os.getpid()))
    backoff, starts = 1.0, 0
    try:
        while not stopping["flag"]:
            started = time.time()
            try:
                p = subprocess.Popen(spec["argv"], cwd=spec.get("cwd") or None, env=spec.get("env") or None,
                                     stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            except OSError as e:
                _log(log, name, "cannot start %s: %s" % (spec["argv"], e))
                p = None
            starts += 1
            if p is not None:
                child["p"] = p
                _write(pidfile + ".child", str(p.pid))
                _log(log, name, "started pid %d (start #%d)" % (p.pid, starts))
                while True:
                    try:
                        code = p.wait(timeout=0.5)
                        break
                    except subprocess.TimeoutExpired:
                        if stopping["flag"]:
                            try:
                                code = p.wait(timeout=STOP_GRACE)
                            except subprocess.TimeoutExpired:
                                p.kill()
                                code = p.wait()
                            break
                _log(log, name, "pid %d exited with %s after %.0f s" % (p.pid, code, time.time() - started))
            if stopping["flag"] or (max_starts is not None and starts >= max_starts):
                break
            if time.time() - started >= STABLE_AFTER:
                backoff = 1.0
            delay, backoff = backoff, min(BACKOFF_MAX, backoff * 2)
            _log(log, name, "restarting in %.0f s" % delay)
            waited = 0.0
            while waited < delay and not stopping["flag"]:
                sleep(0.2)
                waited += 0.2
    finally:
        for path in (pidfile, pidfile + ".child"):
            try:
                os.remove(path)
            except OSError:
                pass
        _log(log, name, "supervisor stopped")
        log.close()
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[0]) as f:
        spec = json.load(f)
    return run(spec)


if __name__ == "__main__":
    sys.exit(main())
