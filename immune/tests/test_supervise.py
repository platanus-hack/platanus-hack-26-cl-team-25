"""immune.supervise: the host processes come back when they die, and stop when told to."""
import json
import os
import signal
import subprocess
import sys
import time

from immune import supervise

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def spec(tmp_path, code):
    return {"name": "t", "argv": [sys.executable, "-c", code], "cwd": str(tmp_path), "env": dict(os.environ),
            "log": str(tmp_path / "logs" / "t.log"), "pidfile": str(tmp_path / "logs" / "t.pid")}


def test_restarts_a_child_that_exits_and_backs_off(tmp_path):
    marker = tmp_path / "starts"
    sp = spec(tmp_path, "open(%r,'a').write('x'); raise SystemExit(3)" % str(marker))
    waits = []

    def sleep(s):
        waits.append(s)

    supervise.run(sp, sleep=sleep, max_starts=3)
    assert marker.read_text() == "xxx"
    log = open(sp["log"]).read()
    assert log.count("exited with 3") == 3 and "restarting in 1 s" in log and "restarting in 2 s" in log
    assert not os.path.exists(sp["pidfile"]) and not os.path.exists(sp["pidfile"] + ".child")


def test_child_output_is_appended_not_truncated(tmp_path):
    sp = spec(tmp_path, "print('hello from the child')")
    os.makedirs(os.path.dirname(sp["log"]))
    open(sp["log"], "w").write("earlier line\n")
    supervise.run(sp, sleep=lambda s: None, max_starts=1)
    log = open(sp["log"]).read()
    assert log.startswith("earlier line\n") and "hello from the child" in log


def _wait(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def _pid(path):
    try:
        return int(open(path).read())
    except (OSError, ValueError):
        return None


def test_real_process_killed_child_returns_and_sigterm_stops_both(tmp_path):
    sp = spec(tmp_path, "import time; time.sleep(300)")
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(sp))
    sup = subprocess.Popen([sys.executable, "-m", "immune.supervise", str(path)], cwd=ROOT,
                           env=dict(os.environ, PYTHONPATH=ROOT))
    try:
        assert _wait(lambda: _pid(sp["pidfile"] + ".child"))
        first = _pid(sp["pidfile"] + ".child")
        assert _pid(sp["pidfile"]) == sup.pid
        os.kill(first, signal.SIGKILL)
        assert _wait(lambda: _pid(sp["pidfile"] + ".child") not in (None, first), 15)
        second = _pid(sp["pidfile"] + ".child")
        sup.send_signal(signal.SIGTERM)
        assert sup.wait(15) == 0

        def gone(pid):
            try:
                os.kill(pid, 0)
                return False
            except OSError:
                return True
        assert _wait(lambda: gone(second))
        assert not os.path.exists(sp["pidfile"])
    finally:
        if sup.poll() is None:
            sup.kill()
