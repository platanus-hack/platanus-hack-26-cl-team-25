"""Helpers shared by the acceptance tests (victim, shadow, gateway)."""
import os, socket, subprocess, sys, threading, time
import httpx, uvicorn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PY = os.path.join(ROOT, ".venv", "Scripts" if sys.platform == "win32" else "bin",
                   "python.exe" if sys.platform == "win32" else "python")
PY = _PY if os.path.exists(_PY) else sys.executable
PYPATH = os.pathsep.join([ROOT, os.path.join(ROOT, "acceptance", "fixture")])


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def wait_http(url: str, timeout: float = 20.0, headers=None) -> None:
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            r = httpx.get(url, timeout=1.0, headers=headers)
            if r.status_code < 500:
                return
            last = r.status_code
        except Exception as e:  # noqa
            last = e
        time.sleep(0.15)
    raise RuntimeError(f"not up: {url}: {last}")


class ThreadServer:
    """Run an ASGI app on 127.0.0.1:<port> in a background thread."""
    def __init__(self, app, port=None):
        self.port = port or free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        end = time.time() + 10
        while not self.server.started and time.time() < end:
            time.sleep(0.05)
        self.addr = f"127.0.0.1:{self.port}"
        self.url = f"http://{self.addr}"

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=5)


def spawn(args, env, cwd=ROOT):
    full = dict(os.environ); full.update(env); full["PYTHONPATH"] = PYPATH
    return subprocess.Popen([PY, *args], env=full, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def kill(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    out = b""
    try:
        out = proc.stdout.read() if proc and proc.stdout else b""
    except Exception:
        pass
    return out.decode(errors="replace")
