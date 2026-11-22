"""Runs inside a `--network none` immune-base:1 container (doctor check 1).

Starts the shadow wrapper (`python -m shadow.run --profile <p>`) on 127.0.0.1 inside the container,
polls the health route, and prints one JSON line: {"ok", "status", "verdict", "seconds", "log"}.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request


def main():
    job = json.loads(sys.stdin.read() or "{}")
    port = int(job.get("port") or 8000)
    log_path = "/tmp/shadow.log"
    t0 = time.monotonic()
    with open(log_path, "wb") as log:
        p = subprocess.Popen([sys.executable, "-m", "shadow.run", "--profile", job["profile"], "--host", "127.0.0.1",
                              "--port", str(port)], stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ))
    out = {"ok": False, "status": None, "verdict": None}
    try:
        deadline = time.monotonic() + float(job.get("timeout") or 90)
        while time.monotonic() < deadline:
            if p.poll() is not None:
                out["error"] = "wrapper exited with code %s" % p.returncode
                break
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, job.get("health") or "/health"), timeout=5) as r:
                    out.update(ok=200 <= r.status < 300, status=r.status, verdict=r.headers.get("x-imm-verdict"))
                    break
            except urllib.error.HTTPError as e:
                out.update(status=e.code, verdict=e.headers.get("x-imm-verdict"), error="health returned %d" % e.code)
                break
            except Exception:
                time.sleep(0.5)
        else:
            out["error"] = "no answer on %s within the timeout" % (job.get("health") or "/health")
    finally:
        p.terminate()
        try:
            p.wait(5)
        except Exception:
            p.kill()
    out["seconds"] = round(time.monotonic() - t0, 1)
    try:
        with open(log_path, "rb") as f:
            out["log"] = f.read()[-1500:].decode("utf-8", "replace")
    except OSError:
        pass
    print(json.dumps(out))


if __name__ == "__main__":
    main()
