"""Overhead measurement: ``.venv/bin/python -m sidecar.tests.bench [N]``.

Brings up the Node demo stack twice (tracer attached / ``--no-trace``) and reports, per route:
- ``app``: time for the app's response as seen by the sidecar (this is where ptrace overhead lands);
- ``client``: end-to-end latency at the client (includes the grace period and sidecar proxying);
- the L1 reset time and the latest observation arrival relative to the response (``late``).
L2 mode is used for the latency runs so the reset does not run between them; a separate L1 run measures it.
"""
from __future__ import annotations

import re
import statistics
import sys
import time

import httpx

from immune_contracts import wire
from sidecar.tests.dockerenv import Stack

ROUTES = [("/health", {}), ("/download", {"name": "manual.v1.txt"}), ("/safe-search", {"q": "usb"}),
          ("/lookup", {"host": "x"})]
LOG = re.compile(r"GET (\S+) mode=(L\d).*app_ms=([\d.]+) window_ms=([\d.]+).*late_ms=([-\d.na]+)")


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def run(trace: bool, n: int, grace: int, durable: bool = False):
    s = Stack(tag=("bt" if trace else "bn") + str(grace), trace=trace, grace_ms=grace, pg_durable=durable).up()
    try:
        client = {}
        with httpx.Client(timeout=30) as c:
            for path, params in ROUTES:
                for _ in range(5):  # warm the pool
                    c.get(s.url + path, params=params, headers={wire.H_MODE: "L2"})
                ts = []
                for _ in range(n):
                    t = time.perf_counter()
                    r = c.get(s.url + path, params=params, headers={wire.H_MODE: "L2"})
                    ts.append((time.perf_counter() - t) * 1000)
                    assert r.headers[wire.H_VERDICT] in ("clean", "oracle"), r.headers
                client[path] = ts
            t = time.perf_counter()
            for _ in range(n // 2):
                c.get(s.url + "/safe-search", params={"q": "usb"}, headers={wire.H_MODE: "L1"})
            l1_total = (time.perf_counter() - t) * 1000 / (n // 2)
        logs = _all_logs(s)
        app, late = {}, {}
        for m in LOG.finditer(logs):
            if m.group(2) == "L2":
                app.setdefault(m.group(1), []).append(float(m.group(3)))
                if m.group(5) != "nan":
                    late.setdefault(m.group(1), []).append(float(m.group(5)))
        resets = [float(x) for x in re.findall(r"L1 reset ([\d.]+) ms", logs)]
        return client, app, late, resets, l1_total
    finally:
        s.down()


def _all_logs(s):
    import subprocess
    return subprocess.run(["docker", "logs", s.sc], capture_output=True, text=True).stderr


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    grace = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    durable = len(sys.argv) > 3 and sys.argv[3] == "durable"
    res = {t: run(t, n, grace, durable) for t in (False, True)}
    print("postgres:", "durable (fsync on)" if durable else "fsync=off synchronous_commit=off full_page_writes=off")
    print(f"N={n} per route, L2 (no reset between requests), grace_ms={grace}; times in ms, median / p95")
    print(f"{'route':14} {'app no-trace':>14} {'app traced':>14} {'client no-trace':>16} {'client traced':>15}")
    for path, _ in ROUTES:
        a0, a1 = res[False][1].get(path, [0]), res[True][1].get(path, [0])
        c0, c1 = res[False][0][path], res[True][0][path]
        f = lambda xs: f"{statistics.median(xs):6.2f}/{pct(xs, 95):6.2f}"
        print(f"{path:14} {f(a0):>14} {f(a1):>14} {f(c0):>16} {f(c1):>15}")
    for t in (False, True):
        r = res[t][3]
        print(f"L1 reset ({'traced' if t else 'no-trace'}): median {statistics.median(r):.1f} p95 {pct(r, 95):.1f} "
              f"max {max(r):.1f} (n={len(r)}); L1 request incl. reset wait: {res[t][4]:.1f} ms/request")
    late = res[True][2]
    for path, xs in late.items():
        print(f"late observation {path}: max {max(xs):+.2f} ms relative to the response (n={len(xs)})")


if __name__ == "__main__":
    main()
