"""python -m sidecar.prodwatch : the syscall oracles on PRODUCTION, alert only (never blocks, never slows).

The clone only sees what the gateway sends it. If a payload is classified clean, or traffic reaches the app
without passing the gateway, it runs in prod: this watcher is what notices. For each prod container it runs
an eBPF tracer (bpftrace, filtered by the container's cgroup: no ptrace, the app is not stopped) on
openat / execve / connect and applies the same rules as the sidecar: same config file, same observer
(sidecar/observer.py), minus `prod_ignore`.

On a policy hit:
  1. find the requests the gateway recorded as sent to prod around that instant (RECORD_PATH);
  2. replay each one on the shadow clone through the sidecar, where the oracles attribute per request;
  3. a replay that fires there is confirmed: the sidecar pushes its evidence and the pipeline opens the
     incident (PoC, containment rule, patch) exactly as if the gateway had detonated it;
  4. publish `prod.alert` on the bus with the candidates and what was confirmed.

No candidate means the traffic bypassed the gateway, or the app did it on its own.

Detection after the fact: the request already ran in prod. What this buys is knowing, and the rule before the
next attempt. What a container does in its first PROD_GRACE_S seconds (start-up) is learnt as normal.

env: PROD_CONTAINERS (comma separated; the ones not running are waited for), SIDECAR_CONFIG, MARKERS_PATH,
     RECORD_PATH, REPRO_URL (sidecar), BUS_URL, BUS_TOKEN, RUN_ID, BPF_IMAGE, PROD_GRACE_S, PROD_COOLDOWN_S.
The tracer container is --privileged (eBPF needs it); it has no network and runs a fixed program.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import queue
import subprocess
import threading
import time
import uuid
from datetime import datetime

import httpx

from immune_contracts import events as E
from immune_contracts import wire
from . import config as cfgmod
from . import observer, strace

log = logging.getLogger("prodwatch")

PROGRAM = r'''
tracepoint:syscalls:sys_enter_openat /cgroup == cgroupid("CG")/ { printf("openat(AT_FDCWD, \"%s\", O_RDONLY) = 3\n", str(args->filename)); }
tracepoint:syscalls:sys_enter_execve /cgroup == cgroupid("CG")/ { printf("execve(\"%s\", [], 0) = 0\n", str(args->filename)); }
tracepoint:syscalls:sys_enter_connect /cgroup == cgroupid("CG")/ {
  $sa = (struct sockaddr *)args->uservaddr;
  if ($sa->sa_family == 2) { $s = (struct sockaddr_in *)$sa;
    printf("connect(0, {sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, 16) = 0\n", bswap($s->sin_port), ntop($s->sin_addr.s_addr)); }
  if ($sa->sa_family == 10) { $t = (struct sockaddr_in6 *)$sa;
    printf("connect(0, {sa_family=AF_INET6, sin6_port=htons(%d), inet_pton(AF_INET6, \"%s\", &sin6_addr)}, 28) = 0\n", bswap($t->sin6_port), ntop($t->sin6_addr.in6_u.u6_addr8)); }
}
'''
HOP = {"host", "content-length", "connection", "transfer-encoding", "accept-encoding"}


def docker(*args) -> str:
    r = subprocess.run(["docker", *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def container_info(name: str):
    """(cgroup path under /sys/fs/cgroup, start time) of a running container, or None."""
    out = docker("inspect", "-f", "{{.State.Running}} {{.State.Pid}} {{.State.StartedAt}}", name).split()
    if len(out) != 3 or out[0] != "true":
        return None
    try:
        with open("/proc/%s/cgroup" % out[1]) as f:
            cg = next(line.strip().split("::", 1)[1] for line in f if line.startswith("0::"))
        started = datetime.fromisoformat(out[2][:26].rstrip("Z") + "+00:00").timestamp()
    except (OSError, StopIteration, ValueError):
        return None
    return "/sys/fs/cgroup" + cg, started


def tracer_cmd(name: str, cgroup: str, image: str, label: str = "") -> list:
    cmd = ["docker", "run", "--rm", "--name", name + "-bpf", "--privileged", "--network", "none",
           "-e", "BPFTRACE_MAX_STRLEN=200", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:ro",
           "-v", "/sys/kernel/tracing:/sys/kernel/tracing", "-v", "/sys/kernel/debug:/sys/kernel/debug"]
    if label:
        cmd += ["--label", label]
    return cmd + [image, "bpftrace", "-B", "line", "-e", PROGRAM.replace("CG", cgroup)]


def candidates(records, ts: float, slack_s: float = 0.3, limit: int = 10) -> list:
    """Recorded requests that were being served by prod at `ts` (record ts = when the response ended)."""
    out, seen = [], set()
    for rec in records:
        end = float(rec.get("ts") or 0)
        start = end - float(rec.get("ms") or 0) / 1000.0
        k = (rec.get("method"), rec.get("path"), rec.get("query"), rec.get("body_b64"))
        if rec.get("route") == "prod" and start - slack_s <= ts <= end + slack_s and k not in seen:
            seen.add(k)
            out.append(rec)
    return sorted(out, key=lambda r: abs(float(r["ts"]) - ts))[:limit]


def read_records(path: str, since: float) -> list:
    out = []
    try:
        with open(path) as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if float(rec.get("ts") or 0) >= since:
                    out.append(rec)
    except OSError:
        pass
    return out


def replay(sidecar: str, rec: dict, client: httpx.Client) -> str:
    """Send one recorded request to the shadow clone (L1). -> the sidecar's verdict."""
    target = (rec["path"] + ("?" + rec["query"] if rec.get("query") else "")).encode("latin-1")
    headers = {k: v for k, v in (rec.get("headers") or {}).items()
               if k.lower() not in HOP and not k.lower().startswith(wire.INTERNAL_PREFIX)}
    headers.update({wire.H_RID: "prodwatch-" + uuid.uuid4().hex[:12], wire.H_MODE: "L1"})
    body = base64.b64decode(rec.get("body_b64") or "")
    r = client.send(client.build_request(rec["method"], httpx.URL(sidecar + "/").copy_with(raw_path=target),
                                         headers=headers, content=body or None, extensions={"target": target}))
    return (r.headers.get(wire.H_VERDICT) or wire.VERDICT_INCONCLUSIVE).lower()


class Watch:
    def __init__(self, obs: observer.Observer, record_path: str = "", sidecar: str = "", bus_url: str = "",
                 bus_token: str = "", run: str = "", grace_s: float = 15.0, cooldown_s: float = 30.0,
                 client: httpx.Client | None = None):
        self.obs, self.record_path, self.sidecar = obs, record_path, sidecar.rstrip("/")
        self.parser = strace.Parser()
        self.bus_url, self.bus_token, self.run = bus_url.rstrip("/"), bus_token, run
        self.grace_s, self.cooldown_s = grace_s, cooldown_s
        self.client = client or httpx.Client(timeout=20)
        self.normal = set()             # (container, kind, key) seen during start-up
        self.last = {}                  # (container, kind, key) -> ts of the last alert
        self.alerts = []
        self._lock = threading.Lock()
        self.queue = queue.Queue()      # (container, started, line, arrival time): triage must not delay the stamps

    def work(self):
        """Blocks: handle the queued tracer lines in order."""
        while True:
            container, started, line, now = self.queue.get()
            try:
                self.observe(container, started, line, now)
            except Exception as e:      # noqa: BLE001
                log.warning("alert handling failed: %s", e)

    def observe(self, container: str, started: float, line: str, now: float | None = None):
        """One tracer line. Returns the alert dict if it produced one."""
        now = now or time.time()
        try:
            sc = self.parser.feed(line)
            o = strace.observe(sc) if sc else None
        except Exception:       # noqa: BLE001  (a path with quotes: bpftrace does not escape)
            o = None
        if o is None:
            return None
        rec = observer.Record()
        rec.obs.append(o)
        events = self.obs.system_events(rec)     # the sidecar's rules, on this one observation
        if not events:
            return None
        ev = dict(events[0], ts=now)
        k = (container, ev["oracle"], json.dumps(ev["detail"], sort_keys=True))
        if now - started < self.grace_s:
            self.normal.add(k)
            return None
        if k in self.normal or now - self.last.get(k, 0) < self.cooldown_s:
            return None
        self.last[k] = now
        return self.alert(container, ev)

    def alert(self, container: str, ev: dict) -> dict:
        detail = ev["detail"]
        cands, confirmed, note = [], [], ""
        if self.record_path:
            time.sleep(max(0.0, ev["ts"] + 1.0 - time.time()))      # the gateway records when the response ends
            cands = candidates(read_records(self.record_path, ev["ts"] - 120), ev["ts"])
        with self._lock:                # one triage at a time: the clone serves one request at a time
            for rec in cands if self.sidecar else []:
                try:
                    if replay(self.sidecar, rec, self.client) == wire.VERDICT_ORACLE:
                        confirmed.append({"method": rec["method"], "path": rec["path"], "query": rec.get("query", "")})
                except httpx.HTTPError as e:
                    log.warning("replay failed: %s", e)
        if not cands:
            note = "no request recorded by the gateway at that instant: traffic that bypassed it, or the app itself"
        elif not confirmed:
            note = "none of the %d candidate request(s) fired on the shadow clone" % len(cands)
        else:
            note = "a request in flight at that instant fires on the shadow clone; the pipeline has the evidence"
        data = {"container": container, "oracle": ev["oracle"], "detail": dict(detail, observed="prod-syscall"),
                "candidates": len(cands), "confirmed": confirmed, "note": note}
        log.warning("PROD ALERT %s %s on %s: %s", ev["oracle"], json.dumps(detail), container, note)
        self.alerts.append(data)
        self.publish(data)
        return data

    def publish(self, data: dict):
        if not self.bus_url:
            return
        try:
            ev = E.make(E.PROD_ALERT, "prodwatch", data, run=self.run)
            self.client.post(self.bus_url + "/events", json=ev, headers={"x-bus-token": self.bus_token}, timeout=2.0)
        except Exception as e:      # noqa: BLE001
            log.warning("bus publish failed: %s", e)

    def follow(self, container: str, image: str, label: str = ""):
        """Blocks: trace `container` whenever it is running (blue/green: colours come and go)."""
        while True:
            info = container_info(container)
            if not info:
                time.sleep(2.0)
                continue
            cgroup, started = info
            docker("rm", "-f", container + "-bpf")
            proc = subprocess.Popen(tracer_cmd(container, cgroup, image, label), stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, errors="replace")
            log.info("watching %s", container)

            def gone(proc=proc):        # the colour was retired: stop its tracer (no more lines would come)
                while proc.poll() is None:
                    time.sleep(2.0)
                    if not container_info(container):
                        proc.terminate()
                        docker("rm", "-f", container + "-bpf")
            threading.Thread(target=gone, daemon=True).start()
            for line in proc.stdout:
                if line.startswith(("openat(", "execve(", "connect(")):
                    self.queue.put((container, started, line.strip(), time.time()))
                elif "ERROR" in line:
                    log.warning("tracer: %s", line.strip()[:300])
            proc.wait()
            docker("rm", "-f", container + "-bpf")
            time.sleep(1.0)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    env = os.environ
    cfg = cfgmod.load(env.get("SIDECAR_CONFIG"))
    # the watcher sees only what the config protects: on prod "outside the allowed roots" would be all noise
    obs = observer.from_config(cfg, observer.load_file_markers(cfg.markers_path), extra_allow=cfg.prod_ignore)
    if not obs.protected:
        obs.protected = ["\0"]      # nothing protected: the file rule never fires (proc and net still do)
    w = Watch(obs, env.get("RECORD_PATH", ""), env.get("REPRO_URL", ""), env.get("BUS_URL", ""),
              env.get("BUS_TOKEN", ""), env.get("RUN_ID", ""), float(env.get("PROD_GRACE_S", "15")),
              float(env.get("PROD_COOLDOWN_S", "30")))
    names = [c for c in env.get("PROD_CONTAINERS", "").split(",") if c]
    threads = [threading.Thread(target=w.follow, args=(c, env.get("BPF_IMAGE", "immune-bpftrace:1"),
                                                      env.get("PROD_LABEL", "")), daemon=True) for c in names]
    threads.append(threading.Thread(target=w.work, daemon=True))
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
