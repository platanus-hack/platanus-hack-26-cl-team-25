import json

import httpx

from immune_contracts import events as E
from immune_contracts import wire
from sidecar.observer import Observer
from sidecar.prodwatch import PROGRAM, Watch, candidates, tracer_cmd


def policy():
    return Observer([], protected=["/etc/grafana/grafana.ini", "/etc/shadow"], net_allow=["*:53"])


OPEN = 'openat(AT_FDCWD, "/etc/grafana/grafana.ini", O_RDONLY) = 3'
EXEC = 'execve("/bin/sh", [], 0) = 0'
CONN = 'connect(0, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("203.0.113.9")}, 16) = 0'

def rec(path, ts, ms=20.0, route="prod", **kw):
    return dict({"method": "GET", "path": path, "query": "", "headers": {"host": "x", "accept": "*/*"},
                 "body_b64": "", "route": route, "ts": ts, "ms": ms}, **kw)


def test_candidates_are_the_requests_in_flight():
    recs = [rec("/old", 900.0), rec("/slow", 1000.9, ms=1500.0), rec("/hit", 1000.2), rec("/hit", 1000.3),
            rec("/denied", 1000.2, route="deny"), rec("/later", 1005.0)]
    assert [r["path"] for r in candidates(recs, 1000.1)] == ["/hit", "/slow"]


def make(tmp_path, verdicts):
    sent, bus = [], []

    def handler(req: httpx.Request):
        if req.url.host == "bus":
            bus.append(json.loads(req.content))
            return httpx.Response(200)
        sent.append((req.extensions.get("target"), req.headers.get(wire.H_MODE)))
        return httpx.Response(200, headers={wire.H_VERDICT: verdicts.get(req.url.path, "clean")})
    path = tmp_path / "requests.jsonl"
    w = Watch(policy(), str(path), "http://sidecar:1", "http://bus", "t", "run1", grace_s=15, cooldown_s=30,
              client=httpx.Client(transport=httpx.MockTransport(handler)))
    return w, path, sent, bus


def test_alert_replays_candidates_and_publishes(tmp_path, monkeypatch):
    monkeypatch.setattr("sidecar.prodwatch.time.sleep", lambda s: None)
    w, path, sent, bus = make(tmp_path, {"/evil": "oracle"})
    path.write_text("\n".join(json.dumps(r) for r in [rec("/api/health", 5000.05), rec("/evil", 5000.1)]) + "\n")
    a = w.observe("prod-blue", started=1000.0, line=OPEN, now=5000.0)
    assert a["oracle"] == "file" and a["candidates"] == 2 and a["confirmed"] == [
        {"method": "GET", "path": "/evil", "query": ""}]
    assert sorted(sent) == [(b"/api/health", "L1"), (b"/evil", "L1")]
    assert bus[0]["type"] == E.PROD_ALERT and bus[0]["src"] == "prodwatch" and bus[0]["data"] == a
    assert a["detail"] == {"path": "/etc/grafana/grafana.ini", "realpath": "/etc/grafana/grafana.ini",
                           "observed": "prod-syscall"}


def test_startup_is_learnt_cooldown_and_bypass(tmp_path, monkeypatch):
    monkeypatch.setattr("sidecar.prodwatch.time.sleep", lambda s: None)
    w, path, sent, bus = make(tmp_path, {})
    assert w.observe("prod-green", started=1000.0, line=OPEN, now=1005.0) is None      # start-up: reads its config
    assert w.observe("prod-green", started=1000.0, line=OPEN, now=2000.0) is None      # learnt as normal
    assert w.observe("prod-green", 1000.0, 'openat(AT_FDCWD, "/usr/share/x.js", O_RDONLY) = 3', 2000.0) is None
    assert w.observe("prod-green", 1000.0, 'connect(0, {sa_family=AF_INET, sin_port=htons(53), '
                     'sin_addr=inet_addr("10.0.0.2")}, 16) = 0', 2000.0) is None      # allowlisted
    a = w.observe("prod-green", started=1000.0, line=EXEC, now=2000.0)
    assert a["oracle"] == "proc" and a["candidates"] == 0 and "bypassed" in a["note"] and not sent
    assert w.observe("prod-green", started=1000.0, line=EXEC, now=2010.0) is None      # cooldown
    assert w.observe("prod-green", started=1000.0, line=EXEC, now=2040.0) is not None
    n = w.observe("prod-green", started=1000.0, line=CONN, now=2000.0)
    assert n["oracle"] == "net" and (n["detail"]["address"], n["detail"]["port"]) == ("203.0.113.9", 4444)
    assert [b["data"]["oracle"] for b in bus] == ["proc", "proc", "net"]


def test_tracer_is_scoped_to_the_container_cgroup():
    cmd = tracer_cmd("prod-blue", "/sys/fs/cgroup/system.slice/docker-abc.scope", "immune-bpftrace:1")
    assert cmd[cmd.index("--network") + 1] == "none" and "--pid=host" not in cmd
    prog = cmd[-1]
    assert prog.count('cgroupid("/sys/fs/cgroup/system.slice/docker-abc.scope")') == PROGRAM.count('cgroupid("CG")') == 3
