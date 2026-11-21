import json

import httpx
import pytest

from immune_contracts import wire
from sidecar.core import Config, Sidecar, verdict_of

MARKERS = {"MKAAAAAAAAAA": {"path": "/etc/grafana/grafana.ini"}}


def scope(path, headers=()):
    return {"type": "http", "method": "GET", "path": path, "raw_path": path.encode(), "query_string": b"",
            "headers": [(k.encode(), v.encode()) for k, v in headers]}


def make(body: bytes, status=200):
    seen, pushed = {}, []

    def app(req: httpx.Request):
        seen["target"] = req.extensions.get("target")
        seen["headers"] = dict(req.headers)
        return httpx.Response(status, content=body)

    def collector(req: httpx.Request):
        pushed.append((req.headers.get(wire.H_SIGNATURE), req.content))
        return httpx.Response(200, json={"ok": True})

    sc = Sidecar(Config(upstream="shadow:3000", markers=MARKERS, clone_key="k", collector_url="http://gw:9000"))
    sc.client = httpx.AsyncClient(transport=httpx.MockTransport(app))
    sc.push_client = httpx.AsyncClient(transport=httpx.MockTransport(collector))
    return sc, seen, pushed


async def test_marker_in_response_is_oracle_and_pushes_signed_evidence():
    sc, seen, pushed = make(b"[security]\nsecret_key = MKAAAAAAAAAA\n")
    path = "/public/plugins/x/../../etc/grafana/grafana.ini"
    status, headers, _ = await sc.handle(scope(path, [("x-imm-rid", "r1"), ("x-imm-mode", "L1"), ("accept", "*/*")]), b"")
    h = dict(headers)
    assert status == 200 and h[wire.H_VERDICT] == "oracle" and h[wire.H_EVENTS] == "1"
    assert seen["target"] == path.encode()                       # dot segments reach the shadow app unchanged
    assert not any(k.startswith("x-imm-") for k in seen["headers"])
    sig, raw = pushed[0]
    assert wire.check("k", raw, sig)
    ev = json.loads(raw)
    assert ev["rid"] == "r1" and ev["events"][0]["oracle"] == "file"
    assert ev["events"][0]["detail"]["path"] == "/etc/grafana/grafana.ini"


async def test_no_marker_is_clean_and_nothing_pushed():
    sc, _, pushed = make(b'{"id":"alertlist"}')
    _, headers, _ = await sc.handle(scope("/public/plugins/alertlist/plugin.json"), b"")
    assert dict(headers)[wire.H_VERDICT] == "clean" and not pushed


@pytest.mark.parametrize("status,events,v", [(404, [], "inconclusive"), (500, [], "inconclusive"),
                                             (302, [], "clean"), (404, [1], "oracle")])
def test_verdict(status, events, v):
    assert verdict_of(status, events) == v


# --- syscall oracles --------------------------------------------------------------------------------------
from sidecar.core import oracle_events          # noqa: E402
from sidecar.syscalls import Collector, Policy, parse_line, tracer_cmd      # noqa: E402

L_OK = '[pid    19] 100.500000 openat(AT_FDCWD</usr/share/grafana>, "/etc/grafana/grafana.ini", O_RDONLY|O_CLOEXEC) = 7'
L_REL = '100.600000 openat(AT_FDCWD</usr/share/grafana>, "public/../../../../etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)'
L_UNF = '[pid 3] 100.700000 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC <unfinished ...>'
L_EXEC = '[pid 77] 100.710000 execve("/bin/sh", ["sh", "-c", "id; echo \\"x\\""], 0xc000 /* 9 vars */) = 0'
L_EXEC_MISS = '[pid 77] 100.705000 execve("/usr/local/bin/sh", ["sh", "-c", "id"], 0xc000 /* 9 vars */) = -1 ENOENT (No such file or directory)'
L_NET = ('[pid 20] 100.720000 connect(9<socket:[1]>, {sa_family=AF_INET, sin_port=htons(80), '
         'sin_addr=inet_addr("169.254.169.254")}, 16) = -1 EINPROGRESS (Operation now in progress)')
L_NET6 = ('100.730000 connect(9, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), '
          'inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = 0')
L_UNIX = '100.740000 connect(9, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file)'
POLICY = Policy(["/etc/grafana/grafana.ini", "/etc/shadow", "/var/lib/app/*.db"], ["/usr/sbin/plugin-*"],
                ["10.0.0.5:5432", "*:53"])


def test_parse_line():
    f = parse_line(L_OK)
    assert (f["kind"], f["ts"], f["realpath"], f["result"]) == ("file", 100.5, "/etc/grafana/grafana.ini", "ok")
    rel = parse_line(L_REL)
    assert rel["realpath"] == "/etc/shadow" and rel["result"] == "EACCES"
    assert parse_line(L_UNF)["result"] == "?"
    x = parse_line(L_EXEC)
    assert (x["kind"], x["key"], x["args"][:3], x["result"]) == ("proc", "/bin/sh", ["/bin/sh", "sh", "-c"], "ok")
    n = parse_line(L_NET)
    assert (n["kind"], n["address"], n["result"]) == ("net", "169.254.169.254:80", "EINPROGRESS")
    assert parse_line(L_NET6)["address"] == "2001:db8::1:443"
    assert parse_line(L_UNIX) is None
    assert parse_line("strace: Process 1 attached with 12 threads") is None
    assert parse_line('[pid 3] 100.8 <... openat resumed>) = 3') is None


def test_policy():
    def ev(kind, key):
        return {"kind": kind, "key": key}
    assert POLICY.relevant(ev("file", "/var/lib/app/main.db")) and not POLICY.relevant(ev("file", "/usr/share/x"))
    assert POLICY.relevant(ev("proc", "/bin/sh")) and not POLICY.relevant(ev("proc", "/usr/sbin/plugin-pg"))
    assert POLICY.relevant(ev("net", "169.254.169.254:80")) and not POLICY.relevant(ev("net", "10.0.0.5:5432"))
    assert not POLICY.relevant(ev("net", "127.0.0.11:53"))


def test_collector_window_and_background():
    t = Collector(POLICY)
    t.feed('90.000000 openat(AT_FDCWD, "/var/lib/app/main.db", O_RDWR) = 5')       # no request in flight
    t.feed('91.000000 execve("/usr/bin/cron-job", ["cron-job"], 0x1 /* 2 vars */) = 0')
    t.feed('100.400000 openat(AT_FDCWD, "/usr/share/x/plugin.json", O_RDONLY) = 7')   # not protected
    for line in (L_OK, L_OK, L_REL, L_EXEC_MISS, L_EXEC, L_NET, L_UNIX):
        t.feed(line)
    t.feed('100.650000 openat(AT_FDCWD, "/var/lib/app/main.db", O_RDWR) = 5')       # background: ignored
    t.feed('100.660000 execve("/usr/bin/cron-job", ["cron-job"], 0x1 /* 2 vars */) = 0')
    t.feed('200.000000 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3')              # a later request
    got = t.take(100.0, 101.0)
    assert [(e["kind"], e["key"]) for e in got] == [
        ("file", "/etc/grafana/grafana.ini"), ("file", "/etc/shadow"), ("proc", "/usr/local/bin/sh"),
        ("proc", "/bin/sh"), ("net", "169.254.169.254:80")]
    assert t.background == {("file", "/var/lib/app/main.db"), ("proc", "/usr/bin/cron-job")}
    assert [e["key"] for e in t.take(199.0, 201.0)] == ["/etc/shadow"]


def test_oracle_events_merge_and_kinds():
    leaked = [("MKAAAAAAAAAA", {"path": "/etc/grafana/grafana.ini"})]
    ev = oracle_events(leaked, [parse_line(x) for x in (L_OK, L_REL, L_EXEC, L_NET)])
    assert [(e["oracle"], e["detail"]["observed"]) for e in ev] == [
        ("file", "response+syscall"), ("file", "syscall"), ("proc", "syscall"), ("net", "syscall")]
    assert ev[1]["detail"]["result"] == "EACCES" and ev[2]["detail"]["args"][0] == "/bin/sh"
    assert ev[3]["detail"] == {"event": "connect", "address": "169.254.169.254:80", "observed": "syscall",
                               "result": "EINPROGRESS"}
    assert {e["oracle"] for e in ev} <= set(wire.ORACLES)


async def test_blind_events_are_oracle_without_marker():
    class Fake:
        async def window(self, t0, t1):
            return [parse_line(L_REL), parse_line(L_EXEC)]

        async def stop(self):
            pass
    sc, _, pushed = make(b"<html>error</html>", status=500)
    sc.tracer = Fake()
    status, headers, _ = await sc.handle(scope("/x"), b"")
    assert dict(headers)[wire.H_VERDICT] == "oracle" and dict(headers)[wire.H_EVENTS] == "2" and len(pushed) == 1
    assert [e["oracle"] for e in json.loads(pushed[0][1])["events"]] == ["file", "proc"]


def test_tracer_cmd_is_confined():
    cmd = tracer_cmd("app", "immune-strace:1", "app-strace", "immune.lab=x")
    assert "--pid=container:app" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL" and "--privileged" not in cmd
