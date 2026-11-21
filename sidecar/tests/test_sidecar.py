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


# --- syscall oracle ---------------------------------------------------------------------------------------
from sidecar.core import file_events          # noqa: E402
from sidecar.syscalls import Tracer, parse_line, tracer_cmd      # noqa: E402

L_OK = '[pid    19] 100.500000 openat(AT_FDCWD</usr/share/grafana>, "/etc/grafana/grafana.ini", O_RDONLY|O_CLOEXEC) = 7'
L_REL = '100.600000 openat(AT_FDCWD</usr/share/grafana>, "public/../../../../etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)'
L_UNF = '[pid 3] 100.700000 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC <unfinished ...>'


def test_parse_line():
    assert parse_line(L_OK) == {"ts": 100.5, "path": "/etc/grafana/grafana.ini",
                                "realpath": "/etc/grafana/grafana.ini", "result": "ok"}
    rel = parse_line(L_REL)
    assert rel["realpath"] == "/etc/shadow" and rel["result"] == "EACCES"
    assert parse_line(L_UNF)["result"] == "?"
    assert parse_line("strace: Process 1 attached with 12 threads") is None
    assert parse_line('[pid 3] 100.8 <... openat resumed>) = 3') is None


def test_tracer_window_and_background():
    t = Tracer([], ["/etc/grafana/grafana.ini", "/etc/shadow", "/var/lib/app/*.db"])
    t.feed('90.000000 openat(AT_FDCWD, "/var/lib/app/main.db", O_RDWR) = 5')       # no request in flight
    t.feed('100.400000 openat(AT_FDCWD, "/usr/share/x/plugin.json", O_RDONLY) = 7')   # not protected
    t.feed(L_OK); t.feed(L_OK); t.feed(L_REL)
    t.feed('100.650000 openat(AT_FDCWD, "/var/lib/app/main.db", O_RDWR) = 5')       # background path: ignored
    t.feed('200.000000 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = 3')              # a later request
    assert [e["realpath"] for e in t.take(100.0, 101.0)] == ["/etc/grafana/grafana.ini", "/etc/shadow"]
    assert t.background == {"/var/lib/app/main.db"}
    assert [e["realpath"] for e in t.take(199.0, 201.0)] == ["/etc/shadow"]


def test_file_events_merge_marker_and_syscall():
    leaked = [("MKAAAAAAAAAA", {"path": "/etc/grafana/grafana.ini"})]
    ev = file_events(leaked, [parse_line(L_OK), parse_line(L_REL)])
    assert [(e["detail"]["realpath"], e["detail"]["observed"]) for e in ev] == [
        ("/etc/grafana/grafana.ini", "response+syscall"), ("/etc/shadow", "syscall")]
    assert ev[1]["detail"]["result"] == "EACCES" and all(e["oracle"] == wire.ORACLE_FILE for e in ev)


async def test_blind_read_is_oracle_without_marker():
    class Fake:
        async def window(self, t0, t1):
            return [{"ts": t0, "path": "/etc/shadow", "realpath": "/etc/shadow", "result": "ok"}]

        async def stop(self):
            pass
    sc, _, pushed = make(b"<html>error</html>", status=500)
    sc.tracer = Fake()
    status, headers, _ = await sc.handle(scope("/x"), b"")
    assert dict(headers)[wire.H_VERDICT] == "oracle" and len(pushed) == 1
    assert json.loads(pushed[0][1])["events"][0]["detail"]["observed"] == "syscall"


def test_tracer_cmd_is_confined():
    cmd = tracer_cmd("app", "immune-strace:1", "app-strace", "immune.lab=x")
    assert "--pid=container:app" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL" and "--privileged" not in cmd
