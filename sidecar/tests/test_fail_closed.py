"""The sidecar must not answer `clean` when it could not observe: markers it was told to load but cannot,
a tracer that died during the request, strace lines it could not parse."""
import json
import os
import types

import pytest

from immune_contracts import wire
from sidecar import config as cfgmod
from sidecar import server, strace
from sidecar.identity import Identity
from sidecar.tracer import Tracer


# ---------------------------------------------------------------- markers
def test_unconfigured_markers_are_the_only_silent_off_case():
    assert Identity().markers({}, None) == {}


def test_markers_file_is_loaded(tmp_path):
    p = tmp_path / "markers.json"
    p.write_text(json.dumps({"MKAAAAAAAAAA": 7}))
    assert Identity().markers({}, str(p)) == {"MKAAAAAAAAAA": 7}


@pytest.mark.parametrize("content", [None, "{not json", '["a list"]', '{"MKAAAAAAAAAA": "not-a-uid"}'])
def test_configured_but_unusable_markers_file_fails(tmp_path, content):
    p = tmp_path / "markers.json"
    if content is not None:
        p.write_text(content)
    with pytest.raises(RuntimeError, match="markers configured .* but not loadable"):
        Identity().markers({}, str(p))


def test_profile_load_markers_that_raises_fails():
    def load_markers(env):
        raise FileNotFoundError(env["MARKERS_PATH"])
    with pytest.raises(RuntimeError, match="profile load_markers"):
        Identity(types.SimpleNamespace(load_markers=load_markers)).markers({"MARKERS_PATH": "/nope"}, None)


def test_sidecar_does_not_start_with_a_corrupt_markers_file(tmp_path):
    p = tmp_path / "markers.json"
    p.write_text("{")
    with pytest.raises(RuntimeError, match="not loadable"):
        server.Sidecar(cfgmod.Config(trace=False, markers_path=str(p)))


# ---------------------------------------------------------------- tracer death during the request
class FakeTracer:
    dropped = 0

    def __init__(self, alive):
        self.answers = list(alive)

    def alive(self):
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]


async def _handle(monkeypatch, alive):
    sc = server.Sidecar(cfgmod.Config(trace=False, grace_ms=0))
    sc.tracer = FakeTracer(alive)
    forwarded = []

    async def request(host, port, method, target, headers, body, timeout):
        forwarded.append(target)
        return 200, [(b"content-type", b"text/plain")], b"ok"

    monkeypatch.setattr(server.http1, "request", request)
    status, headers, body, _ = await sc.handle("GET", "/x", b"/x", b"", [], b"")
    return status, dict(headers)[wire.H_VERDICT.encode()].decode(), forwarded


async def test_live_tracer_gives_clean(monkeypatch):
    assert await _handle(monkeypatch, [True]) == (200, "clean", ["/x"])


async def test_tracer_that_dies_during_the_request_is_never_clean(monkeypatch):
    status, verdict, forwarded = await _handle(monkeypatch, [True, False])
    assert forwarded == ["/x"] and verdict == "inconclusive"


async def test_tracer_dead_before_the_request_is_not_forwarded(monkeypatch):
    assert await _handle(monkeypatch, [False]) == (503, "inconclusive", [])


# ---------------------------------------------------------------- dropped strace lines
def test_parser_counts_lines_it_cannot_turn_into_a_syscall():
    p = strace.Parser(default_pid=1)
    assert p.feed('openat(AT_FDCWD</app>, "x", O_RDONLY) = 3</app/x>') is not None
    assert p.feed("+++ exited with 0 +++") is None and p.feed("--- SIGCHLD {si_signo=SIGCHLD} ---") is None
    assert p.feed('openat(AT_FDCWD</app>, "x", O_RDONLY <unfinished ...>') is None
    assert p.dropped == 0                                         # none of those is a lost syscall
    assert p.feed("garbage that is not a call") is None
    assert p.feed('openat(AT_FDCWD</app>, "x", O_RDONLY) no return value') is None
    assert p.feed("[pid 9] <... openat resumed>) = 3</app/x>") is None    # resumed without its start
    assert p.dropped == 3


def test_tracer_exposes_the_dropped_count():
    seen = []
    t = Tracer(seen.append)
    r, w = os.pipe()
    os.write(w, b'1 openat(AT_FDCWD</app>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>\n1 not a syscall line\n')
    os.close(w)
    t._read(r)
    assert t.lines == 2 and t.dropped == 1 and [o.kind for o in seen] == ["file"]
