"""Judge mode (pipeline's ephemeral clones): bound parameters are captured for the trace, never as statement text."""
import struct

from sidecar.observer import Observer
from sidecar.pgproxy import BackendReader, FrontendReader, StatementTracker, bind_params

from .test_pgproxy import B, CC, DATA, E, P, ROWD, S, Z, msg


def feed(front, back, on_bound):
    got = []
    tr = StatementTracker(lambda *a: got.append(a), on_bound)
    fr, br = FrontendReader(), BackendReader()
    fr.started = True
    for t, p in fr.feed(front):
        tr.frontend(t, p)
    for t, p in br.feed(back):
        tr.backend(t, p)
    return got


def test_bound_params_reported_separately_and_statement_text_unchanged():
    bound = []
    front = P("SELECT id FROM tasks WHERE title ILIKE $1 AND user_id = $2") + B([b"%O'Brien%", b"7"]) + E() + S
    back = msg("1", b"") + msg("2", b"") + ROWD + DATA + CC() + Z
    got = feed(front, back, lambda sql, params: bound.append((sql, params)))
    assert got == [("SELECT id FROM tasks WHERE title ILIKE $1 AND user_id = $2", True, None, "extended")]
    assert bound == [("SELECT id FROM tasks WHERE title ILIKE $1 AND user_id = $2", ["%O'Brien%", "7"])]


def test_no_bound_sink_by_default_and_failed_execute_not_reported():
    assert feed(P("SELECT $1") + B([b"x"]) + E() + S, msg("1", b"") + msg("2", b"") + DATA + CC() + Z, None)
    bound = []
    err = msg("E", b"SERROR\x00C22P02\x00Mbad\x00\x00")
    feed(P("SELECT $1::int") + B([b"x"]) + E() + S, msg("1", b"") + err + Z, lambda *a: bound.append(a))
    assert bound == []


def test_bind_params_null_and_binary():
    body = b"\x00\x00" + struct.pack("!H", 3) + struct.pack("!HHH", 0, 0, 1) + struct.pack("!H", 3)
    body += struct.pack("!i", 2) + b"ab" + struct.pack("!i", -1) + struct.pack("!i", 4) + b"\x00\x00\x00\x01"
    assert bind_params(body + struct.pack("!H", 0), 2) == ["ab", None, None]
    assert bind_params(b"\x00\x00\xff", 2) == []


def test_observer_keeps_bound_only_inside_a_window():
    o = Observer([])
    o.on_bound("SELECT 1", ["a"])
    rec = o.begin()
    o.on_bound("SELECT $1", ["b"])
    o.end()
    assert rec.bound == [("SELECT $1", ["b"])]
