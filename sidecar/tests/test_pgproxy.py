"""Unit tests for the Postgres wire-protocol parser/tracker and the proxy byte path (fake upstream)."""
import asyncio
import struct

import pytest

from sidecar.pgproxy import (SSL_REQUEST, BackendReader, FrontendReader, PgProxy, ProtocolError,
                             StatementTracker)


def msg(t: str, payload: bytes) -> bytes:
    return t.encode() + struct.pack("!I", len(payload) + 4) + payload


def startup(user="app", db="clone") -> bytes:
    body = struct.pack("!I", 196608) + b"user\x00" + user.encode() + b"\x00database\x00" + db.encode() + b"\x00\x00"
    return struct.pack("!I", len(body) + 4) + body


def ssl_request() -> bytes:
    return struct.pack("!II", 8, SSL_REQUEST)


Q = lambda sql: msg("Q", sql.encode() + b"\x00")
P = lambda sql, name="": msg("P", name.encode() + b"\x00" + sql.encode() + b"\x00" + struct.pack("!H", 0))


def B(params, portal="", stmt=""):
    p = portal.encode() + b"\x00" + stmt.encode() + b"\x00" + struct.pack("!H", 0) + struct.pack("!H", len(params))
    for v in params:
        p += struct.pack("!i", len(v)) + v
    return msg("B", p + struct.pack("!H", 0))


E = lambda portal="": msg("E", portal.encode() + b"\x00" + struct.pack("!I", 0))
S = msg("S", b"")
CC = lambda tag="SELECT 1": msg("C", tag.encode() + b"\x00")
Z = msg("Z", b"I")
ERR = lambda code="42601", m="syntax error": msg("E", b"SERROR\x00C" + code.encode() + b"\x00M" + m.encode() + b"\x00\x00")
ROWD = msg("T", struct.pack("!H", 0))
DATA = msg("D", struct.pack("!H", 1) + struct.pack("!i", 2) + b"ok")


def run(front: bytes, back: bytes, chunk: int | None = None):
    """Feed both streams to a tracker (front first, as the proxy does). Returns [(sql, ok, err, via)]."""
    got = []
    tr = StatementTracker(lambda *a: got.append(a))
    fr, br = FrontendReader(), BackendReader()
    fr.started = True
    for data, reader, fn in ((front, fr, tr.frontend), (back, br, tr.backend)):
        step = chunk or len(data) or 1
        for i in range(0, len(data), step):
            for t, p in reader.feed(data[i:i + step]):
                fn(t, p)
    return got


def test_simple_query_success_and_error():
    got = run(Q("SELECT 1") + Q("SELECT '%O'Brien%'"), ROWD + DATA + CC() + Z + ERR() + Z)
    assert got[0] == ("SELECT 1", True, None, "simple")
    assert got[1][0] == "SELECT '%O'Brien%'" and got[1][1] is False and "42601" in got[1][2]


def test_multi_statement_simple_query_counts_as_executed_if_any_part_ran():
    sql = "SELECT 1; SELECT * FROM nope"
    got = run(Q(sql), CC() + ERR("42P01", "relation does not exist") + Z)
    assert got == [(sql, True, "42P01 relation does not exist", "simple")]
    # empty query string
    assert run(Q(""), msg("I", b"") + Z) == [("", True, None, "simple")]


def test_extended_protocol_text_is_parse_and_params_never_appear():
    front = P("SELECT id FROM items WHERE name ILIKE $1") + B([b"%x' UNION SELECT 1--%"]) + msg("D", b"P\x00") + E() + S
    back = msg("1", b"") + msg("2", b"") + ROWD + DATA + CC() + Z
    got = run(front, back)
    assert got == [("SELECT id FROM items WHERE name ILIKE $1", True, None, "extended")]
    assert "UNION" not in got[0][0]


def test_extended_error_fails_rest_of_batch_until_sync():
    front = (P("SELECT 1", "s1") + B([], "p1", "s1") + E("p1") +
             P("SELECT bad syntax(", "s2") + B([], "p2", "s2") + E("p2") +
             P("SELECT 3", "s3") + B([], "p3", "s3") + E("p3") + S +
             B([], "p4", "s1") + E("p4") + S)  # named statement reused after the error
    back = (msg("1", b"") + msg("2", b"") + CC() + ERR() + Z +
            msg("2", b"") + CC() + Z)
    got = run(front, back)
    assert [(g[0], g[1]) for g in got] == [("SELECT 1", True), ("SELECT bad syntax(", False), ("SELECT 3", False),
                                          ("SELECT 1", True)]


def test_portal_suspended_counts_as_executed():
    got = run(P("SELECT g FROM generate_series(1,10) g") + B([]) + E() + S, msg("1", b"") + msg("2", b"") + msg("s", b"") + Z)
    assert got[0][1] is True


def test_large_messages_split_across_reads_byte_by_byte():
    big = "SELECT '" + "x" * 200_000 + "'"
    got = run(Q(big) + Q("SELECT 2"), CC() + Z + CC() + Z, chunk=1)
    assert [g[0] for g in got] == [big, "SELECT 2"]
    got = run(Q(big), CC() + Z, chunk=4093)
    assert got[0][0] == big


def test_startup_sequence_and_bad_length():
    fr = FrontendReader()
    out = fr.feed(ssl_request() + startup()[:5])
    assert out[0][0] == "startup" and struct.unpack("!I", out[0][1][:4])[0] == SSL_REQUEST
    assert fr.started is False
    out = fr.feed(startup()[5:] + Q("SELECT 1"))
    assert [t for t, _ in out] == ["startup", "Q"] and fr.started
    with pytest.raises(ProtocolError):
        BackendReader().feed(b"Z\x00\x00\x00\x01")


async def test_proxy_refuses_ssl_forwards_bytes_unchanged_and_reports():
    """Fake upstream: records what it receives and answers each Q with CommandComplete+ReadyForQuery."""
    received = bytearray()

    async def upstream(r, w):
        fr = FrontendReader()
        while True:
            data = await r.read(65536)
            if not data:
                break
            received.extend(data)
            for t, p in fr.feed(data):
                if t == "startup":
                    w.write(msg("R", struct.pack("!I", 0)) + Z)   # AuthenticationOk, ReadyForQuery
                elif t == "Q":
                    w.write(ERR() + Z if b"bad" in p else CC() + Z)
            await w.drain()
        w.close()

    up = await asyncio.start_server(upstream, "127.0.0.1", 0)
    up_port = up.sockets[0].getsockname()[1]
    seen = []
    px = PgProxy("127.0.0.1", 0, "127.0.0.1", up_port, lambda *a: seen.append(a))
    await px.start()
    port = px.server.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(ssl_request()); await w.drain()
    assert await r.readexactly(1) == b"N"  # refused locally, never forwarded
    payload = startup() + Q("SELECT 1") + Q("SELECT bad")
    # send in odd-sized pieces to exercise reassembly in the proxy
    for i in range(0, len(payload), 7):
        w.write(payload[i:i + 7]); await w.drain()
    br = BackendReader()
    msgs = []
    while sum(1 for t, _ in msgs if t == "Z") < 3:
        msgs += br.feed(await r.read(65536))
    w.close()
    await asyncio.sleep(0.05)
    assert bytes(received) == payload  # SSLRequest not forwarded; everything else byte-identical
    assert [(s[0], s[1]) for s in seen] == [("SELECT 1", True), ("SELECT bad", False)]
    await px.stop(); up.close()
