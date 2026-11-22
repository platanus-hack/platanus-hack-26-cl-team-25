"""MySQL / MariaDB wire-protocol tracker, dirty-table detection, client helpers and (docker) a live round trip
through the proxy against the pinned MariaDB image."""
import asyncio
import os
import shutil
import socket
import struct
import subprocess
import time
import uuid

import pytest

from sidecar import mysqlclient
from sidecar.mysqlproxy import (CLIENT_COMPRESS, CLIENT_DEPRECATE_EOF, CLIENT_PROTOCOL_41, CLIENT_SSL, MysqlProxy,
                                PacketReader, StatementTracker, frame, patch_greeting, split_statements,
                                written_tables)
from sidecar.server import reset_statements


def greeting(caps=CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_COMPRESS | CLIENT_DEPRECATE_EOF, mariadb=True):
    low, high = caps & 0xFFFF, caps >> 16
    if mariadb:
        low &= ~1
    p = b"\x0a" + b"11.8.8-MariaDB\x00" + struct.pack("<I", 7) + b"abcdefgh" + b"\x00"
    p += struct.pack("<H", low) + b"\x2d" + struct.pack("<H", 2) + struct.pack("<H", high) + bytes([21])
    p += b"\x00" * 6 + (b"\x0f\x00\x00\x00" if mariadb else b"\x00" * 4) + b"ijklmnopqrst\x00"
    p += b"mysql_native_password\x00"
    return p


def handshake_response(caps):
    return struct.pack("<IIB", caps, 1 << 24, 45) + b"\x00" * 23 + b"app\x00\x00"


OK = lambda status=2: b"\x00\x00\x00" + struct.pack("<HH", status, 0)
ERR = b"\xff" + struct.pack("<H", 1064) + b"#42000You have an error in your SQL syntax"
EOF = lambda status=2: b"\xfe\x00\x00" + struct.pack("<H", status)
OK_EOF = lambda status=2: b"\xfe\x00\x00" + struct.pack("<HH", status, 0)


def resultset(ncols=1, rows=1, deprecate=False, status=2):
    out = [bytes([ncols])] + [b"\x03def" + b"\x00" * 10 for _ in range(ncols)]
    if not deprecate:
        out.append(EOF())
    out += [b"\x02ok" * ncols for _ in range(rows)]
    out.append(OK_EOF(status) if deprecate else EOF(status))
    return out


def run(server_first, commands, deprecate=False):
    got, writes = [], []
    tr = StatementTracker(lambda *a: got.append(a), writes.append)
    caps = CLIENT_PROTOCOL_41 | (CLIENT_DEPRECATE_EOF if deprecate else 0)
    tr.backend(0, greeting())
    tr.frontend(1, handshake_response(caps))
    tr.backend(2, OK())
    for client, replies in commands:
        tr.frontend(0, client)
        for i, r in enumerate(replies):
            tr.backend(i + 1, r)
    return got, writes


def q(sql):
    return b"\x03" + sql.encode()


def test_greeting_disables_tls_compression_and_mariadb_extensions():
    g = greeting()
    p = patch_greeting(g)
    pos = g.index(b"\x00", 1) + 1 + 4 + 8 + 1
    low = struct.unpack_from("<H", p, pos)[0]
    assert not low & CLIENT_SSL and not low & CLIENT_COMPRESS
    assert p[pos + 2 + 1 + 2 + 2 + 1 + 6:][:4] == b"\x00\x00\x00\x00"
    assert len(p) == len(g)
    assert patch_greeting(b"\xff\x10\x04Too many connections") == b"\xff\x10\x04Too many connections"


@pytest.mark.parametrize("deprecate", [False, True])
def test_query_outcomes(deprecate):
    got, writes = run(None, [
        (q("SELECT 1"), resultset(deprecate=deprecate)),
        (q("SELEC 1"), [ERR]),
        (q("UPDATE patient_data SET fname='x' WHERE pid=1"), [OK()]),
        (q("SELECT * FROM t WHERE n = 'O\\'Brien'"), resultset(2, 3, deprecate)),
    ], deprecate)
    assert [(g[0], g[1]) for g in got] == [("SELECT 1", True), ("SELEC 1", False),
                                          ("UPDATE patient_data SET fname='x' WHERE pid=1", True),
                                          ("SELECT * FROM t WHERE n = 'O\\'Brien'", True)]
    assert got[1][2].startswith("1064")
    assert writes == [{"patient_data"}]


def test_multi_statement_runs_until_the_first_error():
    more = 2 | 0x0008
    got, _ = run(None, [(q("SELECT 1; SELECT 2"), resultset(status=more) + resultset()),
                        (q("SELECT 1; SELEC 2"), resultset(status=more) + [ERR]),
                        (q("SELEC 1; SELECT 2"), [ERR]),
                        (q("INSERT INTO a VALUES (1); INSERT INTO b VALUES (2)"), [OK(more), OK()])])
    assert [g[1] for g in got] == [True, True, False, True]


def test_prepared_statement_text_is_recorded_and_params_never_are():
    got, writes = run(None, [
        (b"\x16SELECT * FROM users WHERE username = ?", [b"\x00" + struct.pack("<IHH", 9, 1, 1) + b"\x00\x00\x00",
                                                         b"\x03def", EOF(), b"\x03def", EOF()]),
        (b"\x17" + struct.pack("<I", 9) + b"\x00\x01\x00\x00\x00" + b"\x01\x0f\x00" + b"\x05admin", resultset()),
        (b"\x16DELETE FROM sessions WHERE id = ?", [b"\x00" + struct.pack("<IHH", 10, 0, 1) + b"\x00\x00\x00",
                                                    b"\x03def", EOF()]),
        (b"\x17" + struct.pack("<I", 10) + b"\x00\x01\x00\x00\x00", [OK()]),
        (b"\x19" + struct.pack("<I", 9), []),
        (q("SELECT 2"), resultset()),
    ])
    assert got == [("SELECT * FROM users WHERE username = ?", True, None, "prepared"),
                   ("DELETE FROM sessions WHERE id = ?", True, None, "prepared"),
                   ("SELECT 2", True, None, "simple")]
    assert writes == [{"sessions"}]
    assert all("admin" not in g[0] for g in got)


def test_simple_commands_do_not_shift_the_queue():
    got, _ = run(None, [(b"\x0e", [OK()]), (b"\x02openemr", [OK()]), (q("SELECT 1"), resultset())])
    assert got == [("SELECT 1", True, None, "simple")]


def test_packet_reader_joins_split_payloads_and_frames_round_trip():
    big = b"\x03" + b"x" * (0xFFFFFF + 10)
    data = frame(0, big)
    pr = PacketReader()
    out = []
    for i in range(0, len(data), 70000):
        out += pr.feed(data[i:i + 70000])
    assert out == [(0, big)] and pr.at_boundary()


@pytest.mark.parametrize("sql,tables", [
    ("SELECT * FROM users", set()),
    ("INSERT INTO `log` (a) VALUES (1)", {"log"}),
    ("insert ignore into openemr.log_comment_encrypt values (1)", {"log_comment_encrypt"}),
    ("REPLACE INTO globals (gl_name) VALUES ('x')", {"globals"}),
    ("UPDATE users_secure SET password = 'x' WHERE id = 1", {"users_secure"}),
    ("DELETE FROM sessions WHERE id = 1", {"sessions"}),
    ("TRUNCATE TABLE x", {"x"}),
    ("CREATE TEMPORARY TABLE tmp AS SELECT 1", set()),
    ("CREATE TABLE IF NOT EXISTS new_t (a int)", {"new_t"}),
    ("UPDATE a JOIN b ON a.id = b.id SET a.x = 1", None),
    ("CALL do_things()", None),
    ("SET NAMES utf8mb4; INSERT INTO a VALUES (';'); SELECT 1", {"a"}),
    ("/* c */ UPDATE `patient_data` SET x=1", {"patient_data"}),
    ("SELECT 1 -- ; DROP TABLE x", set()),
])
def test_written_tables(sql, tables):
    assert written_tables(sql) == tables


def test_split_statements_respects_quotes_and_comments():
    assert split_statements("SELECT 'a;b'; SELECT \"c;\" # x;y\n; SELECT 3") == \
        ["SELECT 'a;b'", " SELECT \"c;\" # x;y\n", " SELECT 3"]


def test_interpolate_escapes_and_respects_quoted_question_marks():
    s = mysqlclient.interpolate("SELECT '?' , ? , ?, ?", ["O'Brien\\", None, 3])
    assert s == "SELECT '?' , 'O\\'Brien\\\\' , NULL, 3"
    with pytest.raises(mysqlclient.MysqlError):
        mysqlclient.interpolate("SELECT ?", [1, 2])


def test_reset_statements_rebuild_only_dirty_tables():
    q = mysqlclient.quote_ident
    seed = {"users": "users", "log": "log", "patient_data": "patient_data"}
    partial = reset_statements("clone", "seed", seed, {"log", "tmp_app"}, False, q)
    assert "DROP TABLE IF EXISTS `clone`.`tmp_app`" in partial
    assert "INSERT INTO `clone`.`log` SELECT * FROM `seed`.`log`" in partial
    assert not any("users" in x for x in partial)
    full = reset_statements("clone", "seed", seed, set(), True, q)
    assert "DROP DATABASE IF EXISTS `clone`" in full and sum(x.startswith("INSERT") for x in full) == 3


def test_native_password_scramble_matches_reference():
    # reference value computed with the MySQL algorithm: SHA1(pw) XOR SHA1(scramble + SHA1(SHA1(pw)))
    import hashlib
    scramble = b"12345678901234567890"
    p1 = hashlib.sha1(b"secret").digest()
    want = bytes(a ^ b for a, b in zip(p1, hashlib.sha1(scramble + hashlib.sha1(p1).digest()).digest()))
    assert mysqlclient.native_password("secret", scramble) == want
    assert mysqlclient.native_password("", scramble) == b""


# ---------------------------------------------------------------------------- live (docker)
MARIADB = "mariadb:11.8.8@sha256:be1ef4fe5f14589325c08a41c76334097ce66c86264b75e1d28342c742782a61"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def mariadb():
    if not shutil.which("docker") or subprocess.run(["docker", "image", "inspect", MARIADB],
                                                    capture_output=True).returncode:
        pytest.skip("docker or the pinned MariaDB image is not available")
    name, port, pw = "immune-test-mysql-" + uuid.uuid4().hex[:8], _free_port(), "rootpw-" + uuid.uuid4().hex[:6]
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1:%d:3306" % port,
                    "-e", "MARIADB_ROOT_PASSWORD=" + pw, MARIADB], check=True, capture_output=True)
    try:
        end = time.time() + 90
        while time.time() < end:
            try:
                asyncio.run(_ping(port, pw))
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.5)
        else:
            pytest.fail("mariadb did not start")
        yield port, pw
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


async def _ping(port, pw):
    c = await mysqlclient.MysqlConn.connect("127.0.0.1", port, "root", pw, "")
    await c.query("SELECT 1")
    await c.close()


@pytest.mark.docker
async def test_live_proxy_observes_statements_and_dirty_tables(mariadb):
    port, pw = mariadb
    got = []
    listen = _free_port()
    proxy = MysqlProxy("127.0.0.1", listen, "127.0.0.1", port, lambda *a: got.append(a))
    await proxy.start()
    try:
        admin = await mysqlclient.MysqlConn.connect("127.0.0.1", port, "root", pw, "")
        await admin.query("CREATE DATABASE seed; CREATE TABLE seed.users (id INT PRIMARY KEY, name VARCHAR(40));"
                          "INSERT INTO seed.users VALUES (1, 'Ana'), (2, 'Bruno')")
        q = mysqlclient.quote_ident
        tables = {"users": "users"}
        stmts = reset_statements("clone", "seed", tables, set(), True, q)
        await admin.query(";".join(stmts))
        app = await mysqlclient.MysqlConn.connect("127.0.0.1", listen, "root", pw, "clone")
        rows = await app.execute("SELECT name FROM users WHERE name = ?", ["O'Brien"])
        assert rows == []
        await app.query("UPDATE users SET name = 'Zoe' WHERE id = 1")
        with pytest.raises(mysqlclient.MysqlError):
            await app.query("SELEC 1")
        multi = await app.query("SELECT 1; SELECT name FROM users ORDER BY id")
        assert multi == [("Zoe",), ("Bruno",)]
        await app.close()
        await asyncio.sleep(0.1)
        assert ("SELECT name FROM users WHERE name = 'O\\'Brien'", True, None, "simple") in got
        assert ("UPDATE users SET name = 'Zoe' WHERE id = 1", True, None, "simple") in got
        assert any(g[0] == "SELEC 1" and g[1] is False for g in got)
        dirty, everything = proxy.take_dirty()
        assert dirty == {"users"} and not everything
        await admin.query(";".join(reset_statements("clone", "seed", tables, dirty, False, q)))
        assert await admin.query("SELECT name FROM clone.users ORDER BY id") == [("Ana",), ("Bruno",)]
        await admin.close()
    finally:
        await proxy.stop()
