"""Minimal asyncio MySQL / MariaDB client (no dependencies) for the sidecar's own work: the clone database
reset (server.Sidecar.reset_db), ``ensure_user`` hooks and test seeding. Twin of ``pgclient.py``.

Auth: ``mysql_native_password`` (MariaDB's default) and the auth-switch to it. Plaintext only (the clone
network is private). Parameters are interpolated client-side as escaped literals (``?`` placeholders
outside quotes), the same thing PHP's mysqli/ADOdb emulation does.
"""
from __future__ import annotations

import asyncio
import hashlib
import struct
from urllib.parse import unquote, urlparse

from .mysqlproxy import (CLIENT_DEPRECATE_EOF, CLIENT_PROTOCOL_41, MAX_PACKET, PacketReader, err_message, frame,
                         lenenc_int)

CLIENT_LONG_FLAG = 1 << 2
CLIENT_CONNECT_WITH_DB = 1 << 3
CLIENT_TRANSACTIONS = 1 << 13
CLIENT_SECURE_CONNECTION = 1 << 15
CLIENT_MULTI_STATEMENTS = 1 << 16
CLIENT_MULTI_RESULTS = 1 << 17
CLIENT_PLUGIN_AUTH = 1 << 19
SERVER_MORE_RESULTS_EXISTS = 0x0008


class MysqlError(Exception):
    pass


def parse_url(url: str) -> dict:
    u = urlparse(url)
    return {"host": u.hostname or "127.0.0.1", "port": u.port or 3306, "user": unquote(u.username or "root"),
            "password": unquote(u.password or ""), "database": (u.path or "/").lstrip("/")}


def quote_ident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def literal(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (bytes, bytearray)):
        return "X'%s'" % bytes(v).hex()
    s = str(v)
    for a, b in (("\\", "\\\\"), ("\x00", "\\0"), ("\n", "\\n"), ("\r", "\\r"), ("'", "\\'"), ('"', '\\"'),
                 ("\x1a", "\\Z")):
        s = s.replace(a, b)
    return "'" + s + "'"


def interpolate(sql: str, params=()) -> str:
    """Replace ``?`` outside quotes/comments by escaped literals."""
    params = list(params or ())
    if not params:
        return sql
    out, i, n, quote = [], 0, len(sql), None
    while i < n:
        c = sql[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(sql[i + 1]); i += 2; continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
            out.append(c)
        elif c == "?":
            if not params:
                raise MysqlError("not enough parameters for the statement")
            out.append(literal(params.pop(0)))
        else:
            out.append(c)
        i += 1
    if params:
        raise MysqlError("too many parameters for the statement")
    return "".join(out)


def native_password(password: str, scramble: bytes) -> bytes:
    if not password:
        return b""
    p1 = hashlib.sha1(password.encode()).digest()
    p2 = hashlib.sha1(p1).digest()
    p3 = hashlib.sha1(scramble[:20] + p2).digest()
    return bytes(a ^ b for a, b in zip(p1, p3))


class MysqlConn:
    def __init__(self, reader, writer):
        self.r, self.w = reader, writer
        self.pr = PacketReader()
        self.pending = []
        self.seq = 0
        self.deprecate_eof = False

    @classmethod
    async def connect(cls, host, port, user, password, database="", timeout=10.0):
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        c = cls(r, w)
        await asyncio.wait_for(c._handshake(user, password, database), timeout)
        return c

    @classmethod
    async def from_url(cls, url: str, database: str | None = None, timeout=10.0):
        p = parse_url(url)
        return await cls.connect(p["host"], p["port"], p["user"], p["password"],
                                 p["database"] if database is None else database, timeout)

    async def _packet(self):
        while not self.pending:
            data = await self.r.read(65536)
            if not data:
                raise ConnectionError("mysql closed the connection")
            self.pending.extend(self.pr.feed(data))
        seq, p = self.pending.pop(0)
        self.seq = (seq + 1) & 0xFF
        return p

    def _send(self, payload: bytes, seq: int | None = None):
        s = self.seq if seq is None else seq
        self.w.write(frame(s, payload))
        self.seq = (s + 1 + len(payload) // MAX_PACKET) & 0xFF

    async def _handshake(self, user, password, database):
        g = await self._packet()
        if g[:1] == b"\xff":
            raise MysqlError(err_message(g))
        if g[0] != 10:
            raise MysqlError("unsupported handshake protocol %d" % g[0])
        end = g.index(b"\x00", 1)
        pos = end + 1 + 4
        part1 = g[pos:pos + 8]
        pos += 9
        low = struct.unpack_from("<H", g, pos)[0]
        pos += 2 + 1 + 2
        high = struct.unpack_from("<H", g, pos)[0]
        pos += 2
        caps = low | (high << 16)
        alen = g[pos]
        pos += 1 + 10
        part2_len = max(13, alen - 8) if caps & CLIENT_SECURE_CONNECTION else 0
        part2 = g[pos:pos + part2_len].rstrip(b"\x00")
        pos += part2_len
        plugin = g[pos:].split(b"\x00", 1)[0].decode() if caps & CLIENT_PLUGIN_AUTH else "mysql_native_password"
        scramble = part1 + part2
        flags = (CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_LONG_FLAG | CLIENT_TRANSACTIONS
                 | CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS | CLIENT_PLUGIN_AUTH | 1)
        if database:
            flags |= CLIENT_CONNECT_WITH_DB
        if caps & CLIENT_DEPRECATE_EOF:
            flags |= CLIENT_DEPRECATE_EOF
            self.deprecate_eof = True
        flags &= caps | CLIENT_PLUGIN_AUTH | 1
        auth = native_password(password, scramble) if plugin == "mysql_native_password" else b""
        body = struct.pack("<IIB", flags, 1 << 24, 45) + b"\x00" * 23 + user.encode() + b"\x00"
        body += bytes([len(auth)]) + auth
        if database:
            body += database.encode() + b"\x00"
        body += b"mysql_native_password\x00"
        self._send(body)
        await self.w.drain()
        while True:
            p = await self._packet()
            if p[:1] == b"\x00":
                return
            if p[:1] == b"\xff":
                raise MysqlError(err_message(p))
            if p[:1] == b"\xfe":
                name, _, data = p[1:].partition(b"\x00")
                if name.decode() != "mysql_native_password":
                    raise MysqlError("unsupported auth plugin %s (use mysql_native_password)" % name.decode())
                self._send(native_password(password, data.rstrip(b"\x00")))
                await self.w.drain()
                continue
            if p[:1] == b"\x01":
                raise MysqlError("unsupported auth exchange (use mysql_native_password)")
            raise MysqlError("unexpected packet during authentication")

    async def query(self, sql: str):
        """Text query (may be a multi-statement string). Returns rows (tuples of str|None) of the last result
        set that had rows."""
        self.seq = 0
        self._send(b"\x03" + sql.encode())
        await self.w.drain()
        rows, err = [], None
        while True:
            p = await self._packet()
            if p[:1] == b"\x00":
                more = self._status_ok(p) & SERVER_MORE_RESULTS_EXISTS
            elif p[:1] == b"\xff":
                raise MysqlError(err_message(p))
            else:
                ncol, _ = lenenc_int(p, 0)
                for _ in range(int(ncol or 0)):
                    await self._packet()
                if not self.deprecate_eof:
                    await self._packet()
                result = []
                while True:
                    r = await self._packet()
                    if r[:1] == b"\xff":
                        raise MysqlError(err_message(r))
                    if r[:1] == b"\xfe" and len(r) < MAX_PACKET and (self.deprecate_eof or len(r) < 9):
                        more = (self._status_ok(r) if self.deprecate_eof else struct.unpack_from("<H", r, 3)[0]) \
                            & SERVER_MORE_RESULTS_EXISTS
                        break
                    row, pos = [], 0
                    for _ in range(int(ncol or 0)):
                        if r[pos] == 0xFB:
                            row.append(None); pos += 1; continue
                        ln, pos = lenenc_int(r, pos)
                        row.append(r[pos:pos + ln].decode("utf-8", "replace")); pos += ln
                    result.append(tuple(row))
                rows = result
            if not more:
                if err:
                    raise err
                return rows

    @staticmethod
    def _status_ok(p: bytes) -> int:
        _, pos = lenenc_int(p, 1)
        _, pos = lenenc_int(p, pos)
        return struct.unpack_from("<H", p, pos)[0] if len(p) >= pos + 2 else 0

    async def execute(self, sql: str, params=()):
        """``?`` placeholders, interpolated as escaped literals."""
        return await self.query(interpolate(sql, params))

    async def close(self):
        try:
            self.seq = 0
            self._send(b"\x01")
            await self.w.drain()
        except Exception:
            pass
        self.w.close()
