"""Minimal asyncio PostgreSQL client (no dependencies) for the sidecar's own work:
the clone database reset (server.Sidecar.reset_db), ``ensure_user`` hooks and test seeding.

Auth: trust, cleartext, md5, SCRAM-SHA-256. Plaintext only (the clone network is private).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import struct
from urllib.parse import unquote, urlparse

from .pgproxy import BackendReader, error_fields


class PgError(Exception):
    def __init__(self, fields: dict):
        self.fields = fields
        super().__init__(f"{fields.get('C', '')} {fields.get('M', '')}")


def parse_url(url: str) -> dict:
    u = urlparse(url)
    return {"host": u.hostname or "127.0.0.1", "port": u.port or 5432, "user": unquote(u.username or "postgres"),
            "password": unquote(u.password or ""), "database": (u.path or "/").lstrip("/") or "postgres"}


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class PgConn:
    def __init__(self, reader, writer):
        self.r, self.w = reader, writer
        self.br = BackendReader()
        self.pending = []

    @classmethod
    async def connect(cls, host, port, user, password, database, timeout=10.0):
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        c = cls(r, w)
        params = b"user\x00" + user.encode() + b"\x00database\x00" + database.encode() + b"\x00\x00"
        body = struct.pack("!I", 196608) + params
        w.write(struct.pack("!I", len(body) + 4) + body)
        await w.drain()
        await asyncio.wait_for(c._auth(user, password), timeout)
        return c

    @classmethod
    async def from_url(cls, url: str, database: str | None = None, timeout=10.0):
        p = parse_url(url)
        return await cls.connect(p["host"], p["port"], p["user"], p["password"], database or p["database"], timeout)

    async def _msg(self):
        while not self.pending:
            data = await self.r.read(65536)
            if not data:
                raise ConnectionError("postgres closed the connection")
            self.pending.extend(self.br.feed(data))
        return self.pending.pop(0)

    def _send(self, t: bytes, payload: bytes):
        self.w.write(t + struct.pack("!I", len(payload) + 4) + payload)

    async def _auth(self, user, password):
        scram = None
        while True:
            t, p = await self._msg()
            if t == "E":
                raise PgError(error_fields(p))
            if t == "R":
                (code,) = struct.unpack("!I", p[:4])
                if code == 0:
                    continue
                if code == 3:
                    self._send(b"p", password.encode() + b"\x00")
                elif code == 5:
                    salt = p[4:8]
                    inner = hashlib.md5(password.encode() + user.encode()).hexdigest().encode()
                    self._send(b"p", b"md5" + hashlib.md5(inner + salt).hexdigest().encode() + b"\x00")
                elif code == 10:
                    mechs = p[4:].split(b"\x00")
                    if b"SCRAM-SHA-256" not in mechs:
                        raise PgError({"M": f"unsupported SASL mechanisms {mechs}"})
                    scram = _Scram(password)
                    first = scram.client_first()
                    self._send(b"p", b"SCRAM-SHA-256\x00" + struct.pack("!i", len(first)) + first)
                elif code == 11:
                    self._send(b"p", scram.client_final(p[4:]))
                elif code == 12:
                    scram.verify(p[4:])
                    continue
                else:
                    raise PgError({"M": f"unsupported auth method {code}"})
                await self.w.drain()
            elif t == "Z":
                return

    async def query(self, sql: str):
        """Simple query. Returns rows (list of tuples of str|None) of the last result set."""
        self._send(b"Q", sql.encode() + b"\x00")
        await self.w.drain()
        return await self._collect()

    async def execute(self, sql: str, params=()):
        """Extended protocol with text parameters (bound, never interpolated)."""
        vals = [None if v is None else str(v).encode() for v in params]
        bind = b"\x00\x00" + struct.pack("!H", 0) + struct.pack("!H", len(vals))
        for v in vals:
            bind += struct.pack("!i", -1) if v is None else struct.pack("!i", len(v)) + v
        bind += struct.pack("!H", 0)
        self._send(b"P", b"\x00" + sql.encode() + b"\x00" + struct.pack("!H", 0))
        self._send(b"B", bind)
        self._send(b"D", b"P\x00")
        self._send(b"E", b"\x00" + struct.pack("!I", 0))
        self._send(b"S", b"")
        await self.w.drain()
        return await self._collect()

    async def _collect(self):
        rows, err = [], None
        while True:
            t, p = await self._msg()
            if t == "T":
                rows = []
            elif t == "D":
                (n,) = struct.unpack("!H", p[:2])
                pos, row = 2, []
                for _ in range(n):
                    (ln,) = struct.unpack("!i", p[pos:pos + 4]); pos += 4
                    if ln < 0:
                        row.append(None)
                    else:
                        row.append(p[pos:pos + ln].decode("utf-8", "replace")); pos += ln
                rows.append(tuple(row))
            elif t == "E":
                err = PgError(error_fields(p))
            elif t == "Z":
                if err:
                    raise err
                return rows

    async def close(self):
        try:
            self._send(b"X", b"")
            await self.w.drain()
        except Exception:
            pass
        self.w.close()


class _Scram:
    def __init__(self, password):
        self.password = password.encode()
        self.nonce = base64.b64encode(os.urandom(18)).decode()
        self.bare = f"n=,r={self.nonce}"

    def client_first(self) -> bytes:
        return ("n,," + self.bare).encode()

    def client_final(self, server_first: bytes) -> bytes:
        sf = server_first.decode()
        attrs = dict(kv.split("=", 1) for kv in sf.split(","))
        if not attrs["r"].startswith(self.nonce):
            raise PgError({"M": "SCRAM nonce mismatch"})
        salted = hashlib.pbkdf2_hmac("sha256", self.password, base64.b64decode(attrs["s"]), int(attrs["i"]))
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        stored = hashlib.sha256(client_key).digest()
        without_proof = f"c=biws,r={attrs['r']}"
        auth_msg = f"{self.bare},{sf},{without_proof}".encode()
        sig = hmac.new(stored, auth_msg, hashlib.sha256).digest()
        proof = bytes(a ^ b for a, b in zip(client_key, sig))
        server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        self.server_sig = hmac.new(server_key, auth_msg, hashlib.sha256).digest()
        return f"{without_proof},p={base64.b64encode(proof).decode()}".encode()

    def verify(self, server_final: bytes):
        v = dict(kv.split("=", 1) for kv in server_final.decode().split(","))
        if base64.b64decode(v.get("v", "")) != self.server_sig:
            raise PgError({"M": "SCRAM server signature mismatch"})

