"""MySQL / MariaDB wire-protocol proxy (asyncio) that observes executed statements.

Twin of ``pgproxy.py`` for apps on MySQL or MariaDB. The proxy sits between the app and the server and
forwards every byte unchanged, except the server greeting: it clears ``CLIENT_SSL`` and
``CLIENT_COMPRESS`` (so the client stays on the same plaintext, uncompressed connection, as the
Postgres proxy does by answering ``N`` to ``SSLRequest``) and zeroes MariaDB's extended capabilities
(metadata caching would make result sets unparseable). Authentication passes through untouched.

Observed statement text:
- ``COM_QUERY``: the whole query string (may hold several statements);
- ``COM_STMT_PREPARE``: the statement text, recorded per statement id; ``COM_STMT_EXECUTE`` of that id is
  the execution. Bound parameters are data and are never recorded as statement text, so they can never
  fire the taint check.

Success:
- ``COM_QUERY``: executed iff at least one OK packet or result set answers it (MySQL runs a
  multi-statement string one statement at a time, so an ERR after the first result still means the
  first one ran);
- ``COM_STMT_EXECUTE``: executed iff OK or a (binary) result set answers it; ERR fails it.

Every write statement (INSERT/UPDATE/DELETE/REPLACE/TRUNCATE/ALTER/CREATE/DROP/RENAME/LOAD), executed or
not and inside a request window or not, marks its target tables dirty: the L1 reset rebuilds only those
from the template database (MySQL has no ``CREATE DATABASE ... TEMPLATE``). A write whose target cannot be
read marks everything dirty.

``StatementTracker`` is pure (no I/O) and unit-tested; ``MysqlProxy`` wires it to sockets.
"""
from __future__ import annotations

import asyncio
import logging
import re
import struct
from collections import deque

log = logging.getLogger("sidecar.mysql")

CLIENT_LONG_PASSWORD = 1
CLIENT_COMPRESS = 1 << 5
CLIENT_PROTOCOL_41 = 1 << 9
CLIENT_SSL = 1 << 11
CLIENT_DEPRECATE_EOF = 1 << 24
SERVER_MORE_RESULTS_EXISTS = 0x0008
MAX_PACKET = 0xFFFFFF

COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST = 0x01, 0x02, 0x03, 0x04
COM_STATISTICS, COM_PING, COM_CHANGE_USER = 0x09, 0x0E, 0x11
COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_SEND_LONG_DATA = 0x16, 0x17, 0x18
COM_STMT_CLOSE, COM_STMT_RESET, COM_SET_OPTION, COM_STMT_FETCH = 0x19, 0x1A, 0x1B, 0x1C
COM_RESET_CONNECTION = 0x1F
NO_RESPONSE = {COM_QUIT, COM_STMT_CLOSE, COM_STMT_SEND_LONG_DATA}


class ProtocolError(Exception):
    pass


# ---------------------------------------------------------------------------- framing
class PacketReader:
    """Incremental splitter of a byte stream into logical packets ``(seq, payload)``.

    A payload of exactly 0xFFFFFF bytes continues in the next packet; the pieces are joined and the
    sequence id of the first piece is reported."""

    def __init__(self):
        self.buf = bytearray()
        self._part = None  # (seq, bytearray) while a split payload is being joined

    def feed(self, data: bytes):
        self.buf += data
        out = []
        while len(self.buf) >= 4:
            n = self.buf[0] | (self.buf[1] << 8) | (self.buf[2] << 16)
            if len(self.buf) < 4 + n:
                break
            seq = self.buf[3]
            payload = bytes(self.buf[4:4 + n])
            del self.buf[:4 + n]
            if self._part is not None:
                self._part[1].extend(payload)
                if n < MAX_PACKET:
                    out.append((self._part[0], bytes(self._part[1])))
                    self._part = None
            elif n == MAX_PACKET:
                self._part = (seq, bytearray(payload))
            else:
                out.append((seq, payload))
        return out

    def at_boundary(self) -> bool:
        return not self.buf and self._part is None


def frame(seq: int, payload: bytes) -> bytes:
    out = bytearray()
    while True:
        chunk, payload = payload[:MAX_PACKET], payload[MAX_PACKET:]
        out += len(chunk).to_bytes(3, "little") + bytes([seq & 0xFF]) + chunk
        seq += 1
        if len(chunk) < MAX_PACKET:
            return bytes(out)


def lenenc_int(buf: bytes, pos: int) -> tuple[int | None, int]:
    first = buf[pos]
    if first < 0xFB:
        return first, pos + 1
    if first == 0xFB:
        return None, pos + 1
    if first == 0xFC:
        return struct.unpack_from("<H", buf, pos + 1)[0], pos + 3
    if first == 0xFD:
        return int.from_bytes(buf[pos + 1:pos + 4], "little"), pos + 4
    return struct.unpack_from("<Q", buf, pos + 1)[0], pos + 9


def ok_status(payload: bytes) -> int:
    """Server status flags of an OK packet (header 0x00 or 0xFE): after affected rows and last insert id."""
    try:
        _, pos = lenenc_int(payload, 1)
        _, pos = lenenc_int(payload, pos)
        return struct.unpack_from("<H", payload, pos)[0]
    except (struct.error, IndexError):
        return 0


def eof_status(payload: bytes) -> int:
    try:
        return struct.unpack_from("<H", payload, 3)[0]
    except struct.error:
        return 0


def err_message(payload: bytes) -> str:
    try:
        code = struct.unpack_from("<H", payload, 1)[0]
        rest = payload[3:]
        if rest[:1] == b"#":
            state, msg = rest[1:6].decode("ascii", "replace"), rest[6:]
        else:
            state, msg = "", rest
        return f"{code} {state} {msg.decode('utf-8', 'replace')}".replace("  ", " ").strip()
    except (struct.error, IndexError):
        return "error"


def patch_greeting(payload: bytes) -> bytes:
    """Initial handshake v10 with CLIENT_SSL / CLIENT_COMPRESS cleared and MariaDB extended capabilities zeroed."""
    if not payload or payload[0] != 10:
        return payload  # protocol v9 / an ERR greeting (too many connections): untouched
    try:
        end = payload.index(b"\x00", 1)
    except ValueError:
        return payload
    pos = end + 1 + 4 + 8 + 1          # version, connection id, auth-plugin-data part 1, filler
    if len(payload) < pos + 2:
        return payload
    buf = bytearray(payload)
    low = struct.unpack_from("<H", buf, pos)[0] & ~(CLIENT_SSL | CLIENT_COMPRESS) & 0xFFFF
    struct.pack_into("<H", buf, pos, low)
    # charset(1) status(2) caps-high(2) auth-data-len(1) reserved(6) mariadb-ext-caps(4)
    ext = pos + 2 + 1 + 2 + 2 + 1 + 6
    if len(buf) >= ext + 4 and not (low & CLIENT_LONG_PASSWORD):
        # MariaDB clears CLIENT_MYSQL (bit 0): those 4 bytes are its extended capabilities
        buf[ext:ext + 4] = b"\x00\x00\x00\x00"
    return bytes(buf)


# ---------------------------------------------------------------------------- dirty tables
_IDENT = r"(?:`(?:[^`]|``)+`|[A-Za-z0-9_$]+)"
_QUALIFIED = r"(%s(?:\s*\.\s*%s)?)" % (_IDENT, _IDENT)
_WRITE_HEAD = re.compile(r"^\s*(?:/\*.*?\*/\s*)*(INSERT|REPLACE|UPDATE|DELETE|TRUNCATE|ALTER|DROP|CREATE|RENAME|LOAD|"
                         r"CALL|GRANT|REVOKE|OPTIMIZE|REPAIR)\b", re.I | re.S)
_TARGETS = [
    re.compile(r"^\s*(?:INSERT|REPLACE)(?:\s+(?:LOW_PRIORITY|DELAYED|HIGH_PRIORITY|IGNORE))*(?:\s+INTO)?\s+" + _QUALIFIED, re.I),
    re.compile(r"^\s*UPDATE(?:\s+(?:LOW_PRIORITY|IGNORE))*\s+" + _QUALIFIED + r"\s+(?:AS\s+\w+\s+|\w+\s+)?SET\b", re.I),
    re.compile(r"^\s*DELETE(?:\s+(?:LOW_PRIORITY|QUICK|IGNORE))*\s+FROM\s+" + _QUALIFIED + r"(?:\s|$|;)", re.I),
    re.compile(r"^\s*TRUNCATE(?:\s+TABLE)?\s+" + _QUALIFIED, re.I),
    re.compile(r"^\s*ALTER(?:\s+(?:ONLINE|IGNORE))*\s+TABLE\s+" + _QUALIFIED, re.I),
    re.compile(r"^\s*DROP\s+(?:TEMPORARY\s+)?TABLE(?:\s+IF\s+EXISTS)?\s+" + _QUALIFIED, re.I),
    re.compile(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMPORARY\s+)?TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+" + _QUALIFIED, re.I),
]
_NO_WRITE = re.compile(r"^\s*CREATE\s+TEMPORARY\b|^\s*DROP\s+TEMPORARY\b", re.I)


def _unquote(name: str) -> str:
    name = re.sub(r"\s*\.\s*", ".", name.strip())
    parts = [p[1:-1].replace("``", "`") if p.startswith("`") else p for p in name.split(".")]
    return parts[-1]


def split_statements(sql: str) -> list[str]:
    """Split a multi-statement string on top-level ``;`` (quotes and comments respected)."""
    out, cur, i, n = [], [], 0, len(sql)
    quote = None
    while i < n:
        c = sql[i]
        if quote:
            cur.append(c)
            if c == "\\" and quote in "'\"" and i + 1 < n:
                cur.append(sql[i + 1]); i += 2; continue
            if c == quote:
                if i + 1 < n and sql[i + 1] == quote:
                    cur.append(sql[i + 1]); i += 2; continue
                quote = None
            i += 1
            continue
        if c in "'\"`":
            quote = c
        elif c == "#" or (c == "-" and sql.startswith("-- ", i)) or sql.startswith("/*", i):
            end = sql.find("*/", i + 2) + 2 if sql.startswith("/*", i) else sql.find("\n", i)
            end = n if end <= (1 if sql.startswith("/*", i) else -1) else end
            cur.append(sql[i:end]); i = end; continue
        elif c == ";":
            out.append("".join(cur)); cur = []; i += 1; continue
        cur.append(c)
        i += 1
    out.append("".join(cur))
    return [s for s in out if s.strip()]


def written_tables(sql: str) -> set | None:
    """Tables a statement string may write. Empty set: a read. None: a write whose target is unknown."""
    tables: set = set()
    for stmt in split_statements(sql):
        body = re.sub(r"^\s*(?:/\*.*?\*/\s*)+", "", stmt, flags=re.S)
        head = _WRITE_HEAD.match(body)
        if not head:
            continue
        if _NO_WRITE.match(body):
            continue
        kw = head.group(1).upper()
        if kw in ("CALL", "GRANT", "REVOKE", "LOAD", "RENAME", "OPTIMIZE", "REPAIR"):
            if kw == "RENAME":
                names = re.findall(_QUALIFIED + r"\s+TO\s+" + _QUALIFIED, body, re.I)
                if names:
                    for a, b in names:
                        tables.update({_unquote(a), _unquote(b)})
                    continue
            if kw == "LOAD":
                m = re.search(r"\bINTO\s+TABLE\s+" + _QUALIFIED, body, re.I)
                if m:
                    tables.add(_unquote(m.group(1)))
                    continue
            if kw in ("OPTIMIZE", "REPAIR"):
                continue
            return None
        if kw == "CREATE" and not re.match(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMPORARY\s+)?TABLE\b", body, re.I):
            if re.match(r"^\s*CREATE\s+(?:UNIQUE\s+|FULLTEXT\s+|SPATIAL\s+)?INDEX\b", body, re.I):
                m = re.search(r"\bON\s+" + _QUALIFIED, body, re.I)
                if m:
                    tables.add(_unquote(m.group(1)))
                    continue
            return None
        if kw == "DROP" and not re.match(r"^\s*DROP\s+(?:TEMPORARY\s+)?TABLE\b", body, re.I):
            if re.match(r"^\s*DROP\s+INDEX\b", body, re.I):
                m = re.search(r"\bON\s+" + _QUALIFIED, body, re.I)
                if m:
                    tables.add(_unquote(m.group(1)))
                    continue
            return None
        if kw == "UPDATE" and re.search(r"\bJOIN\b|,", body.split(" SET ")[0] if " SET " in body.upper() else body, re.I):
            return None  # multi-table update: targets are hard to read
        if kw == "DELETE" and not re.match(r"^\s*DELETE(?:\s+(?:LOW_PRIORITY|QUICK|IGNORE))*\s+FROM\b", body, re.I):
            return None  # multi-table delete
        target = None
        for rx in _TARGETS:
            m = rx.match(body)
            if m:
                target = m.group(1)
                break
        if target is None:
            return None
        tables.add(_unquote(target))
    return tables


# ---------------------------------------------------------------------------- tracker
class StatementTracker:
    """Pairs client commands with server outcomes for one connection.

    ``on_result(sql, ok, error, via)`` is called once per finished statement; ``on_write(tables)`` for
    every write statement sent (tables None = unknown target)."""

    def __init__(self, on_result, on_write=None, on_bound=None):
        self.on_result = on_result
        self.on_write = on_write
        self.on_bound = on_bound
        self.phase = "greeting"           # greeting -> auth -> command
        self.server_caps = 0
        self.client_caps = 0
        self.deprecate_eof = False
        self.stmts: dict[int, str] = {}   # statement id -> text
        self.queue: deque = deque()       # pending commands: dicts
        self.cur = None                   # response being parsed
        self.greeting_out = None          # patched greeting bytes (payload)

    # client -> server
    def frontend(self, seq: int, p: bytes):
        if self.phase == "greeting":
            return
        if self.phase == "auth":
            if seq == 1 and p and len(p) >= 4 and not self.client_caps:
                self.client_caps = struct.unpack_from("<I", p, 0)[0] if (self.server_caps & CLIENT_PROTOCOL_41) else \
                    struct.unpack_from("<H", p, 0)[0]
                self.deprecate_eof = bool(self.server_caps & self.client_caps & CLIENT_DEPRECATE_EOF)
            return
        if seq != 0 or not p:
            return  # continuation of a long command or LOCAL INFILE data
        cmd = p[0]
        if cmd == COM_QUERY:
            sql = p[1:].decode("utf-8", "replace")
            self._write(sql)
            self.queue.append({"kind": "query", "sql": sql, "done": 0, "error": None})
        elif cmd == COM_STMT_PREPARE:
            self.queue.append({"kind": "prepare", "sql": p[1:].decode("utf-8", "replace")})
        elif cmd == COM_STMT_EXECUTE:
            sid = struct.unpack_from("<I", p, 1)[0] if len(p) >= 5 else -1
            sql = self.stmts.get(sid, "")
            self._write(sql)
            self.queue.append({"kind": "execute", "sql": sql, "done": 0, "error": None})
        elif cmd == COM_STMT_CLOSE:
            if len(p) >= 5:
                self.stmts.pop(struct.unpack_from("<I", p, 1)[0], None)
        elif cmd == COM_CHANGE_USER:
            self.queue.append({"kind": "auth"})
        elif cmd == COM_STMT_FETCH:
            self.queue.append({"kind": "rows"})
        elif cmd in NO_RESPONSE:
            return
        else:
            self.queue.append({"kind": "simple"})

    def _write(self, sql: str):
        if self.on_write is None or not sql:
            return
        tables = written_tables(sql)
        if tables is None or tables:
            self.on_write(tables)

    # server -> client
    def backend(self, seq: int, p: bytes) -> bytes | None:
        """Returns a replacement payload for the greeting, else None (forward unchanged)."""
        if self.phase == "greeting":
            self.phase = "auth"
            if p and p[0] == 0xFF:
                return None
            patched = patch_greeting(p)
            try:
                end = patched.index(b"\x00", 1)
                pos = end + 1 + 4 + 8 + 1
                low = struct.unpack_from("<H", patched, pos)[0]
                high = struct.unpack_from("<H", patched, pos + 5)[0] if len(patched) >= pos + 7 else 0
                self.server_caps = low | (high << 16)
            except (ValueError, struct.error):
                self.server_caps = 0
            return patched if patched != p else None
        if self.phase == "auth":
            if p and p[0] in (0x00, 0xFF):
                self.phase = "command"
            return None
        self._response(p)
        return None

    def _finish(self, ok: bool, error: str | None = None):
        head = self.queue.popleft() if self.queue else None
        self.cur = None
        if head is None:
            return
        if head["kind"] in ("query", "execute"):
            self.on_result(head["sql"], ok, error, "simple" if head["kind"] == "query" else "prepared")

    def _response(self, p: bytes):
        if not self.queue:
            return
        head = self.queue[0]
        kind = head["kind"]
        if kind == "auth":
            if p and p[0] in (0x00, 0xFF):
                self.queue.popleft()
            return
        if kind == "simple":
            self.queue.popleft()
            return
        if kind == "prepare":
            st = self.cur
            if st is None:
                if p[:1] == b"\xff":
                    self.queue.popleft()
                    return
                if p[:1] != b"\x00" or len(p) < 9:
                    self.queue.popleft()
                    return
                sid, ncol, npar = struct.unpack_from("<IHH", p, 1)
                self.stmts[sid] = head["sql"]
                remaining = npar + ncol
                if not self.deprecate_eof:
                    remaining += (1 if npar else 0) + (1 if ncol else 0)
                if remaining == 0:
                    self.queue.popleft()
                else:
                    self.cur = {"left": remaining}
                return
            st["left"] -= 1
            if st["left"] <= 0:
                self.cur = None
                self.queue.popleft()
            return
        # query / execute / rows: a sequence of results
        st = self.cur
        if st is None:
            first = p[:1]
            if kind == "rows":
                st = self.cur = {"stage": "rows"}
            elif first == b"\x00":
                head["done"] += 1
                if not ok_status(p) & SERVER_MORE_RESULTS_EXISTS:
                    self._finish(True)
                return
            elif first == b"\xff":
                err = err_message(p)
                self._finish(head["done"] > 0, None if head["done"] else err)
                return
            elif first == b"\xfb" and kind == "query":
                return  # LOCAL INFILE request: the client streams the file, then OK/ERR follows
            else:
                try:
                    ncol, _ = lenenc_int(p, 0)
                except (IndexError, struct.error):
                    ncol = 0
                self.cur = {"stage": "cols", "left": int(ncol or 0)}
                return
        if st["stage"] == "cols":
            st["left"] -= 1
            if st["left"] <= 0:
                st["stage"] = "rows" if self.deprecate_eof else "coleof"
            return
        if st["stage"] == "coleof":
            st["stage"] = "rows"
            return
        if st["stage"] == "rows":
            if p[:1] == b"\xff":
                err = err_message(p)
                if kind == "rows":
                    self.cur = None
                    self.queue.popleft()
                    return
                self._finish(head["done"] > 0, None if head["done"] else err)
                return
            if p[:1] == b"\xfe" and len(p) < MAX_PACKET and (self.deprecate_eof or len(p) < 9):
                status = ok_status(p) if self.deprecate_eof else eof_status(p)
                if kind == "rows":
                    self.cur = None
                    self.queue.popleft()
                    return
                head["done"] += 1
                self.cur = None
                if not status & SERVER_MORE_RESULTS_EXISTS:
                    self._finish(True)
            return


# ---------------------------------------------------------------------------- proxy
class MysqlProxy:
    """Listens on ``listen`` and forwards to ``upstream``. ``sink(sql, ok, error, via)`` gets every statement."""

    def __init__(self, listen_host: str, listen_port: int, up_host: str, up_port: int, sink, bound_sink=None):
        self.listen_host, self.listen_port = listen_host, listen_port
        self.up_host, self.up_port = up_host, up_port
        self.sink = sink
        self.bound_sink = bound_sink
        self.server = None
        self.ready = asyncio.Event()  # cleared during a database reset: new connections wait
        self.ready.set()
        self.conns: set = set()
        self.upstreams: dict = {}     # app-side writer -> (upstream writer, client reader)
        self.dirty: set = set()
        self.dirty_all = False

    def on_write(self, tables):
        if tables is None:
            self.dirty_all = True
        else:
            self.dirty.update(t.lower() for t in tables)

    def take_dirty(self):
        """(tables, everything) written since the last call."""
        out = (set(self.dirty), self.dirty_all)
        self.dirty.clear()
        self.dirty_all = False
        return out

    async def start(self):
        self.server = await asyncio.start_server(self._client, self.listen_host, self.listen_port)
        log.info("mysql proxy %s:%s -> %s:%s", self.listen_host, self.listen_port, self.up_host, self.up_port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for w in list(self.conns):
            w.close()

    async def terminate_all(self):
        """End every proxied session: COM_QUIT upstream (at a packet boundary) and close the app side."""
        for cw, (sw, fr) in list(self.upstreams.items()):
            try:
                if fr.at_boundary():
                    sw.write(frame(0, bytes([COM_QUIT])))
                sw.close()
            except Exception:
                pass
            try:
                cw.close()
            except Exception:
                pass
        self.upstreams.clear()

    async def _client(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter):
        self.conns.add(cw)
        sw = None
        try:
            await self.ready.wait()
            sr, sw = await asyncio.open_connection(self.up_host, self.up_port)
            self.conns.add(sw)
            fr = PacketReader()
            self.upstreams[cw] = (sw, fr)
            tracker = StatementTracker(self.sink, self.on_write, self.bound_sink)
            await asyncio.gather(self._pump_front(cr, sw, fr, tracker), self._pump_back(sr, cw, tracker))
        except (ConnectionError, ProtocolError, asyncio.IncompleteReadError, OSError) as e:
            log.debug("mysql connection ended: %r", e)
        finally:
            self.upstreams.pop(cw, None)
            for w in (cw, sw):
                if w is not None:
                    self.conns.discard(w)
                    try:
                        w.close()
                    except Exception:
                        pass

    async def _pump_front(self, cr, sw, fr, tracker):
        try:
            while True:
                data = await cr.read(65536)
                if not data:
                    break
                for seq, p in fr.feed(data):  # parse first so the tracker sees commands before replies
                    tracker.frontend(seq, p)
                sw.write(data)
                await sw.drain()
        finally:
            try:
                sw.close()
            except Exception:
                pass

    async def _pump_back(self, sr, cw, tracker):
        br = PacketReader()
        try:
            while True:
                data = await sr.read(65536)
                if not data:
                    break
                if tracker.phase == "greeting":
                    # the greeting is the only packet we rewrite: re-frame what was parsed, forward the rest raw
                    out = bytearray()
                    for seq, p in br.feed(data):
                        if tracker.phase == "greeting":
                            repl = tracker.backend(seq, p)
                            out += frame(seq, repl if repl is not None else p)
                        else:
                            tracker.backend(seq, p)
                            out += frame(seq, p)
                    out += bytes(br.buf)
                    cw.write(bytes(out))   # a partial next packet stays in br.buf for parsing only
                else:
                    for seq, p in br.feed(data):
                        tracker.backend(seq, p)
                    cw.write(data)
                await cw.drain()
        finally:
            try:
                cw.close()
            except Exception:
                pass

