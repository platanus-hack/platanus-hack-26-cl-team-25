"""PostgreSQL wire-protocol proxy (asyncio) that observes executed statements.

The proxy sits between the app and Postgres and forwards every byte unchanged, except
that it answers ``SSLRequest`` / ``GSSENCRequest`` itself with ``N`` (so the client falls
back to plaintext on the same connection). Authentication passes through untouched.

Observed statement text:
- simple query ``Q``: the whole query string (may hold several statements);
- extended protocol: the text of ``P`` (Parse). ``B`` (Bind) parameters are data and are never
  recorded as statement text, so they can never fire the taint check.

Success:
- ``Q``: executed iff at least one ``CommandComplete``/``EmptyQueryResponse`` arrives before its
  ``ReadyForQuery``. Postgres parses the whole multi-statement string before running any of it,
  so a syntax error anywhere means nothing ran (the ``O'Brien`` case).
- ``E`` (Execute): executed iff ``CommandComplete``/``EmptyQueryResponse``/``PortalSuspended``
  answers it; an ``ErrorResponse`` fails it and every later Execute up to the next ``Sync``.

``StatementTracker`` is pure (no I/O) and unit-tested; ``PgProxy`` wires it to sockets.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from collections import deque

log = logging.getLogger("sidecar.pg")

SSL_REQUEST = 80877103
GSSENC_REQUEST = 80877104
CANCEL_REQUEST = 80877102
MAX_MSG = 1 << 30


class ProtocolError(Exception):
    pass


def _cstr(buf: bytes, pos: int) -> tuple[str, int]:
    end = buf.index(b"\x00", pos)
    return buf[pos:end].decode("utf-8", "replace"), end + 1


class FrontendReader:
    """Incremental splitter of client->server bytes into (type, payload). First message is untyped."""

    def __init__(self):
        self.buf = bytearray()
        self.started = False

    def feed(self, data: bytes):
        self.buf += data
        out = []
        while True:
            if not self.started:
                if len(self.buf) < 8:
                    break
                (n,) = struct.unpack("!I", self.buf[:4])
                if n < 8 or n > MAX_MSG:
                    raise ProtocolError(f"bad startup length {n}")
                if len(self.buf) < n:
                    break
                payload = bytes(self.buf[4:n]); del self.buf[:n]
                (code,) = struct.unpack("!I", payload[:4])
                out.append(("startup", payload))
                if code not in (SSL_REQUEST, GSSENC_REQUEST):
                    self.started = True  # StartupMessage or CancelRequest; typed messages follow
                continue
            if len(self.buf) < 5:
                break
            t = chr(self.buf[0])
            (n,) = struct.unpack("!I", self.buf[1:5])
            if n < 4 or n > MAX_MSG:
                raise ProtocolError(f"bad length {n} for {t!r}")
            if len(self.buf) < 1 + n:
                break
            payload = bytes(self.buf[5:1 + n]); del self.buf[:1 + n]
            out.append((t, payload))
        return out


class BackendReader:
    """Incremental splitter of server->client bytes (always typed)."""

    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes):
        self.buf += data
        out = []
        while len(self.buf) >= 5:
            t = chr(self.buf[0])
            (n,) = struct.unpack("!I", self.buf[1:5])
            if n < 4 or n > MAX_MSG:
                raise ProtocolError(f"bad length {n} for {t!r}")
            if len(self.buf) < 1 + n:
                break
            payload = bytes(self.buf[5:1 + n]); del self.buf[:1 + n]
            out.append((t, payload))
        return out


def error_fields(payload: bytes) -> dict:
    out, pos = {}, 0
    while pos < len(payload) and payload[pos] != 0:
        code = chr(payload[pos])
        val, pos = _cstr(payload, pos + 1)
        out[code] = val
    return out


class StatementTracker:
    """Pairs frontend requests with backend outcomes for one connection.

    ``on_result(sql, ok, error, via)`` is called once per finished statement.
    """

    def __init__(self, on_result):
        self.on_result = on_result
        self.stmts: dict[str, str] = {}    # prepared statement name -> text
        self.portals: dict[str, str] = {}  # portal name -> text
        self.queue: deque = deque()        # items: ["Q", sql, completes, error] | ["E", sql] | ["S"]
        self.params: dict[str, list] = {}  # portal -> bound params (kept for debugging only)

    # client -> server
    def frontend(self, t: str, p: bytes):
        if t == "startup":
            (code,) = struct.unpack("!I", p[:4])
            if code not in (SSL_REQUEST, GSSENC_REQUEST, CANCEL_REQUEST):
                self.queue.append(["START"])  # authentication ends with its own ReadyForQuery
        elif t == "Q":
            sql, _ = _cstr(p, 0)
            self.queue.append(["Q", sql, 0, None])
        elif t == "P":
            name, pos = _cstr(p, 0)
            sql, _ = _cstr(p, pos)
            self.stmts[name] = sql
        elif t == "B":
            portal, pos = _cstr(p, 0)
            stmt, pos = _cstr(p, pos)
            self.portals[portal] = self.stmts.get(stmt, "")
        elif t == "E":
            portal, _ = _cstr(p, 0)
            self.queue.append(["E", self.portals.get(portal, "")])
        elif t == "S":
            self.queue.append(["S"])
        elif t == "C":  # Close statement/portal
            kind = chr(p[0]) if p else ""
            name, _ = _cstr(p, 1)
            (self.stmts if kind == "S" else self.portals).pop(name, None)

    # server -> client
    def backend(self, t: str, p: bytes):
        if t in ("C", "I", "s"):  # CommandComplete, EmptyQueryResponse, PortalSuspended
            while self.queue and self.queue[0][0] == "START":
                self.queue.popleft()  # defensive: we missed the startup ReadyForQuery
            if not self.queue:
                return
            head = self.queue[0]
            if head[0] == "Q":
                head[2] += 1
            elif head[0] == "E":
                self.queue.popleft()
                self.on_result(head[1], True, None, "extended")
        elif t == "E":  # ErrorResponse
            err = error_fields(p)
            msg = f"{err.get('C', '')} {err.get('M', '')}".strip()
            if not self.queue:
                return
            head = self.queue[0]
            if head[0] == "START":
                self.queue.popleft()  # authentication failed; the server closes the connection
            elif head[0] == "Q":
                head[3] = msg
            else:
                # error in Parse/Bind/Execute: the rest of the batch up to Sync is skipped by the server
                while self.queue and self.queue[0][0] == "E":
                    item = self.queue.popleft()
                    self.on_result(item[1], False, msg, "extended")
        elif t == "Z":  # ReadyForQuery
            if not self.queue:
                return
            head = self.queue[0]
            if head[0] == "START":
                self.queue.popleft()
            elif head[0] == "Q":
                self.queue.popleft()
                self.on_result(head[1], head[2] > 0, head[3], "simple")
            elif head[0] == "S":
                self.queue.popleft()
                # Executes left before this Sync never got an answer (should not happen): failed
            else:
                while self.queue and self.queue[0][0] == "E":
                    item = self.queue.popleft()
                    self.on_result(item[1], False, "no response before ReadyForQuery", "extended")
                if self.queue and self.queue[0][0] == "S":
                    self.queue.popleft()


class PgProxy:
    """Listens on ``listen`` and forwards to ``upstream``. ``sink(sql, ok, error, via)`` gets every statement."""

    def __init__(self, listen_host: str, listen_port: int, up_host: str, up_port: int, sink):
        self.listen_host, self.listen_port = listen_host, listen_port
        self.up_host, self.up_port = up_host, up_port
        self.sink = sink
        self.server = None
        self.ready = asyncio.Event()  # cleared during a database reset: new connections wait
        self.ready.set()
        self.conns: set = set()     # every open writer (app side and upstream side)
        self.upstreams: dict = {}  # app-side writer -> (upstream writer, frontend reader)

    async def start(self):
        self.server = await asyncio.start_server(self._client, self.listen_host, self.listen_port)
        log.info("pg proxy %s:%s -> %s:%s", self.listen_host, self.listen_port, self.up_host, self.up_port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for w in list(self.conns):
            w.close()

    async def terminate_all(self):
        """End every proxied session gracefully: send Terminate ('X') upstream so each backend exits at
        once, and close the app side. Used before dropping the clone database: a backend that leaves on
        its own is gone in ~1 ms, while DROP ... WITH (FORCE) / pg_terminate_backend wait in 100 ms steps.
        Only call between requests (connections idle, at a message boundary)."""
        for cw, (sw, fr) in list(self.upstreams.items()):
            try:
                if not fr.buf:  # not in the middle of a client message
                    sw.write(b"X\x00\x00\x00\x04")
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
        sr = sw = None
        try:
            fr = FrontendReader()
            tracker = StatementTracker(self.sink)
            # handle SSL/GSS negotiation locally, before connecting upstream
            first = []
            while not first:
                data = await cr.read(65536)
                if not data:
                    return
                for t, p in fr.feed(data):
                    if t == "startup":
                        (code,) = struct.unpack("!I", p[:4])
                        if code in (SSL_REQUEST, GSSENC_REQUEST):
                            cw.write(b"N"); await cw.drain()
                            continue
                    first.append((t, p))
            await self.ready.wait()
            sr, sw = await asyncio.open_connection(self.up_host, self.up_port)
            self.conns.add(sw)
            self.upstreams[cw] = (sw, fr)
            for t, p in first:
                sw.write(_frame(t, p))
                tracker.frontend(t, p)
            if fr.buf:  # a partial next message: forward raw, the reader keeps it to finish parsing
                sw.write(bytes(fr.buf))
            await sw.drain()
            await asyncio.gather(self._pump_front(cr, sw, fr, tracker), self._pump_back(sr, cw, tracker))
        except (ConnectionError, ProtocolError, asyncio.IncompleteReadError, OSError) as e:
            log.debug("pg connection ended: %r", e)
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
                for t, p in fr.feed(data):  # parse first so the tracker sees requests before replies
                    tracker.frontend(t, p)
                sw.write(data)
                await sw.drain()
        finally:
            try:
                sw.close()
            except Exception:
                pass

    async def _pump_back(self, sr, cw, tracker):
        br = BackendReader()
        try:
            while True:
                data = await sr.read(65536)
                if not data:
                    break
                for t, p in br.feed(data):
                    tracker.backend(t, p)
                cw.write(data)
                await cw.drain()
        finally:
            try:
                cw.close()
            except Exception:
                pass


def _frame(t: str, p: bytes) -> bytes:
    if t == "startup":
        return struct.pack("!I", len(p) + 4) + p
    return t.encode() + struct.pack("!I", len(p) + 4) + p
