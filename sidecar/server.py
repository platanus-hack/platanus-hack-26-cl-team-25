"""``python -m sidecar``: the out-of-process shadow wrapper.

Per request (contracts/README.md §5, under one lock):
 1. strip ``x-imm-*``;  2. identity hook (``x-imm-uid`` -> app credentials, ``ensure_user`` on the clone db);
 3. (L2 pre-state: not available for Postgres / MySQL, ``pre_state_b64`` is null);
 4. open the observation window, forward to the app on loopback, buffer the whole response, keep the
    window open ``grace_ms`` longer, close it;  5. oracles;  6. verdict;  7. signed evidence push before
    the response is released;  8. response with verdict headers;  9. L1: recreate the clone database.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import logging
import os
import sys
import time

from immune_contracts import wire

from . import config as cfgmod
from . import constants as constmod
from . import http1, identity, mysqlclient, observer, pgclient, phptrace, sqllog
from .learn import H_LEARN, learn_message
from .mysqlproxy import MysqlProxy, written_tables
from .pgproxy import PgProxy
from .tracer import Tracer

log = logging.getLogger("sidecar")
WARMUP_MISSING = "/__sidecar_warmup__/missing"


class Sidecar:
    def __init__(self, cfg: cfgmod.Config):
        self.cfg = cfg
        self.env = dict(os.environ)
        self.file_markers = observer.load_file_markers(cfg.markers_path)   # planted secrets: marker -> file
        self.obs = observer.from_config(cfg, self.file_markers)
        self.ident = identity.Identity(identity.load_profile(cfg.profile), cfg.identity_command)
        self.markers = self.ident.markers(self.env, cfg.markers_path)
        self.public = self.ident.public_paths(cfg.public_paths)
        self.tracer = Tracer(self.obs.on_obs, mode=cfg.mode, command=cfg.command, anchor=cfg.target_pid,
                             container=cfg.container, image=cfg.tracer_image, label=cfg.tracer_label,
                             attempts=bool(self.obs.protected), on_attach=self._reattached) \
            if cfg.trace else None
        self.sqllog = sqllog.LogFollower(cfg.sql_log_cmd, cfg.sql_dialect, self.obs.on_statement) \
            if cfg.sql_log_cmd else None
        self.baseline = sqllog.Baseline(cfg.sql_baseline or "")
        self.warming = False
        self.loop = None
        self.proxy = None
        self.admin = None
        self.constants = None
        self.lock = asyncio.Lock()
        self._http = None
        self.last_reset_ms = None
        self.last_reset_tables = None
        self._seed_tables = None     # mysql: {lower name: name} of the template database
        self._admin_dirty = set()    # mysql: tables written by ensure_user (outside the proxy)
        self.dialect = cfg.sql_dialect if self.sqllog else ("mysql" if cfg.mysql else "sqlite")
        self.baseline_dialect = "mysql" if cfg.mysql and not self.sqllog else cfg.sql_dialect
        self.calltrace = phptrace.CallTracer.from_config(cfg.tracer, cfg.source_dirs) if cfg.tracer else None
        self.spec = None
        if cfg.openapi:
            try:
                from gateway.spec import Spec
                self.spec = Spec.load(cfg.openapi)
            except Exception as e:  # noqa: BLE001 - without it every path segment counts as input
                log.warning("openapi %s not loaded: %r", cfg.openapi, e)
        # judge mode (pipeline's ephemeral clones only, never fleet clones): every response also carries
        # x-imm-trace = base64(JSON {events, sql:[{sql, params}], failed, opens, marker_owners})
        self.judge = os.environ.get("SIDECAR_JUDGE") == "1"

    # ------------------------------------------------------------------ lifecycle
    async def start(self):
        cfg = self.cfg
        if cfg.postgres:
            await self.reset_db()
            pg = cfg.postgres
            self.proxy = PgProxy(pg.listen_host, pg.listen_port, pg.up_host, pg.up_port, self.obs.on_statement,
                                 self.obs.on_bound if self.judge else None)
            await self.proxy.start()
        elif cfg.mysql:
            await self.reset_db(full=True)
            my = cfg.mysql
            self.proxy = MysqlProxy(my.listen_host, my.listen_port, my.up_host, my.up_port, self.obs.on_statement,
                                    self.obs.on_bound if self.judge else None)
            await self.proxy.start()
        self.loop = asyncio.get_running_loop()
        if self.sqllog:
            self.sqllog.start()
        self.obs.learning = True
        if self.tracer:
            await asyncio.to_thread(self.tracer.start)
        await self._warmup()
        root = self.tracer.root_dir() if self.tracer else "/"
        exes = [f"/proc/{p}/exe" for p in self.tracer.app_pids_now()] if self.tracer else []
        self.constants = await asyncio.to_thread(constmod.scan, root, cfg.source_dirs, exes,
                                                 int(cfg.scan_executable_max_mb) << 20)
        if cfg.postgres:
            await self.reset_db()
        elif cfg.mysql:
            await self.reset_db(full=True)
        if self.calltrace:
            self.calltrace.root = root
            await asyncio.to_thread(self.calltrace.clear)
        log.info("ready: tracer=%s pids=%s allowlist=%d files, %d net; %d markers; %d constants; reset %.1f ms",
                 cfg.mode if self.tracer else "off", self.tracer.pids if self.tracer else [],
                 len(self.obs.file_allow), len(self.obs.net_allow), len(self.markers),
                 len(self.constants.strings), self.last_reset_ms or 0)

    async def _warmup(self):
        cfg = self.cfg
        await self._wait_health()
        self.obs.paused = False
        self.obs.learning = True
        for _ in range(max(1, int(cfg.warmup_rounds))):
            for p in [cfg.health, *cfg.warmup_paths, WARMUP_MISSING]:
                try:
                    await http1.request(cfg.app_host, cfg.app_port, "GET", p, [(b"host", b"localhost")], b"", 10)
                except Exception as e:
                    log.info("warm-up %s: %r", p, e)
        await asyncio.sleep(max(cfg.grace_ms, 50) / 1000)
        self.obs.learning = False

    def _reattached(self):
        """Tracer thread, docker mode: the app container was replaced. Its start-up must not be judged:
        fail closed until the warm-up has run again."""
        self.warming = True
        self.obs.paused = True      # what it reads while starting (its own config) is neither a finding nor "normal"
        asyncio.run_coroutine_threadsafe(self._rewarm(), self.loop)

    async def _rewarm(self):
        async with self.lock:
            try:
                await self._warmup()
                log.info("warm-up after re-attach done: allowlist=%d files", len(self.obs.file_allow))
            except Exception:
                log.exception("warm-up after re-attach failed")
            finally:
                self.obs.learning = False
                self.warming = False

    async def stop(self):
        if self.sqllog:
            self.sqllog.stop()
        if self.proxy:
            await self.proxy.stop()
        if self.admin:
            await self.admin.close()
        if self.tracer:
            self.tracer.stop()
        if self._http:
            await self._http.aclose()

    async def _wait_health(self, timeout=60.0):
        end = time.time() + timeout
        last = None
        while time.time() < end:
            try:
                st, _, _ = await http1.request(self.cfg.app_host, self.cfg.app_port, "GET", self.cfg.health,
                                               [(b"host", b"localhost")], b"", 5)
                if st < 500:
                    return
                last = st
            except Exception as e:
                last = e
            await asyncio.sleep(0.2)
        raise RuntimeError(f"app not healthy on {self.cfg.app_host}:{self.cfg.app_port}{self.cfg.health}: {last!r}")

    async def reset_db(self, full: bool = False):
        if self.cfg.mysql:
            return await self._reset_mysql(full)
        pg = self.cfg.postgres
        t = time.perf_counter()
        if self.proxy:
            self.proxy.ready.clear()  # new app connections wait until the database exists again
        try:
            if self.proxy:
                await self.proxy.terminate_all()
            for attempt in range(2):
                try:
                    if self.admin is None:
                        self.admin = await pgclient.PgConn.from_url(pg.admin_url)
                    q = pgclient.quote_ident
                    # wait (bounded) for the sessions we just ended to leave; FORCE covers anything else,
                    # e.g. a connection the app opened directly to Postgres
                    end = time.perf_counter() + 0.5
                    while time.perf_counter() < end:
                        rows = await self.admin.execute("SELECT count(*) FROM pg_stat_activity WHERE datname = $1",
                                                        (pg.database,))
                        if rows[0][0] == "0":
                            break
                        await asyncio.sleep(0.002)
                    await self.admin.query(f"DROP DATABASE IF EXISTS {q(pg.database)} WITH (FORCE)")
                    await self.admin.query(f"CREATE DATABASE {q(pg.database)} TEMPLATE {q(pg.template)}")
                    break
                except (ConnectionError, OSError):
                    self.admin = None
                    if attempt:
                        raise
        finally:
            if self.proxy:
                self.proxy.ready.set()
        self.last_reset_ms = (time.perf_counter() - t) * 1000

    async def _reset_mysql(self, full: bool):
        """Rebuild the clone database from the template: every table written since the last reset (the proxy
        and ensure_user report them), or all of them when a write target was unknown, and on start."""
        my = self.cfg.mysql
        t = time.perf_counter()
        if self.proxy:
            self.proxy.ready.clear()
        try:
            if self.proxy:
                await self.proxy.terminate_all()
                dirty, everything = self.proxy.take_dirty()
            else:
                dirty, everything = set(), True
            dirty |= self._admin_dirty
            self._admin_dirty = set()
            full = full or everything
            for attempt in range(2):
                try:
                    if self.admin is None:
                        self.admin = await mysqlclient.MysqlConn.from_url(my.admin_url, database="")
                    q = mysqlclient.quote_ident
                    if self._seed_tables is None:
                        rows = await self.admin.execute(
                            "SELECT table_name FROM information_schema.tables WHERE table_schema = ? "
                            "AND table_type = 'BASE TABLE'", (my.template,))
                        self._seed_tables = {r[0].lower(): r[0] for r in rows}
                    stmts = reset_statements(my.database, my.template, self._seed_tables, dirty, full, q)
                    head = stmts[:2]
                    for i in range(2, len(stmts), 400):   # bounded multi-statement batches
                        await self.admin.query(";".join(head + stmts[i:i + 400]))
                    self.last_reset_tables = sum(1 for x in stmts if x.startswith("INSERT"))
                    break
                except (ConnectionError, OSError, mysqlclient.MysqlError):
                    self.admin = None
                    if attempt:
                        raise
        finally:
            if self.proxy:
                self.proxy.ready.set()
        self.last_reset_ms = (time.perf_counter() - t) * 1000

    def _note_admin_write(self, sql: str):
        tables = written_tables(sql)
        if tables is None:
            if self.proxy:
                self.proxy.dirty_all = True
            else:
                self._admin_dirty |= set(self._seed_tables or {})
        else:
            self._admin_dirty |= {x.lower() for x in tables}

    async def ensure_user(self, uid, role):
        p = self.ident.profile
        if p is None or not hasattr(p, "ensure_user") or not (self.cfg.postgres or self.cfg.mysql):
            return
        if self.cfg.mysql:
            my = self.cfg.mysql
            conn = await mysqlclient.MysqlConn.from_url(my.admin_url, database=my.database)
            facade = identity.SyncMysql(conn, asyncio.get_running_loop(), self._note_admin_write)
            try:
                await asyncio.to_thread(p.ensure_user, facade, uid, role)
            finally:
                await conn.close()
            return
        pg = self.cfg.postgres
        conn = await pgclient.PgConn.from_url(pg.admin_url, database=pg.database)
        try:
            await asyncio.to_thread(p.ensure_user, identity.SyncPg(conn, asyncio.get_running_loop()), uid, role)
        finally:
            await conn.close()

    # ------------------------------------------------------------------ one request
    async def handle(self, method, path, raw_path, query_string: bytes, headers, body: bytes):
        cfg = self.cfg
        imm, client = {}, []
        for k, v in headers:
            kl = k.decode("latin-1").lower()
            if kl.startswith(wire.INTERNAL_PREFIX):
                imm[kl] = v.decode("latin-1")
            else:
                client.append((kl.encode("latin-1"), v))
        rid = imm.get(wire.H_RID, "")
        mode = "L2" if imm.get(wire.H_MODE, "L1").upper() == "L2" else "L1"
        target = raw_path + (b"?" + query_string if query_string else b"")
        # learn mode: a legitimate request replayed by `python -m sidecar.learn`, signed with the clone key
        learn = imm.get(wire.H_MODE, "").lower() == "learn" and wire.check(
            cfg.clone_key, learn_message(method, target), imm.get(H_LEARN, ""))
        client_h = _hdict(client)
        uid = role = None
        app_headers = list(client)
        if imm.get(wire.H_UID, "").strip():
            try:
                uid = int(imm[wire.H_UID])
            except ValueError:
                uid = None
        if uid is not None:
            role = imm.get(wire.H_ROLE) or "user"
            await self.ensure_user(uid, role)
            # in a thread: a profile may log in over HTTP, and the app's database traffic runs through the
            # proxy on this event loop
            new = await asyncio.to_thread(self.ident.headers_for, self.env, uid, role)
            if new:
                names = {k.encode() for k in new}
                app_headers = [(k, v) for k, v in app_headers if k not in names] + \
                              [(k.encode(), v.encode("latin-1")) for k, v in new.items()]
        else:
            uid, role = self.ident.identify(self.env, client_h)

        if uid is not None and self.ident.rewrites():
            # session-bound values of the client's request (e.g. CSRF tokens) -> the clone session's
            qs, body = await asyncio.to_thread(self.ident.rewrite_request, self.env, uid, role,
                                               query_string.decode("latin-1"), _hdict(app_headers), body)
            query_string = qs.encode("latin-1")   # http1 recomputes content-length from the body
            target = raw_path + (b"?" + query_string if query_string else b"")
        t0 = time.perf_counter()
        if self.sqllog:
            self.sqllog.flush()     # a statement still being assembled belongs to no request
        self.baseline.add(sqllog.fingerprint(s, self.baseline_dialect) for s in self.obs.take_background_sql())
        if self.tracer and (self.warming or not self.tracer.alive()):
            # fail closed: without the tracer we cannot judge
            status, rheaders, rbody, rec = 503, [(b"content-type", b"text/plain")], b"sidecar tracer is not running", None
            self.obs.begin(); rec = self.obs.end()
            tracer_dead = True
        else:
            tracer_dead = False
            if self.calltrace:
                await asyncio.to_thread(self.calltrace.clear)
                app_headers = phptrace.with_trigger(app_headers)
            self.obs.begin()
            try:
                status, rheaders, rbody = await http1.request(cfg.app_host, cfg.app_port, method,
                                                              target.decode("latin-1"), app_headers, body,
                                                              cfg.request_timeout_s)
            except (http1.AppError, asyncio.TimeoutError) as e:
                log.warning("rid=%s app error %r", rid, e)
                status, rheaders, rbody = 502, [(b"content-type", b"text/plain")], b"Bad Gateway"
            t_app = time.perf_counter()
            await asyncio.sleep(cfg.grace_ms / 1000)
            if self.sqllog:
                self.sqllog.flush()
            rec = self.obs.end()
        t1 = time.perf_counter()

        query = query_string.decode("latin-1")
        rh = _hdict(rheaders)
        failed = [s for s, _ in rec.failed]
        if learn:
            n = self.baseline.add((sqllog.fingerprint(s, self.baseline_dialect) for s in rec.statements),
                                  from_request=True)
            out = [(k, v) for k, v in rheaders if not k.startswith(wire.INTERNAL_PREFIX.encode())]
            out += [(b"content-length", str(len(rbody)).encode()), (wire.H_VERDICT.encode(), b"clean"),
                    (wire.H_EVENTS.encode(), b"0"), (b"x-imm-learnt", str(n).encode())]
            log.info("rid=%s learn %s %s -> %s: %d new structure(s)", rid, method, path, status, n)
            return status, out, rbody, mode
        # the database log cannot tell a failed statement from an executed one reliably (error-based
        # injection fails on purpose), so with that source failed statements are checked too
        tainted = rec.statements + (failed if self.sqllog else [])
        inputs = observer.extract_inputs(path, query, client_h, body, self.spec, method.upper())
        events = observer.sql_events(tainted, inputs, self.constants, self.dialect)
        if (self.sqllog and self.dialect == "mysql") or not (self.constants and self.constants.strings):
            # without the app's own string constants a one-token match cannot be told from an identifier or
            # keyword the app wrote itself (input "name" in "SELECT name"): only multi-token matches count
            events = [e for e in events if e["detail"]["reason"] != "token"]
        events += sqllog.structure_events(self.baseline, rec.statements + failed, self.baseline_dialect,
                                          skip={e["detail"]["statement"] for e in events})
        events += observer.marker_events(self.file_markers, rh, rbody, self.obs.system_events(rec))
        events += observer.owner_events(self.markers, self.public, path, rh, rbody, uid, role, bool(events))
        if events and self.calltrace:
            try:   # where in the app's code: never changes the verdict
                await asyncio.to_thread(self.calltrace.attach, events)
            except Exception as e:  # noqa: BLE001
                log.warning("rid=%s call trace unavailable: %r", rid, e)
        if events:
            verdict = wire.VERDICT_ORACLE
        elif status in (401, 404) or status >= 500 or tracer_dead:
            verdict = wire.VERDICT_INCONCLUSIVE
        else:
            verdict = wire.VERDICT_CLEAN
        for sql, err in rec.failed:
            log.info("rid=%s failed statement (no sql event): %s -> %s", rid, sql[:300], err)
        evidence = None
        if verdict == wire.VERDICT_ORACLE:
            evidence = {"clone": cfg.clone_id, "rid": rid, "mode": mode, "release": cfg.release, "verdict": verdict,
                        "uid": uid, "role": role,
                        "request": {"method": method.upper(), "path": path, "query": query, "headers": client_h,
                                    "body_b64": base64.b64encode(body).decode()},
                        "status": status, "events": events, "pre_state_b64": None}
            if cfg.collector_url:
                await self._push(evidence)
        out = [(k, v) for k, v in rheaders if not k.startswith(wire.INTERNAL_PREFIX.encode())]
        out += [(b"content-length", str(len(rbody)).encode()),
                (wire.H_VERDICT.encode(), verdict.encode()), (wire.H_EVENTS.encode(), str(len(events)).encode())]
        if self.judge:
            out.append((b"x-imm-trace", base64.b64encode(wire.dumps(self._trace(rec, events, rbody, uid)))))
        t_resp = t0 if tracer_dead else t_app
        # latest observation relative to the moment the app's response was complete (grace-period evidence)
        late = max(((t - t_resp) * 1000 for t in rec.times), default=float("nan"))
        log.info("rid=%s %s %s mode=%s uid=%s -> %s %s %s app_ms=%.1f window_ms=%.1f stmts=%d obs=%d late_ms=%.2f",
                 rid, method, path, mode, uid, status, verdict, [e["oracle"] for e in events],
                 (t_resp - t0) * 1000, (t1 - t0) * 1000, len(rec.statements), len(rec.obs), late)
        return status, out, rbody, mode

    def _trace(self, rec, events, rbody, uid) -> dict:
        bq = {}
        for s, prm in rec.bound:
            bq.setdefault(s, []).append(prm)
        sql = [{"sql": s, "params": bq[s].pop(0) if bq.get(s) else []} for s in rec.statements]
        owners = sorted({self.markers[m.decode()] for m in observer.MARKER_RE.findall(rbody or b"")
                         if m.decode() in self.markers})
        opens = sorted({o.detail["realpath"] for o in rec.obs if o.kind == "file"})
        return {"events": events, "sql": sql[:100], "failed": [list(f) for f in rec.failed[:20]], "opens": opens,
                "marker_owners": owners, "uid": uid}

    async def finish(self, mode):
        if mode == "L1" and (self.cfg.postgres or self.cfg.mysql):
            try:
                await self.reset_db()
                log.info("L1 reset %.1f ms", self.last_reset_ms)
            except Exception:
                log.exception("L1 reset failed")

    async def _push(self, evidence):
        import httpx
        body = wire.dumps(evidence)
        hdrs = {"content-type": "application/json", wire.H_CLONE_ID: self.cfg.clone_id,
                wire.H_SIGNATURE: wire.sign(self.cfg.clone_key, body)}
        try:
            if self._http is None:
                self._http = httpx.AsyncClient(timeout=2.0)
            r = await self._http.post(self.cfg.collector_url.rstrip("/") + "/_clone/evidence", content=body, headers=hdrs)
            log.info("evidence rid=%s pushed: %s", evidence["rid"], r.status_code)
        except Exception as e:
            log.warning("evidence rid=%s push failed: %r", evidence["rid"], e)


def reset_statements(database: str, template: str, seed_tables: dict, dirty, full: bool, q) -> list:
    """SQL that rebuilds `database` from `template` (MySQL has no CREATE DATABASE ... TEMPLATE).
    The first two statements are session settings repeated in every batch."""
    cl, sd = q(database), q(template)
    stmts = ["SET SESSION foreign_key_checks = 0", "SET SESSION sql_mode = 'NO_AUTO_VALUE_ON_ZERO'"]
    if full:
        stmts += [f"DROP DATABASE IF EXISTS {cl}",
                  f"CREATE DATABASE {cl} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"]
        names = sorted(seed_tables.values())
    else:
        names = []
        for name in sorted(dirty):
            real = seed_tables.get(name.lower())
            if real is None:
                stmts.append(f"DROP TABLE IF EXISTS {cl}.{q(name)}")   # a table the app created
            else:
                names.append(real)
    for name in names:
        if not full:
            stmts.append(f"DROP TABLE IF EXISTS {cl}.{q(name)}")
        stmts += [f"CREATE TABLE {cl}.{q(name)} LIKE {sd}.{q(name)}",
                  f"INSERT INTO {cl}.{q(name)} SELECT * FROM {sd}.{q(name)}"]
    return stmts


def _hdict(pairs) -> dict:
    out = {}
    for k, v in pairs:
        k = k.decode("latin-1").lower() if isinstance(k, bytes) else k.lower()
        v = v.decode("latin-1") if isinstance(v, bytes) else v
        out[k] = f"{out[k]}, {v}" if k in out else v
    return out


class App:
    """ASGI front end (served by uvicorn)."""

    def __init__(self, sc: Sidecar):
        self.sc = sc

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    try:
                        await self.sc.start()
                    except Exception as e:
                        log.exception("startup failed")
                        await send({"type": "lifespan.startup.failed", "message": repr(e)})
                        return
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await self.sc.stop()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        body = bytearray()
        while True:
            msg = await receive()
            if msg["type"] == "http.request":
                body += msg.get("body", b"")
                if not msg.get("more_body", False):
                    break
            elif msg["type"] == "http.disconnect":
                return
        raw_path = scope.get("raw_path") or scope["path"].encode("utf-8")
        async with self.sc.lock:
            status, headers, rbody, mode = await self.sc.handle(scope["method"], scope["path"], raw_path,
                                                                scope.get("query_string", b""),
                                                                list(scope.get("headers", [])), bytes(body))
            try:
                await send({"type": "http.response.start", "status": status, "headers": headers})
                await send({"type": "http.response.body", "body": rbody, "more_body": False})
            finally:
                await self.sc.finish(mode)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m sidecar")
    ap.add_argument("--config", default=os.environ.get("SIDECAR_CONFIG"))
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--app-port", type=int)
    ap.add_argument("--mode", choices=["attach", "launch"])
    ap.add_argument("--no-trace", action="store_true", help="do not attach strace (overhead measurement only)")
    ap.add_argument("--log-level", default=os.environ.get("SIDECAR_LOG_LEVEL", "info"))
    ap.add_argument("command", nargs="*", help="launch mode: the app command (after --)")
    a = ap.parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=a.log_level.upper(),
                        format="%(asctime)s sidecar %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    cfg = cfgmod.load(a.config)
    if a.host:
        cfg.listen_host = a.host
    if a.port:
        cfg.listen_port = a.port
    if a.app_port:
        cfg.app_port = a.app_port
    if a.mode:
        cfg.mode = a.mode
    if a.command:
        cfg.command = a.command
    if a.no_trace:
        cfg.trace = False
    import uvicorn
    uvicorn.run(App(Sidecar(cfg)), host=cfg.listen_host, port=cfg.listen_port, log_level="warning",
                lifespan="on", access_log=False)
