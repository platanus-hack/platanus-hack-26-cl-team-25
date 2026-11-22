"""The shared core used by both the server (shadow.run) and the in-process Harness.

Both frontends call ``Engine.handle`` (contract §5 steps 1-8) and then
``Engine.finish`` (step 9), so a request gets the same verdict either way.
"""
from __future__ import annotations

import asyncio
import base64
import gzip
import importlib
import json
import logging
import mimetypes
import os
import re
import sys
import tempfile
import zlib
from dataclasses import dataclass, field

from immune_contracts import authtoken, wire

from . import db, inputs, instrument, sqltaint
from .instrument import STATE, RequestRecord

log = logging.getLogger("shadow")

MARKER_RE = re.compile(rb"MK[A-Z0-9]{10}")
WARMUP_PATHS = ("/health", "/", "/openapi.json", "/docs", "/__shadow_warmup__/missing")
MAX_OWNER_EVENTS = 20


@dataclass
class Result:
    status: int
    headers: dict
    body: bytes
    verdict: str
    events: list
    rid: str = ""
    mode: str = "L1"
    uid: int | None = None
    role: str | None = None
    raw_headers: list = field(default_factory=list)
    evidence: dict | None = None


def _hdict(pairs) -> dict:
    out = {}
    for k, v in pairs:
        k = k.decode("latin-1").lower() if isinstance(k, bytes) else k.lower()
        v = v.decode("latin-1") if isinstance(v, bytes) else v
        out[k] = f"{out[k]}, {v}" if k in out else v
    return out


class Lifespan:
    def __init__(self, app):
        self.app = app
        self.state = {}
        self.task = None
        self.rq = None

    async def startup(self):
        self.rq = asyncio.Queue()
        sq = asyncio.Queue()

        async def receive():
            return await self.rq.get()

        async def send(msg):
            await sq.put(msg)

        scope = {"type": "lifespan", "asgi": {"version": "3.0", "spec_version": "2.0"}, "state": self.state}
        self.task = asyncio.ensure_future(self.app(scope, receive, send))
        await self.rq.put({"type": "lifespan.startup"})
        getter = asyncio.ensure_future(sq.get())
        done, _ = await asyncio.wait({getter, self.task}, return_when=asyncio.FIRST_COMPLETED, timeout=60)
        if getter in done:
            msg = getter.result()
            if msg["type"] == "lifespan.startup.failed":
                raise RuntimeError(f"app startup failed: {msg.get('message')}")
        else:
            getter.cancel()
            self.task = None  # app does not support lifespan

    async def shutdown(self):
        if self.task is None or self.task.done():
            return
        await self.rq.put({"type": "lifespan.shutdown"})
        try:
            await asyncio.wait_for(self.task, timeout=10)
        except Exception:
            pass


class Engine:
    def __init__(self, profile: str, seed_db: str | None, state: bytes | None = None, collector: str | None = None,
                 clone_id: str = "", clone_key: str = "", release: str = "", db_env: str | None = None,
                 release_root: str | None = None, release_paths: list[str] | None = None):
        instrument.install()  # before anything of the app is imported
        # the env var through which the app receives its sqlite path (database.path_env)
        self.db_env = db_env or os.environ.get("SHADOW_DB_ENV") or "APP_DB"
        if not os.environ.get(self.db_env):
            os.environ[self.db_env] = os.path.join(tempfile.mkdtemp(prefix="shadow-"), "app.db")
        os.environ.setdefault("APP_SECRET", "shadow-secret")
        self.db_path = os.environ[self.db_env]
        self.release_root = release_root or os.environ.get("SHADOW_RELEASE_ROOT") or None
        rp = release_paths if release_paths is not None else os.environ.get("SHADOW_RELEASE_PATHS", "").split(":")
        self.release_paths = [p for p in rp if p]
        self.seed_db = seed_db
        self.base_state = state
        self.collector = collector.rstrip("/") if collector else None
        self.clone_id, self.clone_key, self.release = clone_id, clone_key, release
        self.profile = importlib.import_module(profile)
        mod_name, _, attr = self.profile.APP.partition(":")
        top = mod_name.split(".")[0]
        pkg = importlib.import_module(top)
        pkg_dir = list(getattr(pkg, "__path__", []))[0] if hasattr(pkg, "__path__") else os.path.dirname(pkg.__file__)
        self.top = top
        self.pkg_dir = os.path.realpath(pkg_dir)
        self.allowed_roots = [os.path.realpath(r) for r in self.profile.allowed_file_roots(dict(os.environ)) if r]
        self.allowlist = set(STATE.allowlist)
        self._activate()
        self.reset()
        self.app = getattr(importlib.import_module(mod_name), attr or "app")
        # a profile whose markers cannot be loaded must not start: with no markers the owner oracle is off
        # and every IDOR would be judged clean. "No markers" is only legitimate when load_markers returns none.
        self.markers = {str(k): int(v) for k, v in (self.profile.load_markers(dict(os.environ)) or {}).items()}
        if not self.markers:
            log.warning("profile has no markers: owner oracle disabled")
        self.public = [p for p in self.profile.public_paths()]
        self.sharing = load_sharing(os.environ.get("SHADOW_SHARING_PATH")
                                    or (os.path.join(os.path.dirname(seed_db), "sharing.json") if seed_db else ""))
        self.lifespan = Lifespan(self.app)
        self._constants = None
        self._const_mods = -1
        self._http = None

    # ------------------------------------------------------------ setup
    def _activate(self):
        instrument.configure(self.pkg_dir, self.allowed_roots, self.release_root, self.release_paths)
        STATE.allowlist = self.allowlist

    async def start(self):
        """App startup (lifespan) + warm-up. Run on the loop that will serve requests."""
        self._activate()
        STATE.learning = True
        try:
            await self.lifespan.startup()
            mimetypes.init()
            for p in WARMUP_PATHS:
                try:
                    await self._run_app("GET", p, b"", [(b"host", b"localhost")], b"", RequestRecord())
                except Exception:
                    pass
        finally:
            STATE.learning = False
        self.reset()
        self.constants()
        log.info("warm-up done: %d allowlisted files, %d markers", len(self.allowlist), len(self.markers))

    async def stop(self):
        await self.lifespan.shutdown()
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    def reset(self):
        if self.base_state is not None:
            db.restore_from_bytes(self.base_state, self.db_path)
        elif self.seed_db:
            db.restore_from_file(self.seed_db, self.db_path)

    def snapshot(self) -> bytes:
        return db.snapshot(self.db_path)

    def constants(self):
        mods = [m for n, m in list(sys.modules.items()) if m is not None and (n == self.top or n.startswith(self.top + "."))]
        if self._constants is None or len(mods) != self._const_mods:
            strings = []
            for m in mods:
                fn = getattr(m, "__file__", None)
                if not fn or not fn.endswith(".py"):
                    continue
                try:
                    with open(fn, "rb") as f:
                        code = compile(f.read(), fn, "exec")
                except Exception:
                    continue
                _collect(code, strings)
            self._constants = sqltaint.Constants(strings)
            self._const_mods = len(mods)
        return self._constants

    def is_public(self, path: str) -> bool:
        for p in self.public:
            if path == p or path.startswith(p if p.endswith("/") else p + "/"):
                return True
        return False

    # ------------------------------------------------------------ running the app
    async def _run_app(self, method, path, query_string, headers, body, rec, extra_scope=None):
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
                 "method": method.upper(), "scheme": "http", "path": path,
                 "raw_path": path.encode("utf-8", "surrogateescape"), "query_string": query_string,
                 "root_path": "", "headers": headers, "client": ("127.0.0.1", 50000),
                 "server": ("127.0.0.1", 8000), "state": dict(self.lifespan.state), "extensions": {}}
        if extra_scope:
            scope.update(extra_scope)
        done = asyncio.Event()
        sent_body = False
        status, rheaders, chunks = None, [], []

        async def receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": body, "more_body": False}
            await done.wait()
            return {"type": "http.disconnect"}

        async def send(msg):
            nonlocal status, rheaders
            t = msg["type"]
            if t == "http.response.start":
                status = msg["status"]
                rheaders = list(msg.get("headers", []))
            elif t == "http.response.body":
                chunks.append(bytes(msg.get("body", b"")))
                if not msg.get("more_body", False):
                    done.set()

        STATE.current = rec
        try:
            await self.app(scope, receive, send)
        except Exception as e:
            log.info("app raised %r", e)
            if status is None:
                status, rheaders, chunks = 500, [(b"content-type", b"text/plain; charset=utf-8")], [b"Internal Server Error"]
        finally:
            STATE.current = None
            done.set()
        if status is None:
            status, rheaders, chunks = 500, [(b"content-type", b"text/plain; charset=utf-8")], [b"Internal Server Error"]
        return status, rheaders, b"".join(chunks), scope

    # ------------------------------------------------------------ one request (steps 1-8)
    async def handle(self, method: str, path: str, query_string: bytes, headers: list, body: bytes,
                     extra_scope: dict | None = None) -> Result:
        self._activate()
        env = dict(os.environ)
        # 1. read and remove x-imm-*
        imm, client = {}, []
        for k, v in headers:
            kl = (k.decode("latin-1") if isinstance(k, bytes) else k).lower()
            vb = v if isinstance(v, bytes) else str(v).encode("latin-1")
            if kl.startswith(wire.INTERNAL_PREFIX):
                imm[kl] = vb.decode("latin-1")
            else:
                client.append((kl.encode("latin-1"), vb))
        rid = imm.get(wire.H_RID, "")
        mode = "L2" if imm.get(wire.H_MODE, "L1").upper() == "L2" else "L1"
        uid, role = None, None
        app_headers = list(client)
        # 2. identity
        if imm.get(wire.H_UID, "").strip():
            try:
                uid = int(imm[wire.H_UID])
            except ValueError:
                uid = None
        if uid is not None:
            role = imm.get(wire.H_ROLE) or "user"
            db.ensure_user(self.profile, self.db_path, uid, role)
            tok = self.profile.mint_token(env, uid, role)
            app_headers = [(k, v) for k, v in app_headers if k != b"authorization"]
            app_headers.append((b"authorization", f"Bearer {tok}".encode()))
        else:
            ident = self._client_identity(_hdict(client), env)
            if ident is not None:
                uid, role = ident.uid, ident.role
        # 3. pre-request state
        pre_state = self.snapshot() if mode == "L2" else None
        # 4. run, fully buffered
        rec = RequestRecord()
        status, rheaders, rbody, scope = await self._run_app(method, path, query_string, app_headers, body, rec, extra_scope)
        # 5. oracles
        client_h = _hdict(client)
        query = query_string.decode("latin-1")
        events = self.evaluate(rec, method, path, query, client_h, body, scope.get("path_params"),
                               rheaders, rbody, uid, role)
        # 6. verdict
        if events:
            verdict = wire.VERDICT_ORACLE
        elif status in (401, 404) or status >= 500:
            verdict = wire.VERDICT_INCONCLUSIVE
        else:
            verdict = wire.VERDICT_CLEAN
        for sql, err in rec.failed:
            log.info("rid=%s failed statement (no sql event): %s -> %s", rid, sql[:500], err)
        out_headers = [(k, v) for k, v in rheaders if not k.lower().startswith(wire.INTERNAL_PREFIX.encode())]
        out_headers += [(wire.H_VERDICT.encode(), verdict.encode()), (wire.H_EVENTS.encode(), str(len(events)).encode())]
        res = Result(status=status, headers=_hdict(out_headers), body=rbody, verdict=verdict, events=events, rid=rid,
                     mode=mode, uid=uid, role=role, raw_headers=out_headers)
        log.info("rid=%s %s %s mode=%s uid=%s -> %s %s %s", rid, method, path, mode, uid, status, verdict,
                 [e["oracle"] for e in events])
        # 7. evidence before releasing the response
        if verdict == wire.VERDICT_ORACLE:
            res.evidence = {
                "clone": self.clone_id, "rid": rid, "mode": mode, "release": self.release, "verdict": verdict,
                "uid": uid, "role": role,
                "request": {"method": method.upper(), "path": path, "query": query, "headers": client_h,
                            "body_b64": base64.b64encode(body).decode()},
                "status": status, "events": events,
                "pre_state_b64": base64.b64encode(pre_state).decode() if pre_state is not None else None,
            }
            if self.collector:
                await self._push(res.evidence)
        return res

    def finish(self, res: Result) -> None:
        """Step 9: L1 resets the database to the base state."""
        if res.mode == "L1":
            self.reset()

    def _client_identity(self, h, env):
        hook = getattr(self.profile, "identify", None)   # optional profile hook: (env, headers) -> (uid, role) | None
        if callable(hook):
            try:
                got = hook(env, h)
            except Exception:
                got = None
            if not got:
                return None
            return authtoken.Identity(uid=int(got[0]), role=str(got[1] or "user"))
        tok = authtoken.bearer(h)
        if not tok:
            return None
        now = None
        if env.get("APP_NOW"):
            try:
                now = float(env["APP_NOW"])
            except ValueError:
                now = None
        return authtoken.verify(env.get("APP_SECRET", ""), tok, now=now)

    async def _push(self, evidence):
        import httpx
        body = wire.dumps(evidence)
        hdrs = {"content-type": "application/json", wire.H_CLONE_ID: self.clone_id,
                wire.H_SIGNATURE: wire.sign(self.clone_key, body)}
        try:
            if self._http is None:
                self._http = httpx.AsyncClient(timeout=2.0)
            r = await self._http.post(self.collector + "/_clone/evidence", content=body, headers=hdrs)
            log.info("evidence rid=%s pushed: %s", evidence["rid"], r.status_code)
        except Exception as e:
            log.warning("evidence rid=%s push failed: %r", evidence["rid"], e)

    # ------------------------------------------------------------ oracles
    def evaluate(self, rec, method, path, query, client_h, body, path_params, rheaders, rbody, uid, role):
        ins = inputs.extract(path, query, client_h, body, path_params)
        events = sqltaint.check(rec.statements, ins, self.constants())
        events += rec.events  # file / proc / net, collected live
        last_stack = rec.statements[-1][1] if rec.statements else []
        events += self.owner_events(path, rheaders, rbody, uid, role, bool(events), last_stack, path_params)
        return events

    def co_members(self, path_params, uid) -> set:
        """Group-shared access (shadow/sharing.json): the members of every group this request addresses
        through a members-scoped path parameter, provided the requester is one of them. Read from the
        clone's own database, so it follows L2 changes. Empty without a declared relation."""
        if not self.sharing or uid is None or not path_params:
            return set()
        out = set()
        for name, spec in self.sharing.items():
            if name not in path_params:
                continue
            val = str(path_params[name])
            try:
                conn = db.ORIG_CONNECT(self.db_path, timeout=10)
                try:
                    rows = conn.execute('SELECT "%s" FROM "%s" WHERE "%s" = ?' % (
                        spec["member"], spec["table"], spec["group"]), (int(val) if val.isdigit() else val,)).fetchall()
                finally:
                    conn.close()
            except Exception as e:  # noqa: BLE001 - never exempt on error
                log.warning("sharing lookup %s=%s failed: %r", name, val, e)
                continue
            members = {_as_int(r[0]) for r in rows}
            if uid in members:
                out |= members
        return out

    def owner_events(self, path, rheaders, rbody, uid, role, other_fired, stack=(), path_params=None):
        """Cross-owner data in the response.

        Fires for every distinct marker owner != requester (anonymous counts as
        different) unless the requester is admin. ``public_paths()`` exist so that
        login/register (which legitimately echo the caller's own private data
        while the caller is still anonymous) do not fire. But a public endpoint
        must never carry private data either, so on a public path we still fire
        when the response is evidently leakage: markers of **two or more**
        different foreign owners (a bulk dump; no single login/register answer is
        about two people), or another oracle fired in the same request (the
        response is the product of an attack, e.g. SQL injection through a public
        search).
        """
        if not self.markers or role == "admin":
            return []
        text = _decoded_body(rheaders, rbody)
        owners = set()
        for m in MARKER_RE.findall(text):
            o = self.markers.get(m.decode())
            if o is not None and o != uid:
                owners.add(o)
        if owners and not other_fired:
            owners -= self.co_members(path_params, uid)
        if not owners:
            return []
        if self.is_public(path) and not (other_fired or len(owners) >= 2):
            return []
        return [{"oracle": wire.ORACLE_OWNER, "detail": {"marker_owner": o, "requester": uid}, "stack": list(stack)}
                for o in sorted(owners)[:MAX_OWNER_EVENTS]]


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


def load_sharing(path: str) -> dict:
    """{path param: {"table", "member", "group"}} from sharing.json (written by immune.shadowdata); {} if absent."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path) as f:
            doc = json.load(f)
        out = {}
        for name, s in ((doc or {}).get("routes") or {}).items():
            if all(isinstance(s.get(k), str) and s[k].replace("_", "").isalnum() for k in ("table", "member", "group")):
                out[str(name)] = {k: s[k] for k in ("table", "member", "group")}
        return out
    except Exception as e:  # noqa: BLE001
        log.warning("sharing file %s unreadable (%r): no group-shared access", path, e)
        return {}


def _decoded_body(rheaders, body: bytes) -> bytes:
    enc = _hdict(rheaders).get("content-encoding", "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body)
    except Exception:
        pass
    return body


def _collect(code, out):
    for c in code.co_consts:
        if isinstance(c, str):
            out.append(c)
        elif isinstance(c, (tuple, frozenset)):
            for x in c:
                if isinstance(x, str):
                    out.append(x)
        elif hasattr(c, "co_consts"):
            _collect(c, out)
