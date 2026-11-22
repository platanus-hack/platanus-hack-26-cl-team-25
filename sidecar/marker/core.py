"""Sidecar in front of an unmodified shadow app (docs/plan-producto.md §6b): marker and syscall oracles.

Speaks the same clone protocol as `shadow/` (contracts/README.md §5), so the gateway cannot tell them apart:

1. strip the x-imm-* request headers, forward the request to the shadow app with the exact request target;
2. buffer the whole response (decoded);
3. `file` oracle: the body contains a marker planted in a protected file of the shadow (grafana.ini, the
   app database, /etc/passwd ...). The marker map says which file each marker lives in. With
   SYSCALL_CONTAINER set, also what the app process did while serving this request (sidecar/marker/syscalls.py):
   `file` it opened a protected path, `proc` it executed a program, `net` it connected to an address.
   With SQL_LOG_CMD set, `sql`: a request value reached a statement of the shadow database as SQL syntax,
   or the statement has a structure the app is not known to produce (sidecar/marker/sqllog.py);
4. verdict: oracle if any event; else inconclusive on 401/404/>=500; else clean;
5. on oracle, POST the signed evidence to {COLLECTOR_URL}/_clone/evidence before releasing the response;
6. release the response with x-imm-verdict / x-imm-events.

One request at a time (lock), as the gateway expects. No stack: the app is not instrumented, so evidence
carries the file path and the request; the patch stage localises the sink from those.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from dataclasses import dataclass, field

import time

import httpx

from immune_contracts import wire
from .sqllog import Baseline, SqlLog, inputs_of
from .syscalls import Policy, Tracer, tracer_cmd

log = logging.getLogger("sidecar")

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length"}
RESP_DROP = HOP | {"content-encoding"}          # the body is sent decoded


@dataclass
class Config:
    upstream: str = "127.0.0.1:3000"          # shadow app host:port
    markers: dict = field(default_factory=dict)   # marker -> {"path": "/etc/grafana/grafana.ini", ...}
    clone_id: str = "sidecar-0"
    clone_key: str = ""
    collector_url: str = ""
    release: str = "t0"
    timeout_s: float = 15.0
    syscall_container: str = ""               # app container to trace; empty = marker oracle only
    syscall_image: str = "immune-strace:1"
    syscall_policy: str = ""                  # JSON {protected, exec_allow, net_allow}; marker paths are always protected
    syscall_label: str = ""
    syscall_settle_s: float = 0.1
    sql_log_cmd: str = ""                     # command that follows the shadow database's statement log; empty = off
    sql_dialect: str = "postgres"             # postgres | mysql
    sql_baseline: str = ""                    # JSON file with the learnt statement structures (new_structure rule)

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        markers = {}
        path = env.get("MARKERS_PATH", "")
        if path:
            with open(path) as f:
                raw = json.load(f)
            markers = {m: (v if isinstance(v, dict) else {"path": str(v)}) for m, v in raw.items()}
        return cls(upstream=env.get("SHADOW_UPSTREAM", "127.0.0.1:3000"), markers=markers,
                   clone_id=env.get("CLONE_ID", "sidecar-0"), clone_key=env.get("CLONE_KEY", ""),
                   collector_url=env.get("COLLECTOR_URL", "").rstrip("/"), release=env.get("RELEASE", "t0"),
                   timeout_s=float(env.get("SIDECAR_TIMEOUT_S", "15")),
                   syscall_container=env.get("SYSCALL_CONTAINER", ""),
                   syscall_image=env.get("SYSCALL_IMAGE", "immune-strace:1"),
                   syscall_policy=env.get("SYSCALL_POLICY", ""),
                   syscall_label=env.get("SYSCALL_LABEL", ""),
                   syscall_settle_s=float(env.get("SYSCALL_SETTLE_S", "0.1")),
                   sql_log_cmd=env.get("SQL_LOG_CMD", ""), sql_dialect=env.get("SQL_DIALECT", "postgres"),
                   sql_baseline=env.get("SQL_BASELINE", ""))


def find_markers(body: bytes, markers: dict) -> list:
    """Markers present in the body, raw or as escaped text (JSON/HTML encoders may wrap them)."""
    found = []
    for m, info in markers.items():
        if m.encode() in body:
            found.append((m, info))
    return found


def oracle_events(leaked: list, observed: list) -> list:
    """Events of one request: markers seen in the response plus what the tracer saw the process do.

    One `file` event per protected file (marker, syscall, or both), one `proc` per program, one `net` per address.
    """
    events, by_path = [], {}
    for m, info in leaked:
        p = info.get("path", "")
        ev = {"oracle": wire.ORACLE_FILE, "detail": {"path": p, "realpath": p, "marker": m, "observed": "response"},
              "stack": []}
        events.append(ev)
        by_path.setdefault(p, []).append(ev)
    for o in observed:
        if o["kind"] == "proc":
            detail = {"event": "execve", "args": o["args"]}
        elif o["kind"] == "net":
            detail = {"event": "connect", "address": o["address"]}
        else:
            same = by_path.get(o["realpath"])
            if same:
                for ev in same:
                    ev["detail"]["observed"] = "response+syscall"
                continue
            detail = {"path": o["path"], "realpath": o["realpath"]}
        events.append({"oracle": {"proc": wire.ORACLE_PROC, "net": wire.ORACLE_NET}.get(o["kind"], wire.ORACLE_FILE),
                       "detail": dict(detail, observed="syscall", result=o["result"]), "stack": []})
    return events


H_LEARN = wire.INTERNAL_PREFIX + "learn"      # signature that authorises a learn-mode request


def learn_message(method: str, target: bytes) -> bytes:
    return b"learn " + method.upper().encode() + b" " + target


def verdict_of(status: int, events: list) -> str:
    if events:
        return wire.VERDICT_ORACLE
    if status in (401, 404) or status >= 500:
        return wire.VERDICT_INCONCLUSIVE
    return wire.VERDICT_CLEAN


class Sidecar:
    def __init__(self, cfg: Config, tracer=None, sqllog=None):
        self.cfg = cfg
        self.sqllog = sqllog or (SqlLog(cfg.sql_log_cmd, cfg.sql_dialect, baseline=Baseline(cfg.sql_baseline))
                                 if cfg.sql_log_cmd else None)
        self.tracer = tracer
        if tracer is None and cfg.syscall_container:
            name = "%s-strace" % cfg.syscall_container
            policy = Policy.load(cfg.syscall_policy, [i.get("path", "") for i in cfg.markers.values()])
            self.tracer = Tracer(tracer_cmd(cfg.syscall_container, cfg.syscall_image, name, cfg.syscall_label),
                                 policy, cfg.syscall_settle_s, name)
        self.lock = asyncio.Lock()
        self.client = httpx.AsyncClient(timeout=cfg.timeout_s, follow_redirects=False)
        self.push_client = httpx.AsyncClient(timeout=3.0)

    async def aclose(self):
        for src in (self.tracer, self.sqllog):
            if src:
                await src.stop()
        await self.client.aclose()
        await self.push_client.aclose()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    for src in (self.tracer, self.sqllog):
                        if src:
                            await src.start()
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await self.aclose()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if not msg.get("more_body"):
                break
        status, headers, rbody = await self.handle(scope, body)
        await send({"type": "http.response.start", "status": status,
                    "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers]})
        await send({"type": "http.response.body", "body": rbody})

    async def handle(self, scope, body: bytes):
        raw_path = scope.get("raw_path") or scope.get("path", "/").encode()
        raw_path = raw_path.decode("latin-1")
        query = (scope.get("query_string") or b"").decode("latin-1")
        imm, client_h = {}, []
        for k, v in scope.get("headers", []):
            name, val = k.decode("latin-1").lower(), v.decode("latin-1")
            if name.startswith(wire.INTERNAL_PREFIX):
                imm[name] = val
            elif name not in HOP:
                client_h.append((name, val))
        rid, mode = imm.get(wire.H_RID, ""), imm.get(wire.H_MODE, "L1")
        target = (raw_path + ("?" + query if query else "")).encode("latin-1")
        learn = mode == "learn" and bool(self.sqllog) and wire.check(
            self.cfg.clone_key, learn_message(scope["method"], target), imm.get(H_LEARN, ""))
        async with self.lock:
            host, _, port = self.cfg.upstream.rpartition(":")
            t0 = time.time()
            try:
                req = self.client.build_request(scope["method"], httpx.URL(scheme="http", host=host, port=int(port),
                                                                           raw_path=target),
                                                headers=client_h, content=body or None, extensions={"target": target})
                r = await self.client.send(req)
                status, rbody = r.status_code, r.content
                rheaders = [(k.lower(), v) for k, v in r.headers.multi_items()
                            if k.lower() not in RESP_DROP and not k.lower().startswith(wire.INTERNAL_PREFIX)]
            except httpx.HTTPError as e:
                log.warning("shadow app unreachable: %s", e)
                return 502, [("content-type", "application/json"), (wire.H_VERDICT, wire.VERDICT_INCONCLUSIVE),
                             (wire.H_EVENTS, "0")], b'{"detail":"Bad Gateway"}'
            t1 = time.time()
            opened = await self.tracer.window(t0, t1) if self.tracer else []
            events = oracle_events(find_markers(rbody, self.cfg.markers), opened)
            if self.sqllog:
                statements = await self.sqllog.window(t0, t1)
                if learn:       # a legitimate request replayed by `python -m sidecar.marker.learn`
                    n = self.sqllog.learn(statements)
                    return status, rheaders + [(wire.H_VERDICT, wire.VERDICT_CLEAN), (wire.H_EVENTS, "0"),
                                               ("x-imm-learnt", str(n))], rbody
                ctype = next((v for k, v in client_h if k == "content-type"), "")
                hits = self.sqllog.events(statements, inputs_of(raw_path, query, body, ctype, client_h))
                events += [{"oracle": wire.ORACLE_SQL, "detail": dict(h, observed="dblog"), "stack": []} for h in hits]
            verdict = verdict_of(status, events)
            if verdict == wire.VERDICT_ORACLE:
                await self._push({
                    "clone": self.cfg.clone_id, "rid": rid, "mode": mode if mode in ("L1", "L2") else "L1",
                    "release": self.cfg.release, "verdict": wire.VERDICT_ORACLE, "uid": None, "role": None,
                    "request": {"method": scope["method"], "path": raw_path, "query": query,
                                "headers": {k: v for k, v in client_h}, "body_b64": base64.b64encode(body).decode()},
                    "status": status, "events": events, "pre_state_b64": None})
        rheaders += [(wire.H_VERDICT, verdict), (wire.H_EVENTS, str(len(events)))]
        return status, rheaders, rbody

    async def _push(self, evidence: dict):
        if not self.cfg.collector_url:
            return
        raw = wire.dumps(evidence)
        try:
            await self.push_client.post(self.cfg.collector_url + "/_clone/evidence", content=raw, headers={
                "content-type": "application/json", wire.H_CLONE_ID: self.cfg.clone_id,
                wire.H_SIGNATURE: wire.sign(self.cfg.clone_key, raw)})
        except httpx.HTTPError as e:     # collector failure must not break the response
            log.warning("evidence push failed: %s", e)
