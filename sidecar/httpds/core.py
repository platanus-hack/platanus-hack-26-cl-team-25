"""Sidecar in front of an unmodified shadow ScadaBR (CVE-2026-8602, authorization oracle).

Speaks the same clone protocol as `shadow/` and `python -m sidecar` (contracts/README.md §5), so the gateway
cannot tell them apart:

1. strip the x-imm-* request headers, forward the request to the shadow ScadaBR with the exact target;
2. buffer the whole response (decoded);
3. authz oracle: the request hit the HTTP Data Source receiver (`/ScadaBR/httpds`) and at least one data
   point value was CONSUMED -- ScadaBR reports a `Unconsumed key: <k>` line for every parameter no point
   consumed, so a configured point parameter present in the query but absent from that report means the
   write landed. The gateway only ever detonates this route for a request it already judged anonymous
   (owner_scoped), so a landed write there is a privileged state change with no established identity;
4. verdict: oracle if any event; else inconclusive on 401/404/>=500; else clean;
5. on oracle, POST the signed evidence to {COLLECTOR_URL}/_clone/evidence before releasing the response;
6. release the response with x-imm-verdict / x-imm-events.

One request at a time (lock). No stack: ScadaBR is not instrumented, so evidence carries the request and
the observed effect (which point parameters were written); the patch stage localises the sink from those.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from dataclasses import dataclass, field
from urllib.parse import parse_qsl

import httpx

from immune_contracts import wire
from sidecar import servlets

from sidecar import observer as sidecar_observer
from sidecar.tracer import Tracer

log = logging.getLogger("sidecar")

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length"}
RESP_DROP = HOP | {"content-encoding"}
HTTPDS_SUFFIX = "/httpds"


@dataclass
class Config:
    upstream: str = "127.0.0.1:8080"
    manifest: dict = field(default_factory=dict)   # {"point_params": [...], "reserved_keys": [...], "reserved_prefixes": [...]}
    clone_id: str = "sidecar-0"
    clone_key: str = ""
    collector_url: str = ""
    release: str = "1.2"
    timeout_s: float = 15.0
    servlets: "servlets.ServletIndex | None" = None   # entry point of a request, for the evidence stack
    # proc oracle (second vuln: authenticated RCE). When tracer_container is set, strace is attached to the
    # shadow container (docker mode) and any process spawned during a request window fires a `proc` oracle.
    tracer_container: str = ""
    tracer_image: str = "immune-strace:1"
    tracer_label: str = ""
    exec_allow: tuple = ()        # program-path globs the JVM legitimately spawns; everything else fires
    grace_ms: int = 150
    # authenticated detonation: the RCE is an admin action, but a fresh shadow clone has no session. For the
    # configured paths (e.g. the DWR process/script endpoints) the sidecar establishes an admin session on
    # the shadow and forwards the attack with it, so the shadow faithfully runs the authenticated action.
    # This MODELS the attacker's authenticated context on the shadow (the same app, the same admin account),
    # the way the lab models the device credential for /httpds. Off unless reauth_paths is set.
    reauth_paths: tuple = ()
    reauth_user: str = "admin"
    reauth_pw: str = ""

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        manifest = {}
        path = env.get("HTTPDS_MANIFEST", "")
        if path:
            with open(path) as f:
                manifest = json.load(f)
        # where in the app's code: WEB-INF/web.xml + WEB-INF/classes of the shadow's webapp (copied out by the lab)
        index = None
        if env.get("HTTPDS_WEB_XML") and env.get("HTTPDS_CLASSES"):
            index = servlets.ServletIndex.load(env["HTTPDS_WEB_XML"], env["HTTPDS_CLASSES"],
                                               context=env.get("HTTPDS_CONTEXT", ""),
                                               src_root=env.get("HTTPDS_SRC_ROOT", "src"))
        exec_allow = tuple(x for x in (env.get("EXEC_ALLOW", "").split(",")) if x.strip())
        return cls(upstream=env.get("SHADOW_UPSTREAM", "127.0.0.1:8080"), manifest=manifest,
                   clone_id=env.get("CLONE_ID", "sidecar-0"), clone_key=env.get("CLONE_KEY", ""),
                   collector_url=env.get("COLLECTOR_URL", "").rstrip("/"), release=env.get("RELEASE", "1.2"),
                   timeout_s=float(env.get("SIDECAR_TIMEOUT_S", "15")), servlets=index,
                   tracer_container=env.get("TRACER_CONTAINER", ""),
                   tracer_image=env.get("TRACER_IMAGE", "immune-strace:1"),
                   tracer_label=env.get("TRACER_LABEL", ""),
                   exec_allow=exec_allow, grace_ms=int(env.get("GRACE_MS", "150")),
                   reauth_paths=tuple(x.strip() for x in env.get("REAUTH_PATHS", "").split(",") if x.strip()),
                   reauth_user=env.get("REAUTH_USER", "admin"), reauth_pw=env.get("REAUTH_PW", ""))


def consumed_points(query: str, body: bytes, manifest: dict) -> list:
    """Configured point parameters the receiver consumed: present in the query, absent from the
    `Unconsumed key: <k>` report ScadaBR writes for every parameter no point took."""
    point_params = set(manifest.get("point_params", []))
    reserved = set(manifest.get("reserved_keys", []))
    prefixes = tuple(manifest.get("reserved_prefixes", []))
    unconsumed = set()
    for line in body.decode("latin-1", "replace").splitlines():
        line = line.strip()
        if line.startswith("Unconsumed key:"):
            unconsumed.add(line.split(":", 1)[1].strip())
    hits = []
    for k, _ in parse_qsl(query, keep_blank_values=True):
        if k in reserved or (prefixes and k.startswith(prefixes)):
            continue
        if k in point_params and k not in unconsumed and k not in hits:
            hits.append(k)
    return hits


def verdict_of(status: int, events: list) -> str:
    if events:
        return wire.VERDICT_ORACLE
    if status in (401, 404) or status >= 500:
        return wire.VERDICT_INCONCLUSIVE
    return wire.VERDICT_CLEAN


class Sidecar:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.lock = asyncio.Lock()
        self.client = httpx.AsyncClient(timeout=cfg.timeout_s, follow_redirects=False)
        self.push_client = httpx.AsyncClient(timeout=3.0)
        self._shadow_cookie: str | None = None    # cached admin session on the shadow (authenticated detonation)
        # proc oracle: observe process spawns in the shadow container during each request window.
        self.obs = self.tracer = None
        if cfg.tracer_container:
            # allow every file and network op (we only care about exec here); exec_allow lists the JVM's
            # own legitimate children, everything else spawned during a request is a `proc` oracle hit.
            self.obs = sidecar_observer.Observer(["/"], dns_fires=False, exec_allow=cfg.exec_allow,
                                                 net_allow=["*:*"])
            self.tracer = Tracer(self.obs.on_obs, mode="docker", container=cfg.tracer_container,
                                 image=cfg.tracer_image, label=cfg.tracer_label)

    async def aclose(self):
        await self.client.aclose()
        await self.push_client.aclose()
        if self.tracer:
            try:
                self.tracer.stop()
            except Exception as e:  # noqa: BLE001
                log.warning("tracer stop failed: %s", e)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    if self.tracer:
                        try:
                            await asyncio.to_thread(self.tracer.start)
                            log.info("proc oracle: strace attached to %s", self.cfg.tracer_container)
                        except Exception as e:  # noqa: BLE001
                            log.warning("proc oracle disabled: tracer could not attach: %s", e)
                            self.obs = self.tracer = None
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
        raw_path = (scope.get("raw_path") or scope.get("path", "/").encode()).decode("latin-1")
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
        async with self.lock:
            host, _, port = self.cfg.upstream.rpartition(":")
            # authenticated detonation: give the shadow an admin session for paths that need one (the RCE
            # endpoints), replacing the attacker's prod cookie (invalid on this clone).
            if self.cfg.reauth_paths and any(p in raw_path for p in self.cfg.reauth_paths):
                cookie = await self._shadow_admin_cookie(host, int(port))
                if cookie:
                    client_h = [(k, v) for k, v in client_h if k.lower() != "cookie"] + [("cookie", cookie)]
            try:
                req = self.client.build_request(scope["method"], httpx.URL(scheme="http", host=host, port=int(port),
                                                                           raw_path=target),
                                                headers=client_h, content=body or None, extensions={"target": target})
                if self.obs:
                    self.obs.begin()        # open the proc observation window across the forwarded request
                r = await self.client.send(req)
                status, rbody = r.status_code, r.content
                rheaders = [(k.lower(), v) for k, v in r.headers.multi_items()
                            if k.lower() not in RESP_DROP and not k.lower().startswith(wire.INTERNAL_PREFIX)]
            except httpx.HTTPError as e:
                log.warning("shadow ScadaBR unreachable: %s", e)
                return 502, [("content-type", "application/json"), (wire.H_VERDICT, wire.VERDICT_INCONCLUSIVE),
                             (wire.H_EVENTS, "0")], b'{"detail":"Bad Gateway"}'
            events = []
            if self.obs:
                # close the window a little after the response so a late fork/exec is still attributed
                await asyncio.sleep(max(self.cfg.grace_ms, 50) / 1000)
                rec = self.obs.end()
                events += [e for e in self.obs.system_events(rec) if e.get("oracle") == wire.ORACLE_PROC]
            if raw_path.endswith(HTTPDS_SUFFIX):
                # a POST receiver carries its parameters in the form body; merge for the consumed check
                scan_query = query
                if scope["method"] == "POST" and body:
                    scan_query = (query + "&" + body.decode("latin-1", "replace")).strip("&")
                hits = consumed_points(scan_query, rbody, self.cfg.manifest)
                if hits:
                    events.append({
                        "oracle": wire.ORACLE_OWNER,
                        "detail": {"route": raw_path, "consumed": hits,
                                   "observed": "data point value written by a request with no established identity",
                                   "expected": "the HTTP Data Source receiver requires an authenticated device"},
                        # the servlet that handled the request (static: web.xml + the compiled class's line table)
                        "stack": self.cfg.servlets.stack(scope["method"], raw_path) if self.cfg.servlets else []})
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

    async def _shadow_admin_cookie(self, host: str, port: int) -> str | None:
        """Establish (and cache) an authenticated admin session on the shadow ScadaBR: GET the login page for
        a JSESSIONID, then POST the credentials to authenticate it. Returns the `JSESSIONID=...` cookie."""
        if self._shadow_cookie:
            return self._shadow_cookie
        login = httpx.URL(scheme="http", host=host, port=port, path="/ScadaBR/login.htm")
        try:
            async with httpx.AsyncClient(timeout=self.cfg.timeout_s, follow_redirects=False) as c:
                await c.get(login)      # ScadaBR issues the JSESSIONID here
                await c.post(login, data={"username": self.cfg.reauth_user, "password": self.cfg.reauth_pw})
                sid = c.cookies.get("JSESSIONID")
                if sid:
                    self._shadow_cookie = "JSESSIONID=%s" % sid
                    log.info("authenticated detonation: admin session established on the shadow")
                else:
                    log.warning("authenticated detonation: no JSESSIONID from the shadow login")
        except httpx.HTTPError as e:
            log.warning("authenticated detonation: shadow login failed: %s", e)
        return self._shadow_cookie

    async def _push(self, evidence: dict):
        if not self.cfg.collector_url:
            return
        raw = wire.dumps(evidence)
        try:
            await self.push_client.post(self.cfg.collector_url + "/_clone/evidence", content=raw, headers={
                "content-type": "application/json", wire.H_CLONE_ID: self.cfg.clone_id,
                wire.H_SIGNATURE: wire.sign(self.cfg.clone_key, raw)})
        except httpx.HTTPError as e:
            log.warning("evidence push failed: %s", e)
