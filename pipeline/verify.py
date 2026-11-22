"""Post-deploy verification.

1. runner: the regression case (PoC + counted variants) fires no oracle on the deployed release;
2. gateway: the same request, sent from a fresh session, is classified, detonated if suspect, and
   FORWARDED TO PROD (route "prod", prodlog forwarded=true) rather than diverted to a clone or denied.
   The fresh identity is minted (immune-token, jwt-hs256) or, with auth.kind introspect (opaque server-side
   sessions), registered through the app's own register/login routes found in the OpenAPI.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import time

import httpx

from . import bus as busmod, reqs

log = logging.getLogger("pipeline.verify")


def in_runner(validator, poc: dict, repro: dict, release_dir: str):
    seqs = [{"name": "poc", "requests": poc["requests"], "repeat": 1}]
    seqs += [{"name": "v:" + v["name"], "requests": poc["requests"][:-1] + [v["request"]]} for v in repro.get("counted") or []]
    res = validator.run(release_dir, {"kind": "harness", "state_b64": poc.get("state_b64"), "sequences": seqs})
    fired = [s["name"] for s in res["sequences"] if any(run[-1]["events"] for run in s["runs"])]
    if fired:
        return False, "on the deployed release %s still fire(s) an oracle" % ", ".join(fired[:3])
    return True, "the PoC and %d variant(s) fire no oracle on the deployed release" % (len(seqs) - 1)


REGISTER_RE = re.compile(r"/(register|signup|sign-up|sign_up|join)/?$", re.I)
LOGIN_RE = re.compile(r"/(login|signin|sign-in|sign_in|token|session|sessions)/?$", re.I)


def _json_body_schema(spec: dict, op: dict) -> dict:
    from . import openapi
    media = ((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {}
    return openapi.resolve(spec, media.get("schema") or {})


def _fill(schema: dict, tag: str) -> dict | None:
    """Values for every required property (and the usual login fields) of a register/login body."""
    out = {}
    props = schema.get("properties") or {}
    for name, p in props.items():
        t = p.get("type") or next((a.get("type") for a in p.get("anyOf") or [] if a.get("type") != "null"), "string")
        n = name.lower()
        if t != "string":
            if name in (schema.get("required") or []):
                return None
            continue
        if "mail" in n:
            out[name] = "immune-verify-%s@verify.example.com" % tag
        elif "pass" in n:
            out[name] = "Verify-%s-Pw9" % tag
        elif n in ("username", "user", "login", "handle", "nick", "nickname"):
            out[name] = "immune_verify_%s" % tag
        elif name in (schema.get("required") or []) or "name" in n:
            out[name] = "Immune Verify %s" % tag
    return out


def _token_in(body) -> str | None:
    if isinstance(body, dict):
        for k in ("token", "access_token", "accessToken", "jwt", "id_token", "session", "session_token"):
            if isinstance(body.get(k), str) and body[k]:
                return body[k]
        for v in body.values():
            t = _token_in(v) if isinstance(v, dict) else None
            if t:
                return t
    return None


def register_fresh(cfg, spec: dict | None = None):
    """A brand-new account through the app's own register route (found in the OpenAPI), then its login
    route, sent through the gateway like any client: -> (authorization header, uid, why).
    The new uid is above seed_max_uid, so it has the trust class of a freshly registered attacker."""
    from . import openapi
    proj = getattr(cfg, "project", None)
    auth = proj.auth if proj is not None else None
    try:
        spec = spec if spec is not None else openapi.load(cfg.openapi_path)
    except Exception as e:  # noqa: BLE001
        return None, None, "cannot read the OpenAPI to find a register route: %s" % e
    ops = [(m, tpl, op) for m, tpl, op in openapi.operations(spec) if m == "POST" and "{" not in tpl]
    reg = next(((tpl, op) for m, tpl, op in ops if REGISTER_RE.search(tpl)), None)
    login = next(((tpl, op) for m, tpl, op in ops if LOGIN_RE.search(tpl)), None)
    if reg is None:
        return None, None, "no register route (POST .../register|signup) in the OpenAPI: cannot open a fresh identity"
    tag = "%08x" % random.getrandbits(32)
    body = _fill(_json_body_schema(spec, reg[1]), tag)
    if not body:
        return None, None, "register route %s has a body the pipeline cannot fill" % reg[0]
    base = cfg.gateway_url.rstrip("/")
    try:
        with httpx.Client(timeout=cfg.http_timeout_s * 3) as c:
            r = c.post(base + reg[0], json=body)
            if r.status_code >= 300:
                return None, None, "register %s answered %d" % (reg[0], r.status_code)
            tok = _token_in(r.json() if "json" in r.headers.get("content-type", "") else {})
            if not tok and login is not None:
                lb = _fill(_json_body_schema(spec, login[1]), tag) or {}
                lb = {k: body.get(k, v) for k, v in lb.items()}
                r2 = c.post(base + login[0], json=lb)
                if r2.status_code >= 300:
                    return None, None, "login %s with the fresh account answered %d" % (login[0], r2.status_code)
                tok = _token_in(r2.json() if "json" in r2.headers.get("content-type", "") else {})
            if not tok:
                return None, None, "neither %s nor a login route returned a token" % reg[0]
            hdr = "Bearer " + tok
            uid = None
            if auth is not None and auth.kind == "introspect" and auth.path:
                me = c.get(base + auth.path, headers={"authorization": hdr})
                if me.status_code == 200:
                    try:
                        uid = int(me.json().get(auth.uid_field or "id"))
                    except (TypeError, ValueError, AttributeError):
                        uid = None
            if uid is None:
                return None, None, "the fresh account's token is not recognised by %s" % (auth.path if auth else "?")
            return hdr, uid, ""
    except httpx.HTTPError as e:
        return None, None, "registering a fresh account through the gateway failed: %s" % e


def login_session(cfg):
    """auth.login (apps without self-registration, e.g. OpenEMR): log in through the gateway with a seeded
    account, like a browser, and return its session cookie -> ({header: value}, uid, why)."""
    proj = getattr(cfg, "project", None)
    raw = (((getattr(proj, "raw", None) or {}).get("auth") or {}).get("login")) if proj is not None else None
    if not isinstance(raw, dict) or not raw.get("path"):
        return None, None, "no auth.login in the project config"
    user = os.environ.get(str(raw.get("user_env") or ""), "") or str(raw.get("default_user") or "")
    pw = os.environ.get(str(raw.get("password_env") or ""), "") or str(raw.get("default_password") or "")
    if not user or not pw:
        return None, None, "auth.login: no verification account (set %s / %s)" % (raw.get("user_env"),
                                                                                    raw.get("password_env"))
    form = {str(k): str(v).replace("{login}", user).replace("{password}", pw)
            for k, v in (raw.get("form") or {}).items()}
    base = cfg.gateway_url.rstrip("/")
    auth = proj.auth
    try:
        with httpx.Client(timeout=cfg.http_timeout_s * 3, follow_redirects=False) as c:
            r = c.post(base + str(raw["path"]), data=form)
            if r.status_code >= 400:
                return None, None, "auth.login %s answered %d" % (raw["path"], r.status_code)
            jar = "; ".join("%s=%s" % (k, v) for k, v in c.cookies.items() if k != "gwsid")
            if not jar:
                return None, None, "auth.login %s set no session cookie" % raw["path"]
            me = c.get(base + auth.path, headers={"cookie": jar})
            try:
                uid = int(me.json().get(auth.uid_field or "id"))
            except (TypeError, ValueError, AttributeError):
                uid = None
            if uid is None:
                return None, None, "auth.login: %s does not recognise the new session" % auth.path
            return {"cookie": jar}, uid, ""
    except httpx.HTTPError as e:
        return None, None, "auth.login through the gateway failed: %s" % e


def _identity(cfg, ev: dict, manifest: dict | None):
    """Authorization header for a fresh session with the same trust class as the attacker."""
    uid = ev.get("uid")
    if uid is None:
        return None, None, ""
    from immune.auth import Authenticator
    proj = getattr(cfg, "project", None)
    auth = proj.auth if proj is not None else None
    kind = auth.kind if auth is not None else "immune-token"
    seed_max = int((manifest or {}).get("seed_max_uid") or 0)
    login = (((getattr(proj, "raw", None) or {}).get("auth") or {}).get("login")) if proj is not None else None
    if kind == "introspect" and isinstance(login, dict) and seed_max and int(uid) <= seed_max:
        # no self-registration: a seeded account logs in, the same trust class as the seeded attacker
        hdr, fresh, why = login_session(cfg)
        if why:
            return None, None, why
        return hdr, "uid:%d" % fresh, ""
    if kind == "introspect":
        if seed_max and int(uid) <= seed_max:
            return None, None, ("auth.kind introspect: the attacker was a seeded (trusted) user; the pipeline cannot "
                                "open a fresh session of that trust class")
        hdr, fresh, why = register_fresh(cfg)
        if why:
            return None, None, why
        if seed_max and fresh <= seed_max:
            return None, None, "the freshly registered uid %d is not above seed_max_uid %d" % (fresh, seed_max)
        return hdr, "uid:%d" % fresh, ""
    if kind == "none":
        return None, None, "auth.kind none: the pipeline cannot mint a fresh identity of the same trust class"
    if not cfg.prod_app_secret:
        return None, None, "prod secret not available: cannot open a fresh identified session"
    fresh = uid if (seed_max and uid <= seed_max) else (max(seed_max, int(uid)) + random.randint(5000, 50000))
    tok = Authenticator(auth.to_dict() if auth is not None else None, cfg.prod_app_secret).mint(
        int(fresh), ev.get("role") or "user")
    if not tok:
        return None, None, "auth.kind %s cannot mint a credential" % kind
    return "Bearer " + tok, "uid:%d" % fresh, ""


def _find_route(cfg, session: str, path: str, since: int, deadline: float):
    """(rid, route) of our request, from the bus (request.classified/routed), else the recordings file."""
    rid = route = None
    while time.time() < deadline:
        try:
            evs = busmod.history(cfg.bus_url, since, "request.", timeout=3)["events"]
        except Exception:  # noqa: BLE001
            evs = []
        for e in evs:
            d = e.get("data") or {}
            if rid is None and e["type"] == "request.classified" and d.get("session") == session and d.get("path") == path:
                rid = e.get("rid")
            if rid and e["type"] == "request.routed" and e.get("rid") == rid:
                route = d.get("would_route") or d.get("route")   # observe mode: what enforce would do
        if rid and route:
            return rid, route
        rec = _from_recordings(cfg.record_path, session, path)
        if rec:
            return rec.get("rid"), rec.get("would_route") or rec.get("route")
        time.sleep(0.3)
    return rid, route


def _from_recordings(path: str, session: str, req_path: str):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 512 * 1024))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("session") == session and rec.get("path") == req_path:
            return rec
    return None


def _off_canary(inc: dict, path: str, manifest: dict | None):
    """A canary path value is evidence for every non-owner, so the gateway always diverts it whatever the
    code does. Verify with the same route and another (non-canary) seed id instead. -> (path, swapped)"""
    param = inc.get("param") or {}
    canaries = {str(v) for v in ((manifest or {}).get("canaries") or {}).get(param.get("name") or "", [])}
    if param.get("in") != "path" or not canaries:
        return path, False
    tpl = (inc.get("route") or "").strip("/").split("/")
    segs = path.strip("/").split("/")
    want = "{%s}" % param["name"]
    if len(tpl) != len(segs) or want not in tpl or segs[tpl.index(want)] not in canaries:
        return path, False
    alt = next(str(i) for i in range(1, 10 ** 6) if str(i) not in canaries)
    segs[tpl.index(want)] = alt
    return "/" + "/".join(segs), True


def through_gateway(cfg, inc: dict, gateway_admin, manifest: dict | None = None):
    ev = inc["evidence"]
    rq = ev.get("request") or {}
    path, query = rq.get("path") or "/", rq.get("query") or ""
    path, swapped = _off_canary(inc, path, manifest)
    headers = reqs.clean_headers(rq.get("headers") or {}, drop_auth=True)
    auth, session, why = _identity(cfg, ev, manifest)
    if why:
        return False, why
    if isinstance(auth, dict):
        headers.update(auth)          # a session cookie (auth.login)
    elif auth:
        headers["authorization"] = auth
    try:
        since = int(busmod.history(cfg.bus_url, 10 ** 12, timeout=3).get("next") or 0)
    except Exception:  # noqa: BLE001
        since = 0
    base = httpx.URL(cfg.gateway_url)
    url = httpx.URL(scheme=base.scheme, host=base.host, port=base.port,
                    raw_path=(path + ("?" + query if query else "")).encode("latin-1", "replace"))
    try:
        r = httpx.request(rq.get("method") or "GET", url, headers=headers, content=reqs.body_of(rq) or None,
                          timeout=cfg.http_timeout_s * 3)
    except httpx.HTTPError as e:
        return False, "gateway request failed: %s" % e
    if session is None:
        sid = r.cookies.get("gwsid")
        if not sid:
            return False, "gateway did not set a session cookie; cannot locate the request"
        session = "gwsid:" + sid
    rid, route = _find_route(cfg, session, path, since, time.time() + cfg.verify_wait_s)
    if not rid:
        return False, "request sent (status %d) but not found on the bus or in the recordings" % r.status_code
    forwarded = None
    try:
        forwarded = gateway_admin.prodlog(rid).get("forwarded")
    except Exception as e:  # noqa: BLE001
        log.warning("prodlog: %s", e)
    if route == "prod" and forwarded is not False:
        return True, "fresh session %s: %s forwarded to prod (status %d, rid %s)%s" % (
            session.split(":")[0], path, r.status_code, rid[:8], " (canary id replaced by a non-canary one)" if swapped else "")
    return False, "fresh session: route %s, forwarded=%s (status %d) — still diverted" % (route, forwarded, r.status_code)
