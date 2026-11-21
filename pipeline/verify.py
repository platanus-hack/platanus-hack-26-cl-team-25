"""Post-deploy verification.

1. runner: the regression case (PoC + counted variants) fires no oracle on the deployed release;
2. gateway: the same request, sent from a fresh session, is classified, detonated if suspect, and
   FORWARDED TO PROD (route "prod", prodlog forwarded=true) rather than diverted to a clone or denied.
"""
from __future__ import annotations

import json
import logging
import os
import random
import time

import httpx

from immune_contracts import authtoken

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


def _identity(cfg, ev: dict, manifest: dict | None):
    """Authorization header for a fresh session with the same trust class as the attacker."""
    uid = ev.get("uid")
    if uid is None:
        return None, None, ""
    if not cfg.prod_app_secret:
        return None, None, "PROD_APP_SECRET not available: cannot open a fresh identified session"
    seed_max = int((manifest or {}).get("seed_max_uid") or 0)
    fresh = uid if (seed_max and uid <= seed_max) else (max(seed_max, int(uid)) + random.randint(5000, 50000))
    tok = authtoken.mint(cfg.prod_app_secret, int(fresh), ev.get("role") or "user")
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
                route = d.get("route")
        if rid and route:
            return rid, route
        rec = _from_recordings(cfg.record_path, session, path)
        if rec:
            return rec.get("rid"), rec.get("route")
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


def through_gateway(cfg, inc: dict, gateway_admin, manifest: dict | None = None):
    ev = inc["evidence"]
    rq = ev.get("request") or {}
    path, query = rq.get("path") or "/", rq.get("query") or ""
    headers = reqs.clean_headers(rq.get("headers") or {}, drop_auth=True)
    auth, session, why = _identity(cfg, ev, manifest)
    if why:
        return False, why
    if auth:
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
        return True, "fresh session %s: forwarded to prod (status %d, rid %s)" % (session.split(":")[0], r.status_code, rid[:8])
    return False, "fresh session: route %s, forwarded=%s (status %d) — still diverted" % (route, forwarded, r.status_code)
