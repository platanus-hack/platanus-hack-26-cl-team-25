"""Legitimate Clínica Delta staff through Inmune's gateway (the OpenEMR twin of `python -m sim.legit`).

    python examples/openemr/legit.py --base http://127.0.0.1:8280 [--duration 60] [--rate 2]

Each worker logs in like a browser (medico1, medico2, recepcion) and walks real OpenEMR screens and the local
REST/FHIR API with its session's APICSRFTOKEN. Per response: no x-imm-* header, no shadow marker
(MK + 10 chars) and an expected status. These clean GETs are also what the pipeline's `legit` gate replays.
Exits 1 on any violation, 5xx or connection error.
"""
from __future__ import annotations

import argparse
import random
import re
import sys
import time

import httpx

ACCOUNTS = [("medico1", "Inmune-medico1-82"), ("medico2", "Inmune-medico2-82"), ("recepcion", "Inmune-recepcion-82")]
MARKER = re.compile(rb"MK[A-Z0-9]{10}")
PAGES = ["/interface/main/finder/dynamic_finder.php", "/interface/main/calendar/index.php",
         "/interface/main/messages/messages.php?form_active=1", "/interface/main/dated_reminders/dated_reminders.php",
         "/apis/default/api/patient", "/apis/default/fhir/Patient",
         "/apis/default/fhir/metadata", "/meta/health/readyz"]


def login(base, user, pw):
    c = httpx.Client(base_url=base, timeout=30, follow_redirects=False)
    r = c.post("/interface/main/main_screen.php?auth=login&site=default",
               data={"new_login_session_management": "1", "authUser": user, "clearPass": pw, "languageChoice": "1"})
    loc = r.headers.get("location", "")
    if r.status_code != 302 or "token_main" not in loc:
        raise RuntimeError("login %s failed (%s)" % (user, r.status_code))
    page = c.get(loc).text
    m = re.search(r'api_csrf_token_js\s*=\s*"([^"]+)"', page)
    return c, (m.group(1) if m else "")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8280")
    ap.add_argument("--duration", type=float, default=60)
    ap.add_argument("--rate", type=float, default=2.0)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args(argv)
    rnd = random.Random(a.seed)
    sessions = [(u,) + login(a.base, u, p) for u, p in ACCOUNTS]
    stats = {"reqs": 0, "violations": 0, "5xx": 0, "errors": 0}
    end = time.time() + a.duration
    while time.time() < end:
        user, c, api = rnd.choice(sessions)
        path = rnd.choice(PAGES)
        try:
            r = c.get(path, headers={"apicsrftoken": api} if path.startswith("/apis/") else {})
        except httpx.HTTPError as e:
            stats["errors"] += 1
            print("error", user, path, e)
            continue
        stats["reqs"] += 1
        bad = [h for h in r.headers if h.lower().startswith("x-imm-")]
        if bad or MARKER.search(r.content) or r.status_code in (401, 403, 404):
            stats["violations"] += 1
            print("violation", user, path, r.status_code, bad)
        if r.status_code >= 500:
            stats["5xx"] += 1
            print("5xx", user, path, r.status_code)
        time.sleep(1.0 / max(a.rate, 0.1))
    print("legit:", stats)
    return 1 if stats["violations"] or stats["5xx"] or stats["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
