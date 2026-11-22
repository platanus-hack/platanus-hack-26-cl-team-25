"""Attacks against the real OpenEMR 8.2.0 surfaces, through Immune's gateway.

    python examples/openemr/attacks.py --base http://127.0.0.1:8280

OpenEMR is unmodified: no vulnerability is planted. Each attack is sent as a logged-in non-administrator
(recepcion) and reported with what really happened: blocked by the gateway (L0 / rule), detonated in a shadow
clone first (clean -> answered by prod, oracle -> incident with the PHP file:line in the dashboard), or not
suspicious. The answer never comes from prod when a clone found an oracle.
"""
from __future__ import annotations

import argparse
import sys
from urllib.parse import quote

import httpx

ATTACKS = [
    ("SQLi: patient finder search", "GET",
     "/interface/main/finder/dynamic_finder_ajax.php?sSearch=" + quote("x' OR 1=1 -- ")),
    ("SQLi: patient search by name", "GET",
     "/interface/main/finder/patient_select.php?searchby=Last&searchparm=" + quote("zz' UNION SELECT 1,2,3 -- ")),
    ("SQLi: REST API filter", "GET", "/apis/default/api/patient?fname=" + quote("a' OR '1'='1")),
    ("Traversal: document retrieve", "GET",
     "/controller.php?document&retrieve&patient_id=1&document_id=" + quote("../../../../../../etc/hostname")),
    ("Traversal: language file", "GET",
     "/interface/main/tabs/main.php?lang=" + quote("../../../../../../etc/hostname")),
    ("Admin only: database backup as front desk", "GET", "/interface/main/backup.php"),
    ("Admin only: globals editor as front desk", "GET", "/interface/super/edit_globals.php"),
    ("Admin only: user administration as front desk", "GET", "/interface/usergroup/usergroup_admin.php"),
    ("IDOR: REST patient by uuid (other provider's patient)", "GET", "/apis/default/api/patient/{other}"),
]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8280")
    ap.add_argument("--user", default="recepcion")
    ap.add_argument("--password", default="Inmune-recepcion-82")
    a = ap.parse_args(argv)
    c = httpx.Client(base_url=a.base, timeout=60, follow_redirects=False)
    r = c.post("/interface/main/main_screen.php?auth=login&site=default",
               data={"new_login_session_management": "1", "authUser": a.user, "clearPass": a.password,
                     "languageChoice": "1"})
    loc = r.headers.get("location", "")
    if "token_main" not in loc:
        sys.exit("login as %s failed (%s)" % (a.user, r.status_code))
    page = c.get(loc).text
    import re
    m = re.search(r'api_csrf_token_js\s*=\s*"([^"]+)"', page)
    api = {"apicsrftoken": m.group(1)} if m else {}
    other = ""
    pl = c.get("/apis/default/api/patient", headers=api)
    if pl.status_code == 200:
        data = pl.json().get("data") or []
        other = (data[-1] or {}).get("uuid", "") if data else ""
    for name, method, path in ATTACKS:
        path = path.replace("{other}", other or "00000000-0000-0000-0000-000000000000")
        r = c.request(method, path, headers=api if path.startswith("/apis/") else {})
        print("%-56s %d %s" % (name, r.status_code, r.headers.get("content-type", "").split(";")[0]))
    print("\nMirá el dashboard (Immune) para el veredicto de cada request: sospechoso, detonado en sombra, incidente,"
          " regla y parche o rule_only con la línea PHP.")


if __name__ == "__main__":
    main()
