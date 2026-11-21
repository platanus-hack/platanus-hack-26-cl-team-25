"""Replay requests through shadow.harness against whatever `victim` is first on sys.path.

    PYTHONPATH=<root-with-victim>:<repo> python -m patcher._harness_probe <workdir>  < {"requests":[...]}
    -> stdout JSON [{"status", "verdict", "oracles"}]

Used by patcher's own tests only (the real gates are in pipeline/).
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys


def main() -> None:
    work = sys.argv[1]
    import victim
    vroot = os.path.dirname(os.path.dirname(os.path.abspath(victim.__file__)))
    paths = {k: os.path.join(work, v) for k, v in
             {"prod": "prod.db", "shadow": "shadow.db", "manifest": "m.json", "markers": "k.json"}.items()}
    if not os.path.exists(paths["shadow"]):
        subprocess.run([sys.executable, "-m", "victim.seed", "--out-prod", paths["prod"], "--out-shadow",
                        paths["shadow"], "--manifest", paths["manifest"], "--markers", paths["markers"], "--seed", "1"],
                       check=True, cwd=vroot, capture_output=True)
    os.environ.update(APP_SECRET="patcher-probe-secret", APP_STATIC=os.path.join(vroot, "victim", "static"),
                      MARKERS_PATH=paths["markers"], APP_DB=os.path.join(work, "app.db"))
    from shadow.harness import Harness
    reqs = json.load(sys.stdin)["requests"]
    out = []
    with Harness(profile="victim.shadow_profile", seed_db=paths["shadow"]) as h:
        for r in reqs:
            res = h.send(r["method"], r["path"], query=r.get("query", ""), headers=r.get("headers") or {},
                         body=base64.b64decode(r.get("body_b64") or ""), uid=r.get("uid"),
                         role=r.get("role") or "user", mode="L1")
            out.append({"status": res.status, "verdict": res.verdict,
                        "oracles": sorted({e["oracle"] for e in res.events})})
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
