"""Time from "defect identified" to "fix serving production traffic", computed from bus events.

    python -m immune.metrics --bus http://127.0.0.1:8090 [--json]

Definitions (all timestamps are event `ts` on the bus):
  t0  identified   oracle.fired whose rid == incident.opened.data.evidence_rid (the shadow copy confirmed the defect)
  rule             rule.active            -> contained at the gateway
  diff             first patch.diff       -> the model returned a fix
  gates            pr.merged              -> the five gates passed and the fix was merged
  in_prod          upstream.switched after pr.merged -> production traffic is served by the fixed release   <-- THE METRIC
  verified         verify.result          -> the original request no longer works on production
Only incidents closed as `patched` count. `queue` (incident.opened - t0) is reported separately: incidents are
processed one at a time, so it is waiting time, not work.
"""
from __future__ import annotations

import argparse
import json
import statistics as st
import sys
import urllib.request


def fetch(bus: str) -> list[dict]:
    out, since = [], 0
    while True:
        with urllib.request.urlopen(f"{bus}/events?since={since}", timeout=10) as r:
            d = json.load(r)
        if not d["events"]:
            return out
        out += d["events"]
        since = d["next"]


def incidents(events: list[dict]) -> list[dict]:
    fired = {e.get("rid") or e["data"].get("rid"): e["ts"] for e in events if e["type"] == "oracle.fired"}
    rows, cur = {}, None
    for e in events:
        t, inc, d = e["type"], e.get("incident"), e["data"]
        if t == "incident.opened":
            rows[inc] = {"incident": inc, "class": d.get("vuln_class"), "route": d.get("route"), "opened": e["ts"],
                         "t0": fired.get(d.get("evidence_rid"), e["ts"]), "attempts": 0}
            cur = inc
        r = rows.get(inc) or (rows.get(cur) if t in ("upstream.switched", "deploy.done", "deploy.started") else None)
        if not r:
            continue
        if t == "rule.active":
            r.setdefault("rule", e["ts"])
        elif t == "patch.attempt":
            r["attempts"] = max(r["attempts"], d.get("attempt", 1)); r["source"] = d.get("source")
        elif t == "patch.diff":
            r.setdefault("diff", e["ts"])
        elif t == "pr.merged":
            r["merged"] = e["ts"]
        elif t == "upstream.switched" and "merged" in r:
            r.setdefault("in_prod", e["ts"])
        elif t == "deploy.done":
            r["deploy_done"] = e["ts"]
        elif t == "verify.result":
            r["verified"] = e["ts"]; r["blocked"] = d.get("exploit_blocked_on_prod")
        elif t == "incident.closed":
            r["outcome"] = d.get("outcome"); r["closed"] = e["ts"]
    out = []
    for r in rows.values():
        if r.get("outcome") != "patched" or "in_prod" not in r:
            out.append({k: r.get(k) for k in ("incident", "class", "route", "outcome")})
            continue
        s = r["opened"]                       # start of work (excludes queue)
        out.append({"incident": r["incident"], "class": r["class"], "route": r["route"], "outcome": "patched",
                    "attempts": r["attempts"], "source": r.get("source"), "blocked": r.get("blocked"),
                    "queue": r["opened"] - r["t0"],
                    "to_rule": r["rule"] - s, "to_diff": r["diff"] - s, "to_merged": r["merged"] - s,
                    "to_prod": r["in_prod"] - s, "to_verified": r.get("verified", r["in_prod"]) - s,
                    "identified_to_prod_wall": r["in_prod"] - r["t0"]})
    return out


def summary(rows: list[dict]) -> dict:
    ok = [r for r in rows if r.get("outcome") == "patched"]
    def agg(k):
        v = sorted(r[k] for r in ok)
        return {"n": len(v), "median": st.median(v), "min": v[0], "max": v[-1], "mean": st.mean(v)} if v else {}
    return {"patched": len(ok), "not_patched": len(rows) - len(ok),
            **{k: agg(k) for k in ("queue", "to_rule", "to_diff", "to_merged", "to_prod", "to_verified")}}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m immune.metrics")
    ap.add_argument("--bus", default="http://127.0.0.1:8090")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rows = incidents(fetch(a.bus))
    if a.json:
        print(json.dumps({"incidents": rows, "summary": summary(rows)}, indent=1))
        return 0
    print(f"{'incident':10} {'class':10} {'att':>3} {'queue':>6} {'rule':>6} {'diff':>6} {'merged':>6} {'PROD':>6} {'verif':>6}  route")
    for r in rows:
        if r.get("outcome") != "patched":
            print(f"{r['incident']:10} {str(r['class']):10} -- {r.get('outcome')}  {r['route']}")
            continue
        print(f"{r['incident']:10} {r['class']:10} {r['attempts']:>3} {r['queue']:6.1f} {r['to_rule']:6.1f} {r['to_diff']:6.1f} "
              f"{r['to_merged']:6.1f} {r['to_prod']:6.1f} {r['to_verified']:6.1f}  {r['route']}")
    s = summary(rows)
    if s["patched"]:
        p = s["to_prod"]
        print(f"\nidentified -> fix serving production: median {p['median']:.1f}s  min {p['min']:.1f}s  max {p['max']:.1f}s  (n={p['n']}, queue excluded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
