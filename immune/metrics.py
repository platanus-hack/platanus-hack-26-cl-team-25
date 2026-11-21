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

For an incident found by the class self-audit (incident.opened origin "audit", pipeline/audit.py) t0 is its
audit.finding event: no request for it ever reached the gateway.

Detection (docs/plan-construccion.md §9d), from the bus and the gateway recording (deduplicated by rid):
  detonated        requests the gateway sent to a shadow clone (verdict clean | oracle | inconclusive)
  clean share      detonations whose verdict was clean: the cost of suspicion (the request went to prod anyway)
  incidents by origin   live (a request through the gateway) vs audit (found by the self-audit)
"""
from __future__ import annotations

import argparse
import json
import os
import statistics as st
import sys
import urllib.request

DETONATED = ("clean", "oracle", "inconclusive")


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
    found = {e["data"].get("incident") or e.get("incident"): e["ts"] for e in events if e["type"] == "audit.finding"}
    rows, cur = {}, None
    for e in events:
        t, inc, d = e["type"], e.get("incident"), e["data"]
        if t == "incident.opened":
            origin = d.get("origin") or "live"
            t0 = found.get(inc, e["ts"]) if origin == "audit" else fired.get(d.get("evidence_rid"), e["ts"])
            rows[inc] = {"incident": inc, "class": d.get("vuln_class"), "route": d.get("route"), "opened": e["ts"],
                         "t0": t0, "attempts": 0, "origin": origin, "parent": d.get("parent"),
                         "method": d.get("method"), "param": (d.get("param") or {}).get("name")}
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
            out.append({k: r.get(k) for k in ("incident", "class", "route", "outcome", "origin", "parent", "method", "param")})
            continue
        s = r["opened"]                       # start of work (excludes queue)
        out.append({"incident": r["incident"], "class": r["class"], "route": r["route"], "outcome": "patched",
                    "origin": r["origin"], "parent": r["parent"], "method": r["method"], "param": r["param"],
                    "attempts": r["attempts"], "source": r.get("source"), "blocked": r.get("blocked"),
                    "queue": r["opened"] - r["t0"],
                    "to_rule": r["rule"] - s, "to_diff": r["diff"] - s, "to_merged": r["merged"] - s,
                    "to_prod": r["in_prod"] - s, "to_verified": r.get("verified", r["in_prod"]) - s,
                    "identified_to_prod_wall": r["in_prod"] - r["t0"]})
    return out


def load_recording(path: str | None) -> list[dict]:
    """Gateway recording lines (contracts/README.md §7); [] when absent."""
    out = []
    if not path:
        return out
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict):
                    out.append(r)
    except OSError:
        pass
    return out


def detection(events: list[dict], recording: list[dict] | None = None) -> dict:
    """Detonations, the share that ended clean, and incidents by origin."""
    verdict = {}
    for e in events:
        if e.get("type") == "request.routed" and e.get("rid"):
            verdict[e["rid"]] = (e.get("data") or {}).get("verdict")
    for r in recording or []:
        if r.get("rid") and "aftercheck" not in r:
            verdict.setdefault(r["rid"], r.get("verdict"))
    requests = len(verdict)
    det = [v for v in verdict.values() if v in DETONATED]
    by_v = {k: det.count(k) for k in DETONATED}
    after = sum(1 for r in recording or [] if r.get("aftercheck") == "oracle")
    origin = {}
    for e in events:
        if e.get("type") == "incident.opened":
            o = (e.get("data") or {}).get("origin") or "live"
            origin[o] = origin.get(o, 0) + 1
    audits = [e.get("data") or {} for e in events if e.get("type") == "audit.done"]
    return {"requests": requests, "detonated": len(det), "detonated_by_verdict": by_v,
            "clean_share": round(by_v["clean"] / len(det), 3) if det else None,
            "no_clone": sum(1 for v in verdict.values() if v == "no_clone"), "aftercheck_oracle": after,
            "incidents_by_origin": origin,
            "audits": {"n": len(audits), "checked": sum(int(a.get("checked") or 0) for a in audits),
                       "findings": sum(int(a.get("findings") or 0) for a in audits),
                       "seconds": round(sum(float(a.get("seconds") or 0) for a in audits), 1)}}


def detection_lines(d: dict) -> list[str]:
    v = d["detonated_by_verdict"]
    share = "-" if d["clean_share"] is None else "%.0f%%" % (100 * d["clean_share"])
    o = d["incidents_by_origin"]
    a = d["audits"]
    return ["requests seen %d; detonated %d (oracle %d, clean %d, inconclusive %d; no clone %d)" % (
                d["requests"], d["detonated"], v["oracle"], v["clean"], v["inconclusive"], d["no_clone"]),
            "detonations that ended clean (cost of suspicion): %s" % share,
            "incidents by origin: live %d, audit %d" % (o.get("live", 0), o.get("audit", 0)),
            "self-audits: %d, %d candidate(s) judged, %d finding(s), %.1fs in the judge" % (
                a["n"], a["checked"], a["findings"], a["seconds"])]


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
    ap.add_argument("--recording", default=None,
                    help="gateway recording (default: <runtime>/recordings/requests.jsonl of the current project)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rec_path = a.recording
    if rec_path is None:
        try:
            from immune import config as icfg
            rec_path = icfg.current().record_path
        except Exception:  # noqa: BLE001
            rec_path = os.path.join("runtime", "recordings", "requests.jsonl")
    evs = fetch(a.bus)
    rows = incidents(evs)
    det = detection(evs, load_recording(rec_path))
    if a.json:
        print(json.dumps({"incidents": rows, "summary": summary(rows), "detection": det}, indent=1))
        return 0
    print(f"{'incident':10} {'class':10} {'origin':14} {'att':>3} {'queue':>6} {'rule':>6} {'diff':>6} {'merged':>6} {'PROD':>6} {'verif':>6}  route")
    for r in rows:
        org = (r.get("origin") or "live") + ("<" + r["parent"] if r.get("parent") else "")
        where = "%s %s [%s]" % (r.get("method") or "", r["route"], r.get("param") or "-")
        if r.get("outcome") != "patched":
            print(f"{r['incident']:10} {str(r['class']):10} {org:14} -- {r.get('outcome')}  {where}")
            continue
        print(f"{r['incident']:10} {r['class']:10} {org:14} {r['attempts']:>3} {r['queue']:6.1f} {r['to_rule']:6.1f} {r['to_diff']:6.1f} "
              f"{r['to_merged']:6.1f} {r['to_prod']:6.1f} {r['to_verified']:6.1f}  {where}")
    s = summary(rows)
    if s["patched"]:
        p = s["to_prod"]
        print(f"\nidentified -> fix serving production: median {p['median']:.1f}s  min {p['min']:.1f}s  max {p['max']:.1f}s  (n={p['n']}, queue excluded)")
        w = [r["identified_to_prod_wall"] for r in rows if r.get("outcome") == "patched"]
        print(f"identified -> production incl. queue: median {st.median(w):.1f}s  max {max(w):.1f}s")
    print()
    for line in detection_lines(det):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
