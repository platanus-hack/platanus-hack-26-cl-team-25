"""Gate self-test (docs/plan-construccion.md §4): `python -m pipeline.selftest`

Against the t0 app, using the real shadow harness in real runner containers:

  1. incidents: every entry of victim/VULNS.md is detonated in the harness with its documented
     exploit; the resulting evidence goes through the normal incident derivation (class, route,
     param, sink). The three oracle.fired events captured from the live stack
     (tests/fixtures/oracle_*.json) must derive to the same incident keys.
  2. known-good fixes: the seven hand-written root-cause fixes in patcher/fallbacks/*.diff, one per
     endpoint, must each pass all five gates for their own incident.
  3. inadequate fixes (pipeline/fixes.py): each must be rejected by the stated gate.

Prints a table; exit 0 only if every expectation holds.

Env: SELFTEST_RELEASE (dir with victim/, default <runtime>/releases/t0, else a copy of the repo's victim/),
SELFTEST_JOBS (parallelism, default 3), SELFTEST_ONLY (comma-separated row names), FALLBACK_DIR
(default <repo>/patcher/fallbacks), plus the runner settings of pipeline.config.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl

from . import fixes, incident as incmod, openapi, poc as pocmod, reqs
from .config import Config
from .gates import GATES, Validator

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
CLASS_NAMES = {"sql injection": "sqli", "path traversal": "traversal", "idor": "idor"}


def t0_release(cfg: Config) -> tuple:
    rel = os.environ.get("SELFTEST_RELEASE") or cfg.release_dir("t0")
    if os.path.isdir(os.path.join(rel, "victim")):
        return rel, None
    tmp = tempfile.mkdtemp(prefix="selftest-t0-")
    shutil.copytree(os.path.join(cfg.repo_dir, "victim"), os.path.join(tmp, "victim"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return tmp, tmp


# ------------------------------------------------------------------ VULNS.md -> exploit requests
def parse_vulns(path: str, manifest: dict) -> list:
    """[{n, cls, method, route, exploit request}] from victim/VULNS.md lines
    `N. <class> | <METHOD route> | <param> | <file:line> | `<exploit>` [with any valid token]`."""
    out = []
    with open(path) as f:
        for line in f:
            m = re.match(r"\s*(\d+)\.\s*([^|]+)\|\s*(\S+)\s+(\S+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*`([^`]+)`(.*)$", line)
            if not m:
                continue
            n, cls, method, route, _param, _loc, exploit, tail = m.groups()
            cls = next((v for k, v in CLASS_NAMES.items() if cls.strip().lower().startswith(k)), "other")
            req = {"method": method.upper(), "path": route, "query": "", "headers": {}, "body_b64": "", "uid": None, "role": None}
            ex = exploit.strip()
            if ex.startswith("{"):
                req = reqs.with_body(req, ex.encode())
                req["headers"] = {"content-type": "application/json"}
            else:
                em, _, target = ex.partition(" ")
                req["method"] = em.upper()
                path, _, query = target.partition("?")
                req["path"] = path
                req["query"] = reqs.encode_query(parse_qsl(query, keep_blank_values=True))
            if "token" in tail:   # "with any valid token": a fresh, untrusted account
                req["uid"], req["role"] = int(manifest.get("seed_max_uid", 0)) + 1, "user"
            out.append({"n": int(n), "cls": cls, "method": method.upper(), "route": route, "request": req})
    return out


def fallback_name(cls: str, method: str, route: str) -> str:
    return "%s__%s" % (cls, re.sub(r"[^a-z0-9_]+", "-", ("%s %s" % (method, route)).lower()).strip("-"))


def _clip(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n - 3] + "..."


def main(argv=None) -> int:
    cfg = Config.from_env()
    only = [x for x in os.environ.get("SELFTEST_ONLY", "").split(",") if x]
    jobs = int(os.environ.get("SELFTEST_JOBS", "3"))
    fb_dir = os.environ.get("FALLBACK_DIR") or os.path.join(cfg.repo_dir, "patcher", "fallbacks")
    base_dir, cleanup = t0_release(cfg)
    spec = openapi.load(cfg.openapi_path)
    v = Validator(cfg)
    t_start = time.time()
    ok_all = True
    print("gate self-test: release %s, runner=%s (%s)" % (base_dir, cfg.runner_mode, cfg.runner_image), flush=True)

    # 1. incidents from the documented exploits, detonated in the harness
    manifest = v.manifest(base_dir)
    vulns = parse_vulns(os.path.join(base_dir, "victim", "VULNS.md"), manifest)
    seqs = [{"name": "vuln%d" % x["n"], "requests": [x["request"]], "with_evidence": True} for x in vulns]
    res = v.run(base_dir, {"kind": "harness", "sequences": seqs})
    incidents = {}
    print("\nincidents derived from victim/VULNS.md exploits:")
    for x, s in zip(vulns, res["sequences"]):
        last = s["runs"][0][-1]
        if last.get("verdict") != "oracle" or not last.get("evidence"):
            print("  #%d %s %s: exploit did not fire an oracle (status %s)  <-- FAIL" % (x["n"], x["method"], x["route"], last["status"]))
            ok_all = False
            continue
        inc = incmod.build({"type": "oracle.fired", "ts": time.time(), "rid": "selftest-%d" % x["n"], "data": last["evidence"]},
                           spec, manifest)
        inc["incident"] = "selftest-%d" % x["n"]
        good = inc["vuln_class"] == x["cls"] and _shape(inc["route"]) == _shape(x["route"])
        x["route"] = inc["route"]   # the OpenAPI template is authoritative
        ok_all &= good
        incidents[inc["key"]] = inc
        x["key"] = inc["key"]
        print("  #%d %-9s %-5s %-32s param=%-22s sink=%s:%s%s" % (
            x["n"], inc["vuln_class"], inc["method"], inc["route"],
            "%s:%s" % ((inc["param"] or {}).get("in"), (inc["param"] or {}).get("name")), inc["sink"]["file"], inc["sink"]["line"],
            "" if good else "  <-- class/route mismatch with VULNS.md"), flush=True)
    for fx in sorted(glob.glob(os.path.join(FIXTURES, "oracle_*.json"))):
        with open(fx) as f:
            live = incmod.build(json.load(f), spec, manifest)
        same = live["key"] in incidents
        ok_all &= same
        print("  live fixture %-22s -> %s %s" % (os.path.basename(fx), live["key"], "(same incident)" if same else "<-- NO MATCH"))

    # 2./3. rows: (name, kind, incident, expect, reason, diff-builder)
    rows = []
    for x in vulns:
        inc = incidents.get(x.get("key"))
        name = fallback_name(x["cls"], x["method"], x["route"])
        path = os.path.join(fb_dir, name + ".diff")
        if inc is None:
            continue
        if not os.path.exists(path):
            print("  no known-good fix %s  <-- FAIL" % path)
            ok_all = False
            continue
        rows.append((name, "known-good", inc, "pass", "patcher/fallbacks/%s.diff" % name, lambda p=path, i=None: open(p).read()))
    by_route = {}
    for inc in incidents.values():
        by_route.setdefault(inc["vuln_class"], []).append(inc)
    for fix in fixes.CATALOGUE:
        if fix.expect == "pass":
            continue   # the known-good set is patcher/fallbacks
        target = next((i for i in sorted(by_route.get(fix.vuln_class, []), key=lambda i: i["incident"])
                       if any(fp == i["sink"]["file"] or fp in [fr["file"] for e in i["evidence"]["events"] for fr in e["stack"]]
                              for fp, _o, _n in _edits(fix, i))), None)
        if target is None:
            print("  no incident for bad fix %s  <-- FAIL" % fix.name)
            ok_all = False
            continue
        rows.append((fix.name, "bad", target, fix.expect, fix.reason,
                     lambda fix=fix, inc=target: fixes.diff_for(fix, base_dir, inc)))
    if only:
        rows = [r for r in rows if r[0] in only]

    # baselines (PoC 3/3 + variants) for the incidents that are used
    need = {r[2]["incident"]: r[2] for r in rows}
    ctx = {}

    def baseline(inc):
        p = pocmod.build(inc, "t0")
        inc["poc"] = p
        extra = []
        try:
            import patcher
            extra = patcher.variants(p, inc["evidence"]) or []
        except Exception as e:  # noqa: BLE001
            print("  patcher.variants unavailable for %s: %s" % (inc["incident"], e))
        return inc["incident"], p, v.reproduce(inc, p, base_dir, extra)

    print("\nbaselines (unpatched t0):")
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        for iid, p, rep in ex.map(baseline, need.values()):
            ctx[iid] = (p, rep)
            inc = need[iid]
            ok_all &= rep["reproducible"]
            print("  %-12s %-5s %-32s PoC %d/%d, %d variant(s) fire, %d do not (not counted)%s" % (
                iid, inc["method"], inc["route"], rep["runs"], rep["of"], len(rep["counted"]), len(rep["ignored"]),
                "" if rep["reproducible"] else "  <-- NOT REPRODUCIBLE"), flush=True)
        if not all(ctx[i][1]["reproducible"] for i in ctx):
            print("baseline failed: the t0 PoCs must reproduce before fixes can be judged\nSELFTEST FAILED")
            return 1
        v.base_scenarios(base_dir)

        def one(row):
            name, kind, inc, expect, reason, mk = row
            p, rep = ctx[inc["incident"]]
            t = time.time()
            try:
                diff = mk()
            except fixes.FixNotApplicable as e:
                return row, False, [("policy", False, "fix not applicable to this release: %s" % e, 0.0)], 0.0
            ok, results, _ = v.validate(inc, p, rep, base_dir, diff)
            return row, ok, results, time.time() - t

        out = list(ex.map(one, rows))

    print()
    hdr = "%-42s %-10s %-26s %-10s %-10s %-3s %-22s %s" % ("fix", "kind", "incident", "expected", "got", "ok", "seconds/gate", "detail")
    print(hdr)
    print("-" * 190)
    gate_times = {g: [] for g in GATES}
    for (name, kind, inc, expect, reason, _mk), ok, results, secs in out:
        got = "pass" if ok else next(g for g, o, _d, _s in results if not o)
        good = got == expect
        ok_all &= good
        for g, _o, _d, s in results:
            gate_times[g].append(s)
        times = " ".join("%s%.1f" % (g[:2], s) for g, _o, _d, s in results)
        detail = results[-1][2] if not ok else "all five gates passed"
        print("%-42s %-10s %-26s %-10s %-10s %-3s %-22s %s" % (
            name, kind, _clip("%s %s" % (inc["method"], inc["route"]), 26), expect, got, "yes" if good else "NO",
            times, _clip(detail, 120)))
        if not good:
            for g, o, d, _s in results:
                print("      %-10s %s %s" % (g, "ok  " if o else "FAIL", _clip(d, 400)))
    print("\nwhy each bad fix is inadequate:")
    for (name, kind, inc, expect, reason, _mk), _ok, _r, _s in out:
        if kind == "bad":
            print("  %-32s [%s] %s" % (name, expect, reason))
    print()
    print("mean seconds per gate: " + ", ".join("%s %.1f (n=%d)" % (g, sum(t) / len(t), len(t))
                                                for g, t in gate_times.items() if t))
    print("runner jobs: %d, total %.0fs wall" % (len(v.runner.calls), time.time() - t_start))
    print("SELFTEST %s" % ("PASSED" if ok_all else "FAILED"))
    if cleanup:
        shutil.rmtree(cleanup, ignore_errors=True)
    return 0 if ok_all else 1


def _shape(template: str) -> str:
    return re.sub(r"\{[^}]*\}", "{}", template)


def _edits(fix, inc):
    try:
        return fix.edits(inc)
    except Exception:  # noqa: BLE001
        return []


if __name__ == "__main__":
    sys.exit(main())
