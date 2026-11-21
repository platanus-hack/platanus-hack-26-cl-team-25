"""python -m anticipate list | check <target> | run <target> [--model opus] [--out DIR]"""
import argparse
import json
import os
import sys

from . import core


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m anticipate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    c = sub.add_parser("check", help="mechanical check of the vulnerable and the official version only (no model)")
    c.add_argument("target")
    r = sub.add_parser("run", help="full run: model review + checks + comparison + report")
    r.add_argument("target")
    r.add_argument("--model")
    r.add_argument("--out")
    rc = sub.add_parser("recheck", help="re-run checks and report on a stored result (no model call)")
    rc.add_argument("result_dir")
    a = ap.parse_args(argv)
    if a.cmd == "recheck":
        res = core.recheck(a.result_dir)
        s = res["checks"]["suggested"]
        print(json.dumps({"equivalence": res["equivalence"], "localisation": res["localisation"]}))
        return 0 if s.get("compiled") and s["passed"] == s["total"] else 1
    if a.cmd == "list":
        for d in sorted(os.listdir(os.path.join(core.HERE, "targets"))):
            t = core.load_target(d)
            print(f"{t['id']:28} {t['name']} ({t['vulnerable_ref']} → {t['fixed_ref']}, {t['vuln_class']})")
        return 0
    t = core.load_target(a.target)
    if a.cmd == "check":
        repo = core.fetch(t)
        for label, ref in (("vulnerable", t["vulnerable_ref"]), ("official", t["fixed_ref"])):
            res = core.run_check(t, core.show(repo, ref, t["check"]["file"]), label)
            print(f"{label:10} {ref:8} {res.get('passed')}/{res.get('total')}" if res["compiled"] else f"{label}: {res['error']}")
            for x in res["results"]:
                print(f"   {'ok ' if x['ok'] else 'BAD'} {x['kind']:11} {x['in']:24} -> ret={x['ret']} {x['out']}")
        return 0
    res = core.run(a.target, model=a.model, out_dir=a.out)
    s = res["checks"]["suggested"]
    return 0 if s.get("compiled") and s["passed"] == s["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
