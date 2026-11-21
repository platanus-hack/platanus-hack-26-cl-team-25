"""End-to-end dry run of one incident with fakes: `python -m pipeline.dryrun [fixture.json ...]`

Fake bus (SSE), fake gateway (admin + data plane), fake fleet; REPO_TARGET=local in a temp runtime;
PATCHER_MODULE defaults to pipeline.stub_patcher; the runner is real (docker) unless RUNNER_MODE says
otherwise. The fixture's oracle.fired event is posted to the fake bus and `python -m pipeline`'s loop
follows it exactly as in production. Prints the ordered event sequence and the merged release dir.
Exit 0 when every incident closed `patched` with the full event sequence.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time

from .bus import Follower, Publisher
from .clients import Fleet, GatewayAdmin
from .config import Config
from .fakes import FakeBus, FakeFleet, FakeGateway
from .orchestrator import Pipeline
from .repo import LocalRepo
from .state import State

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED = ["incident.opened", "poc.ready", "rule.active", "patch.attempt", "patch.diff", "gate.result:policy",
            "pr.opened", "gate.result:properties", "gate.result:poc", "gate.result:tests", "gate.result:legit",
            "pr.merged", "deploy.started", "deploy.done", "rule.expired", "verify.result", "incident.closed"]


def label(e):
    return e["type"] + (":" + e["data"]["gate"] if e["type"] == "gate.result" else "")


def run(fixtures: list, workdir: str | None = None, env: dict | None = None, timeout: float = 600) -> dict:
    work = workdir or tempfile.mkdtemp(prefix="pipeline-dryrun-")
    rt = os.path.join(work, "runtime")
    cfg0 = Config.from_env()
    src_t0 = cfg0.release_dir("t0")
    if not os.path.isdir(os.path.join(src_t0, "victim")):
        src_t0 = cfg0.repo_dir
    os.makedirs(os.path.join(rt, "releases", "t0"), exist_ok=True)
    if not os.path.isdir(os.path.join(rt, "releases", "t0", "victim")):
        shutil.copytree(os.path.join(src_t0, "victim"), os.path.join(rt, "releases", "t0", "victim"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    os.makedirs(os.path.join(rt, "data"), exist_ok=True)
    man = cfg0.manifest_path if os.path.exists(cfg0.manifest_path) else None
    if man:
        shutil.copy(man, os.path.join(rt, "data", "manifest.json"))
    bus = FakeBus("bus-t")
    gw = FakeGateway(bus, "adm-t")
    fl = FakeFleet(bus, rt, "adm-t")
    e = dict(os.environ)
    e.update({"RUNTIME_DIR": rt, "RUN_ID": "dry", "BUS_TOKEN": "bus-t", "ADMIN_TOKEN": "adm-t",
              "PIPELINE_BUS_URL": bus.url, "GATEWAY_ADMIN_URL": gw.admin_url, "GATEWAY_URL": gw.data_url,
              "FLEET_URL": fl.url, "REPO_TARGET": "local", "PATCHER_MODULE": e.get("PATCHER_MODULE", "pipeline.stub_patcher"),
              "PIPELINE_VERIFY_WAIT_S": "3"})
    e.pop("REPO_TARGET_DIR", None)
    e.update(env or {})
    cfg = Config.from_env(e)
    state = State(os.path.join(cfg.state_dir, "state.json"))
    pub = Publisher(cfg.bus_url, cfg.bus_token, cfg.run_id, log_path=os.path.join(cfg.state_dir, "events.jsonl"))
    repo = LocalRepo(os.path.join(rt, "repo"), cfg.run_id, cfg.release_dir("t0"))
    pipe = Pipeline(cfg, state, pub, GatewayAdmin(cfg.gateway_admin_url, cfg.admin_token),
                    Fleet(cfg.fleet_url, cfg.admin_token), repo)
    follower = Follower(cfg.bus_url, lambda: state.data["last_seq"], pipe.on_event, pipe.on_reset)
    follower.start()
    t0 = time.time()
    try:
        for fx in fixtures:
            with open(fx) as f:
                ev = json.load(f)
            ev = {k: v for k, v in ev.items() if k != "seq"}
            ev["ts"] = time.time()
            bus.add(ev)
        want = len(fixtures)
        deadline = time.time() + timeout
        while time.time() < deadline:
            pipe.step()
            closed = [i for i in state.data["incidents"].values() if i.get("status") == "closed"]
            if len(closed) >= want and not state.data["queue"]:
                break
            time.sleep(0.2)
        time.sleep(0.3)
        incs = state.data["incidents"]
        events = [x for x in bus.events if x["type"] != "oracle.fired" and not x["type"].startswith("request.")]
        return {"work": work, "runtime": rt, "incidents": incs, "events": events, "seconds": round(time.time() - t0, 1),
                "rules_deleted": list(gw.deleted), "deploys": list(fl.deploys), "gw_requests": list(gw.requests),
                "repo": repo, "all_events": list(bus.events)}
    finally:
        follower.stop()
        bus.stop()
        gw.stop()
        fl.stop()


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    fixtures = argv or [os.path.join(HERE, "tests", "fixtures", "oracle_sqli.json")]
    res = run(fixtures)
    ok = True
    print("dry run in %s (%.1fs)\n" % (res["work"], res["seconds"]))
    print("ordered events (excluding the gateway's request.* traffic):")
    for x in res["events"]:
        d = x["data"]
        extra = ""
        if x["type"] == "gate.result":
            extra = " ok=%s %s" % (d["ok"], d["detail"][:110])
        elif x["type"] in ("pr.opened", "pr.merged"):
            extra = " " + (d.get("sha") or d.get("branch") or "")[:40]
        elif x["type"] == "incident.closed":
            extra = " %s rule=%ss patch=%ss" % (d["outcome"], d["seconds_to_rule"], d["seconds_to_patch"])
        elif x["type"] in ("deploy.done", "deploy.started"):
            extra = " " + d["release"]
        elif x["type"] == "verify.result":
            extra = " blocked=%s" % d["exploit_blocked_on_prod"]
        print("  %-12s %-9s %-26s%s" % (x.get("incident") or "-", x["src"], label(x), extra))
    for iid, inc in res["incidents"].items():
        seq = [label(x) for x in res["events"] if x.get("incident") == iid or
               (x["type"].startswith("deploy.") and x["data"].get("release") == inc.get("release")) or
               (x["type"] == "rule.expired" and x["data"].get("id") == (inc.get("rule") or {}).get("id"))]
        rel = os.path.join(res["runtime"], "releases", inc.get("release") or "-", "victim")
        good = inc.get("outcome") == "patched" and seq == EXPECTED and os.path.isdir(rel)
        ok &= good
        print("\n%s: outcome=%s reason=%s" % (iid, inc.get("outcome"), inc.get("reason")))
        print("  merged release dir: %s (%s)" % (rel, "exists" if os.path.isdir(rel) else "MISSING"))
        print("  sequence matches expected: %s" % (seq == EXPECTED))
        if seq != EXPECTED:
            print("  got:      %s\n  expected: %s" % (seq, EXPECTED))
        for line in inc.get("log", []):
            print("    " + line)
    print("\nDRYRUN %s" % ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
