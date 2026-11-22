"""python -m pipeline — host process: follow the bus, one incident at a time.

    python -m pipeline                 run forever (SSE from PIPELINE_BUS_URL, resume from the last seq)
    python -m pipeline --once          process what is queued (plus what arrives within --idle s), then exit
    python -m pipeline --replay F.json enqueue a saved oracle.fired event (no bus follow), process, exit
    python -m pipeline --status        print the persisted state summary

While <runtime>/pipeline/PAUSE exists no new incident is started.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time

from .bus import Follower, Publisher
from .clients import Fleet, GatewayAdmin
from .config import Config
from .orchestrator import Pipeline
from .repo import LocalRepo, make_target
from .state import State

log = logging.getLogger("pipeline")


def build(cfg: Config, patcher=None) -> Pipeline:
    os.makedirs(cfg.state_dir, exist_ok=True)
    state = State(os.path.join(cfg.state_dir, "state.json"))
    pub = Publisher(cfg.bus_url, cfg.bus_token, cfg.run_id, log_path=os.path.join(cfg.state_dir, "events.jsonl"))
    gw = GatewayAdmin(cfg.gateway_admin_url, cfg.admin_token, cfg.http_timeout_s)
    fleet = Fleet(cfg.fleet_url, cfg.admin_token, cfg.http_timeout_s)
    repo = make_target(cfg)

    def local():
        return LocalRepo(os.environ.get("REPO_TARGET_DIR") or os.path.join(cfg.runtime_dir, "repo"), cfg.run_id,
                         cfg.release_dir("t0"), paths=cfg.project.app.release_paths, t0_tag=cfg.project.repo.t0_tag)
    if os.environ.get("PIPELINE_APP") == "external" or cfg.project.app.runtime == "generic":
        # app outside the in-process harness (any language): pipeline/external.py
        from .external import ExternalPipeline
        return ExternalPipeline(cfg, state, pub, gw, fleet, repo, patcher=patcher, local_fallback=local,
                                repro_url=os.environ.get("REPRO_URL", ""))
    return Pipeline(cfg, state, pub, gw, fleet, repo, patcher=patcher, local_fallback=local)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m pipeline")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--idle", type=float, default=3.0, help="with --once: exit after this many idle seconds")
    ap.add_argument("--replay", action="append", default=[], help="saved oracle.fired event (JSON); implies --once")
    ap.add_argument("--status", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=os.environ.get("PIPELINE_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    if not os.environ.get("PIPELINE_LOG_HTTP"):
        for noisy in ("httpx", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
    cfg = Config.from_env()
    pipe = build(cfg)
    if a.status:
        d = pipe.state.data
        print(json.dumps({"last_seq": d["last_seq"], "current_release": d["current_release"], "queue": d["queue"],
                          "incidents": {k: {x: v.get(x) for x in ("status", "outcome", "vuln_class", "route", "hits",
                                                                  "reason", "seconds_to_rule", "seconds_to_patch")}
                                        for k, v in d["incidents"].items()}}, indent=1))
        return 0
    pipe.resume_interrupted()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    follower = None
    if a.replay:
        for path in a.replay:
            with open(path) as f:
                ev = json.load(f)
            for e in (ev.get("events") if isinstance(ev, dict) and "events" in ev else [ev]):
                pipe.enqueue(e)
        a.once = True
    else:
        follower = Follower(cfg.bus_url, lambda: pipe.state.data["last_seq"], pipe.on_event, pipe.on_reset)
        follower.start()
    log.info("pipeline up: run=%s bus=%s repo=%s runner=%s patcher=%s", cfg.run_id, cfg.bus_url, cfg.repo_target,
             cfg.runner_image, cfg.patcher_module)
    idle_since = time.time()
    was_paused = False
    while not stop.is_set():
        paused = pipe.paused()
        if paused != was_paused:
            log.info("PAUSE file %s: %s", cfg.pause_file, "paused, no new incident will start" if paused else "resumed")
            was_paused = paused
        did = pipe.step()
        if not did and not paused and not a.once:
            pipe.maintain()
        pipe.state.flush()
        if did:
            idle_since = time.time()
            continue
        if a.once and not pipe.state.data["queue"] and time.time() - idle_since >= (0 if a.replay else a.idle):
            break
        stop.wait(0.5)
    if follower:
        follower.stop()
    pipe.state.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
