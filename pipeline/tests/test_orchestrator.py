"""Incident lifecycle with a scripted validator (no app code), the stub patcher, local repo and HTTP fakes."""
import copy
import os
import shutil

import pytest

from pipeline import diffs, stub_patcher
from pipeline.bus import Publisher
from pipeline.clients import Fleet, GatewayAdmin
from pipeline.config import Config
from pipeline.fakes import FakeBus, FakeFleet, FakeGateway
from pipeline.gates import GATES
from pipeline.orchestrator import Pipeline
from pipeline.repo import LocalRepo
from pipeline.state import State

from .conftest import ROOT


class ScriptedValidator:
    """Stands in for gates.Validator. plan: list per attempt of the failing gate name, or None (= pass)."""

    def __init__(self, reproducible=True, plan=None):
        self.reproducible, self.plan, self.calls, self.cache = reproducible, list(plan or []), [], {}
        self.diffs = []

    def reproduce(self, inc, p, base_dir, extra=None, corpus=None):
        return {"runs": 3 if self.reproducible else 1, "of": 3, "reproducible": self.reproducible, "counted": [],
                "ignored": [], "sink_match": True, "statuses": [200] * 3}

    def run(self, release_dir, job, timeout=None):     # used by verify.in_runner
        return {"sequences": [{"name": s["name"], "runs": [[{"events": []}]]} for s in job["sequences"]]}

    def validate(self, inc, p, rep, base_dir, diff, on_result=None, after_policy=None, keep=False, gates=GATES):
        self.diffs.append(diff)
        fail = self.plan.pop(0) if self.plan else None
        work = diffs.copy_release(base_dir, os.path.dirname(os.path.dirname(base_dir)))
        try:
            diffs.apply(diff, work)
        except diffs.DiffError as e:
            on_result("policy", False, "REJECTED: %s" % e, 0.0)
            return False, [("policy", False, str(e), 0.0)], None
        results = []
        for g in GATES:
            ok = g != fail
            d = "%s %s" % (g, "ok" if ok else "rejected: scripted")
            results.append((g, ok, d, 0.0))
            on_result(g, ok, d, 0.0)
            if not ok:
                return False, results, None
            if g == "policy" and after_policy:
                after_policy(work)
        return True, results, work


@pytest.fixture()
def env(tmp_path, monkeypatch):
    rt = tmp_path / "runtime"
    shutil.copytree(os.path.join(ROOT, "victim"), rt / "releases" / "t0" / "victim",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    b = FakeBus("bt")
    gw = FakeGateway(b, "at")
    fl = FakeFleet(b, str(rt), "at")
    monkeypatch.delenv("STUB_PATCHER_PLAN", raising=False)
    stub_patcher.calls.clear()
    e = {"RUNTIME_DIR": str(rt), "RUN_ID": "t", "BUS_TOKEN": "bt", "ADMIN_TOKEN": "at", "PIPELINE_BUS_URL": b.url,
         "GATEWAY_ADMIN_URL": gw.admin_url, "GATEWAY_URL": gw.data_url, "FLEET_URL": fl.url, "REPO_DIR": ROOT,
         "PIPELINE_VERIFY_WAIT_S": "2", "MANIFEST_PATH_HOST": str(tmp_path / "none.json")}
    cfg = Config.from_env(e)
    yield {"cfg": cfg, "bus": b, "gw": gw, "fleet": fl, "rt": str(rt)}
    b.stop()
    gw.stop()
    fl.stop()


def make(env, validator=None, patcher=stub_patcher, audit=False):
    cfg = env["cfg"]
    st = State(os.path.join(cfg.state_dir, "state.json"))
    p = Pipeline(cfg, st, Publisher(cfg.bus_url, cfg.bus_token, cfg.run_id), GatewayAdmin(cfg.gateway_admin_url, "at"),
                 Fleet(cfg.fleet_url, "at"), LocalRepo(os.path.join(env["rt"], "repo"), "t", cfg.release_dir("t0")),
                 validator=validator or ScriptedValidator(), patcher=patcher)
    if not audit:   # the class self-audit has its own tests (test_audit.py)
        p.audit_settings = lambda: (False, 40, 120)
    return p


def seq(env, iid):
    return [e["type"] + (":" + e["data"]["gate"] if e["type"] == "gate.result" else "")
            for e in env["bus"].events if e.get("incident") == iid]


def test_happy_path_patched(env, events):
    p = make(env)
    iid = p.enqueue(events["sqli"])
    assert p.step() == iid
    inc = p.state.incident(iid)
    assert inc["outcome"] == "patched", inc["reason"]
    assert seq(env, iid) == ["incident.opened", "poc.ready", "rule.active", "patch.attempt", "patch.diff",
                             "gate.result:policy", "pr.opened", "gate.result:properties", "gate.result:poc",
                             "gate.result:tests", "gate.result:legit", "pr.merged", "verify.result", "incident.closed"]
    rel = inc["release"]
    assert os.path.isdir(os.path.join(env["rt"], "releases", rel, "victim"))
    assert "LIKE ? OR category" in open(os.path.join(env["rt"], "releases", rel, "victim/app/products.py")).read()
    assert env["fleet"].deploys == [rel] and env["gw"].deleted == [inc["rule"]["id"]]
    closed = [e for e in env["bus"].events if e["type"] == "incident.closed"][0]["data"]
    assert closed["seconds_to_rule"] is not None and closed["seconds_to_patch"] >= closed["seconds_to_rule"]
    assert p.state.data["current_release"] == rel


def test_dedupe_and_no_reopen(env, events):
    p = make(env)
    a = p.enqueue(events["idor"])
    other = copy.deepcopy(events["idor"])
    other["data"]["request"]["path"] = "/api/orders/31"
    assert p.enqueue(other) is None                  # same kind+method+route+param
    assert p.enqueue(events["sqli"]) is not None
    p.step()
    assert p.state.incident(a)["outcome"] == "patched"
    assert p.enqueue(events["idor"]) is None         # patched: never reopened
    assert p.state.incident(a)["hits"] == 3


def test_queue_one_at_a_time_and_pause(env, events):
    p = make(env)
    a, b = p.enqueue(events["sqli"]), p.enqueue(events["traversal"])
    os.makedirs(env["cfg"].state_dir, exist_ok=True)
    open(env["cfg"].pause_file, "w").close()
    assert p.step() is None and p.state.data["queue"] == [a, b]
    os.remove(env["cfg"].pause_file)
    assert p.step() == a and p.state.data["queue"] == [b]
    assert p.state.incident(b)["status"] == "queued"


def test_restart_resumes_open_incident(env, events):
    p = make(env)
    a = p.enqueue(events["sqli"])
    p.state.data["queue"].clear()
    p.state.incident(a)["status"] = "open"           # crashed mid-incident
    p.state.save()
    p2 = make(env)
    p2.resume_interrupted()
    assert p2.state.data["queue"] == [a]
    assert p2.step() == a and p2.state.incident(a)["outcome"] == "patched"


def test_not_reproducible(env, events):
    p = make(env, ScriptedValidator(reproducible=False))
    a = p.enqueue(events["sqli"])
    p.step()
    inc = p.state.incident(a)
    assert inc["outcome"] == "not_reproducible" and "1/3" in inc["reason"]
    assert env["gw"].rules == {} and not stub_patcher.calls


def test_feedback_loop_then_rule_only(env, events):
    v = ScriptedValidator(plan=["poc", "tests", "legit"])
    p = make(env, v)
    a = p.enqueue(events["traversal"])
    p.step()
    inc = p.state.incident(a)
    assert inc["outcome"] == "rule_only" and "3 attempts" in inc["reason"]
    assert [c["attempt"] for c in stub_patcher.calls] == [1, 2, 3]
    assert stub_patcher.calls[2]["feedback"] == ["Attempt 1 was rejected by the poc gate: poc rejected: scripted",
                                                 "Attempt 2 was rejected by the tests gate: tests rejected: scripted"]
    assert inc["rule"]["id"] in env["gw"].rules       # rule stays
    assert seq(env, a).count("pr.opened") == 1         # one PR, force-pushed per attempt
    assert not env["fleet"].deploys


def test_diff_that_does_not_apply_is_rejected(env, events, monkeypatch):
    monkeypatch.setenv("STUB_PATCHER_PLAN", "nonexistent-fix,adequate")
    p = make(env)
    a = p.enqueue(events["sqli"])
    p.step()
    inc = p.state.incident(a)
    assert inc["outcome"] == "patched" and len(inc["attempts"]) == 2
    assert not inc["attempts"][0]["gates"][0]["ok"]


def test_rollback_keeps_rule(env, events):
    env["fleet"].outcome = "rollback"
    p = make(env)
    a = p.enqueue(events["idor"])
    p.step()
    inc = p.state.incident(a)
    assert inc["outcome"] == "rule_only" and "rolled back" in inc["reason"]
    assert inc["rule"]["id"] in env["gw"].rules and env["gw"].deleted == []
    assert p.state.data["current_release"] is None


def test_failure_closes_rule_only_and_loop_continues(env, events):
    class Boom:
        def propose(self, *a):
            raise RuntimeError("boom")
        def derive_rule(self, inc, spec):
            raise RuntimeError("no rule")
    p = make(env, patcher=Boom())
    a, b = p.enqueue(events["sqli"]), p.enqueue(events["idor"])
    env["fleet"].srv.stop()                          # fleet down too
    p.step()
    assert p.state.incident(a)["outcome"] == "rule_only"
    assert p.state.incident(a)["rule"]["scope"] == "param"   # built-in rule after derive_rule failed
    p.step()
    assert p.state.incident(b)["status"] == "closed"


def _project_with(tmp_path, **over):
    """A copy of the demo project config (victim/ and the OpenAPI symlinked) with top-level keys replaced."""
    import yaml
    from immune import config as icfg
    proj = tmp_path / "proj"
    (proj / ".immune").mkdir(parents=True)
    (proj / "contracts").mkdir()
    os.symlink(os.path.join(ROOT, "victim"), proj / "victim")
    os.symlink(os.path.join(ROOT, "contracts", "openapi.yaml"), proj / "contracts" / "openapi.yaml")
    raw = yaml.safe_load(open(os.path.join(ROOT, ".immune", "config.yaml")))
    for k, v in over.items():
        if v is None:
            raw.pop(k, None)
        else:
            raw[k] = v
    (proj / ".immune" / "config.yaml").write_text(yaml.safe_dump(raw))
    return icfg.load(str(proj))


def test_autopatch_pr_stops_after_the_pr(env, events, tmp_path):
    env["cfg"].app = _project_with(tmp_path, autopatch="pr")
    p = make(env)
    iid = p.enqueue(events["sqli"])
    p.step()
    inc = p.state.incident(iid)
    assert (inc["outcome"], inc["outcome_detail"]) == ("rule_only", "pr_open"), inc["reason"]
    s = seq(env, iid)
    assert "pr.opened" in s and "gate.result:legit" in s and "pr.merged" not in s and env["fleet"].deploys == []
    assert env["gw"].deleted == []                                   # the rule stays
    closed = [e for e in env["bus"].events if e["type"] == "incident.closed"][-1]["data"]
    assert closed["outcome"] == "rule_only" and closed["outcome_detail"] == "pr_open"


def test_no_tests_command_caps_merge_at_pr(env, events, tmp_path):
    env["cfg"].app = _project_with(tmp_path, autopatch="merge", tests=None)
    p = make(env)
    iid = p.enqueue(events["sqli"])
    p.step()
    inc = p.state.incident(iid)
    assert (inc["outcome"], inc["outcome_detail"], inc["autopatch"]) == ("rule_only", "pr_open", "pr"), inc["reason"]
    assert "no tests.command" in inc["reason"] and env["fleet"].deploys == []


def test_autopatch_off_keeps_only_the_rule(env, events, tmp_path):
    env["cfg"].app = _project_with(tmp_path, autopatch="off")
    p = make(env)
    iid = p.enqueue(events["sqli"])
    p.step()
    inc = p.state.incident(iid)
    assert (inc["outcome"], inc["outcome_detail"]) == ("rule_only", "autopatch_off")
    s = seq(env, iid)
    assert "rule.active" in s and "patch.attempt" not in s and stub_patcher.calls == []
