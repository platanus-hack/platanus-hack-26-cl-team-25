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
    # it fired once: contained by the rule and escalated, but no automatic fix without a reliable PoC
    assert (inc["outcome"], inc["outcome_detail"]) == ("rule_only", "escalated") and "1/3" in inc["reason"]
    assert len(env["gw"].rules) == 1 and not stub_patcher.calls


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


# ---------------------------------------------------------------- things that fail around the pipeline
class FlakyFleet:
    """Stands in for clients.Fleet's transport: scripted answers for POST /deploy and GET /state."""

    def __init__(self, deploys, states):
        self.deploys, self.states, self.calls = list(deploys), list(states), []

    def install(self, fleet):
        from pipeline.clients import ServiceError

        class R:
            def __init__(self, code, body):
                self.status_code, self._b, self.text = code, body, str(body)

            def json(self):
                return self._b

        def req(method, path, timeout=None, **kw):
            self.calls.append((method, path))
            script = self.deploys if path == "/deploy" else self.states
            item = script.pop(0) if len(script) > 1 else script[0]
            if isinstance(item, Exception):
                raise item
            return R(*item)
        fleet._req = req
        fleet.RESTART_WAIT_S = 2.0
        return ServiceError


def test_deploy_survives_a_fleet_restart(env):
    from pipeline.clients import ServiceError
    up = (200, {"ready": True, "prod": {"active": "blue", "release": "t0"}})
    f = Fleet("http://127.0.0.1:1", "at")
    FlakyFleet([ServiceError("POST /deploy: Server disconnected"), (200, {"ok": True, "rolled_back": False,
                                                                         "release": "abc", "detail": "deployed"})],
               [ServiceError("down"), up]).install(f)
    res = f.deploy("abc")
    assert res["ok"] and res["attempts"] == 2
    # it died after finishing the switch: the state says the release is live, nothing is deployed twice
    f = Fleet("http://127.0.0.1:1", "at")
    fl = FlakyFleet([ServiceError("POST /deploy: Server disconnected")],
                    [(200, {"ready": True, "prod": {"active": "green", "release": "abc"}})])
    fl.install(f)
    res = f.deploy("abc")
    assert res["ok"] and "confirmed" in res["detail"] and [c for c in fl.calls if c[1] == "/deploy"] == [("POST", "/deploy")]
    # still adopting the run (409), then fine
    f = Fleet("http://127.0.0.1:1", "at")
    FlakyFleet([(409, {"detail": "no active prod"}), (200, {"ok": True, "rolled_back": False, "detail": "deployed"})],
               [up]).install(f)
    assert f.deploy("abc")["ok"]
    # a real refusal is not retried
    f = Fleet("http://127.0.0.1:1", "at")
    fl = FlakyFleet([(200, {"ok": False, "rolled_back": True, "detail": "prod_5xx grew"})], [up])
    fl.install(f)
    assert f.deploy("abc")["rolled_back"] and len(fl.calls) == 1
    # never coming back is an error, not a silent success
    f = Fleet("http://127.0.0.1:1", "at")
    FlakyFleet([ServiceError("down")], [ServiceError("down")]).install(f)
    f.RESTART_WAIT_S = 0.3
    with pytest.raises(ServiceError):
        f.deploy("abc")


class DownPatcher:
    """The generator is unreachable: it never proposes anything."""
    calls = 0

    @classmethod
    def propose(cls, base_dir, incident, feedback, attempt):
        cls.calls += 1
        return {"diff": "", "source": "fallback", "notes": "fallback (claude: command not found); no fallback"}


def test_generator_outage_is_contained_then_retried_until_it_is_back(env, events):
    DownPatcher.calls = 0
    p = make(env, patcher=DownPatcher)
    p.cfg.retry_cooldown_s = 0.0
    iid = p.enqueue(events["sqli"])
    p.step()
    inc = p.state.incident(iid)
    assert inc["outcome"] == "rule_only" and inc["outcome_detail"] == "transient"
    assert inc["rule"]["id"] in env["gw"].rules                      # contained meanwhile
    first_rule, to_rule = inc["first_rule_posted"], inc["seconds_to_rule"]
    assert p.retry_transient() == [iid] and inc["status"] == "queued" and inc["retries"] == 1
    p.step()
    assert inc["outcome_detail"] == "transient" and inc["retries"] == 1
    p._patcher = stub_patcher                                         # the generator is back
    assert p.retry_transient() == [iid]
    p.step()
    assert inc["outcome"] == "patched", inc["reason"]
    assert inc["first_rule_posted"] == first_rule and inc["seconds_to_rule"] == to_rule   # a retry does not move it
    assert p.retry_transient() == []                                  # patched: left alone


def test_retries_are_bounded_and_spaced(env, events):
    p = make(env, patcher=DownPatcher)
    iid = p.enqueue(events["sqli"])
    p.step()
    inc = p.state.incident(iid)
    p.cfg.retry_cooldown_s, p.cfg.max_retries = 60.0, 2
    assert p.retry_transient() == []                                  # too soon
    inc["closed_at"] -= 61
    assert p.retry_transient() == [iid]
    p.step()
    inc["closed_at"] -= 61
    assert p.retry_transient() == []                                  # second wait is 4x longer
    inc["closed_at"] -= 200
    assert p.retry_transient() == [iid]
    p.step()
    inc["closed_at"] -= 10 ** 6
    assert p.retry_transient() == [] and inc["retries"] == 2          # gave up; the rule keeps it contained


def test_a_patch_the_gates_reject_is_not_retried(env, events):
    p = make(env, validator=ScriptedValidator(plan=["poc", "poc", "poc"]))
    p.cfg.retry_cooldown_s = 0.0
    iid = p.enqueue(events["sqli"])
    p.step()
    inc = p.state.incident(iid)
    assert inc["outcome"] == "rule_only" and inc.get("outcome_detail") != "transient"
    assert p.retry_transient() == []


def test_rule_of_an_unpatched_incident_is_renewed_and_restored(env, events):
    p = make(env, validator=ScriptedValidator(plan=["poc", "poc", "poc"]))
    iid = p.enqueue(events["sqli"])
    p.step()
    inc = p.state.incident(iid)
    rid = inc["rule"]["id"]
    env["gw"].rules[rid]["expires_in"] = 3000.0                       # plenty left: untouched
    assert p.keep_rules() == 0
    env["gw"].rules[rid]["expires_in"] = 30.0                         # about to expire
    assert p.keep_rules() == 1 and "expires_in" not in env["gw"].rules[rid]
    del env["gw"].rules[rid]                                          # the gateway lost it
    assert p.keep_rules() == 1 and rid in env["gw"].rules
    # a patched incident's rule is never put back
    q = make(env)
    other = q.enqueue(events["traversal"])
    q.step()
    assert q.state.incident(other)["outcome"] == "patched"
    n = len(env["gw"].rules)
    assert q.keep_rules() <= 1 and len(env["gw"].rules) == n and q.state.incident(other)["rule"]["id"] not in env["gw"].rules


@pytest.mark.parametrize("verdicts,outcome,detail", [
    (["oracle", "clean", "oracle"], "rule_only", "escalated"),      # non-deterministic: contained, a person decides
    (["clean", "clean", "clean"], "rule_only", "escalated"),        # it did fire once on the live request
    (["oracle", "oracle", "oracle"], "rule_only", None),            # reliable PoC: goes on (no patch target here)
])
def test_external_replay_below_3_of_3_keeps_the_rule_and_escalates(env, events, verdicts, outcome, detail):
    from pipeline.external import ExternalPipeline
    cfg = env["cfg"]
    p = ExternalPipeline(cfg, State(os.path.join(cfg.state_dir, "state.json")),
                         Publisher(cfg.bus_url, cfg.bus_token, cfg.run_id), GatewayAdmin(cfg.gateway_admin_url, "at"),
                         Fleet(cfg.fleet_url, "at"), None, validator=ScriptedValidator(), patcher=stub_patcher,
                         repro_url="http://sidecar:1")
    p.audit_settings = lambda: (False, 40, 120)
    it = iter(verdicts)
    p.replay = lambda req, tag: next(it)
    a = p.enqueue(events["traversal"])
    p.step()
    inc = p.state.incident(a)
    assert (inc["outcome"], inc["outcome_detail"]) == (outcome, detail), inc["reason"]
    assert len(env["gw"].rules) == 1
    if detail:
        assert "%d/3" % verdicts.count("oracle") in inc["reason"] and "needs a person" in inc["reason"]
