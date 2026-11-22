"""Class self-audit (pipeline/audit.py + orchestrator wiring) and the technique corpus, with fakes only."""
from __future__ import annotations

import json
import os
import threading
import time

import pytest

from pipeline import audit, openapi, properties, reqs
from pipeline.bus import AUDIT_DONE, AUDIT_FINDING, AUDIT_STARTED
from pipeline.corpus import Corpus

from .test_orchestrator import ScriptedValidator, make

MANIFEST = {"seed_max_uid": 60, "legit_users": [{"id": 2, "role": "user"}, {"id": 3, "role": "user"}],
            "admin": {"id": 1}, "canaries": {"order_id": [12, 31], "user_id": [7, 19]},
            "ownership": {"orders": {"1": 2, "2": 3, "12": 7, "31": 19}}}


def labels(cands):
    return [c.label for c in cands]


# ------------------------------------------------------------------ candidate selection
def test_candidates_string_classes_skip_enum_and_integer(spec):
    for cls in ("sqli", "traversal"):
        got = labels(audit.candidates(spec, cls, MANIFEST))
        assert "GET /api/products query:q" in got
        assert "POST /api/login json:email" in got
        assert "GET /api/files/download query:name" in got
        assert "GET /api/products/{product_id}/image query:file" in got
        assert "POST /api/orders json:note" in got
        for skipped in ("query:category", "query:sort", "query:page", "path:product_id", "path:order_id",
                        "json:items[0].qty", "json:items[0].product_id"):
            assert not any(skipped in g for g in got), (cls, skipped, got)


def test_candidates_idor_are_identifiers(spec):
    got = labels(audit.candidates(spec, "idor", MANIFEST))
    assert got == ["GET /api/products/{product_id} path:product_id",
                   "GET /api/products/{product_id}/image path:product_id",
                   "GET /api/orders/{order_id} path:order_id",
                   "GET /api/orders/{order_id}/invoice path:order_id",
                   "GET /api/users/{user_id}/profile path:user_id"]
    assert audit.candidates(spec, "other", MANIFEST) == []


def test_probe_requests_identity_and_base_values(spec):
    by = {c.label: c for c in audit.candidates(spec, "sqli", MANIFEST)}
    login = by["POST /api/login json:email"]
    rq = audit.probe_request(login, "x' --", *audit.identity("sqli", login, MANIFEST))
    body = json.loads(reqs.body_of(rq))
    assert body["email"] == "x' --" and "password" in body and rq["uid"] is None
    note = by["POST /api/orders json:note"]
    assert note.secured and audit.identity("sqli", note, MANIFEST) == (2, "user")   # legitimate seed identity
    body = json.loads(reqs.body_of(audit.probe_request(note, "v", 2, "user")))
    assert body == {"items": [{"product_id": 1, "qty": 1}], "note": "v"}
    img = by["GET /api/products/{product_id}/image query:file"]
    rq = audit.probe_request(img, "../x", None, None)
    assert rq["path"] == "/api/products/1/image" and reqs.get_value(rq, img.param, img.route) == "../x"
    prof = {c.label: c for c in audit.candidates(spec, "idor", MANIFEST)}["GET /api/users/{user_id}/profile path:user_id"]
    assert audit.identity("idor", prof, MANIFEST) == (1060, "user")                  # a new user owning nothing
    assert audit.probe_request(prof, "7", 1060, "user")["path"] == "/api/users/7/profile"


def test_battery_is_the_properties_inputs_plus_corpus(spec):
    c = {x.label: x for x in audit.candidates(spec, "sqli", MANIFEST)}["GET /api/products query:q"]
    b = audit.battery("sqli", c, MANIFEST, ["zz' OR 1=1 --", properties.SQL_META[0]])
    assert b[:len(properties.SQL_META)] == properties.SQL_META and b[-1] == "zz' OR 1=1 --"
    assert len(b) == len(properties.SQL_META) + 1                                     # deduplicated
    t = audit.battery("traversal", c, MANIFEST, [])
    assert t == properties.TRAVERSAL
    d = {x.label: x for x in audit.candidates(spec, "idor", MANIFEST)}["GET /api/orders/{order_id}/invoice path:order_id"]
    ids = audit.battery("idor", d, MANIFEST, ["../etc", "77"])
    assert ids[:2] == ["12", "31"] and "77" in ids and "../etc" not in ids


# ------------------------------------------------------------------ fake judge
class FakeJudge(ScriptedValidator):
    """ScriptedValidator + a harness that fires `fires[(method, route, param name)]` for battery values."""

    def __init__(self, fires=None, delay=0.0, **kw):
        super().__init__(**kw)
        self.fires = dict(fires or {})
        self.delay = delay
        self.jobs = []
        self.lock = threading.Lock()
        self.spec = openapi.load(os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "openapi.yaml"))

    def manifest(self, base_dir):
        return MANIFEST

    def _events(self, rq):
        tpl, _op, pp = openapi.find(self.spec, rq["method"], rq["path"])
        for (m, route, name), kind in self.fires.items():
            if m != rq["method"] or route != tpl:
                continue
            loc = "path" if name in (pp or {}) else ("json" if rq.get("body_b64") else "query")
            param = {"in": loc, "name": name}
            val = str(reqs.get_value(rq, param, tpl))
            if kind == "sql" and val in properties.SQL_META[3:]:
                return [{"oracle": "sql", "detail": {"param": name, "location": loc, "input": val},
                         "stack": [{"file": "victim/app/x.py", "line": 3, "func": "f"}]}]
            if kind == "file" and val in properties.TRAVERSAL:
                return [{"oracle": "file", "detail": {"path": "/srv/static/" + val}, "stack": []}]
            if kind == "owner" and val in ("12", "31", "7", "19"):
                return [{"oracle": "owner", "detail": {"marker_owner": 7, "requester": rq.get("uid")}, "stack": []}]
        return []

    def run(self, release_dir, job, timeout=None):
        if not any(s.get("with_evidence") for s in job.get("sequences") or []):
            return super().run(release_dir, job, timeout)
        with self.lock:
            self.jobs.append(job)
        time.sleep(self.delay)
        out = []
        for s in job["sequences"]:
            rq = s["requests"][-1]
            evs = self._events(rq)
            item = {"status": 200, "verdict": "oracle" if evs else "clean", "events": evs}
            out.append({"name": s["name"], "runs": [[item]]})
        return {"sequences": out, "manifest": MANIFEST}


# ------------------------------------------------------------------ budget
def test_budget_max_jobs_deadline_and_stop(spec):
    cands = audit.candidates(spec, "sqli", MANIFEST)
    assert len(cands) >= 6
    v = FakeJudge()
    r = audit.run(v, "/rel", "sqli", cands, MANIFEST, max_jobs=3, max_seconds=60)
    assert r.jobs == 3 == len(v.jobs) == len(r.checked)
    assert len(r.skipped) == len(cands) - 3 and all("max_jobs" in w for _c, w in r.skipped)
    slow = FakeJudge(delay=0.4)
    r = audit.run(slow, "/rel", "sqli", cands, MANIFEST, max_jobs=40, max_seconds=0.5, parallel=1)
    assert 1 <= r.jobs <= 2 and r.jobs + len(r.skipped) == len(cands)
    assert any("max_seconds" in w for _c, w in r.skipped)
    r = audit.run(FakeJudge(), "/rel", "sqli", cands, MANIFEST, stop=lambda: True)
    assert r.jobs == 0 and len(r.skipped) == len(cands) and all(w == "paused" for _c, w in r.skipped)


def test_run_reports_only_the_class_oracle(spec):
    cands = audit.candidates(spec, "sqli", MANIFEST)
    v = FakeJudge({("POST", "/api/login", "email"): "sql", ("GET", "/api/files/download", "name"): "file"})
    r = audit.run(v, "/rel", "sqli", cands, MANIFEST)
    assert [f.candidate.label for f in r.findings] == ["POST /api/login json:email"]
    f = r.findings[0]
    assert f.evidence["events"][0]["oracle"] == "sql" and f.evidence["request"]["path"] == "/api/login"
    assert len(v.jobs) == len(cands)                                   # one judge job per candidate


# ------------------------------------------------------------------ orchestrator: dedupe, loop prevention, events
def _audit_events(env_):
    return [e for e in env_["bus"].events if e["type"].startswith("audit.")]


def test_audit_after_patch_opens_audit_incidents(env, events):
    v = FakeJudge({("POST", "/api/login", "email"): "sql", ("GET", "/api/products", "q"): "sql"})
    p = make(env, validator=v, audit=True)
    a = p.enqueue(events["sqli"])                    # live: GET /api/products q
    assert p.step() == a and p.state.incident(a)["outcome"] == "patched"
    assert p.state.data["audit_pending"] == [a]
    assert p.step() == a                             # the audit runs before the next incident
    evs = _audit_events(env)
    assert [e["type"] for e in evs] == [AUDIT_STARTED, AUDIT_FINDING, AUDIT_DONE]
    started, finding, done = (e["data"] for e in evs)
    assert started["incident"] == a and started["vuln_class"] == "sqli"
    assert started["candidates"] == len(audit.candidates(p.spec, "sqli", MANIFEST)) - 1   # own route excluded
    new = finding["incident"]
    assert finding["parent"] == a and finding["route"] == "/api/login" and finding["param"] == {"in": "json", "name": "email"}
    assert done["findings"] == 1 and done["checked"] == started["candidates"]
    inc = p.state.incident(new)
    assert inc["origin"] == "audit" and inc["parent"] == a and p.state.data["queue"] == [new]
    # the audit incident goes through the normal flow, its incident.opened says where it came from
    assert p.step() == new and p.state.incident(new)["status"] == "closed"
    # the stub's sqli fix already patched auth.py together with products.py: it has nothing left to propose
    # for the login route, so the audit incident stays contained by its rule and is marked for a retry
    closed = p.state.incident(new)
    assert (closed["outcome"], closed["outcome_detail"]) == ("rule_only", "transient"), closed["reason"]
    assert closed["rule"]["id"] in env["gw"].rules
    opened = [e["data"] for e in env["bus"].events if e["type"] == "incident.opened"]
    assert opened[0]["origin"] == "live" and "parent" not in opened[0]
    assert opened[1]["origin"] == "audit" and opened[1]["parent"] == a
    # its closure re-audits only what no earlier sqli audit judged: nothing left -> no new audit events
    n = len(_audit_events(env))
    assert p.step() == new
    assert len(_audit_events(env)) == n
    last = p.state.incident(new)["log"][-1]
    assert "no sqli candidate left" in last or "already audited on release" in last, last
    assert p.state.data["queue"] == []


def test_audit_dedupes_against_known_incidents(env, events):
    v = FakeJudge({("GET", "/api/orders/{order_id}/invoice", "order_id"): "owner",
                   ("GET", "/api/users/{user_id}/profile", "user_id"): "owner"})
    p = make(env, validator=v, audit=True)
    a = p.enqueue(events["idor"])                    # live: GET /api/orders/{order_id}
    # a live incident on the profile route is already known (queued): the audit must not duplicate it
    prof = json.loads(json.dumps(events["idor"]))
    prof["data"]["request"]["path"] = "/api/users/7/profile"
    b = p.enqueue(prof)
    assert b is not None
    assert p.step() == a
    assert p.step() == a                             # audit
    finds = [e["data"] for e in _audit_events(env) if e["type"] == AUDIT_FINDING]
    assert [f["route"] for f in finds] == ["/api/orders/{order_id}/invoice"]
    started = [e["data"] for e in _audit_events(env) if e["type"] == AUDIT_STARTED][0]
    assert started["candidates"] == 3                # 5 identifier candidates - own route - the known profile incident
    keys = [i["key"] for i in p.state.data["incidents"].values()]
    assert len(keys) == len(set(keys)) == 3


def test_one_audit_per_class_per_release_and_pause(env, events):
    v = FakeJudge({})
    p = make(env, validator=v, audit=True)
    a = p.enqueue(events["sqli"])
    p.step()
    rel = p.current_release()
    open(env["cfg"].pause_file, "w").close()
    assert p.step() is None and p.state.data["audit_pending"] == [a]      # PAUSE: the audit waits
    os.remove(env["cfg"].pause_file)
    p.step()
    assert p.state.data["audits"]["sqli"]["releases"][rel]["by"] == a
    jobs = len(v.jobs)
    # a second sqli incident closing on the same release does not audit again
    p.state.data["audit_pending"].append(a)
    p.step()
    assert len(v.jobs) == jobs and "already audited on release" in p.state.incident(a)["log"][-1]


def test_audit_disabled_or_not_reproducible_does_not_schedule(env, events):
    p = make(env, validator=FakeJudge(reproducible=False), audit=True)
    a = p.enqueue(events["sqli"])
    p.step()
    assert p.state.incident(a)["outcome"] == "not_reproducible" and not p.state.data.get("audit_pending")
    p2 = make(env, validator=FakeJudge(), audit=False)
    b = p2.enqueue(events["traversal"])
    p2.step()
    assert p2.state.incident(b)["outcome"] == "patched" and not p2.state.data.get("audit_pending")


# ------------------------------------------------------------------ corpus
def test_corpus_dedupe_bound_and_values_only(tmp_path):
    c = Corpus(str(tmp_path / "corpus"), limit=5)
    assert c.add("sqli", ["a'--", "a'--", None, {"x": 1}, "b'--"], "inc-1", "GET /r", "query:q") == 2
    assert c.add("sqli", ["a'--"], "inc-2") == 0
    for i in range(10):
        c.add("sqli", ["v%d" % i], "inc-3")
    rows = c.load("sqli")
    assert len(rows) == 5 and [r["value"] for r in rows] == ["v5", "v6", "v7", "v8", "v9"]
    assert set(rows[0]) == {"value", "incident", "route", "param", "ts"}
    assert c.values("sqli", limit=2) == ["v9", "v8"]
    assert c.add("idor", [12, 12, 31]) == 2 and c.values("idor") == ["31", "12"]
    with pytest.raises(ValueError):
        c.path("../x")
    assert Corpus(str(tmp_path / "corpus")).limit == 500


def test_corpus_filled_by_the_flow_and_used_by_reproduce(env, events):
    seen = {}

    class V(FakeJudge):
        def reproduce(self, inc, p, base_dir, extra=None, corpus=None):
            seen[inc["incident"]] = corpus
            r = super().reproduce(inc, p, base_dir, extra)
            r["counted"] = [{"name": "m0", "request": reqs.set_value(p["requests"][-1], inc["param"], "zz' OR 1=1 --",
                                                                      inc["route"])}]
            return r
    p = make(env, validator=V(), audit=False)
    a = p.enqueue(events["sqli"])
    p.step()
    vals = p.corpus.values("sqli")
    assert "zz' OR 1=1 --" in vals and len(vals) == 2      # the PoC value and the counted variant
    rows = p.corpus.load("sqli")
    assert all(r["incident"] == a and r["param"] == "query:q" for r in rows)
    assert all(set(r) == {"value", "incident", "route", "param", "ts"} for r in rows)
    # a second sqli incident (another route) gets the corpus values as extra variants of its own parameter
    other = json.loads(json.dumps(events["sqli"]))
    rq = other["data"]["request"]
    rq.update(method="POST", path="/api/login", query="", headers={"content-type": "application/json"})
    rq["body_b64"] = __import__("base64").b64encode(json.dumps({"email": "x' --", "password": "p"}).encode()).decode()
    for e in other["data"]["events"]:
        if e.get("oracle") == "sql":
            e["detail"].update(param="email", location="json", input="x' --")
    b = p.enqueue(other)
    assert b is not None
    p.step()
    assert seen[a] is None                                  # the corpus was empty for the first one
    got = {val: json.loads(reqs.body_of(r))["email"] for val, r in seen[b]}
    assert got and all(k == v for k, v in got.items()) and "zz' OR 1=1 --" in got


def test_audit_origin_reaudits_only_unaudited_candidates(env):
    p = make(env, validator=FakeJudge(), audit=True)
    all_ = audit.candidates(p.spec, "sqli", MANIFEST)
    p.state.data["audits"] = {"sqli": {"releases": {"r1": {"by": "inc-0001"}},
                                       "audited": [c.key("sqli") for c in all_[:-2]]}}
    live = {"vuln_class": "sqli", "key": "-", "origin": "live"}
    found = {"vuln_class": "sqli", "key": "-", "origin": "audit"}
    c, why = p.audit_candidates(live, "r1", MANIFEST)
    assert c == [] and "already audited on release r1" in why           # one audit per class per release
    c, why = p.audit_candidates(live, "r2", MANIFEST)
    assert not why and labels(c) == labels(all_)                         # a live incident: full audit on a new release
    c, why = p.audit_candidates(found, "r2", MANIFEST)
    assert not why and labels(c) == labels(all_[-2:])                    # an audit incident: only what was never judged
