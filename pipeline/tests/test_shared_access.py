"""Group-shared access in the properties gate, partial-coverage scenarios in the legit gate, and the
fresh-registration identity of the verification step (auth.kind introspect). No containers."""
import json
import types

import httpx
import pytest

from pipeline import gates, properties, verify

MAN = {"seed_max_uid": 30, "admin": {"id": 1}, "legit_users": [{"id": 3}, {"id": 4}, {"id": 6}],
       "groups": {"teams": {"1": [1, 3, 5], "2": [4, 6], "3": [7]}}, "group_routes": {"team_id": "teams"}}
INC = {"vuln_class": "idor", "method": "GET", "route": "/teams/{team_id}/members", "param": {"in": "path", "name": "team_id"},
       "request": {"method": "GET", "path": "/teams/2/members", "query": "", "headers": {}}}
POC = {"requests": [dict(INC["request"], uid=99, role="user")]}


class FakeV:
    """v.run on a harness job: the response is decided by app(release, gid, uid, role)."""
    def __init__(self, app):
        self.app, self.cache, self.jobs = app, {}, []

    def manifest(self, base_dir):
        return MAN

    def run(self, release, job):
        self.jobs.append((release, job))
        out = []
        for s in job["sequences"]:
            rq = s["requests"][-1]
            gid = rq["path"].split("/")[2]
            st, owners, verdict = self.app(release, gid, rq.get("uid"), rq.get("role"))
            out.append({"name": s["name"], "runs": [[{"status": st, "verdict": verdict, "events": [],
                                                       "marker_owners": owners, "sha": "%s-%s" % (st, owners)}]]})
        return {"sequences": out, "manifest": MAN}


def members(gid):
    return MAN["groups"]["teams"].get(gid, [])


def unpatched(release, gid, uid, role):
    if uid is None:
        return 401, [], "inconclusive"
    ms = members(gid)
    foreign = [m for m in ms if m != uid]
    leak = role != "admin" and uid not in ms and bool(foreign)
    return 200, ms, ("oracle" if leak else "clean")


def good_fix(release, gid, uid, role):
    if release == "base":
        return unpatched(release, gid, uid, role)
    if uid is not None and role != "admin" and uid not in members(gid):
        return 404, [], "inconclusive"
    return unpatched(release, gid, uid, role)


def test_members_scoped_matrix_accepts_the_membership_check():
    ok, detail = properties.check(FakeV(good_fix), INC, POC, "base", "patched")
    assert ok, detail
    assert "members-scoped matrix" in detail and "non-member" in detail


@pytest.mark.parametrize("fix,want", [
    (unpatched, "want 403/404"),                                                       # no fix at all
    (lambda r, g, u, ro: (404, [], "inconclusive") if (r != "base" and u is not None and ro != "admin")
     else unpatched(r, g, u, ro), "instead of 2xx"),                                  # deny everyone
    (lambda r, g, u, ro: (200, [u], "clean") if (r != "base" and u is not None and ro != "admin" and u in members(g))
     else good_fix(r, g, u, ro), "same response"),                                    # members see only themselves
    (lambda r, g, u, ro: (403, [], "inconclusive") if (r != "base" and ro == "admin") else good_fix(r, g, u, ro),
     "admin"),                                                                        # admin locked out
])
def test_members_scoped_matrix_rejects_inadequate_fixes(fix, want):
    ok, detail = properties.check(FakeV(fix), INC, POC, "base", "patched")
    assert not ok and want in detail, detail


def test_one_owner_routes_unchanged_without_groups():
    v = FakeV(good_fix)
    v.manifest = lambda base: {k: v_ for k, v_ in MAN.items() if k not in ("groups", "group_routes")}
    ok, detail = properties.check(v, INC, POC, "base", "patched")
    assert not ok and "fewer than 2 resources with an identifiable owner" in detail


# ------------------------------------------------------------------ legit gate with generated (partial) scenarios
def _validator(before, after):
    v = gates.Validator.__new__(gates.Validator)
    v.cfg = types.SimpleNamespace(scenarios_module="scenarios")
    v.cache, v.caps = {}, []
    v.base_scenarios = lambda base: before
    v.scenarios = lambda rel: after
    return v


def test_partial_scenarios_without_coverage_cap_instead_of_reject():
    res = {"note": "", "partial": True, "scenarios": [{"name": "s", "steps": [
        {"step": "x", "method": "GET", "path": "/notes", "status": 200, "body": []}]}]}
    ctx = {"inc": {"method": "POST", "route": "/notes"}, "base_dir": "b", "patched_dir": "p"}
    out = _validator(res, res).gate_legit(ctx)
    assert out[0] is False and out[2] is True and "no coverage" in out[1]
    assert ctx["caps"] == ["legit: no coverage of POST /notes"]
    full = dict(res, partial=False)
    out = _validator(full, full).gate_legit({"inc": {"method": "POST", "route": "/notes"}, "base_dir": "b", "patched_dir": "p"})
    assert out[0] is False and len(out) == 2 and "not deployable" in out[1]
    ctx = {"inc": {"method": "GET", "route": "/notes"}, "base_dir": "b", "patched_dir": "p"}
    assert _validator(res, res).gate_legit(ctx)[0] is True and "caps" not in ctx


# ------------------------------------------------------------------ verification identity for auth.kind introspect
SPEC = {"paths": {
    "/auth/register": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/R"}}}}}},
    "/auth/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/L"}}}}}},
    "/auth/me": {"get": {}}},
    "components": {"schemas": {
        "R": {"type": "object", "required": ["email", "name", "password"],
              "properties": {"email": {"type": "string"}, "name": {"type": "string"}, "password": {"type": "string"}}},
        "L": {"type": "object", "required": ["email", "password"],
              "properties": {"email": {"type": "string"}, "password": {"type": "string"}}}}}}


def _cfg(tmp_path):
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps(SPEC))
    auth = types.SimpleNamespace(kind="introspect", path="/auth/me", uid_field="id")
    return types.SimpleNamespace(openapi_path=str(p), gateway_url="http://gw.test", http_timeout_s=1,
                                 project=types.SimpleNamespace(auth=auth), prod_app_secret="")


def test_register_fresh_through_the_apps_own_routes(tmp_path, monkeypatch):
    seen, accounts = [], {}

    def handler(req):
        seen.append((req.method, req.url.path))
        if req.url.path == "/auth/register":
            b = json.loads(req.content)
            accounts[b["email"]] = (b["password"], 41)
            return httpx.Response(201, json={"id": 41, "email": b["email"]})
        if req.url.path == "/auth/login":
            b = json.loads(req.content)
            if accounts.get(b["email"], (None,))[0] != b["password"]:
                return httpx.Response(401, json={})
            return httpx.Response(200, json={"token": "tok41", "token_type": "bearer"})
        if req.url.path == "/auth/me":
            ok = req.headers.get("authorization") == "Bearer tok41"
            return httpx.Response(200 if ok else 401, json={"id": 41} if ok else {})
        return httpx.Response(404)
    real = httpx.Client
    monkeypatch.setattr(verify.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    cfg = _cfg(tmp_path)
    hdr, session, why = verify._identity(cfg, {"uid": 26, "role": "user"}, {"seed_max_uid": 25})
    assert why == "" and hdr == "Bearer tok41" and session == "uid:41"
    assert seen == [("POST", "/auth/register"), ("POST", "/auth/login"), ("GET", "/auth/me")]
    # a trusted attacker (seeded uid) cannot be reproduced by registering
    assert "trusted" in verify._identity(cfg, {"uid": 3, "role": "user"}, {"seed_max_uid": 25})[2]


def test_register_fresh_without_register_route(tmp_path):
    cfg = _cfg(tmp_path)
    (tmp_path / "openapi.json").write_text(json.dumps({"paths": {"/auth/me": {"get": {}}}}))
    assert "no register route" in verify._identity(cfg, {"uid": 26}, {"seed_max_uid": 25})[2]
