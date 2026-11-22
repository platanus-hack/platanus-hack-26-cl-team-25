"""Generated legit journeys (.immune/scenarios.py): plan derivation and the deterministic runtime."""
import importlib
import json
import sys
import types

from immune import legit
from immune.initsteps import scenarios as scen

DOC = {"paths": {
    "/health": {"get": {}},
    "/notes": {"get": {"parameters": [
        {"name": "q", "in": "query", "schema": {"anyOf": [{"type": "string"}, {"type": "null"}]}},
        {"name": "sort", "in": "query", "schema": {"type": "string", "pattern": "^(created|title)$"}},
        {"name": "authorization", "in": "header", "schema": {"type": "string"}}]},
        "post": {}},
    "/notes/{note_id}": {"get": {"parameters": [{"name": "note_id", "in": "path", "required": True}]}},
    "/teams/{team_id}/members": {"get": {"parameters": [{"name": "team_id", "in": "path", "required": True}]}},
    "/templates/download": {"get": {"parameters": [{"name": "name", "in": "query", "required": True,
                                                    "schema": {"type": "string"}}]}},
    "/search": {"get": {"parameters": [{"name": "term", "in": "query", "required": True, "schema": {"type": "string"}}]}},
    "/things/{thing_id}": {"get": {}},
}}
COLS = {"users_table": "users", "user_id_column": "id",
        "tables": {"users": {"owner": "id"}, "notes": {"owner": "owner_id"},
                   "teams": {"public": True, "shared_via": {"table": "memberships", "member": "user_id", "group": "team_id"}},
                   "things": {"public": True}},
        "routes": {"note_id": {"table": "notes", "column": "id"},
                   "team_id": {"table": "teams", "column": "id", "access": "members"},
                   "thing_id": {"table": "things", "column": "id"}}}


def test_plan_covers_get_routes_with_legitimate_values():
    plan = scen.build_plan(DOC, COLS, "profile")
    ops = {o["path"]: o for o in plan["ops"]}
    assert set(ops) == {"/health", "/notes", "/notes/{note_id}", "/teams/{team_id}/members", "/templates/download"}
    assert ops["/notes/{note_id}"]["path_params"] == {"note_id": {"own": "notes"}}
    assert ops["/teams/{team_id}/members"]["path_params"] == {"team_id": {"group": "teams"}}
    q = {x["name"]: x for x in ops["/notes"]["query"]}
    assert q["sort"]["values"] == ["created", "title"] and not any(set("'\";-/%") & set(v) for v in q["q"]["values"])
    assert ops["/templates/download"]["query"] == [{"name": "name", "required": True, "values": "files"}]
    assert ops["/health"]["admin"] is True and ops["/notes/{note_id}"]["admin"] is False
    unc = {u["op"]: u["why"] for u in plan["uncovered"]}
    assert set(unc) == {"GET /search", "GET /things/{thing_id}"}
    src = scen.render(plan, "demo")
    compile(src, "scenarios.py", "exec")
    assert "PARTIAL_COVERAGE = True" in src


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._b = status, body
        self.headers = {"content-type": "application/json"}
        self.content = json.dumps(body).encode()
        self.text = self.content.decode()

    def json(self):
        return self._b


def test_runtime_reads_only_own_resources(monkeypatch, tmp_path):
    root = tmp_path / "files"
    root.mkdir()
    (root / "plan.v1.2.txt").write_text("x")
    (root / "a.txt").write_text("y")
    prof = types.ModuleType("p5_fake_profile")
    prof.mint_token = lambda env, uid, role: "tok-%d" % uid
    prof.allowed_file_roots = lambda env: [str(root)]
    monkeypatch.setitem(sys.modules, "p5_fake_profile", prof)
    plan = scen.build_plan(DOC, COLS, "p5_fake_profile")
    manifest = {"legit_users": [{"id": 3, "role": "member"}, {"id": 4, "role": "member"}], "admin": {"id": 1, "role": "admin"},
                "ownership": {"notes": {"10": 3, "11": 4, "12": 9, "13": 3}},
                "groups": {"teams": {"1": [3, 9], "2": [4]}}}
    calls = []

    class Client:
        def request(self, method, url, headers=None):
            calls.append((method, url, headers["authorization"]))
            return _Resp(200, {"url": url})
    runs = []
    for _ in range(2):
        calls.clear()
        runs.append([fn(Client(), manifest) for fn in legit.scenarios_from(plan)])
    assert runs[0] == runs[1]                                   # deterministic
    urls = {(u, a) for _m, u, a in calls}
    assert ("/notes/10", "Bearer tok-3") in urls and ("/notes/11", "Bearer tok-4") in urls
    assert not any(u.startswith("/notes/12") for u, _a in urls)          # never someone else's note
    assert ("/teams/1/members", "Bearer tok-3") in urls and ("/teams/2/members", "Bearer tok-4") in urls
    assert not any(u == "/teams/2/members" and a == "Bearer tok-3" for u, a in urls)
    assert ("/templates/download?name=plan.v1.2.txt", "Bearer tok-3") in urls
    assert ("/health", "Bearer tok-1") in urls                           # admin on parameter-free routes
    assert all(m == "GET" for m, _u, _a in calls)
