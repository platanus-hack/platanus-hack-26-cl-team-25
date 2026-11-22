"""immune.config (the .immune/config.yaml loader) and how the pipeline uses it: edit area,
release copies, skipped tests gate, autopatch caps and recording replay (contracts/product.md §2, §3)."""
import json
import os
import shutil
import textwrap

import pytest
import yaml

from immune import config as icfg

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

MIN = """
version: 1
name: shop
app:
  release_paths: [src]
  source_dirs: [src/app]
  asgi: src.app.main:app
data:
  prod_db: data/prod.db
openapi: openapi.yaml
shadow:
  profile: profile
"""


def project(tmp_path, text=MIN, files=("src/app/main.py", "openapi.yaml")):
    for f in files:
        p = tmp_path / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")
    (tmp_path / ".immune").mkdir(exist_ok=True)
    (tmp_path / ".immune" / "config.yaml").write_text(textwrap.dedent(text))
    return str(tmp_path)


def errors(tmp_path, text, **kw):
    with pytest.raises(icfg.ConfigError) as e:
        icfg.load(project(tmp_path, text, **kw))
    return str(e.value)


# ------------------------------------------------------------------ loader
def test_root_demo_config():
    c = icfg.load(ROOT)
    assert c.name == "tienda" and c.app.release_paths == ["victim"] and c.app.source_dirs == ["victim/app"]
    assert c.runtime_dir == os.path.join(ROOT, "runtime") and c.data.prod_db == os.path.join(ROOT, "runtime", "data", "prod", "app.db")
    assert c.openapi == os.path.join(ROOT, "contracts", "openapi.yaml") and c.auth.kind == "immune-token"
    assert c.scenarios == "sim.scenarios" and c.tests_command.startswith("python -m pytest victim/tests")
    assert c.ports == {"gateway": 8080, "admin": 8081, "dashboard": 8090, "fleet": 8070}
    assert c.prefix == "immune-tienda" and c.network("prodnet") == "immune-tienda_prodnet"
    assert c.app_env(db="/data/app.db", secret="S") == {"APP_DB": "/data/app.db", "APP_STATIC": "/app/victim/static",
                                                        "APP_SECRET": "S"}
    assert c.effective_autopatch() == ("merge", [])
    assert c.release_complete(ROOT) and not c.release_complete(str(ROOT) + "/contracts")


def test_defaults_and_resolution(tmp_path):
    c = icfg.load(project(tmp_path))
    p = os.path.realpath(str(tmp_path))
    assert c.project_dir == p and c.runtime_dir == os.path.join(p, ".immune", "runtime")
    assert c.data.prod_db == os.path.join(p, "data", "prod.db") and c.openapi == os.path.join(p, "openapi.yaml")
    assert (c.mode, c.autopatch, c.pool_size, c.auth.kind, c.repo.target) == ("enforce", "merge", 4, "immune-token", "local")
    assert c.database.path_env == "APP_DB" and c.app.port == 8000 and c.app.health == "/health"
    assert c.app.package == "src" and c.shadow.columns == "" and c.tests_command == "" and c.scenarios == ""
    # no tests.command: autopatch capped at pr
    assert c.effective_autopatch() == ("pr", ["no tests.command: autopatch capped at pr"])
    assert c.app_env(db="/d.db", secret="x") == {"APP_DB": "/d.db"}
    assert c.in_source_dirs("src/app/x.py") and not c.in_source_dirs("src/other.py")
    assert not c.in_source_dirs("src/app/../../etc/passwd")


def test_substitution(tmp_path):
    c = icfg.load(project(tmp_path, MIN + textwrap.dedent("""
        app:
          release_paths: [src]
          source_dirs: [src/app]
          asgi: src.app.main:app
          static: src/static
          env: {DB_FILE: "{db}", STATIC: "{static}", KEY: "k-{secret}", PLAIN: 3}
        database: {path_env: DB_FILE}
        data:
          prod_db: data/prod.db
          seed_command: "python -m src.seed {prod_db} {shadow_db} {manifest} {markers} --seed {seed}"
        """)))
    assert c.app_env(db="/data/a b.db", secret="S", root="/app") == {
        "DB_FILE": "/data/a b.db", "STATIC": "/app/src/static", "KEY": "k-S", "PLAIN": "3"}
    assert c.seed_command_for(prod_db="/x y/p.db", shadow_db="/s.db", manifest="/m.json", markers="/k.json", seed=2) == \
        "python -m src.seed '/x y/p.db' /s.db /m.json /k.json --seed 2"


def test_validation_messages(tmp_path):
    msg = errors(tmp_path, """
        name: Bad_Name
        app:
          runtime: cobol
          release_paths: [../outside, missing]
          source_dirs: [elsewhere]
          asgi: "not an asgi"
          env: {X: "{nope}"}
        auth: {kind: jwt-hs256}
        mode: loud
        autopatch: maybe
        pool_size: 99
        ports: {gateway: 8080, admin: 8080}
        """)
    for want in ["config.yaml is invalid", "name: must be a lower-case slug", "app.runtime: must be one of",
                 "'../outside' must be a relative path", "'missing' does not exist", "openapi: is required",
                 "auth.secret_env: is required for auth.kind jwt-hs256", "mode: must be one of observe|enforce",
                 "autopatch: must be one of off|pr|merge", "pool_size: must be between 0 and 32",
                 "ports: host ports must be distinct", "app.env.X: unknown placeholder(s) {nope}",
                 "data.prod_db: is required"]:
        assert want in msg, (want, msg)
    assert "app.asgi" in errors(tmp_path, MIN.replace("src.app.main:app", "nocolon"))
    assert "is not inside app.release_paths" in errors(tmp_path, MIN.replace("[src/app]", "[lib]"))
    assert "{static} is used but app.static" in errors(
        tmp_path, MIN.replace("  asgi:", "  env: {S: \"{static}\"}\n  asgi:"))
    assert "unknown placeholder(s) {db}" in errors(tmp_path, MIN.replace(
        "  prod_db: data/prod.db", "  prod_db: data/prod.db\n  seed_command: \"seed {db}\""))
    assert "overlaps runtime_dir" in errors(tmp_path, MIN + "runtime_dir: src/rt\n")
    assert "top level must be a mapping" in errors(tmp_path, "- 1\n")
    assert "invalid YAML" in errors(tmp_path, "name: [\n")
    (tmp_path / "empty").mkdir()
    with pytest.raises(icfg.ConfigError, match="config.yaml not found"):
        icfg.load(str(tmp_path / "empty"))
    with pytest.raises(icfg.ConfigError, match="does not exist"):
        icfg.load(str(tmp_path / "nowhere"))


def test_yaml_off_and_set_key(tmp_path):
    p = project(tmp_path, MIN + "autopatch: off   # keep the comment\nmode: observe\n")
    c = icfg.load(p)
    assert c.autopatch == "off" and c.mode == "observe"
    icfg.set_key(p, "autopatch", "pr")
    icfg.set_key(p, "mode", "enforce")
    text = open(os.path.join(p, ".immune", "config.yaml")).read()
    assert "autopatch: pr   # keep the comment" in text and "mode: enforce" in text
    c = icfg.load(p)
    assert (c.autopatch, c.mode) == ("pr", "enforce")
    with pytest.raises(icfg.ConfigError):
        icfg.set_key(p, "mode", "loud")
    assert icfg.load(p).mode == "enforce"           # an invalid value never reaches the file


def test_find_project_and_current(tmp_path, monkeypatch):
    p = project(tmp_path)
    sub = tmp_path / "src" / "app"
    assert icfg.find_project(str(sub)) == os.path.realpath(p)
    monkeypatch.setenv("IMMUNE_PROJECT", p)
    icfg.reset_cache()
    try:
        assert icfg.current().name == "shop"
    finally:
        monkeypatch.delenv("IMMUNE_PROJECT")
        icfg.reset_cache()
    assert icfg.current().name == "tienda"


# ------------------------------------------------------------------ pipeline consumers
def test_policy_edit_area_is_source_dirs(tmp_path):
    from pipeline import diffs, policy
    rel = tmp_path / "rel"
    (rel / "pkg" / "core").mkdir(parents=True)
    (rel / "pkg" / "other").mkdir(parents=True)
    (rel / "pkg" / "core" / "a.py").write_text("def f(x):\n    return x\n")
    (rel / "pkg" / "other" / "b.py").write_text("def g(x):\n    return x\n")
    work = diffs.copy_release(str(rel), str(tmp_path), paths=["pkg"])
    assert sorted(os.listdir(os.path.join(work, "pkg"))) == ["core", "other"]
    ok_diff = diffs.make(str(rel), {"pkg/core/a.py": "def f(x):\n    return int(x)\n"})
    bad_diff = diffs.make(str(rel), {"pkg/other/b.py": "def g(x):\n    return int(x)\n"})
    for d in (ok_diff, bad_diff):
        p = diffs.copy_release(str(rel), str(tmp_path), paths=["pkg"])
        diffs.apply(d, p)
        res = policy.check(d, str(rel), p, dirs=["pkg/core"])
        assert res[0] is (d is ok_diff), res
    assert "only files under pkg/core/ may change" in policy.check(bad_diff, str(rel), p, dirs=["pkg/core"])[1]


def test_patcher_workspace_and_edit_scope(tmp_path):
    from patcher.core import editable_files
    from patcher.workspace import Workspace
    from patcher import claude_cli
    rel = tmp_path / "rel"
    for f in ("pkg/core/a.py", "pkg/tests/test_a.py", "lib.py", "other/x.py"):
        (rel / f).parent.mkdir(parents=True, exist_ok=True)
        (rel / f).write_text("x = 1\n")
    with Workspace(str(rel), paths=["pkg", "lib.py"]) as ws:
        assert sorted(os.listdir(ws.work)) == ["lib.py", "pkg"]
        inc = {"evidence": {"events": [{"stack": [{"file": "lib.py", "line": 1}, {"file": "pkg/core/a.py", "line": 1},
                                                  {"file": "pkg/core/db.py", "line": 1}]}]},
               "sink": {"file": "pkg/core/a.py", "line": 1}}
        assert editable_files(inc, ws.work, ["pkg/core"]) == ["pkg/core/a.py"]
        st = claude_cli.settings_for(ws.work, ["pkg/core/a.py"])
        allow, deny = st["permissions"]["allow"], st["permissions"]["deny"]
        assert [a for a in allow if a.startswith("Edit(")] == \
            ["Edit(/%s/pkg/core/a.py)" % os.path.realpath(ws.work).replace(os.sep, "/")]
        assert "Edit(/%s/pkg/tests/**)" % os.path.realpath(ws.work).replace(os.sep, "/") in deny
        assert [a for a in claude_cli.settings_for(ws.work, [])["permissions"]["allow"] if a.startswith("Edit(")] == []


class _Cfg:
    """Pipeline config stand-in for gate unit tests."""

    def __init__(self, project, record_path="", scenarios_module=""):
        self.project, self.record_path, self.scenarios_module = project, record_path, scenarios_module


class _Runner:
    def __init__(self, fn):
        self.fn, self.jobs = fn, []

    def run(self, release_dir, job, timeout=None):
        self.jobs.append((release_dir, job))
        return self.fn(release_dir, job)


def _inc():
    return {"method": "GET", "route": "/api/items/{item_id}", "param": {"in": "path", "name": "item_id"}}


def test_tests_gate_skipped_without_command(tmp_path):
    from pipeline.gates import Validator
    c = icfg.load(project(tmp_path))
    v = Validator(_Cfg(c), runner=_Runner(lambda r, j: pytest.fail("no runner job without tests.command")))
    ctx = {"patched_dir": str(tmp_path)}
    ok, detail = v.gate_tests(ctx)
    assert ok and detail.startswith("skipped:") and ctx["caps"]


def test_legit_gate_replays_recordings_without_scenarios(tmp_path):
    from pipeline.gates import Validator
    c = icfg.load(project(tmp_path))
    rec = tmp_path / "requests.jsonl"
    rows = [
        {"method": "GET", "path": "/api/items/3", "query": "", "class": "clean", "route": "prod", "status": 200, "uid": 3},
        {"method": "GET", "path": "/api/items/3", "query": "", "class": "clean", "route": "prod", "status": 200, "uid": 3},
        {"method": "POST", "path": "/api/items", "query": "", "class": "clean", "route": "prod", "status": 200},
        {"method": "GET", "path": "/api/items", "query": "q=x", "class": "suspect", "route": "prod", "status": 200},
        {"method": "GET", "path": "/api/other", "query": "", "class": "clean", "route": "prod", "status": 404},
        {"method": "GET", "path": "/api/list", "query": "page=2", "class": "clean", "route": "prod", "status": 200},
    ]
    rec.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    bodies = {"base": {"/api/items/3": {"id": 3}, "/api/list": [1, 2]}}

    def fake(rel, job):
        assert job["kind"] == "replay"
        out = []
        for rq in job["requests"]:
            body = dict(bodies["base"]).get(rq["path"])
            if rel == "patched-bad" and rq["path"] == "/api/list":
                body = []
            out.append({"name": rq["name"], "method": "GET", "path": rq["path"], "status": 200, "body": body})
        return {"results": out}
    v = Validator(_Cfg(c, str(rec)), runner=_Runner(fake))
    reqs_ = v.recorded_requests()
    assert [(r["path"], r["query"], r.get("uid")) for r in reqs_] == [("/api/items/3", "", 3), ("/api/list", "page=2", None)]
    ctx = {"inc": _inc(), "base_dir": "base", "patched_dir": "patched"}
    ok, detail = v.gate_legit(ctx)
    assert ok and "2 recorded request(s) identical" in detail and "GET /api/items/{item_id} (1)" in detail
    ctx = {"inc": _inc(), "base_dir": "base", "patched_dir": "patched-bad"}
    ok, detail = v.gate_legit(ctx)[:2]
    assert not ok and "legit behaviour changed" in detail and "/api/list" in detail
    # no recorded request on the patched route: soft failure that caps autopatch at pr
    ctx = {"inc": dict(_inc(), route="/api/orders/{order_id}"), "base_dir": "base", "patched_dir": "patched"}
    out = v.gate_legit(ctx)
    assert out[0] is False and out[2] is True and out[1].startswith("no coverage") and ctx["caps"]
    # no recording at all
    v2 = Validator(_Cfg(c, str(tmp_path / "none.jsonl")), runner=_Runner(fake))
    ctx = {"inc": _inc(), "base_dir": "base", "patched_dir": "patched"}
    out = v2.gate_legit(ctx)
    assert out[0] is False and out[2] is True and "no coverage" in out[1]


def test_verify_swaps_a_canary_path_value():
    from pipeline.verify import _off_canary
    inc = {"route": "/api/orders/{order_id}", "param": {"in": "path", "name": "order_id"}}
    m = {"canaries": {"order_id": [1, 12]}}
    assert _off_canary(inc, "/api/orders/12", m) == ("/api/orders/2", True)
    assert _off_canary(inc, "/api/orders/5", m) == ("/api/orders/5", False)
    assert _off_canary(dict(inc, param={"in": "query", "name": "q"}), "/api/orders/12", m) == ("/api/orders/12", False)
    assert _off_canary(inc, "/api/orders/12", {}) == ("/api/orders/12", False)


def test_recorded_requests_exclude_what_the_aftercheck_flagged(tmp_path):
    """A request recorded as clean and later found to be an attack by the gateway's after-check is not legit traffic."""
    from pipeline.gates import Validator
    c = icfg.load(project(tmp_path))
    rec = tmp_path / "requests.jsonl"
    clean = {"method": "GET", "class": "clean", "route": "prod", "status": 200}
    rows = [
        dict(clean, path="/api/items", query="q=bad", uid=3),
        dict(clean, path="/api/items", query="q=ok", uid=3),
        {"rid": "r1", "aftercheck": "oracle", "method": "GET", "path": "/api/items", "query": "q=bad", "uid": 3},
        dict(clean, path="/api/items", query="q=bad", uid=3),      # repeated before the session was captured
        dict(clean, path="/api/items", query="q=bad", uid=4),      # another identity: not flagged
    ]
    rec.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    v = Validator(_Cfg(c, str(rec)), runner=_Runner(lambda r, j: pytest.fail("not used")))
    assert [(r["query"], r.get("uid")) for r in v.recorded_requests()] == [("q=ok", 3), ("q=bad", 4)]


def test_audit_block(tmp_path):
    c = icfg.load(project(tmp_path))
    assert (c.audit.enabled, c.audit.max_jobs, c.audit.max_seconds) == (True, 40, 120)   # python-asgi default
    c = icfg.load(project(tmp_path, MIN + "audit: {enabled: false, max_jobs: 5, max_seconds: 30}\n"))
    assert (c.audit.enabled, c.audit.max_jobs, c.audit.max_seconds) == (False, 5, 30)
    msg = errors(tmp_path, MIN + "audit: {enabled: maybe, max_jobs: -1}\n")
    assert "audit.enabled" in msg and "audit.max_jobs" in msg
    assert icfg.load(ROOT).audit.enabled is True
