"""Deploy decisions without Docker: the smoke step, the watch window, the admin token."""
import os

import pytest
from fastapi.testclient import TestClient

import fleet.app
from fleet.app import create_app
from fleet.config import Config, derive_smoke_path
from fleet.manager import Fleet

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Stats:
    """Scripted gateway: counters start at zero on the switch, then report `after`."""
    def __init__(self, after, before=None):
        self.after, self.before, self.switched, self.upstreams = after, before or {}, False, []

    def set_upstream(self, addr, release):
        self.switched = True
        self.upstreams.append((addr, release))

    def stats(self):
        if not self.switched:
            return self.before
        if self.switched is True:                   # the baseline read right after the switch
            self.switched = "polled"
            return {"prod_requests": 0, "prod_5xx": 0}
        return self.after


class NoDocker(Fleet):
    """Fleet._deploy with the container work stubbed out; records every path it probes."""
    def __init__(self, cfg, gw, broken=()):
        super().__init__(cfg, client=object())
        self.gw, self.probed, self.broken = gw, [], set(broken)

    def start_prod(self, color, release):
        return color

    def wait_healthy(self, c, path=None):
        return self.healthy(c, path or self.cfg.health_path)

    def healthy(self, c, path="/health", timeout=6.0):
        self.probed.append(path)
        return path not in self.broken

    def destroy(self, c):
        pass

    def destroy_name(self, name):
        pass

    def _refresh_clones(self, release):
        return 0

    def _prune_releases(self):
        return 0

    def _save(self):
        pass


def deploy(after, tmp_path, before=None, broken=(), **over):
    kw = dict(repo_dir=str(tmp_path), runtime_dir=str(tmp_path), run_id="unit", admin_token="t", smoke_path="/api/items",
              deploy_watch_s=0.05, watch_poll_s=0.01)
    kw.update(over)
    f = NoDocker(Config(**kw), Stats(after, before), broken)
    return f._deploy("r2", "blue", "r1", "green"), f


# ---------------------------------------------------------------- watch window (minimum sample)
def test_one_failed_request_right_after_the_switch_does_not_roll_back(tmp_path):
    res, f = deploy({"prod_requests": 1, "prod_5xx": 1}, tmp_path)
    assert res["ok"] and not res["rolled_back"] and f.gw.upstreams == [("prod-green:8000", "r2")]
    assert res["traffic_validated"] is False and "not validated by traffic" in res["detail"]
    assert res["watch"] == {"seconds": 0.05, "requests": 1, "prod_5xx": 1, "min_requests": 20}


def test_no_traffic_in_the_watch_window_is_reported_as_not_validated(tmp_path):
    res, _ = deploy({"prod_requests": 0, "prod_5xx": 0}, tmp_path)
    assert res["ok"] and res["traffic_validated"] is False and res["watch"]["requests"] == 0
    assert "not validated by traffic (0 request(s)" in res["detail"]


def test_enough_clean_traffic_validates_the_deploy(tmp_path):
    res, _ = deploy({"prod_requests": 40, "prod_5xx": 0}, tmp_path)
    assert res["ok"] and res["traffic_validated"] is True and res["detail"] == "deployed"


def test_a_5xx_rate_over_the_minimum_sample_rolls_back(tmp_path):
    res, f = deploy({"prod_requests": 20, "prod_5xx": 4}, tmp_path)
    assert not res["ok"] and res["rolled_back"] and res["release"] == "r1"
    assert f.gw.upstreams == [("prod-green:8000", "r2"), ("prod-blue:8000", "r1")]
    assert res["watch"]["requests"] == 20 and res["watch"]["prod_5xx"] == 4


def test_the_minimum_sample_is_configurable(tmp_path):
    res, _ = deploy({"prod_requests": 3, "prod_5xx": 3}, tmp_path, deploy_min_requests=3)
    assert res["rolled_back"]


# ---------------------------------------------------------------- smoke step
def test_smoke_is_a_second_distinct_request(tmp_path):
    res, f = deploy({"prod_requests": 40, "prod_5xx": 0}, tmp_path)
    assert f.probed == ["/health", "/api/items"] and res["smoke"] == "GET /api/items ok"


def test_failing_smoke_request_stops_the_deploy_before_the_switch(tmp_path):
    res, f = deploy({}, tmp_path, broken={"/api/items"})
    assert not res["ok"] and not res["rolled_back"] and res["detail"] == "smoke request /api/items failed"
    assert f.gw.upstreams == []


@pytest.mark.parametrize("smoke", ["", "/health"])
def test_smoke_is_skipped_and_reported_when_it_would_repeat_the_health_check(tmp_path, smoke):
    res, f = deploy({"prod_requests": 40, "prod_5xx": 0}, tmp_path, smoke_path=smoke)
    assert res["ok"] and f.probed == ["/health"]            # the health path is not asked twice
    assert res["smoke"].startswith("skipped: no request distinct from the health check /health")


def test_derive_smoke_path_picks_a_public_parameterless_get(tmp_path):
    spec = tmp_path / "openapi.yaml"
    spec.write_text("""
paths:
  /health: {get: {responses: {"200": {description: ok}}}}
  /api/login: {post: {responses: {"200": {description: ok}}}}
  /api/me: {get: {security: [{bearer: []}], responses: {"200": {description: ok}}}}
  /api/items/{id}: {get: {responses: {"200": {description: ok}}}}
  /api/file: {get: {parameters: [{name: name, in: query, required: true}], responses: {"200": {description: ok}}}}
  /api/items: {get: {parameters: [{name: q, in: query}], responses: {"200": {description: ok}}}}
""")
    assert derive_smoke_path(str(spec), "/health") == "/api/items"
    spec.write_text("security: [{bearer: []}]\npaths:\n  /health: {get: {}}\n  /api/items: {get: {}}\n"
                    "  /open: {get: {security: []}}\n")
    assert derive_smoke_path(str(spec), "/health") == "/open"          # global security, opted out per operation
    spec.write_text("paths:\n  /health: {get: {}}\n  /api/me: {get: {security: [{bearer: []}]}}\n")
    assert derive_smoke_path(str(spec), "/health") == ""               # nothing distinct: the deploy says "skipped"
    assert derive_smoke_path(str(tmp_path / "missing.yaml"), "/health") == ""


def test_shipped_specs_give_the_demo_a_real_smoke_request():
    assert derive_smoke_path(os.path.join(ROOT, "contracts", "openapi.yaml"), "/health") == "/api/products"
    # every other route of the Node example needs a session: its deploys report the smoke step as skipped
    assert derive_smoke_path(os.path.join(ROOT, "examples", "tareas-node", ".immune", "openapi.yaml"), "/health") == ""


# ---------------------------------------------------------------- admin token
@pytest.fixture()
def demo_project(monkeypatch):
    from immune import config as icfg
    monkeypatch.setenv("IMMUNE_PROJECT", ROOT)
    for k in ("SMOKE_PATH", "DEPLOY_MIN_REQUESTS"):
        monkeypatch.delenv(k, raising=False)
    icfg.reset_cache()
    yield
    icfg.reset_cache()


def test_fleet_refuses_to_start_without_an_explicit_admin_token(demo_project, monkeypatch):
    monkeypatch.delenv("ADMIN_TOKEN", raising=False)        # deploy/demo.env has one: it must not be picked up
    with pytest.raises(RuntimeError, match="ADMIN_TOKEN is not set"):
        Config.from_env()
    monkeypatch.setenv("ADMIN_TOKEN", "")
    with pytest.raises(RuntimeError, match="ADMIN_TOKEN is not set"):
        Config.from_env()


def test_from_env_takes_the_token_from_the_environment_and_a_distinct_smoke_path(demo_project, monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "explicit-token")
    cfg = Config.from_env()
    assert cfg.admin_token == "explicit-token"
    assert cfg.smoke_path == "/api/products" != cfg.health_path and cfg.deploy_min_requests == 20
    monkeypatch.setenv("SMOKE_PATH", "/x")
    assert Config.from_env().smoke_path == "/x"


def test_api_checks_the_token_in_constant_time(tmp_path, monkeypatch):
    calls = []
    real = fleet.app.hmac.compare_digest
    monkeypatch.setattr(fleet.app.hmac, "compare_digest", lambda a, b: calls.append((a, b)) or real(a, b))

    class Idle:
        def loop(self): pass
        def stop(self): pass
        def state(self): return {"ok": True}

    cfg = Config(repo_dir=str(tmp_path), runtime_dir=str(tmp_path), run_id="unit", admin_token="s3cret")
    with TestClient(create_app(cfg, Idle())) as cl:
        assert cl.get("/state").status_code == 401
        assert cl.get("/state", headers={"x-admin-token": "wrong"}).status_code == 401
        assert cl.get("/state", headers={"x-admin-token": "s3cret"}).json() == {"ok": True}
    assert calls == [(b"", b"s3cret"), (b"wrong", b"s3cret"), (b"s3cret", b"s3cret")]
    cfg.admin_token = ""
    with TestClient(create_app(cfg, Idle())) as cl:          # no token configured: nothing is authorised
        assert cl.get("/state", headers={"x-admin-token": ""}).status_code == 401
