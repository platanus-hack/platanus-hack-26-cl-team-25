"""Pipeline configuration. Every path, URL and limit comes from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _f(env, k, d):
    try:
        return float(env.get(k, d))
    except (TypeError, ValueError):
        return float(d)


def _i(env, k, d):
    try:
        return int(env.get(k, d))
    except (TypeError, ValueError):
        return int(d)


def _demo_env(repo: str) -> dict:
    """deploy/demo.env values, used only as fallbacks for unset secrets."""
    out = {}
    try:
        with open(os.path.join(repo, "deploy", "demo.env")) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


@dataclass
class Config:
    repo_dir: str = REPO_ROOT
    runtime_dir: str = os.path.join(REPO_ROOT, "runtime")
    state_dir: str = ""                 # <runtime>/pipeline
    run_id: str = "dev"
    bus_url: str = "http://127.0.0.1:8090"
    bus_token: str = ""
    gateway_admin_url: str = "http://127.0.0.1:8081"
    gateway_url: str = "http://127.0.0.1:8080"
    fleet_url: str = "http://127.0.0.1:8070"
    admin_token: str = ""
    prod_app_secret: str = ""
    openapi_path: str = ""
    manifest_path: str = ""
    record_path: str = ""
    base_release: str = "t0"
    patcher_module: str = "patcher"
    scenarios_module: str = "sim.scenarios"
    repo_target: str = "local"
    github_repo: str = ""
    # runner (always a docker container: pipeline/runner.py)
    runner_image: str = "immune-base:1"
    runner_prefix: str = "immune-runner"
    runner_timeout_s: float = 240.0
    runner_memory: str = "1g"
    runner_cpus: str = "2"
    runner_pids: int = 256
    seed: int = 1
    app_now: str = "1767225600"        # 2026-01-01T00:00:00Z, frozen clock for every runner job
    # loop
    max_attempts: int = 3
    http_timeout_s: float = 5.0
    deploy_timeout_s: float = 300.0
    patcher_timeout_s: float = 600.0
    verify_wait_s: float = 8.0
    reopen_cooldown_s: float = 300.0
    retry_cooldown_s: float = 60.0      # transient close: tried again after this, x4 per retry, capped at 1 h
    max_retries: int = 5
    policy_max_lines: int = 120
    policy_max_files: int = 4
    rule_ttl_s: int | None = None   # None: a rule lives until its patch is verified (PIPELINE_RULE_TTL_S overrides)
    extra: dict = field(default_factory=dict)
    app: object = None                  # immune.config.Config of the project (None = immune.config.current())

    @property
    def project(self):
        """The project's immune.config.Config (app facts)."""
        if self.app is None:
            from immune import config as icfg
            self.app = icfg.current()
        return self.app

    def reload_project(self):
        """Re-read .immune/config.yaml (autopatch / mode may change while the pipeline runs)."""
        from immune import config as icfg
        try:
            self.app = icfg.load(self.project.project_dir)
        except icfg.ConfigError as e:
            import logging
            logging.getLogger("pipeline").warning("config reload failed, keeping the previous one: %s", e)
        return self.app

    @classmethod
    def from_env(cls, env=None) -> "Config":
        from immune import config as icfg
        env = dict(os.environ if env is None else env)
        app = icfg.current(env)
        repo = env.get("REPO_DIR") or REPO_ROOT
        demo = _demo_env(repo)
        rt = env.get("RUNTIME_DIR") or app.runtime_dir
        run_id = env.get("RUN_ID") or ""
        if not run_id:
            try:
                run_id = open(os.path.join(rt, "run_id")).read().strip()
            except OSError:
                run_id = "dev"
        from immune.auth import prod_secret_for
        secrets = {"PROD_APP_SECRET": env.get("PROD_APP_SECRET") or demo.get("PROD_APP_SECRET", "")}
        if app.auth.secret_env and env.get(app.auth.secret_env):
            secrets[app.auth.secret_env] = env[app.auth.secret_env]
        target = env.get("REPO_TARGET") or ("official" if app.repo.target == "github" else "local")
        c = cls(
            repo_dir=repo,
            runtime_dir=rt,
            state_dir=env.get("PIPELINE_STATE_DIR") or os.path.join(rt, "pipeline"),
            run_id=run_id or "dev",
            bus_url=(env.get("PIPELINE_BUS_URL") or env.get("FLEET_BUS_URL")
                     or "http://127.0.0.1:%d" % app.ports["dashboard"]).rstrip("/"),
            bus_token=env.get("BUS_TOKEN") or demo.get("BUS_TOKEN", ""),
            gateway_admin_url=(env.get("GATEWAY_ADMIN_URL") or "http://127.0.0.1:%d" % app.ports["admin"]).rstrip("/"),
            gateway_url=(env.get("GATEWAY_URL") or "http://127.0.0.1:%d" % app.ports["gateway"]).rstrip("/"),
            fleet_url=(env.get("FLEET_URL") or "http://127.0.0.1:%s" % env.get("FLEET_PORT", app.ports["fleet"])).rstrip("/"),
            admin_token=env.get("ADMIN_TOKEN") or demo.get("ADMIN_TOKEN", ""),
            prod_app_secret=prod_secret_for(app.auth.to_dict(), secrets),
            openapi_path=env.get("OPENAPI_PATH_HOST") or app.openapi,
            manifest_path=env.get("MANIFEST_PATH_HOST") or os.path.join(rt, "data", "manifest.json"),
            record_path=env.get("RECORD_PATH_HOST") or os.path.join(rt, "recordings", "requests.jsonl"),
            base_release=env.get("PIPELINE_BASE_RELEASE", "t0"),
            patcher_module=env.get("PATCHER_MODULE", "patcher"),
            scenarios_module=env.get("SCENARIOS_MODULE", app.scenarios),
            repo_target=target,
            github_repo=env.get("GITHUB_REPO", app.repo.github),
            runner_image=env.get("RUNNER_IMAGE", "immune-base:1"),
            runner_prefix=env.get("RUNNER_PREFIX", app.prefix + "-runner"),
            runner_timeout_s=_f(env, "RUNNER_TIMEOUT_S", 240),
            runner_memory=env.get("RUNNER_MEMORY", "1g"),
            runner_cpus=env.get("RUNNER_CPUS", "2"),
            runner_pids=_i(env, "RUNNER_PIDS", 256),
            seed=_i(env, "SEED", 1),
            app_now=env.get("RUNNER_APP_NOW", "1767225600"),
            max_attempts=_i(env, "PIPELINE_MAX_ATTEMPTS", 3),
            http_timeout_s=_f(env, "PIPELINE_HTTP_TIMEOUT_S", 5),
            deploy_timeout_s=_f(env, "PIPELINE_DEPLOY_TIMEOUT_S", 300),
            patcher_timeout_s=_f(env, "PIPELINE_PATCHER_TIMEOUT_S", 600),
            verify_wait_s=_f(env, "PIPELINE_VERIFY_WAIT_S", 8),
            reopen_cooldown_s=_f(env, "PIPELINE_REOPEN_COOLDOWN_S", 300),
            retry_cooldown_s=_f(env, "PIPELINE_RETRY_COOLDOWN_S", 60),
            max_retries=_i(env, "PIPELINE_MAX_RETRIES", 5),
            policy_max_lines=_i(env, "POLICY_MAX_LINES", 120),
            policy_max_files=_i(env, "POLICY_MAX_FILES", 4),
            rule_ttl_s=_i(env, "PIPELINE_RULE_TTL_S", 0) or None,
            app=app,
        )
        return c

    @property
    def releases_dir(self) -> str:
        return os.path.join(self.runtime_dir, "releases")

    def release_dir(self, release: str) -> str:
        return os.path.join(self.releases_dir, release)

    @property
    def pause_file(self) -> str:
        return os.path.join(self.state_dir, "PAUSE")
