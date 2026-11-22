from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env_file(path: str) -> dict:
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def derive_smoke_path(openapi_path: str, health_path: str) -> str:
    """First GET of the project's OpenAPI spec that can be requested as is and is not the health check: no path
    or required parameter, no `security`. '' when the spec has none (the deploy then skips the smoke step and
    says so)."""
    try:
        import yaml
        with open(openapi_path) as f:
            spec = yaml.safe_load(f) or {}
    except Exception:  # noqa: BLE001
        return ""
    if not isinstance(spec, dict):
        return ""
    for path, item in (spec.get("paths") or {}).items():
        op = item.get("get") if isinstance(item, dict) else None
        if not isinstance(op, dict) or "{" in path or path == health_path:
            continue
        params = list(item.get("parameters") or []) + list(op.get("parameters") or [])
        if any(isinstance(p, dict) and p.get("required") for p in params):
            continue
        if op.get("security", spec.get("security")):
            continue
        return path
    return ""


@dataclass
class Config:
    repo_dir: str                  # IMMUNE_HOME: mounted read-only at /opt/immune in every container
    runtime_dir: str
    run_id: str
    admin_token: str
    port: int = 8070
    gateway_url: str = "http://127.0.0.1:8081"
    bus_url: str = "http://127.0.0.1:8090"
    bus_token: str = ""
    image: str = "immune-base:1"
    name_prefix: str = "immune"
    project: str = ""              # project name (label immune.project)
    prodnet: str = "immune_prodnet"
    clonenet: str = "immune_clonenet"
    # app facts (from .immune/config.yaml; see from_env)
    release_paths: list = field(default_factory=list)
    asgi: str = ""
    shadow_profile: str = ""
    app_port: int = 8000
    health_path: str = "/health"
    app_env: dict = field(default_factory=lambda: {"APP_DB": "{db}", "APP_SECRET": "{secret}"})
    static: str = ""               # release-relative dir for {static}
    db_env: str = "APP_DB"
    prod_data_dir: str = ""        # host dir mounted rw at /data in prod (default <runtime>/data/prod)
    prod_db_name: str = "app.db"
    dot_immune: str = ""           # <project>/.immune, mounted read-only at /app/.immune when set
    clone_cmd: str = ""  # override; default built from shadow_profile
    prod_secret: str = ""
    shadow_secret: str = ""
    collector_url: str = "http://gateway:9000"
    extra_pythonpath: str = ""  # extra container path appended to PYTHONPATH
    smoke_path: str = "/openapi.json"  # '' or the health path: the deploy skips the smoke step and reports it
    deploy_watch_s: float = 20.0
    deploy_min_requests: int = 20      # requests through the new release before its 5xx rate is judged
    # canary: before the switch, this share of the real traffic goes to the new release for canary_s seconds
    canary_weight: float = 0.2     # 0 turns the canary off (plain switch + watch)
    canary_s: float = 8.0
    canary_min_requests: int = 20  # fewer canary requests than this prove nothing: fall back to the plain watch
    watch_poll_s: float = 0.25
    health_timeout_s: float = 40.0
    reconcile_s: float = 1.0
    user: str = field(default_factory=lambda: f"{os.getuid()}:{os.getgid()}")

    @classmethod
    def from_env(cls) -> "Config":
        from immune import config as icfg
        from immune.auth import prod_secret_for
        e = os.environ
        app = icfg.current()
        repo = os.path.abspath(e.get("REPO_DIR") or REPO_ROOT)
        # the process that manages the prod and clone containers takes its admin token from its own environment, never from a
        # file in the repository (`immune up` always passes it: immune/__main__.py host_env)
        if not e.get("ADMIN_TOKEN"):
            raise RuntimeError("ADMIN_TOKEN is not set: the fleet does not start without an explicit admin token")
        denv = _env_file(os.path.join(REPO_ROOT, "deploy", "demo.env"))

        def g(k, d=""):
            return e.get(k) if e.get(k) is not None else denv.get(k, d)

        runtime = os.path.abspath(e.get("RUNTIME_DIR") or app.runtime_dir)
        run_id = g("RUN_ID")
        if not run_id:
            try:
                run_id = open(os.path.join(runtime, "run_id")).read().strip()
            except OSError:
                run_id = "dev"
        secrets_env = {k: g(k) for k in ("PROD_APP_SECRET",)}
        secrets_env.update({k: v for k, v in e.items() if k == app.auth.secret_env})
        return cls(
            repo_dir=repo,
            runtime_dir=runtime,
            run_id=run_id,
            admin_token=e["ADMIN_TOKEN"],
            port=int(e.get("FLEET_PORT", app.ports["fleet"])),
            gateway_url=e.get("GATEWAY_ADMIN_URL", "http://127.0.0.1:%d" % app.ports["admin"]).rstrip("/"),
            bus_url=e.get("BUS_URL_HOST", e.get("FLEET_BUS_URL", "http://127.0.0.1:%d" % app.ports["dashboard"])).rstrip("/"),
            bus_token=g("BUS_TOKEN"),
            image=e.get("IMMUNE_IMAGE", "immune-base:1"),
            name_prefix=e.get("NAME_PREFIX", app.prefix),
            project=app.name,
            prodnet=e.get("PRODNET", app.network("prodnet")),
            clonenet=e.get("CLONENET", app.network("clonenet")),
            release_paths=list(app.app.release_paths),
            asgi=app.app.asgi,
            shadow_profile=e.get("SHADOW_PROFILE", app.shadow.profile),
            app_port=app.app.port,
            health_path=app.app.health,
            app_env=dict(app.app.env),
            static=app.app.static,
            db_env=app.database.path_env,
            prod_data_dir=app.prod_data_dir,
            prod_db_name=app.prod_db_name,
            dot_immune=app.dot_immune if os.path.isdir(app.dot_immune) else "",
            clone_cmd=e.get("CLONE_CMD", ""),
            prod_secret=prod_secret_for(app.auth.to_dict(), secrets_env),
            shadow_secret=g("SHADOW_APP_SECRET"),
            collector_url=e.get("COLLECTOR_URL", "http://gateway:9000"),
            extra_pythonpath=e.get("EXTRA_PYTHONPATH", ""),
            smoke_path=e["SMOKE_PATH"] if "SMOKE_PATH" in e else derive_smoke_path(app.openapi, app.app.health),
            deploy_watch_s=float(e.get("DEPLOY_WATCH_S", 20)),
            deploy_min_requests=int(e.get("DEPLOY_MIN_REQUESTS", 20)),
            canary_weight=min(1.0, max(0.0, float(e.get("CANARY_WEIGHT", 0.2)))),
            canary_s=float(e.get("CANARY_S", 8)),
            canary_min_requests=int(e.get("CANARY_MIN_REQUESTS", 20)),
            watch_poll_s=float(e.get("WATCH_POLL_S", 0.25)),
            health_timeout_s=float(e.get("HEALTH_TIMEOUT_S", 40)),
            reconcile_s=float(e.get("RECONCILE_S", 1)),
        )

    def env_for(self, db: str, secret: str) -> dict:
        """The app's env (app.env with {db} {static} {secret}) inside a container (release at /app)."""
        from immune.config import substitute
        vals = {"db": db, "secret": secret, "static": "/app/" + self.static if self.static else ""}
        out = {k: substitute(str(v), vals) for k, v in self.app_env.items()}
        if self.db_env:
            out.setdefault(self.db_env, db)
        return out

    def clone_command(self) -> list[str]:
        if self.clone_cmd:
            return shlex.split(self.clone_cmd)
        return ["python", "-m", "shadow.run", "--profile", self.shadow_profile, "--port", "8000"]
