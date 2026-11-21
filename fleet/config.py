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


@dataclass
class Config:
    repo_dir: str
    runtime_dir: str
    run_id: str
    admin_token: str
    port: int = 8070
    gateway_url: str = "http://127.0.0.1:8081"
    bus_url: str = "http://127.0.0.1:8090"
    bus_token: str = ""
    image: str = "immune-base:1"
    name_prefix: str = "immune"
    prodnet: str = "immune_prodnet"
    clonenet: str = "immune_clonenet"
    release_pkg: str = "victim"
    victim_app: str = "victim.app.main:app"
    shadow_profile: str = "victim.shadow_profile"
    clone_cmd: str = ""  # override; default built from shadow_profile
    prod_secret: str = ""
    shadow_secret: str = ""
    collector_url: str = "http://gateway:9000"
    extra_pythonpath: str = ""  # extra container path appended to PYTHONPATH
    smoke_path: str = "/openapi.json"
    deploy_watch_s: float = 20.0
    watch_poll_s: float = 1.0
    health_timeout_s: float = 40.0
    reconcile_s: float = 1.0
    user: str = field(default_factory=lambda: f"{os.getuid()}:{os.getgid()}")

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ
        repo = os.path.abspath(e.get("REPO_DIR") or REPO_ROOT)
        denv = _env_file(os.path.join(REPO_ROOT, "deploy", "demo.env"))

        def g(k, d=""):
            return e.get(k) if e.get(k) is not None else denv.get(k, d)

        runtime = os.path.abspath(e.get("RUNTIME_DIR") or os.path.join(repo, "runtime"))
        run_id = g("RUN_ID")
        if not run_id:
            try:
                run_id = open(os.path.join(runtime, "run_id")).read().strip()
            except OSError:
                run_id = "dev"
        return cls(
            repo_dir=repo,
            runtime_dir=runtime,
            run_id=run_id,
            admin_token=g("ADMIN_TOKEN"),
            port=int(e.get("FLEET_PORT", 8070)),
            gateway_url=e.get("GATEWAY_ADMIN_URL", "http://127.0.0.1:8081").rstrip("/"),
            bus_url=e.get("BUS_URL_HOST", e.get("FLEET_BUS_URL", "http://127.0.0.1:8090")).rstrip("/"),
            bus_token=g("BUS_TOKEN"),
            image=e.get("IMMUNE_IMAGE", "immune-base:1"),
            name_prefix=e.get("NAME_PREFIX", "immune"),
            prodnet=e.get("PRODNET", "immune_prodnet"),
            clonenet=e.get("CLONENET", "immune_clonenet"),
            release_pkg=e.get("RELEASE_PKG", "victim"),
            victim_app=e.get("VICTIM_APP", "victim.app.main:app"),
            shadow_profile=e.get("SHADOW_PROFILE", "victim.shadow_profile"),
            clone_cmd=e.get("CLONE_CMD", ""),
            prod_secret=g("PROD_APP_SECRET"),
            shadow_secret=g("SHADOW_APP_SECRET"),
            collector_url=e.get("COLLECTOR_URL", "http://gateway:9000"),
            extra_pythonpath=e.get("EXTRA_PYTHONPATH", ""),
            smoke_path=e.get("SMOKE_PATH", "/openapi.json"),
            deploy_watch_s=float(e.get("DEPLOY_WATCH_S", 20)),
            watch_poll_s=float(e.get("WATCH_POLL_S", 1)),
            health_timeout_s=float(e.get("HEALTH_TIMEOUT_S", 40)),
            reconcile_s=float(e.get("RECONCILE_S", 1)),
        )

    def clone_command(self) -> list[str]:
        if self.clone_cmd:
            return shlex.split(self.clone_cmd)
        return ["python", "-m", "shadow.run", "--profile", self.shadow_profile, "--port", "8000"]
