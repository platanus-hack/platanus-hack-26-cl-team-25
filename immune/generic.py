"""`app.runtime: generic` (contracts/product.md §6): facts, and `immune up` / `immune down` for such a project.

Config keys specific to this runtime. `facts` reads app.workdir, app.bind_env, app.warmup_paths, data.prod_url_env
and data.demo_postgres from the raw YAML; immune/config.py does not validate them, so a misspelt key is ignored:

  app.build: {context: ., dockerfile: Dockerfile}  the image is built from the RELEASE directory (context
                                  is release-relative); tag immune-<name>-app:<release>
  app.workdir: /app               where the image keeps the release; the pipeline's judge clones mount a
                                  patched copy of the release there over the t0 image (source overlay)
  app.bind_env: HOST              env var carrying the bind address (prod 0.0.0.0, clones 127.0.0.1, so
                                  nothing reaches the app in a clone except through the observer)
  app.warmup_paths: [...]         extra benign GETs for the observer's warm-up
  database.url_env                env var through which the app gets its Postgres URL
  data.prod_url_env: NAME         env var (of `immune up`) holding the real prod URL, as reachable from
                                  the prod network
  data.demo_postgres: {database, user, seed_command}
                                  without that env var: a Postgres container (postgres:16-alpine) on the
                                  prod network, seeded once by running seed_command in the app image
  shadow.profile: module          <project>/.immune/<module>.py, loaded by the observer (identity hooks)
"""
from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field

PG_IMAGE = "postgres:16-alpine"
SIDECAR_IMAGE = "immune-sidecar:1"


@dataclass
class Facts:
    name: str
    image_repo: str                   # immune-<name>-app
    context: str = "."
    dockerfile: str = "Dockerfile"
    workdir: str = "/app"
    bind_env: str = ""
    port: int = 3000
    health: str = "/health"
    command: list = field(default_factory=list)
    env: dict = field(default_factory=dict)
    url_env: str = "DATABASE_URL"
    allowed_file_roots: list = field(default_factory=list)
    source_dirs: list = field(default_factory=list)      # as seen by the app (workdir-joined)
    warmup_paths: list = field(default_factory=list)
    profile_module: str = ""
    prod_url_env: str = ""
    demo: dict = field(default_factory=dict)

    def image(self, release: str) -> str:
        return "%s:%s" % (self.image_repo, release)

    def profile_file(self) -> str:
        return self.profile_module.replace(".", "/") + ".py" if self.profile_module else ""

    def host_path(self, release_dir: str, app_path: str) -> str | None:
        """An in-container path under workdir -> the same file in a release dir on the host."""
        w = self.workdir.rstrip("/")
        if app_path == w or app_path.startswith(w + "/"):
            return os.path.join(release_dir, app_path[len(w):].lstrip("/"))
        return None


class GenericError(RuntimeError):
    pass


def facts(cfg) -> Facts:
    raw = cfg.raw or {}
    a = raw.get("app") or {}
    d = raw.get("data") or {}
    b = a.get("build") if isinstance(a.get("build"), dict) else {}
    f = Facts(name=cfg.name, image_repo="immune-%s-app" % cfg.name,
              context=str(b.get("context") or "."), dockerfile=str(b.get("dockerfile") or "Dockerfile"),
              workdir=str(a.get("workdir") or "/app"), bind_env=str(a.get("bind_env") or ""),
              port=cfg.app.port, health=cfg.app.health, command=list(cfg.app.command), env=dict(cfg.app.env),
              url_env=cfg.database.url_env or "DATABASE_URL", allowed_file_roots=list(cfg.app.allowed_file_roots),
              warmup_paths=[str(x) for x in (a.get("warmup_paths") or [])], profile_module=cfg.shadow.profile,
              prod_url_env=str(d.get("prod_url_env") or ""),
              demo=dict(d.get("demo_postgres") or {}) if isinstance(d.get("demo_postgres"), dict) else {})
    f.source_dirs = [f.workdir.rstrip("/") + "/" + s for s in cfg.app.source_dirs]
    errs = []
    if cfg.app.image and not b:
        errs.append("app.image without app.build is not supported yet (fleet needs one image per release)")
    if cfg.database.kind != "postgres":
        errs.append("database.kind must be postgres for the generic runtime (only Postgres has a proxy)")
    if not f.prod_url_env and not f.demo:
        errs.append("data.prod_url_env or data.demo_postgres is required")
    if f.context.startswith("/") or ".." in f.context.split("/"):
        errs.append("app.build.context must be release-relative")
    if errs:
        raise GenericError("%s: %s" % (cfg.config_path, "; ".join(errs)))
    return f


# ---------------------------------------------------------------------------- prod database URL
def demo_env_path(cfg) -> str:
    return cfg.rt("stack", "demo-db.env")


def prod_url(cfg, f: Facts | None = None, env=None) -> str:
    """The prod database URL as seen from the prod network: env[data.prod_url_env], else the demo DB's."""
    f = f or facts(cfg)
    env = os.environ if env is None else env
    if f.prod_url_env and env.get(f.prod_url_env):
        return env[f.prod_url_env]
    vals = {}
    try:
        with open(demo_env_path(cfg)) as fh:
            for line in fh:
                k, _, v = line.strip().partition("=")
                if k:
                    vals[k] = v
    except OSError:
        pass
    if vals.get("DEMO_DB_URL"):
        return vals["DEMO_DB_URL"]
    raise GenericError("no prod database: export %s or configure data.demo_postgres" % (f.prod_url_env or "<url env>"))


def demo_db_name(cfg) -> str:
    return "%s-proddb" % cfg.prefix


def write_demo_env(cfg, f: Facts) -> str:
    os.makedirs(cfg.rt("stack"), exist_ok=True)
    path = demo_env_path(cfg)
    pw = secrets.token_hex(12)
    url = "postgres://%s:%s@proddb:5432/%s" % (f.demo.get("user") or cfg.name, pw, f.demo.get("database") or cfg.name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("DEMO_DB_PASSWORD=%s\nDEMO_DB_URL=%s\n" % (pw, url))
    return url


# ---------------------------------------------------------------------------- immune up / down
def cmd_up(cfg, reset: bool) -> int:
    """`immune up` for a generic project. Order: stack services (networks, gateway, dashboard) -> t0 release
    and its image -> prod database (demo: started + seeded) -> shadow seed from prod -> fleet /reset -> pipeline."""
    from . import __main__ as cli
    from fleet import generic as fg
    from . import shadowdata_pg
    f = facts(cfg)
    t_all = time.time()
    sec = cli.stack_secrets(cfg)
    cli.stop_host(cfg)
    cli.remove_owned(cfg)
    sec_file = cli.write_stack_env(cfg, sec)
    if reset:
        cli.compose(cfg, cli.compose_env(cfg, sec_file, "dev"), "down", "--remove-orphans", check=False)
    # ports this stack does not hold right now: all four after a `reset` (compose down above); only the
    # fleet's (a host process, stopped above) on a plain `up`, where the stack's own containers may be running
    cli.check_ports(cfg, ("gateway", "admin", "dashboard", "fleet") if reset else ("fleet",))
    fg.remove_images(cfg.name)
    import shutil
    for d in ("data", "recordings", "bus", "releases", "pipeline", "repo"):
        shutil.rmtree(cfg.rt(d), ignore_errors=True)
    for d in ("data/shadow", "recordings", "bus", "releases", "logs", "stack"):
        os.makedirs(cfg.rt(d), exist_ok=True)
    for fn in os.listdir(cfg.rt("logs")):      # logs belong to the run, as in the python-asgi path
        if fn.endswith(".log"):
            os.remove(cfg.rt("logs", fn))
    cli.build_release(cfg, cfg.release_dir("t0"), os.environ.get("T0_REF") or None)
    run_id = time.strftime("%m%d-%H%M%S")
    with open(cfg.rt("run_id"), "w") as fh:
        fh.write(run_id + "\n")
    cenv = cli.compose_env(cfg, sec_file, run_id)
    cli.compose(cfg, cenv, "up", "-d", "--force-recreate")
    t = time.time()
    fg.build_image(cfg, f, cfg.release_dir("t0"), "t0")
    cli.say("built %s in %.1fs" % (f.image("t0"), time.time() - t))
    prodnet = cfg.network("prodnet")
    if f.prod_url_env and os.environ.get(f.prod_url_env):
        url = os.environ[f.prod_url_env]
        cli.say("prod database from $%s" % f.prod_url_env)
    else:
        url = write_demo_env(cfg, f)
        t = time.time()
        fg.start_demo_db(cfg, f, url, prodnet)
        cli.say("demo prod database %s up and seeded in %.1fs" % (demo_db_name(cfg), time.time() - t))
    t = time.time()
    rep = shadowdata_pg.build(cfg, url, prodnet)
    cli.say("shadow seed: %s rows, canaries %s, %d bytes (%.1fs)" % (rep["tables"], rep["canary_rows"], rep["bytes"],
                                                                   time.time() - t))
    tok = sec["ADMIN_TOKEN"]
    cli.wait_url("http://127.0.0.1:%d/health" % cfg.ports["dashboard"])
    cli.wait_url("http://127.0.0.1:%d/_admin/health" % cfg.ports["admin"], tok)
    henv = cli.host_env(cfg, sec, run_id)
    cli.start_host(cfg, "fleet", "fleet", henv)
    cli.wait_url("http://127.0.0.1:%d/state" % cfg.ports["fleet"], tok)
    t = time.time()
    res = cli.http("POST", "http://127.0.0.1:%d/reset" % cfg.ports["fleet"],
                   {"release": "t0", "pool_size": int(os.environ.get("POOL_SIZE") or cfg.pool_size)}, tok, timeout=300)
    cli.say("fleet reset in %.1fs: %s" % (time.time() - t, res))
    if cfg.mode != "enforce":
        cli.http("POST", "http://127.0.0.1:%d/_admin/mode" % cfg.ports["admin"], {"mode": cfg.mode}, tok)
    if not os.environ.get("NO_PIPELINE"):
        cli.start_host(cfg, "pipeline", "pipeline", henv)
    eff, why = cfg.effective_autopatch()
    cli.say("stack immune-%s up in %.0fs (runtime generic): gateway http://127.0.0.1:%d  dashboard http://127.0.0.1:%d"
            "  mode=%s autopatch=%s%s" % (cfg.name, time.time() - t_all, cfg.ports["gateway"], cfg.ports["dashboard"],
                                          cfg.mode, eff, (" (%s)" % "; ".join(why)) if why else ""))
    return 0


def cmd_down(cfg) -> int:
    from . import __main__ as cli
    from fleet import generic as fg
    cli.stop_host(cfg)
    cli.remove_owned(cfg)
    sec_file = cfg.rt("stack", "containers.env")
    if not os.path.isfile(sec_file):
        sec_file = cli.DEMO_ENV
    cli.compose(cfg, cli.compose_env(cfg, sec_file, "dev"), "down", "--remove-orphans", check=False)
    cli.remove_owned(cfg)
    fg.remove_networks(cfg.name)
    n = fg.remove_images(cfg.name)
    cli.say("stack immune-%s down (%d app image(s) removed)" % (cfg.name, n))
    return 0
