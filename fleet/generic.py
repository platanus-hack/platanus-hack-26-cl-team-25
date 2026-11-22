"""Fleet for `app.runtime: generic` (contracts/product.md §6): the app runs unmodified from its own image.

Per clone n (all three on the stack's clone network, labelled immune.run=<RUN_ID>):

  immune-<name>-clone-<n>-db   postgres:16-alpine, tmpfs data, fsync off, uid 70, --cap-drop ALL; its init
                               script creates role `app` and the template database `seed` from the shadow
                               dump (<runtime>/data/shadow/pginit). Random passwords per clone.
  immune-<name>-clone-<n>      the app image immune-<name>-app:<release>, --cap-drop ALL, read-only, bound
                               to 127.0.0.1 (app.bind_env), DATABASE_URL -> 127.0.0.1:5432 (the proxy)
  immune-<name>-clone-<n>-obs  immune-sidecar:1 (python -m sidecar, attach mode) with
                               --network container:<app> --pid container:<app>
                               --cap-drop ALL --cap-add SYS_PTRACE (the only added capability anywhere);
                               serves the wire protocol on :8000 of the app's network namespace, runs the
                               pg proxy on 127.0.0.1:5432 and resets `clone` from `seed` after L1 requests

The gateway's clone address is `immune-<name>-clone-<n>:8000` (the observer's port in the app's netns).
Prod: the same image on the prod network as prod-<colour>, against the real database URL. Blue/green =
a new image tag per release (built here on /deploy from the materialised release directory).

database.kind mysql: the clone database is the pinned MariaDB (uid 999, tmpfs datadir, init script from
<runtime>/data/shadow/myinit creating user `app` and the databases `seed` and `clone`), the observer runs the
MySQL proxy on 127.0.0.1:3306 and rebuilds the tables of `clone` written by L1 requests from `seed`.
shadow.tracer: clones run <image>-trace (the release image + the call tracer; prod never does) with a bigger
/tmp for the per-request traces, and the observer turns them into evidence stacks.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import subprocess
import time

from docker.errors import NotFound

from immune import dbkind
from immune import generic as ig

from .manager import PROD_RESTART, Clone, Fleet, FleetError

log = logging.getLogger("fleet.generic")
PG_ARGS = ["-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"]


# ---------------------------------------------------------------------------- helpers shared with `immune up`
def _docker(*args, check=True, timeout=600, input_=None) -> subprocess.CompletedProcess:
    p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, input=input_)
    if check and p.returncode != 0:
        raise FleetError("docker %s: %s" % (" ".join(args[:2]), (p.stderr or p.stdout).strip()[-800:]))
    return p


def image_exists(tag: str) -> bool:
    return _docker("image", "inspect", tag, check=False).returncode == 0


def build_image(cfg, f: ig.Facts, release_dir: str, release: str) -> float:
    """docker build of the release directory -> immune-<name>-app:<release>. The only image build of the
    product (t0 by `immune up`, later releases by /deploy). -> seconds."""
    t = time.time()
    ctx = os.path.normpath(os.path.join(release_dir, f.context))
    _docker("build", "-q", "-t", f.image(release), "-f", os.path.join(ctx, f.dockerfile),
            "--label", "immune.project=%s" % cfg.name, "--label", "immune.release=%s" % release, ctx, timeout=900)
    return time.time() - t


def remove_images(name: str) -> int:
    ids = _docker("images", "-q", "--filter", "label=immune.project=%s" % name, check=False).stdout.split()
    tags = [l for l in _docker("images", "--format", "{{.Repository}}:{{.Tag}}", "immune-%s-app" % name,
                               check=False).stdout.split() if l]
    refs = sorted(set(tags)) or sorted(set(ids))
    if refs:
        _docker("rmi", "-f", *refs, check=False)
    return len(refs)


def remove_networks(name: str) -> None:
    for n in _docker("network", "ls", "-q", "--filter", "label=immune.project=%s" % name, check=False).stdout.split():
        _docker("network", "rm", n, check=False)


def pg_ready(container: str, timeout: float = 60.0) -> bool:
    """TCP readiness of a Postgres container (the entrypoint's init phase listens on the unix socket only)."""
    return dbkind.KINDS["postgres"].ready(container, "", timeout)


def db_ready(kind: dbkind.DbKind, container: str, su_pw: str, timeout: float = 90.0) -> bool:
    return kind.ready(container, su_pw, timeout)


def _tmpfs_args(tmpfs: dict) -> list:
    out = []
    for path, opts in tmpfs.items():
        out += ["--tmpfs", "%s:rw,%s" % (path, opts)]
    return out


def start_demo_db(cfg, f: ig.Facts, url: str, network: str) -> None:
    """The demo's prod database on the prod network (alias proddb), then data.demo_<kind>.seed_command in the app
    image (t0) against it. Labelled with the project only (not the run): fleet /reset keeps it."""
    kind = f.db
    p = kind.parse(url)
    root_pw = ig.demo_root_password(cfg) or p["password"]
    name = ig.demo_db_name(cfg)
    _docker("rm", "-f", name, check=False)
    env = []
    for k, v in kind.demo_env(p["user"], p["password"], p["database"], root_pw).items():
        env += ["-e", "%s=%s" % (k, v)]
    _docker("run", "-d", "--name", name, "--network", network, "--network-alias", "proddb",
            "--label", "immune.project=%s" % cfg.name, "--label", "immune.role=proddb",
            "--user", kind.user, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            *_tmpfs_args(kind.tmpfs()), *env, kind.image, *(kind.args if kind.name == "mysql" else []))
    if not db_ready(kind, name, root_pw, 120):
        raise FleetError("demo prod database did not start: %s" % _docker("logs", name, check=False).stderr[-600:])
    cmd = f.demo.get("seed_command")
    if cmd:
        cmd = cmd if isinstance(cmd, list) else ["sh", "-c", str(cmd)]
        envs = dict(f.db_env_for(url), IMMUNE_DB_ROOT_PASSWORD=root_pw, IMMUNE_DB_URL=url)
        eargs = []
        for k, v in envs.items():
            eargs += ["-e", "%s=%s" % (k, v)]
        if f.demo.get("seed_privileged"):
            # installers that write their own config files: writable root fs, the image's own user (root
            # entrypoints drop privileges themselves), no added capabilities beyond docker's defaults
            sandbox = ["--security-opt", "no-new-privileges"]
        else:
            sandbox = ["--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
        p = _docker("run", "--rm", "--network", network, *sandbox, "--label", "immune.project=%s" % cfg.name,
                    *eargs, "--entrypoint", "", f.image("t0"), *[str(x) for x in cmd], timeout=1200, check=False)
        if p.returncode != 0:
            raise FleetError("demo seed failed: %s" % (p.stderr or p.stdout).strip()[-1500:])


TRACE_DOCKERFILE = """FROM {image}
USER root
RUN apk add --no-cache {package} && rm -f {ini}/*xdebug*.ini && mkdir -p {dir} && chmod 0777 {dir}
COPY zz-immune-xdebug.ini {ini}/zz-immune-xdebug.ini
COPY immune-trace-prepend.php /immune-trace/prepend.php
RUN chmod 0755 /immune-trace && chmod 0644 /immune-trace/prepend.php
USER {user}
"""

TRACE_INI = """; Inmune: shadow clones only (this image never serves prod). One function trace per judged request (the
; observer sets the XDEBUG_TRACE cookie on it; logins and warm-up are not traced), read and removed by the observer (sidecar/phptrace.py), which turns it into the evidence's file:line stack.
zend_extension=xdebug.so
xdebug.mode=trace
xdebug.start_with_request=trigger
xdebug.trigger_value=
xdebug.trace_format=1
xdebug.use_compression=0
xdebug.output_dir={dir}
xdebug.trace_output_name=trace.%u
xdebug.var_display_max_data=4096
xdebug.var_display_max_children=8
xdebug.var_display_max_depth=1
xdebug.log_level=0
opcache.jit=off
auto_prepend_file=/immune-trace/prepend.php
"""

# Keeps the per-request trace small: calls into excluded trees (e.g. vendor/: template engines, frameworks) are
# not recorded; the app's own calls, including its calls into the database layer, are.
TRACE_PREPEND = """<?php
if (function_exists('xdebug_set_filter')) {{
    xdebug_set_filter(XDEBUG_FILTER_TRACING, XDEBUG_PATH_EXCLUDE, {paths});
}}
"""


def trace_excludes(f: ig.Facts) -> list:
    """shadow.tracer.exclude fragments as absolute path prefixes inside the image (relative to app.workdir)."""
    out = []
    for x in (f.tracer or {}).get("exclude") or ["/vendor/"]:
        x = str(x)
        out.append(x if x.startswith(f.workdir.rstrip("/") + "/") else f.workdir.rstrip("/") + "/" + x.strip("/") + "/")
    return out


def build_trace_image(cfg, f: ig.Facts, release: str) -> float:
    """<image>-trace: the release image + Xdebug in trace mode, for shadow clones only. -> seconds."""
    t = time.time()
    base = f.image(release)
    probe = _docker("run", "--rm", "--entrypoint", "sh", "--user", "0", base, "-c",
                    "v=$(php -r 'echo PHP_MAJOR_VERSION.PHP_MINOR_VERSION;'); echo $v; "
                    "php --ini | sed -n 's/^Scan for additional .ini files in: *//p' | tr -d '\042'; true",
                    check=False, timeout=120)
    lines = probe.stdout.split()
    if probe.returncode != 0 or len(lines) < 2:
        raise FleetError("shadow.tracer: %s has no PHP CLI (%s)" % (base, (probe.stderr or "")[-200:]))
    user = _docker("image", "inspect", "-f", "{{.Config.User}}", base, check=False).stdout.strip() or "root"
    trace_dir = (f.tracer or {}).get("dir") or "/tmp/immune-trace"
    # the image keeps /tmp on a tmpfs at run time: the directory is re-created by the app's start script, the
    # one baked here only covers images whose /tmp is not replaced
    dockerfile = TRACE_DOCKERFILE.format(image=base, package="php%s-pecl-xdebug" % lines[0], dir=trace_dir,
                                         ini=lines[1], user=user)
    import tempfile
    with tempfile.TemporaryDirectory(prefix="immune-trace-") as ctx:
        with open(os.path.join(ctx, "Dockerfile"), "w", newline="\n") as fh:
            fh.write(dockerfile)
        with open(os.path.join(ctx, "zz-immune-xdebug.ini"), "w", newline="\n") as fh:
            fh.write(TRACE_INI.format(dir=trace_dir))
        with open(os.path.join(ctx, "immune-trace-prepend.php"), "w", newline="\n") as fh:
            fh.write(TRACE_PREPEND.format(paths=json.dumps(trace_excludes(f))))
        _docker("build", "-q", "-t", f.trace_image(release), "--label", "immune.project=%s" % cfg.name,
                "--label", "immune.release=%s" % release, "--label", "immune.trace=1", ctx, timeout=900)
    return time.time() - t


# ---------------------------------------------------------------------------- fleet
class GenericFleet(Fleet):
    def __init__(self, cfg, client=None, project=None):
        super().__init__(cfg, client)
        from immune import config as icfg
        self.project = project or icfg.current()
        self.f = ig.facts(self.project)

    # ------------------------------------------------------------ containers
    def _run(self, name, image, cmd, *, role, release, env, network=None, aliases=None, ns_of=None, user=None,
             binds=None, tmpfs=None, cap_add=None, pids=256, mem="512m", labels=None):
        self.destroy_name(name)
        api = self.dk.api
        hc = api.create_host_config(
            binds=binds or [], tmpfs=tmpfs or {"/tmp": "size=64m,mode=1777"}, read_only=True, cap_drop=["ALL"],
            cap_add=cap_add or None, security_opt=["no-new-privileges:true"], pids_limit=pids, mem_limit=mem,
            memswap_limit=mem, network_mode=("container:%s" % ns_of) if ns_of else network,
            pid_mode=("container:%s" % ns_of) if ns_of else None,
            restart_policy=PROD_RESTART if role == "prod" else None)
        nc = None if ns_of else api.create_networking_config(
            {network: api.create_endpoint_config(aliases=aliases or None)})
        lab = self._labels(role, release)
        lab.update(labels or {})
        cid = api.create_container(image, cmd, name=name, environment=env, host_config=hc, networking_config=nc,
                                   labels=lab, user=user or "")["Id"]
        c = self.dk.containers.get(cid)
        c.start()
        return c

    def _prod_url(self) -> str:
        return ig.prod_url(self.project, self.f)

    def ensure_image(self, release) -> None:
        tag = self.f.image(release)
        if not image_exists(tag):
            secs = build_image(self.project, self.f, self._release_dir(release), release)
            log.info("built %s in %.1fs", tag, secs)
            self.timings["build_s"] = round(secs, 1)
        if self.f.tracer and not image_exists(self.f.trace_image(release)):
            secs = build_trace_image(self.project, self.f, release)
            log.info("built %s in %.1fs", self.f.trace_image(release), secs)

    @property
    def timings(self):
        if not hasattr(self, "_timings"):
            self._timings = {}
        return self._timings

    def app_env(self, url: str, bind: str, secret: str) -> dict:
        from immune.config import substitute
        out = {k: substitute(str(v), {"db": url, "secret": secret, "static": ""}) for k, v in self.f.env.items()}
        out.update(self.f.db_env_for(url))
        if self.f.bind_env:
            out[self.f.bind_env] = bind
        return out

    def start_prod(self, color, release):
        self.ensure_image(release)
        env = dict(self.app_env(self._prod_url(), "0.0.0.0", self.cfg.prod_secret), RELEASE=release)
        return self._run(f"{self.cfg.name_prefix}-prod-{color}", self.f.image(release), self.f.command or None,
                         role="prod", release=release, env=env, network=self.cfg.prodnet, aliases=[f"prod-{color}"])

    def start_clone(self, clone: Clone):
        try:
            return self._start_triple(clone)
        except Exception:
            for n in (clone.name + "-obs", clone.name, clone.name + "-db"):   # never leave half a triple behind
                try:
                    Fleet.destroy(self, self.dk.containers.get(n))
                except Exception:  # noqa: BLE001
                    pass
            raise

    def _start_triple(self, clone: Clone):
        t0 = time.time()
        self.ensure_image(clone.release)
        shadow = os.path.join(self.cfg.runtime_dir, "data", "shadow")
        kind = self.f.db
        initdir = os.path.join(shadow, kind.init_dir)
        if not os.path.isfile(os.path.join(initdir, "01-seed.sh")):
            raise FleetError("no shadow seed at %s (immune up builds it)" % initdir)
        su_pw, app_pw = secrets.token_hex(12), secrets.token_hex(12)
        db = clone.name + "-db"
        self._run(db, kind.image, kind.args, role="clone-db", release=clone.release, user=kind.user,
                  env=kind.env(su_pw, app_pw), network=self.cfg.clonenet,
                  binds=[f"{initdir}:/docker-entrypoint-initdb.d:ro"], mem=kind.clone_memory,
                  tmpfs=kind.tmpfs())
        if not db_ready(kind, db, su_pw, 180):
            raise FleetError("clone database %s did not start" % db)
        t_db = time.time()
        url = kind.url("app", app_pw, "127.0.0.1", "clone")
        traced = bool(self.f.tracer)
        app = self._run(clone.name, self.f.trace_image(clone.release) if traced else self.f.image(clone.release),
                        self.f.command or None, role="clone",
                        release=clone.release, env=self.app_env(url, "127.0.0.1", self.cfg.shadow_secret),
                        network=self.cfg.clonenet, mem="1g" if traced else "384m",
                        tmpfs={"/tmp": "size=384m,mode=1777"} if traced else None)
        cfgdir = os.path.join(self.cfg.runtime_dir, "stack", "clones")
        os.makedirs(cfgdir, exist_ok=True)
        cpath = os.path.join(cfgdir, clone.name + ".json")
        sc = sidecar_config(self.f, db, su_pw, profile="/profile/" + self.f.profile_file() if self.f.profile_module else None)
        if traced:
            sc["tracer"] = dict(self.f.tracer)
        fd = os.open(cpath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(sc, fh)
        os.chmod(cpath, 0o644)   # read by root-without-DAC_OVERRIDE in the observer; the dir is private (0700)
        os.chmod(cfgdir, 0o711)
        binds, tmpfs = self._observer_mounts(cpath)
        markers = os.path.join(self.cfg.runtime_dir, "data", "markers.json")
        env = {"PYTHONPATH": "/opt/immune", "PYTHONDONTWRITEBYTECODE": "1", "CLONE_ID": clone.id, "CLONE_KEY": clone.key,
               "COLLECTOR_URL": self.cfg.collector_url, "RELEASE": clone.release, "MARKERS_PATH": "/markers/markers.json"}
        if os.path.isfile(markers):
            binds.append(f"{markers}:/markers/markers.json:ro")
        self._run(clone.name + "-obs", ig.SIDECAR_IMAGE, ["python", "-m", "sidecar", "--config", "/cfg/sidecar.json"],
                  role="clone-obs", release=clone.release, env=env, ns_of=app.id, cap_add=["SYS_PTRACE"],
                  binds=binds, tmpfs=tmpfs, mem="256m")
        log.info("clone %s: db %.1fs, app+observer created %.1fs", clone.name, t_db - t0, time.time() - t0)
        return app

    def _observer_mounts(self, cpath):
        home = os.path.realpath(self.cfg.repo_dir)
        binds = [f"{home}:/opt/immune:ro", f"{cpath}:/cfg/sidecar.json:ro"]
        tmpfs = {"/tmp": "size=32m,mode=1777"}
        for d in (os.path.join(home, "runtime"), os.path.join(home, ".git"), os.path.realpath(self.cfg.runtime_dir)):
            if os.path.isdir(d) and d.startswith(home + os.sep):
                tmpfs["/opt/immune/" + os.path.relpath(d, home)] = "size=1m,mode=0555"
        dot = self.project.dot_immune
        if self.f.profile_module and os.path.isdir(dot):
            binds.append(f"{dot}:/profile:ro")
            rt = os.path.realpath(self.cfg.runtime_dir)
            if rt.startswith(os.path.realpath(dot) + os.sep):
                tmpfs["/profile/" + os.path.relpath(rt, os.path.realpath(dot))] = "size=1m,mode=0555"
        return binds, tmpfs

    def _clone_key(self, c):
        # the app container is the customer's image, unmodified: the key lives in its observer
        obs = self._container(c.name + "-obs")
        db = self._container(c.name + "-db")
        if obs is None or db is None or obs.status != "running" or db.status != "running":
            return None
        return super()._clone_key(obs)

    def destroy(self, c):
        try:
            c.reload()
        except NotFound:
            return
        role = (c.labels or {}).get("immune.role")
        if role == "clone":
            for sib in (c.name + "-obs", c.name + "-db"):
                try:
                    s = self.dk.containers.get(sib)
                    super().destroy(s)
                except NotFound:
                    pass
            try:
                os.remove(os.path.join(self.cfg.runtime_dir, "stack", "clones", c.name + ".json"))
            except OSError:
                pass
        super().destroy(c)

    def healthy(self, c, path="/health", timeout=6.0) -> bool:
        role = (c.labels or {}).get("immune.role")
        if role == "prod":
            alias = c.name.rsplit("-", 1)[-1]
            target, url = f"{self.project.prefix}-gateway", f"http://prod-{alias}:{self.f.port}{path}"
        else:
            target, url = c.name + "-obs", f"http://127.0.0.1:8000{path}"
        script = "import urllib.request;urllib.request.urlopen(%r,timeout=3)" % url
        p = _docker("exec", target, "python", "-c", script, check=False, timeout=timeout)
        return p.returncode == 0

    def wait_healthy(self, c, path=None) -> bool:
        if (c.labels or {}).get("immune.role") == "clone":
            # the observer attaches, warms up and resets the db before serving; fail fast if it died
            path = path or self.cfg.health_path
            end = time.time() + max(self.cfg.health_timeout_s, 90)
            while time.time() < end:
                st = _docker("inspect", "-f", "{{.State.Running}}", c.name + "-obs", check=False).stdout.strip()
                if st != "true":
                    log.warning("observer %s-obs not running: %s", c.name,
                                _docker("logs", "--tail", "20", c.name + "-obs", check=False).stderr[-800:])
                    return False
                if self.healthy(c, path):
                    return True
                time.sleep(0.3)
            return False
        return super().wait_healthy(c, path)

    def reconcile_once(self):
        # a triple whose observer or database died counts as a dead clone
        if self.lock.acquire(blocking=False):
            try:
                for cl in list(self.clones.values()):
                    for sib in (cl.name + "-obs", cl.name + "-db"):
                        try:
                            ok = self.dk.containers.get(sib).status == "running"
                        except NotFound:
                            ok = False
                        if not ok:
                            log.warning("clone %s: %s is not running; replacing the triple", cl.name, sib)
                            try:
                                self.destroy_name(cl.name)
                            except Exception:  # noqa: BLE001
                                pass
                            break
            finally:
                self.lock.release()
        super().reconcile_once()

    def deploy(self, release):
        self._release_dir(release)
        t = time.time()
        try:
            self.ensure_image(release)
        except FleetError as e:
            return {"ok": False, "rolled_back": False, "detail": "image build failed: %s" % e}
        built = round(time.time() - t, 1)
        res = super().deploy(release)
        res["build_s"] = built
        return res

    def state(self):
        s = super().state()
        s["runtime"] = "generic"
        s["image"] = self.f.image(self.release) if self.release else None
        return s


def sidecar_config(f: ig.Facts, db: str, su_pw: str, profile: str | None, app_port: int | None = None) -> dict:
    cfg = {"listen_port": 8000, "app_port": app_port or f.port, "health": f.health,
           "allowed_file_roots": f.allowed_file_roots, "source_dirs": f.source_dirs, "warmup_paths": f.warmup_paths,
           **f.db.sidecar(db, su_pw)}
    if f.openapi_in_profile:
        cfg["openapi"] = "/profile/" + f.openapi_in_profile
    if profile:
        cfg["profile"] = profile
    return cfg


def make_fleet(cfg):
    """Fleet for the configured project: GenericFleet for app.runtime generic, else the Python fleet."""
    from immune import config as icfg
    try:
        if icfg.current().app.runtime == "generic":
            return GenericFleet(cfg)
    except icfg.ConfigError:
        pass
    return Fleet(cfg)
