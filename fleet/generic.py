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
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import subprocess
import time

from docker.errors import NotFound

from immune import generic as ig

from .manager import Clone, Fleet, FleetError

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
    """TCP readiness (the entrypoint's init phase listens on the unix socket only)."""
    end = time.time() + timeout
    while time.time() < end:
        p = _docker("exec", container, "pg_isready", "-q", "-h", "127.0.0.1", "-p", "5432", check=False, timeout=10)
        if p.returncode == 0:
            return True
        st = _docker("inspect", "-f", "{{.State.Running}}", container, check=False).stdout.strip()
        if st != "true":
            return False
        time.sleep(0.15)
    return False


def start_demo_db(cfg, f: ig.Facts, url: str, network: str) -> None:
    """The demo's prod database: postgres on the prod network (alias proddb), then data.demo_postgres.seed_command
    in the app image (t0) against it. Labelled with the project only (not the run): fleet /reset keeps it."""
    from sidecar.pgclient import parse_url
    p = parse_url(url)
    name = ig.demo_db_name(cfg)
    _docker("rm", "-f", name, check=False)
    _docker("run", "-d", "--name", name, "--network", network, "--network-alias", "proddb",
            "--label", "immune.project=%s" % cfg.name, "--label", "immune.role=proddb",
            "--user", "70:70", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/var/lib/postgresql/data:rw,uid=70,gid=70,mode=0700", "--tmpfs", "/var/run/postgresql:rw,uid=70,gid=70",
            "--tmpfs", "/tmp:rw,mode=1777", "-e", "POSTGRES_USER=%s" % p["user"], "-e", "POSTGRES_PASSWORD=%s" % p["password"],
            "-e", "POSTGRES_DB=%s" % p["database"], ig.PG_IMAGE)
    if not pg_ready(name):
        raise FleetError("demo prod database did not start: %s" % _docker("logs", name, check=False).stderr[-600:])
    cmd = f.demo.get("seed_command")
    if cmd:
        cmd = cmd if isinstance(cmd, list) else ["sh", "-c", str(cmd)]
        _docker("run", "--rm", "--network", network, "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--label", "immune.project=%s" % cfg.name,
                "-e", "%s=%s" % (f.url_env, url), f.image("t0"), *[str(x) for x in cmd], timeout=300)


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
            pid_mode=("container:%s" % ns_of) if ns_of else None)
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

    @property
    def timings(self):
        if not hasattr(self, "_timings"):
            self._timings = {}
        return self._timings

    def app_env(self, url: str, bind: str, secret: str) -> dict:
        from immune.config import substitute
        out = {k: substitute(str(v), {"db": url, "secret": secret, "static": ""}) for k, v in self.f.env.items()}
        out[self.f.url_env] = url
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
        pginit = os.path.join(shadow, "pginit")
        if not os.path.isfile(os.path.join(pginit, "01-seed.sh")):
            raise FleetError("no shadow seed at %s (immune up builds it)" % pginit)
        su_pw, app_pw = secrets.token_hex(12), secrets.token_hex(12)
        db = clone.name + "-db"
        self._run(db, ig.PG_IMAGE, PG_ARGS, role="clone-db", release=clone.release, user="70:70",
                  env={"POSTGRES_PASSWORD": su_pw, "APP_DB_PASSWORD": app_pw}, network=self.cfg.clonenet,
                  binds=[f"{pginit}:/docker-entrypoint-initdb.d:ro"], mem="256m",
                  tmpfs={"/var/lib/postgresql/data": "uid=70,gid=70,mode=0700", "/var/run/postgresql": "uid=70,gid=70",
                         "/tmp": "size=32m,mode=1777"})
        if not pg_ready(db):
            raise FleetError("clone database %s did not start" % db)
        t_db = time.time()
        url = "postgres://app:%s@127.0.0.1:5432/clone" % app_pw
        app = self._run(clone.name, self.f.image(clone.release), self.f.command or None, role="clone",
                        release=clone.release, env=self.app_env(url, "127.0.0.1", self.cfg.shadow_secret),
                        network=self.cfg.clonenet, mem="384m")
        cfgdir = os.path.join(self.cfg.runtime_dir, "stack", "clones")
        os.makedirs(cfgdir, exist_ok=True)
        cpath = os.path.join(cfgdir, clone.name + ".json")
        sc = sidecar_config(self.f, db, su_pw, profile="/profile/" + self.f.profile_file() if self.f.profile_module else None)
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
           "postgres": {"listen": "127.0.0.1:5432", "upstream": "%s:5432" % db,
                        "admin_url": "postgres://postgres:%s@%s:5432/postgres" % (su_pw, db),
                        "database": "clone", "template": "seed"}}
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
