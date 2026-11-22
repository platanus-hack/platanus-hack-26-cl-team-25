from __future__ import annotations

import concurrent.futures as cf
import json
import logging
import os
import re
import secrets
import shutil
import threading
import time
from dataclasses import dataclass

import docker
import httpx
from docker.errors import NotFound

from .config import Config

log = logging.getLogger("fleet")
RELEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_POOL = cf.ThreadPoolExecutor(max_workers=16, thread_name_prefix="fleet-x")


class FleetError(Exception):
    def __init__(self, msg, status=500):
        super().__init__(msg)
        self.status = status


class GatewayError(Exception):
    pass


# prod comes back by itself after a crash or a host reboot; clones are replaced by the reconcile loop instead
PROD_RESTART = {"Name": "unless-stopped"}


@dataclass
class Clone:
    n: int
    key: str
    release: str
    prefix: str = "immune"

    @property
    def name(self):
        return f"{self.prefix}-clone-{self.n}"

    @property
    def id(self):
        return f"clone-{self.n}"

    @property
    def addr(self):
        return f"{self.name}:8000"


class Gateway:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def call(self, method, path, body=None, timeout=3.0):
        try:
            r = httpx.request(method, self.cfg.gateway_url + path, json=body, timeout=timeout,
                              headers={"x-admin-token": self.cfg.admin_token})
            r.raise_for_status()
            return r.json() if r.content else {}
        except Exception as e:  # noqa: BLE001
            raise GatewayError(f"{method} {path}: {e}") from e

    def get_pool(self):
        return self.call("GET", "/_admin/pool").get("clones", [])

    def put_pool(self, clones):
        self.call("PUT", "/_admin/pool", {"clones": [
            {"id": c.id, "addr": c.addr, "key": c.key, "release": c.release} for c in clones]})

    def get_upstream(self):
        return self.call("GET", "/_admin/upstream")

    def set_upstream(self, addr, release):
        self.call("POST", "/_admin/upstream", {"addr": addr, "release": release}, timeout=30.0)

    def stats(self):
        return self.call("GET", "/_admin/stats")

    def reset(self):
        self.call("POST", "/_admin/reset")


class Fleet:
    def __init__(self, cfg: Config, client=None):
        self.cfg = cfg
        self.dk = client or docker.from_env()
        self.gw = Gateway(cfg)
        self.lock = threading.RLock()  # serialises reset / deploy / reconcile
        self.active: str | None = None  # "blue" | "green"
        self.release: str | None = None
        self.pool_size = 0
        self.clones: dict[str, Clone] = {}
        self.gw_states: dict[str, str] = {}
        self.gw_ok = False
        self._next_n = 1
        self._last_pool_sig = None
        self._stop = threading.Event()

    # -------------------------------------------------- persisted state
    # What a restarted fleet process cannot read back from Docker: which colour is live, the pool size, the
    # clone counter. Written after every change; adopt() uses it so a restart never needs a /reset (which
    # would put t0, the unpatched release, back in production).
    def _state_path(self) -> str:
        return os.path.join(self.cfg.runtime_dir, "stack", "fleet-state.json")

    def _save(self) -> None:
        path = self._state_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"run_id": self.cfg.run_id, "active": self.active, "release": self.release,
                           "pool_size": self.pool_size, "next_n": self._next_n, "ts": time.time()}, f)
            os.replace(tmp, path)
        except OSError as e:
            log.warning("cannot persist fleet state at %s: %s", path, e)

    def _load(self) -> dict | None:
        try:
            with open(self._state_path()) as f:
                st = json.load(f)
        except (OSError, ValueError):
            return None
        if not isinstance(st, dict) or st.get("run_id") != self.cfg.run_id:
            return None
        if st.get("active") not in ("blue", "green") or not RELEASE_RE.match(str(st.get("release") or "")):
            return None
        return st

    def _container(self, name):
        try:
            return self.dk.containers.get(name)
        except NotFound:
            return None

    def _clone_key(self, c) -> str | None:
        """CLONE_KEY of a running clone (generic runtime: it lives in the observer, see fleet/generic.py)."""
        for kv in (c.attrs.get("Config") or {}).get("Env") or []:
            if kv.startswith("CLONE_KEY="):
                return kv.split("=", 1)[1] or None
        return None

    def adopt(self) -> bool:
        """After a restart: take over the containers of this run instead of starting from nothing."""
        with self.lock:
            if self.active:
                return True
            st = self._load()
            if st is None:
                return False
            active, release = st["active"], st["release"]
            other = "green" if active == "blue" else "blue"
            prod = self._container(f"{self.cfg.name_prefix}-prod-{active}")
            alt = self._container(f"{self.cfg.name_prefix}-prod-{other}")
            try:
                up = self.gw.get_upstream().get("addr")
            except GatewayError:
                up = None
            if alt is not None and alt.status == "running" and up == self._addr(other) \
                    and self.healthy(alt, self.cfg.health_path):
                # we died between the upstream switch and recording it: the gateway is the truth
                active, other = other, active
                release = (alt.labels or {}).get("immune.release") or release
                prod, alt = alt, prod
            try:
                self._release_dir(release)
            except FleetError as e:
                log.error("cannot adopt run %s: %s", self.cfg.run_id, e)
                return False
            if prod is None or prod.status not in ("running", "restarting") or not self.wait_healthy(prod):
                log.warning("adopt: prod-%s is not serving; starting release %s again", active, release)
                try:
                    prod = self.start_prod(active, release)
                    if not self.wait_healthy(prod):
                        log.error("adopt: prod-%s failed its health check", active)
                except Exception as e:  # noqa: BLE001
                    log.error("adopt: cannot start prod-%s: %s", active, e)
            if alt is not None:
                try:
                    self.destroy(alt)
                except Exception as e:  # noqa: BLE001
                    log.warning("adopt: leftover prod-%s: %s", other, e)
            self.active, self.release = active, release
            self.pool_size = int(st.get("pool_size") or 0)
            top = 0
            for c in self.owned():
                if (c.labels or {}).get("immune.role") != "clone":
                    continue
                m = re.search(r"-clone-(\d+)$", c.name)
                n = int(m.group(1)) if m else 0
                top = max(top, n)
                key = self._clone_key(c) if c.status == "running" else None
                if m and key and (c.labels or {}).get("immune.release") == release \
                        and len(self.clones) < self.pool_size:
                    cl = Clone(n=n, key=key, release=release, prefix=self.cfg.name_prefix)
                    self.clones[cl.name] = cl
                else:
                    try:
                        self.destroy(c)
                    except Exception as e:  # noqa: BLE001
                        log.warning("adopt: leftover %s: %s", c.name, e)
            self._next_n = max(int(st.get("next_n") or 1), top + 1)
            self._last_pool_sig = None
            self._save()
            log.info("adopted run %s: prod-%s on %s, %d/%d clone(s)", self.cfg.run_id, active, release,
                     len(self.clones), self.pool_size)
            return True

    def _ensure_prod(self) -> None:
        """Reconcile: the live colour must exist. Docker restarts a crashed one; a removed one is recreated."""
        name = f"{self.cfg.name_prefix}-prod-{self.active}"
        c = self._container(name)
        if c is not None and c.status in ("running", "restarting", "created"):
            return
        log.error("prod container %s is %s; starting release %s again", name, c.status if c else "gone",
                  self.release)
        try:
            c = self.start_prod(self.active, self.release)
            if not self.wait_healthy(c):
                log.error("prod container %s failed its health check after the restart", name)
        except Exception as e:  # noqa: BLE001
            log.error("cannot restart %s: %s", name, e)

    def _ensure_services(self) -> None:
        """Reconcile: gateway and dashboard (compose services) must be running. Docker's restart policy covers
        a crash; it does not cover a container that was stopped or killed by hand, and the gateway is the only
        way in."""
        for svc in ("gateway", "dashboard"):
            c = self._container(f"{self.cfg.name_prefix}-{svc}")
            if c is None or c.status not in ("exited", "dead", "created"):
                continue
            log.error("%s container is %s; starting it", svc, c.status)
            try:
                c.start()
            except Exception as e:  # noqa: BLE001
                log.error("cannot start %s: %s", c.name, e)

    # ---------------------------------------------------------------- bus
    def publish(self, type_, data):
        def send():
            try:
                from immune_contracts import events
                ev = events.make(type_, "fleet", data, run=self.cfg.run_id)
                httpx.post(self.cfg.bus_url + "/events", json=ev, timeout=1.0,
                           headers={"x-bus-token": self.cfg.bus_token})
            except Exception:  # noqa: BLE001
                pass
        threading.Thread(target=send, daemon=True).start()

    # ------------------------------------------------------------- docker
    def _labels(self, role, release):
        lab = {"immune.run": self.cfg.run_id, "immune.role": role, "immune.release": release}
        if self.cfg.project:
            lab["immune.project"] = self.cfg.project
        return lab

    def _owned_label(self, c) -> bool:
        return (c.labels or {}).get("immune.run") == self.cfg.run_id

    def owned(self):
        return self.dk.containers.list(all=True, filters={"label": f"immune.run={self.cfg.run_id}"})

    def destroy(self, c):
        """Remove a container, but only if it carries our label."""
        c.reload()
        if not self._owned_label(c):
            raise FleetError(f"refusing to remove {c.name}: not labelled immune.run={self.cfg.run_id}")
        try:
            c.remove(force=True)
        except NotFound:
            pass

    def destroy_name(self, name):
        try:
            c = self.dk.containers.get(name)
        except NotFound:
            return
        self.destroy(c)

    def _release_dir(self, release):
        if not RELEASE_RE.match(release or ""):
            raise FleetError(f"bad release id {release!r}", 400)
        d = os.path.join(self.cfg.runtime_dir, "releases", release)
        missing = [p for p in self.cfg.release_paths if not os.path.exists(os.path.join(d, p))]
        if not os.path.isdir(d) or missing:
            raise FleetError(f"release {release!r} not found at {d} (missing {missing})", 400)
        return d

    def _addr(self, color) -> str:
        return f"prod-{color}:{self.cfg.app_port}"

    def _create(self, name, role, release, net, aliases, cmd, env, binds, tmpfs, pids, mem):
        self.destroy_name(name)  # raises if an unlabelled container owns the name
        api = self.dk.api
        env = dict(env, PYTHONDONTWRITEBYTECODE="1")
        path = ["/app"] + (["/app/.immune"] if self.cfg.dot_immune else []) + ["/opt/immune"]
        if self.cfg.extra_pythonpath:
            path.append(self.cfg.extra_pythonpath)
        env["PYTHONPATH"] = ":".join(path)
        tmpfs = dict(tmpfs, **self._masks())
        hc = api.create_host_config(
            binds=binds, tmpfs=tmpfs, read_only=True, cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"], pids_limit=pids, mem_limit=mem, memswap_limit=mem,
            network_mode=net, restart_policy=PROD_RESTART if role == "prod" else None)
        nc = api.create_networking_config({net: api.create_endpoint_config(aliases=aliases or None)})
        cid = api.create_container(
            self.cfg.image, cmd, name=name, environment=env, host_config=hc, networking_config=nc,
            labels=self._labels(role, release), user=self.cfg.user, working_dir="/app")["Id"]
        c = self.dk.containers.get(cid)
        c.start()
        return c

    def _masks(self) -> dict:
        """tmpfs over host state inside the read-only IMMUNE_HOME mount (runtime data, .git, .env)."""
        home = os.path.realpath(self.cfg.repo_dir)
        out = {}
        rt = os.path.realpath(self.cfg.runtime_dir)
        cands = [os.path.join(home, "runtime"), os.path.join(home, ".git"), rt]
        if self.cfg.dot_immune:
            cands.append(os.path.join(os.path.realpath(self.cfg.dot_immune), "runtime"))
        for d in cands:
            if os.path.isdir(d):
                if d.startswith(home + os.sep):
                    out["/opt/immune/" + os.path.relpath(d, home)] = "size=1m,mode=0555"
                if self.cfg.dot_immune and d.startswith(os.path.realpath(self.cfg.dot_immune) + os.sep):
                    out["/app/.immune/" + os.path.relpath(d, os.path.realpath(self.cfg.dot_immune))] = "size=1m,mode=0555"
        return out

    def _mounts(self, release):
        rel = self._release_dir(release)
        binds = [f"{self.cfg.repo_dir}:/opt/immune:ro", f"{rel}:/app:ro"]
        if self.cfg.dot_immune:
            try:  # docker needs the mountpoint to exist inside the read-only release mount
                os.makedirs(os.path.join(rel, ".immune"), exist_ok=True)
                binds.append(f"{self.cfg.dot_immune}:/app/.immune:ro")
            except OSError as e:
                log.warning("cannot mount %s into the release: %s", self.cfg.dot_immune, e)
        return binds

    def start_prod(self, color, release):
        data = self.cfg.prod_data_dir or os.path.join(self.cfg.runtime_dir, "data", "prod")
        os.makedirs(data, exist_ok=True)
        binds = self._mounts(release) + [f"{data}:/data:rw"]
        env = dict(self.cfg.env_for(f"/data/{self.cfg.prod_db_name}", self.cfg.prod_secret), RELEASE=release)
        cmd = ["uvicorn", self.cfg.asgi, "--host", "0.0.0.0", "--port", str(self.cfg.app_port)]
        return self._create(f"{self.cfg.name_prefix}-prod-{color}", "prod", release, self.cfg.prodnet, [f"prod-{color}"],
                            cmd, env, binds, {"/tmp": "size=64m,mode=1777"}, 256, "512m")

    def start_clone(self, clone: Clone):
        shadow = os.path.join(self.cfg.runtime_dir, "data", "shadow")
        os.makedirs(shadow, exist_ok=True)
        binds = self._mounts(clone.release) + [f"{shadow}:/seed:ro"]
        env = dict(self.cfg.env_for("/data/app.db", self.cfg.shadow_secret))
        env.update({"CLONE_ID": clone.id, "CLONE_KEY": clone.key, "COLLECTOR_URL": self.cfg.collector_url,
                    "SHADOW_SEED_DB": "/seed/seed.db", "RELEASE": clone.release, "SHADOW_DB_ENV": self.cfg.db_env,
                    "SHADOW_RELEASE_ROOT": "/app", "SHADOW_RELEASE_PATHS": ":".join(self.cfg.release_paths)})
        markers = os.path.join(self.cfg.runtime_dir, "data", "markers.json")
        if os.path.isfile(markers):
            binds.append(f"{markers}:/markers/markers.json:ro")
            env["MARKERS_PATH"] = "/markers/markers.json"
        return self._create(clone.name, "clone", clone.release, self.cfg.clonenet, None,
                            self.cfg.clone_command(), env, binds,
                            {"/tmp": "size=32m,mode=1777", "/data": "size=64m,mode=1777"}, 128, "256m")

    def healthy(self, c, path="/health", timeout=6.0) -> bool:
        port = self.cfg.app_port if (c.labels or {}).get("immune.role") == "prod" else 8000
        script = ("import urllib.request;"
                  f"urllib.request.urlopen('http://127.0.0.1:{port}{path}',timeout=3)")
        fut = _POOL.submit(c.exec_run, ["python", "-c", script])
        try:
            return fut.result(timeout=timeout).exit_code == 0
        except Exception:  # noqa: BLE001
            return False

    def wait_healthy(self, c, path=None) -> bool:
        path = path or self.cfg.health_path
        deadline = time.time() + self.cfg.health_timeout_s
        while time.time() < deadline:
            try:
                c.reload()
                if c.status not in ("running", "created"):
                    return False
            except NotFound:
                return False
            if self.healthy(c, path):
                return True
            time.sleep(0.5)
        return False

    def _new_clone(self, release) -> Clone:
        n = self._next_n
        self._next_n += 1
        return Clone(n=n, key=secrets.token_hex(16), release=release, prefix=self.cfg.name_prefix)

    def _spawn_clones(self, release, count):
        """Create `count` healthy clones. Failed ones are removed. Returns the healthy Clone list."""
        new = [self._new_clone(release) for _ in range(count)]

        def one(cl):
            try:
                c = self.start_clone(cl)
            except Exception as e:  # noqa: BLE001
                log.warning("clone %s create failed: %s", cl.name, e)
                return None
            if self.wait_healthy(c):
                return cl
            log.warning("clone %s unhealthy, removing", cl.name)
            try:
                self.destroy(c)
            except Exception:  # noqa: BLE001
                pass
            return None

        return [c for c in _POOL_map(one, new) if c]

    # ------------------------------------------------------------ gateway
    def register(self):
        try:
            self.gw.put_pool(list(self.clones.values()))
            self._last_pool_sig = tuple(sorted(self.clones))
            return True
        except GatewayError as e:
            log.warning("register failed: %s", e)
            return False

    def _refresh_gw_pool(self):
        try:
            pool = self.gw.get_pool()
        except GatewayError:
            self.gw_ok = False
            return None
        self.gw_ok = True
        self.gw_states = {c["id"]: c.get("state", "free") for c in pool}
        return pool

    # --------------------------------------------------------------- ops
    def reset(self, release, pool_size):
        pool_size = int(pool_size)
        if pool_size < 0 or pool_size > 32:
            raise FleetError("pool_size out of range", 400)
        self._release_dir(release)
        with self.lock:
            for c in self.owned():
                self.destroy(c)
            self.clones.clear()
            self.gw_states.clear()
            self.active = self.release = None
            self.pool_size = pool_size
            prod = self.start_prod("blue", release)
            if not self.wait_healthy(prod):
                self.destroy(prod)
                raise FleetError("prod-blue failed health check", 500)
            self.active, self.release = "blue", release
            for cl in self._spawn_clones(release, pool_size):
                self.clones[cl.name] = cl
            errors = []
            try:
                self.gw.put_pool(list(self.clones.values()))
                self._last_pool_sig = tuple(sorted(self.clones))
                self.gw.set_upstream(self._addr("blue"), release)
                self.gw.reset()
                self.gw_ok = True
            except GatewayError as e:
                errors.append(str(e))
                self.gw_ok = False
            self._save()
            return {"ok": True, "prod": {"active": "blue", "release": release},
                    "clones": [c.id for c in self.clones.values()], "gateway_errors": errors}

    def deploy(self, release):
        self._release_dir(release)
        with self.lock:
            if not self.active:
                raise FleetError("no active prod; call /reset first", 409)
            old, old_rel = self.active, self.release
            new = "green" if old == "blue" else "blue"
            self.publish("deploy.started", {"release": release})
            res = self._deploy(release, old, old_rel, new)
            self.publish("deploy.done", {"release": release, "ok": res["ok"],
                                         "rolled_back": res["rolled_back"], "detail": res["detail"]})
            return res

    def _deploy(self, release, old, old_rel, new):
        def fail(detail, c=None, rolled_back=False):
            if c is not None:
                try:
                    self.destroy(c)
                except Exception:  # noqa: BLE001
                    pass
            return {"ok": False, "rolled_back": rolled_back, "release": old_rel, "active": old, "detail": detail}

        try:
            c = self.start_prod(new, release)
        except FleetError:
            raise
        except Exception as e:  # noqa: BLE001
            return fail(f"start failed: {e}")
        if not self.wait_healthy(c):
            return fail("new release failed health check", c)
        if not self.healthy(c, self.cfg.smoke_path):
            return fail(f"smoke request {self.cfg.smoke_path} failed", c)
        # error rate of the release being replaced: the yardstick for the one coming in. Without it, anyone able
        # to make the app answer 5xx (old release included) could undo every deploy by doing so during the watch.
        before_rate = 0.0
        try:
            st = self.gw.stats()
            before_rate = int(st.get("prod_5xx", 0)) / max(1, int(st.get("prod_requests", 0)))
        except (GatewayError, ValueError, TypeError):
            pass
        try:
            self.gw.set_upstream(self._addr(new), release)
        except GatewayError as e:
            return fail(f"gateway upstream switch failed: {e}", c)
        self.active, self.release = new, release
        self._save()
        baseline = 0
        try:
            baseline = int(self.gw.stats().get("prod_5xx", 0))
        except GatewayError:
            pass
        deadline = time.time() + self.cfg.deploy_watch_s
        grew = False
        while True:
            try:
                st = self.gw.stats()
                errs, reqs = int(st.get("prod_5xx", 0)) - baseline, max(1, int(st.get("prod_requests", 0)))
                # a regression: 5xx since the switch, at a clearly higher rate than the old release had
                if errs > 0 and errs / reqs > max(2 * before_rate, before_rate + 0.02):
                    grew = True
                    break
            except GatewayError:
                pass
            if time.time() >= deadline:
                break
            time.sleep(min(self.cfg.watch_poll_s, max(0.0, deadline - time.time())))
        if grew:
            try:
                self.gw.set_upstream(self._addr(old), old_rel)
            except GatewayError as e:
                log.error("rollback switch failed: %s", e)
            self.active, self.release = old, old_rel
            self._save()
            return fail("prod_5xx grew after switch; rolled back", c, rolled_back=True)
        try:
            self.destroy_name(f"{self.cfg.name_prefix}-prod-{old}")
        except Exception as e:  # noqa: BLE001
            log.warning("old colour cleanup: %s", e)
        replaced = self._refresh_clones(release)
        self._prune_releases()
        return {"ok": True, "rolled_back": False, "release": release, "active": new,
                "detail": "deployed", "clones_replaced": replaced}

    def _refresh_clones(self, release):
        """Replace every free clone not on `release`; captive/busy clones are left alone."""
        self._refresh_gw_pool()
        stale = [c for c in self.clones.values()
                 if c.release != release and self.gw_states.get(c.id, "free") == "free"]
        if not stale:
            return 0
        fresh = self._spawn_clones(release, len(stale))
        for cl in fresh:
            self.clones[cl.name] = cl
        self.register()  # old + new, so nothing drops while we re-check
        self._refresh_gw_pool()
        done = 0
        for old in stale[:]:
            if len(fresh) <= done:
                break
            if self.gw_states.get(old.id, "free") != "free":
                continue
            self.clones.pop(old.name, None)
            done += 1
        # excess fresh clones (old became busy meanwhile) are trimmed by reconcile? keep: pool may be > size briefly
        self.register()
        for old in stale:
            if old.name not in self.clones:
                try:
                    self.destroy_name(old.name)
                except Exception as e:  # noqa: BLE001
                    log.warning("destroy %s: %s", old.name, e)
        self._trim()
        return done

    KEEP_RELEASES = 5

    def _prune_releases(self) -> int:
        """Every fix leaves a release directory behind. Keep t0, what is in production, anything a container
        still mounts (a captive clone stays on its release) and the newest KEEP_RELEASES; remove the rest."""
        root = os.path.join(self.cfg.runtime_dir, "releases")
        try:
            names = [n for n in os.listdir(root) if RELEASE_RE.match(n) and os.path.isdir(os.path.join(root, n))]
        except OSError:
            return 0
        keep = {"t0", self.release}
        try:
            keep |= {(c.labels or {}).get("immune.release") for c in self.owned()}
        except Exception:  # noqa: BLE001
            return 0            # cannot tell what is mounted: remove nothing
        rest = sorted((n for n in names if n not in keep), key=lambda n: os.path.getmtime(os.path.join(root, n)))
        removed = 0
        for n in rest[:max(0, len(rest) - self.KEEP_RELEASES)]:
            shutil.rmtree(os.path.join(root, n), ignore_errors=True)
            removed += 1
        if removed:
            log.info("pruned %d old release dir(s)", removed)
        return removed

    def _trim(self):
        """Drop surplus free clones above pool_size (newest-release preferred)."""
        extra = len(self.clones) - self.pool_size
        if extra <= 0:
            return
        cands = sorted((c for c in self.clones.values() if self.gw_states.get(c.id, "free") == "free"),
                       key=lambda c: (c.release == self.release, c.n))
        removed = False
        for c in cands[:extra]:
            self.clones.pop(c.name, None)
            removed = True
        if removed:
            self.register()
        for name in [n for n in self._owned_clone_names() if n not in self.clones]:
            try:
                self.destroy_name(name)
            except Exception:  # noqa: BLE001
                pass

    def _owned_clone_names(self):
        return [c.name for c in self.owned() if (c.labels or {}).get("immune.role") == "clone"]

    # --------------------------------------------------------- reconcile
    def reconcile_once(self):
        if not self.lock.acquire(blocking=False):
            return
        try:
            if not self.active:
                return
            self._ensure_services()
            self._ensure_prod()
            pool = self._refresh_gw_pool()
            dead = []
            for cl in list(self.clones.values()):
                try:
                    c = self.dk.containers.get(cl.name)
                    if c.status != "running":
                        dead.append(cl)
                except NotFound:
                    dead.append(cl)
            retired = [c for c in self.clones.values()
                       if self.gw_states.get(c.id) == "retired"] if pool is not None else []
            gone = {c.name: c for c in dead + retired}
            for name in gone:
                self.clones.pop(name, None)
                self.gw_states.pop(gone[name].id, None)
            need = self.pool_size - len(self.clones)
            if need > 0:
                for cl in self._spawn_clones(self.release, need):
                    self.clones[cl.name] = cl
            changed = bool(gone) or need > 0
            if pool is not None:
                gw_ids = {c["id"] for c in pool}
                if gw_ids != {c.id for c in self.clones.values()}:
                    changed = True
            if changed or (pool is not None and self._last_pool_sig is None):
                self.register()
            for name, cl in gone.items():
                try:
                    self.destroy_name(name)
                except Exception as e:  # noqa: BLE001
                    log.warning("destroy %s: %s", name, e)
            if pool is not None and self.active:
                try:
                    up = self.gw.get_upstream()
                    want = self._addr(self.active)
                    if up.get("addr") and up.get("addr") != want:
                        self.gw.set_upstream(want, self.release)
                except GatewayError:
                    pass
            self._publish_pool()
        except Exception:  # noqa: BLE001
            log.exception("reconcile pass failed")
        finally:
            self.lock.release()

    def _publish_pool(self):
        st = [self.gw_states.get(c.id, "free") for c in self.clones.values()]
        data = {"l1_free": st.count("free"), "l2_busy": sum(1 for s in st if s in ("busy", "captive")),
                "size": len(st)}
        sig = tuple(sorted(data.items()))
        if sig != getattr(self, "_pub_sig", None):
            self._pub_sig = sig
            self.publish("pool.state", data)

    def loop(self):
        try:
            self.adopt()
        except Exception:  # noqa: BLE001
            log.exception("adopt failed")
        self.adopted = True
        while not self._stop.is_set():
            self.reconcile_once()
            self._stop.wait(self.cfg.reconcile_s)

    def stop(self):
        self._stop.set()

    def state(self):
        return {"prod": {"active": self.active, "release": self.release}, "ready": getattr(self, "adopted", False),
                "pool_size": self.pool_size, "gateway_ok": self.gw_ok, "run_id": self.cfg.run_id,
                "clones": [{"id": c.id, "name": c.name, "addr": c.addr, "release": c.release,
                            "state": self.gw_states.get(c.id, "free")} for c in list(self.clones.values())]}


def _POOL_map(fn, items):
    futs = [_POOL.submit(fn, i) for i in items]
    return [f.result() for f in futs]
