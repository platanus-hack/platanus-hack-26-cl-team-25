"""Host side of the sandboxed runner (contracts/interfaces.md "Runner").

Every execution of application code happens in

    docker run --rm -i --network none --read-only ... immune-base:1 python -m pipeline.runner_entry

with IMMUNE_HOME mounted read-only at /opt/immune and the release under test mounted
read-only at /app (working directory; PYTHONPATH=/app:/app/.immune:/opt/immune). The
project's app facts (.immune/config.yaml) travel in the job as "app".
`RUNNER_MODE=local` runs the same entry module as a host subprocess
(rlimits + timeout, no network isolation): only for the pipeline's own unit tests.
"""
from __future__ import annotations

import itertools
import json
import logging
import os
import subprocess
import sys
import threading
import time

from .config import Config

log = logging.getLogger("pipeline.runner")
MARK = "@@RESULT@@"


class RunnerError(Exception):
    pass


class Runner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._n = itertools.count(1)
        self._lock = threading.Lock()
        self.calls = []   # (kind, release_dir, seconds) for timing reports

    def _name(self) -> str:
        with self._lock:
            n = next(self._n)
        return "%s-%d-%d" % (self.cfg.runner_prefix, os.getpid(), n)

    def _seed_mounts(self) -> list:
        """Without data.seed_command the runner uses the stack's shadow seed (never prod data)."""
        app = self.cfg.project
        if app.data.seed_command:
            return []
        out = []
        if os.path.isdir(app.shadow_dir):
            out.append((app.shadow_dir, "/seed"))
        if os.path.isfile(app.manifest_path):
            out.append((app.manifest_path, "/seed-manifest/manifest.json"))
        return out

    def docker_cmd(self, release_dir: str, name: str) -> list:
        c = self.cfg
        app = c.project
        home = os.path.realpath(c.repo_dir)
        rel = os.path.realpath(release_dir)
        if not app.release_complete(rel):
            raise RunnerError("release %s lacks %s" % (release_dir, ", ".join(app.app.release_paths)))
        dot = os.path.realpath(app.dot_immune) if os.path.isdir(app.dot_immune) else ""
        pypath = "/app:/app/.immune:/opt/immune" if dot else "/app:/opt/immune"
        cmd = ["docker", "run", "--rm", "-i", "--name", name, "--network", "none", "--read-only",
               "--tmpfs", "/tmp:rw,size=512m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", str(c.runner_pids), "--memory", c.runner_memory, "--cpus", str(c.runner_cpus),
               "--user", "%d:%d" % (os.getuid(), os.getgid()), "--label", "immune.component=runner",
               "--label", "immune.project=%s" % app.name,
               "-e", "PYTHONPATH=" + pypath, "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
               "-w", "/app", "-v", "%s:/opt/immune:ro" % home, "-v", "%s:/app:ro" % rel]
        if dot:
            os.makedirs(os.path.join(rel, ".immune"), exist_ok=True)   # mountpoint inside the ro release
            cmd += ["-v", "%s:/app/.immune:ro" % dot]
        # hide host state the code under test has no business reading
        hidden = set()
        for d in (os.path.join(home, "runtime"), os.path.join(home, ".git"), os.path.realpath(c.runtime_dir)):
            if os.path.isdir(d) and d.startswith(home + os.sep) and d not in hidden:
                hidden.add(d)
                cmd += ["--mount", "type=tmpfs,destination=/opt/immune/%s" % os.path.relpath(d, home)]
            if dot and os.path.isdir(d) and d.startswith(dot + os.sep):
                cmd += ["--mount", "type=tmpfs,destination=/app/.immune/%s" % os.path.relpath(d, dot)]
        if os.path.isfile(os.path.join(home, ".env")):
            cmd += ["-v", "/dev/null:/opt/immune/.env:ro"]
        for src, dst in self._seed_mounts():
            cmd += ["-v", "%s:%s:ro" % (src, dst)]
        cmd += [c.runner_image, "python", "-m", "pipeline.runner_entry"]
        return cmd

    def run(self, release_dir: str, job: dict, timeout: float | None = None) -> dict:
        job = dict(job)
        job.setdefault("app", self.cfg.project.facts())
        job.setdefault("seed", self.cfg.seed)
        job.setdefault("app_now", self.cfg.app_now)
        timeout = float(timeout or self.cfg.runner_timeout_s)
        if self.cfg.runner_mode != "local" and self._seed_mounts():
            job["seed_paths"] = {"dir": "/seed", "manifest": "/seed-manifest/manifest.json"}
        t0 = time.time()
        name = self._name()
        if self.cfg.runner_mode == "local":
            app = self.cfg.project
            env = dict(os.environ)
            path = [os.path.realpath(release_dir)]
            if os.path.isdir(app.dot_immune):
                path.append(app.dot_immune)
            env["PYTHONPATH"] = os.pathsep.join(path + [os.path.realpath(self.cfg.repo_dir)])
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")
            for k in set(app.app.env) | {"APP_DB", "APP_NOW", "APP_SECRET", "APP_STATIC", "MARKERS_PATH",
                                         app.database.path_env, app.app.frozen_time_env}:
                env.pop(k, None)
            seeds = self._seed_mounts()
            if seeds:
                job["seed_paths"] = {"dir": seeds[0][0] if seeds[0][1] == "/seed" else "",
                                     "manifest": next((s for s, d in seeds if d.endswith("manifest.json")), "")}
            cmd, cwd, pre = [sys.executable, "-m", "pipeline.runner_entry"], os.path.realpath(release_dir), _limits
        else:
            cmd, cwd, pre, env = self.docker_cmd(release_dir, name), None, None, None
        data = json.dumps(job).encode()
        try:
            p = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, cwd=cwd, env=env, preexec_fn=pre)
        except subprocess.TimeoutExpired:
            if self.cfg.runner_mode != "local":
                subprocess.run(["docker", "kill", name], capture_output=True, timeout=30)
            raise RunnerError("runner job %s exceeded %.0fs (killed)" % (job.get("kind"), timeout))
        finally:
            self.calls.append((job.get("kind"), os.path.basename(os.path.normpath(release_dir)), round(time.time() - t0, 2)))
        out = p.stdout.decode("utf-8", "replace")
        for line in reversed(out.splitlines()):
            if line.startswith(MARK):
                res = json.loads(line[len(MARK):])
                if not res.get("ok_run"):
                    raise RunnerError("runner job %s failed: %s" % (job.get("kind"), res.get("error")))
                res["wall_s"] = round(time.time() - t0, 2)
                return res
        err = p.stderr.decode("utf-8", "replace")[-1500:]
        raise RunnerError("runner job %s produced no result (exit %s): %s" % (job.get("kind"), p.returncode, err))


def _limits():  # pragma: no cover - runs in the child
    import resource
    gib = 1024 ** 3
    try:
        resource.setrlimit(resource.RLIMIT_AS, (4 * gib, 4 * gib))
        resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
    except (ValueError, OSError):
        pass
