"""Host side of the sandboxed runner (contracts/interfaces.md "Runner").

Every execution of application code happens in

    docker run --rm -i --network none --read-only ... immune-base:1 python -m pipeline.runner_entry

with the repo mounted read-only at /srv and the release under test mounted read-only
over /srv/victim. `RUNNER_MODE=local` runs the same entry module as a host subprocess
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

    def docker_cmd(self, release_dir: str, name: str) -> list:
        c = self.cfg
        repo = os.path.realpath(c.repo_dir)
        victim = os.path.join(os.path.realpath(release_dir), "victim")
        if not os.path.isdir(victim):
            raise RunnerError("release has no victim/ dir: %s" % release_dir)
        cmd = ["docker", "run", "--rm", "-i", "--name", name, "--network", "none", "--read-only",
               "--tmpfs", "/tmp:rw,size=512m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--pids-limit", str(c.runner_pids), "--memory", c.runner_memory, "--cpus", str(c.runner_cpus),
               "--user", "%d:%d" % (os.getuid(), os.getgid()), "--label", "immune.component=runner",
               "-e", "PYTHONPATH=/srv", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
               "-w", "/srv", "-v", "%s:/srv:ro" % repo, "-v", "%s:/srv/victim:ro" % victim]
        # hide host state the code under test has no business reading
        for d in ("runtime", ".git"):
            if os.path.isdir(os.path.join(repo, d)):
                cmd += ["--mount", "type=tmpfs,destination=/srv/%s" % d]
        rt = os.path.realpath(c.runtime_dir)
        if rt.startswith(repo + os.sep) and os.path.isdir(rt) and os.path.relpath(rt, repo) != "runtime":
            cmd += ["--mount", "type=tmpfs,destination=/srv/%s" % os.path.relpath(rt, repo)]
        if os.path.isfile(os.path.join(repo, ".env")):
            cmd += ["-v", "/dev/null:/srv/.env:ro"]
        cmd += [c.runner_image, "python", "-m", "pipeline.runner_entry"]
        return cmd

    def run(self, release_dir: str, job: dict, timeout: float | None = None) -> dict:
        job = dict(job)
        job.setdefault("seed", self.cfg.seed)
        job.setdefault("app_now", self.cfg.app_now)
        timeout = float(timeout or self.cfg.runner_timeout_s)
        data = json.dumps(job).encode()
        t0 = time.time()
        name = self._name()
        if self.cfg.runner_mode == "local":
            env = dict(os.environ)
            env["PYTHONPATH"] = os.pathsep.join([os.path.realpath(release_dir), os.path.realpath(self.cfg.repo_dir)])
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            for k in ("APP_DB", "APP_NOW", "APP_SECRET", "APP_STATIC", "MARKERS_PATH"):
                env.pop(k, None)
            cmd, cwd, pre = [sys.executable, "-m", "pipeline.runner_entry"], os.path.realpath(release_dir), _limits
        else:
            cmd, cwd, pre, env = self.docker_cmd(release_dir, name), None, None, None
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
