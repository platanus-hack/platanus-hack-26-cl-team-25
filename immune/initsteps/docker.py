"""Minimal docker CLI wrapper for init/doctor probes (image immune-base:1, no builds, no network)."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess

from immune._cfg import IMMUNE_HOME, CONTAINER_HOME

IMAGE = os.environ.get("IMMUNE_BASE_IMAGE", "immune-base:1")
PREFIX = "immunedoctor-"     # never "immune-": those belong to the running stack / fleet


def available() -> tuple[bool, str]:
    if not shutil.which("docker"):
        return False, "docker CLI not found"
    try:
        p = subprocess.run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], capture_output=True,
                           text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, "docker not usable: %s" % e
    if p.returncode != 0:
        msg = (p.stderr or p.stdout).strip().splitlines()
        return False, "image %s not available (%s)" % (IMAGE, msg[-1] if msg else "docker error")
    return True, ""


def run(mounts: list[tuple[str, str, str]], cmd: list[str], env: dict | None = None, stdin: str | None = None,
        timeout: float = 300, workdir: str = "/app", tmpfs=("/tmp", "/data")) -> tuple[int, str, str]:
    """docker run --rm --network none --read-only ... ; mounts: (host, container, "ro"|"rw")."""
    name = PREFIX + secrets.token_hex(4)
    args = ["docker", "run", "--rm", "-i", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--pids-limit", "256", "--memory", "1g", "-w", workdir,
            "--user", "%d:%d" % (os.getuid(), os.getgid())]
    for t in tmpfs:
        args += ["--tmpfs", "%s:rw,exec,size=256m" % t]
    for host, cont, mode in mounts:
        args += ["-v", "%s:%s:%s" % (os.path.realpath(host), cont, mode)]
    for k, v in (env or {}).items():
        args += ["-e", "%s=%s" % (k, v)]
    args += ["-e", "HOME=/tmp", IMAGE] + cmd
    try:
        p = subprocess.run(args, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return 124, "", "timeout after %ds" % timeout


def boot(module: str, roots: list[str]) -> list[str]:
    code = ("import sys, runpy; sys.path[:0] = %r; sys.argv = [%r]; runpy.run_module(%r, run_name='__main__', "
            "alter_sys=True)") % (roots, module, module)
    return ["python", "-I", "-B", "-c", code]


def last_json(out: str):
    for line in reversed((out or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None


HOME_MOUNT = (IMMUNE_HOME, CONTAINER_HOME, "ro")
