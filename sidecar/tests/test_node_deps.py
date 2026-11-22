"""The Node fixture's node_modules is installed on demand (not kept in git): sidecar/tests/dockerenv.py."""
import os
import shutil

import pytest

from sidecar.tests import dockerenv
from sidecar.tests.dockerenv import DepsUnavailable, ensure_node_deps


class Run:
    """Stands in for subprocess.run: records the command; `install` decides whether it leaves node_modules/pg."""
    def __init__(self, app_dir, install=True, code=0):
        self.app_dir, self.install, self.code, self.calls = str(app_dir), install, code, []

    def __call__(self, cmd, cwd=None, **kw):
        self.calls.append((cmd, cwd))
        if self.install:
            os.makedirs(os.path.join(self.app_dir, "node_modules", "pg"))
        return type("P", (), {"returncode": self.code, "stdout": "", "stderr": "npm ERR! network"})()


def which(*present):
    return lambda name: "/usr/bin/" + name if name in present else None


def test_installed_dependencies_are_left_alone(tmp_path, monkeypatch):
    os.makedirs(tmp_path / "node_modules" / "pg")
    run = Run(tmp_path)
    monkeypatch.setattr(dockerenv.subprocess, "run", run)
    ensure_node_deps(str(tmp_path))
    assert run.calls == []


def test_missing_dependencies_are_installed_from_the_lockfile_with_host_npm(tmp_path, monkeypatch):
    run = Run(tmp_path)
    monkeypatch.setattr(dockerenv.subprocess, "run", run)
    monkeypatch.setattr(dockerenv.shutil, "which", which("npm", "docker"))
    ensure_node_deps(str(tmp_path))
    assert run.calls == [(["npm", "ci", "--omit=dev", "--no-audit", "--no-fund"], str(tmp_path))]


def test_without_npm_a_one_off_container_of_the_app_image_installs_them(tmp_path, monkeypatch):
    run = Run(tmp_path)
    monkeypatch.setattr(dockerenv.subprocess, "run", run)
    monkeypatch.setattr(dockerenv.shutil, "which", which("docker"))
    ensure_node_deps(str(tmp_path))
    [(cmd, cwd)] = run.calls
    assert cmd[:3] == ["docker", "run", "--rm"] and f"{tmp_path}:/app" in cmd and "--network" not in cmd
    assert cmd[cmd.index("node:22-alpine") + 1:] == ["npm", "ci", "--omit=dev", "--no-audit", "--no-fund"]


@pytest.mark.parametrize("tools,install,code", [((), False, 0), (("npm",), False, 1), (("docker",), False, 0)])
def test_when_they_cannot_be_installed_the_reason_is_explicit(tmp_path, monkeypatch, tools, install, code):
    monkeypatch.setattr(dockerenv.subprocess, "run", Run(tmp_path, install, code))
    monkeypatch.setattr(dockerenv.shutil, "which", which(*tools))
    with pytest.raises(DepsUnavailable, match="node_modules is missing"):
        ensure_node_deps(str(tmp_path))


def test_node_modules_is_ignored_by_git():
    root = dockerenv.ROOT
    if shutil.which("git") is None or not os.path.isdir(os.path.join(root, ".git")):
        pytest.skip("not a git checkout")
    import subprocess
    for d in ("sidecar/examples/node/node_modules/x", "examples/tareas-node/node_modules/x"):
        r = subprocess.run(["git", "-C", root, "check-ignore", "-q", "--no-index", d])
        assert r.returncode == 0, d
