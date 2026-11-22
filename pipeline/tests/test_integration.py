"""Real runner containers (docker --network none, immune-base:1) with the real shadow harness.
Skipped when Docker or the image is unavailable. Containers are named pipetest-runner-*."""
import os
import shutil
import subprocess

import pytest

from pipeline import fixes, incident, poc
from pipeline.config import Config
from pipeline.gates import Validator

from .conftest import FIX


def _docker_ok():
    if not shutil.which("docker"):
        return False
    p = subprocess.run(["docker", "image", "inspect", "immune-base:1"], capture_output=True)
    return p.returncode == 0


pytestmark = [pytest.mark.skipif(not _docker_ok(), reason="docker / immune-base:1 unavailable"),
              pytest.mark.timeout(600)]


@pytest.fixture()
def docker_env(monkeypatch, tmp_path):
    monkeypatch.setenv("RUNNER_PREFIX", "pipetest-runner")
    monkeypatch.setenv("PIPELINE_STATE_DIR", str(tmp_path / "state"))


def test_gates_real_runner(docker_env, t0, spec, events):
    cfg = Config.from_env()
    v = Validator(cfg)
    inc = incident.build(events["traversal"], spec)
    inc["incident"] = "it-1"
    p = poc.build(inc, "t0")
    rep = v.reproduce(inc, p, t0)
    assert rep["reproducible"] and rep["counted"]
    seen = []
    ok, res, _ = v.validate(inc, p, rep, t0, fixes.diff_for(fixes.adequate("traversal"), t0, inc),
                            on_result=lambda g, o, d, s: seen.append(g))
    assert ok and seen == ["policy", "properties", "poc", "tests", "legit"], res
    ok, res, _ = v.validate(inc, p, rep, t0, fixes.diff_for(fixes.BY_NAME["traversal-pardir-only"], t0, inc))
    assert not ok and res[-1][0] == "poc" and "still fires the file oracle" in res[-1][2]


def test_dry_run_end_to_end(docker_env, tmp_path):
    from pipeline import dryrun
    res = dryrun.run([os.path.join(FIX, "oracle_sqli.json")], workdir=str(tmp_path / "dry"))
    (iid, inc), = res["incidents"].items()
    assert inc["outcome"] == "patched", inc.get("reason")
    seq = [dryrun.label(e) for e in res["events"]]
    assert seq == dryrun.EXPECTED
    rel = os.path.join(res["runtime"], "releases", inc["release"], "victim", "app", "products.py")
    assert "LIKE ? OR category" in open(rel).read()
    assert res["rules_deleted"] == [inc["rule"]["id"]] and res["deploys"] == [inc["release"]]
    assert subprocess.run(["docker", "ps", "-aq", "--filter", "name=pipetest-runner"], capture_output=True,
                          text=True).stdout.strip() == ""
