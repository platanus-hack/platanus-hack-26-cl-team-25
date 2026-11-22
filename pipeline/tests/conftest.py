import json
import os
import shutil
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
FIX = os.path.join(HERE, "fixtures")


def load_fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def spec():
    from pipeline import openapi
    return openapi.load(os.path.join(ROOT, "contracts", "openapi.yaml"))


@pytest.fixture()
def t0(tmp_path):
    """A release dir with a pristine copy of the repo's victim/ (== t0)."""
    d = tmp_path / "t0"
    shutil.copytree(os.path.join(ROOT, "victim"), d / "victim", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return str(d)


@pytest.fixture()
def events():
    return {k: load_fixture("oracle_%s.json" % k) for k in ("sqli", "traversal", "idor")}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Fake bus, gateway and fleet over HTTP, a t0 release in a temp runtime, and the pipeline Config for them
    (shared by test_orchestrator.py and test_audit.py)."""
    from pipeline import stub_patcher
    from pipeline.config import Config
    from pipeline.fakes import FakeBus, FakeFleet, FakeGateway
    rt = tmp_path / "runtime"
    shutil.copytree(os.path.join(ROOT, "victim"), rt / "releases" / "t0" / "victim",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    b = FakeBus("bt")
    gw = FakeGateway(b, "at")
    fl = FakeFleet(b, str(rt), "at")
    monkeypatch.delenv("STUB_PATCHER_PLAN", raising=False)
    stub_patcher.calls.clear()
    e = {"RUNTIME_DIR": str(rt), "RUN_ID": "t", "BUS_TOKEN": "bt", "ADMIN_TOKEN": "at", "PIPELINE_BUS_URL": b.url,
         "GATEWAY_ADMIN_URL": gw.admin_url, "GATEWAY_URL": gw.data_url, "FLEET_URL": fl.url, "REPO_DIR": ROOT,
         "PIPELINE_VERIFY_WAIT_S": "2", "MANIFEST_PATH_HOST": str(tmp_path / "none.json")}
    cfg = Config.from_env(e)
    yield {"cfg": cfg, "bus": b, "gw": gw, "fleet": fl, "rt": str(rt)}
    b.stop()
    gw.stop()
    fl.stop()
