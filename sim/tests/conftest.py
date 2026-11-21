import importlib
import json
import os
import sqlite3
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

FROZEN = "1767225600"  # 2026-01-01T00:00:00Z


@pytest.fixture(scope="session")
def seeded(tmp_path_factory):
    d = tmp_path_factory.mktemp("seed")
    p = {k: str(d / v) for k, v in {"prod": "prod.db", "shadow": "shadow.db", "manifest": "m.json", "markers": "k.json"}.items()}
    subprocess.run([sys.executable, "-m", "victim.seed", "--out-prod", p["prod"], "--out-shadow", p["shadow"],
                    "--manifest", p["manifest"], "--markers", p["markers"], "--seed", "1"], check=True, cwd=ROOT)
    p["m"] = json.load(open(p["manifest"]))
    return p


def fresh_db(seeded, path):
    src, dst = sqlite3.connect(seeded["prod"]), sqlite3.connect(str(path))
    src.backup(dst)
    src.close()
    dst.close()
    return str(path)


def load_app(db, monkeypatch, frozen=True):
    monkeypatch.setenv("APP_DB", db)
    monkeypatch.setenv("APP_SECRET", "test-secret")
    monkeypatch.setenv("APP_STATIC", os.path.join(ROOT, "victim", "static"))
    if frozen:
        monkeypatch.setenv("APP_NOW", FROZEN)
    else:
        monkeypatch.delenv("APP_NOW", raising=False)
    for m in [m for m in sys.modules if m == "victim" or m.startswith("victim.")]:
        del sys.modules[m]
    return importlib.import_module("victim.app.main").app


@pytest.fixture()
def make_client(seeded, tmp_path, monkeypatch):
    from starlette.testclient import TestClient
    n = [0]

    def make():
        n[0] += 1
        return TestClient(load_app(fresh_db(seeded, tmp_path / ("w%d.db" % n[0])), monkeypatch))
    return make


@pytest.fixture()
def manifest(seeded):
    return seeded["m"]
