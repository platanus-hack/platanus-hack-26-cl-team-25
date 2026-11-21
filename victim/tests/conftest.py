import importlib
import os
import sqlite3
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import json  # noqa: E402


@pytest.fixture(scope="session")
def seeded(tmp_path_factory):
    d = tmp_path_factory.mktemp("seed")
    p = {k: str(d / v) for k, v in {"prod": "prod.db", "shadow": "shadow.db", "manifest": "m.json", "markers": "k.json"}.items()}
    subprocess.run([sys.executable, "-m", "victim.seed", "--out-prod", p["prod"], "--out-shadow", p["shadow"],
                    "--manifest", p["manifest"], "--markers", p["markers"], "--seed", "1"], check=True, cwd=ROOT)
    p["m"] = json.load(open(p["manifest"]))
    return p


def make_client(db, monkeypatch):
    monkeypatch.setenv("APP_DB", db)
    monkeypatch.setenv("APP_SECRET", "test-secret")
    monkeypatch.setenv("APP_STATIC", os.path.join(ROOT, "victim", "static"))
    monkeypatch.delenv("APP_NOW", raising=False)
    for m in [m for m in sys.modules if m == "victim" or m.startswith("victim.")]:
        del sys.modules[m]
    from starlette.testclient import TestClient
    return TestClient(importlib.import_module("victim.app.main").app)


@pytest.fixture()
def client(seeded, tmp_path, monkeypatch):
    work = str(tmp_path / "work.db")
    src, dst = sqlite3.connect(seeded["prod"]), sqlite3.connect(work)
    src.backup(dst)
    src.close(); dst.close()
    return make_client(work, monkeypatch)


@pytest.fixture()
def manifest(seeded):
    return seeded["m"]


def auth_header(c, user):
    r = c.post("/api/login", json={"email": user["email"], "password": user["password"]})
    assert r.status_code == 200, r.text
    return {"authorization": "Bearer " + r.json()["token"]}


@pytest.fixture()
def user_h(client, manifest):
    u = manifest["legit_users"][0]
    return u, auth_header(client, u)


@pytest.fixture()
def admin_h(client, manifest):
    return auth_header(client, manifest["admin"])
