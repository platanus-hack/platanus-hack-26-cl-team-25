import os
import sqlite3
import subprocess
import sys
import uuid

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session")
def db_file(tmp_path_factory):
    path = str(tmp_path_factory.mktemp("db") / "test.db")
    subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "init_db.py"), "--db", path],
        check=True,
        cwd=ROOT,
    )
    return path


@pytest.fixture(scope="session", autouse=True)
def env(db_file):
    os.environ["NOTAS_DB"] = db_file
    os.environ["NOTAS_FILES"] = os.path.join(ROOT, "notas", "files")
    yield


@pytest.fixture()
def client(env):
    from notas.main import app

    return TestClient(app)


def login(client, email, password):
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["token"]}


@pytest.fixture()
def admin(client):
    return login(client, "admin@notas.example", "admin123")


@pytest.fixture()
def make_user(client):
    def make(name="Usuario de Prueba"):
        email = "prueba.%s@notas.example" % uuid.uuid4().hex[:10]
        r = client.post(
            "/auth/register", json={"email": email, "name": name, "password": "secreto1"}
        )
        assert r.status_code == 201
        return {"id": r.json()["id"], "email": email, "headers": login(client, email, "secreto1")}

    return make


@pytest.fixture()
def db_query(db_file):
    def run(sql, params=()):
        conn = sqlite3.connect(db_file)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    return run
