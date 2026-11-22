import os
import shutil
import sqlite3
import textwrap

import pytest
import yaml

from immune.initsteps import detect, drafts, llm, openapi as oa, validate
from immune import shadowdata

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _w(base, rel, text):
    p = os.path.join(base, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(textwrap.dedent(text))


@pytest.fixture()
def proj(tmp_path):
    b = str(tmp_path / "shop")
    _w(b, "requirements.txt", "fastapi\nuvicorn\npytest\n")
    _w(b, "shop/__init__.py", "")
    _w(b, "shop/api/__init__.py", "")
    _w(b, "shop/api/server.py", """
        import os
        from fastapi import FastAPI
        DB = os.environ.get("SHOP_DATABASE", "var/shop.sqlite")
        KEY = os.environ["SHOP_SECRET_KEY"]
        NOW = os.getenv("SHOP_NOW")
        STATIC = os.environ.get("SHOP_STATIC_DIR", "x")
        api = FastAPI(title="Mi Tienda API")
        """)
    _w(b, "shop/api/static/logo.txt", "x")
    _w(b, "tests/test_api.py", "def test_x():\n    assert True\n")
    _w(b, "tests/conftest.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _w(b, "Dockerfile", "FROM python:3.12\nEXPOSE 9000\nCMD uvicorn shop.api.server:api --port 9000\n")
    _w(b, "docker-compose.yml", """
        services:
          db-admin: {image: adminer}
          web:
            build: .
            ports: ["127.0.0.1:8088:9000"]
            environment: [SHOP_DATABASE=/data/shop.sqlite]
            volumes: [shopdata:/data]
        volumes: {shopdata: {}}
        """)
    os.makedirs(os.path.join(b, "var"))
    c = sqlite3.connect(os.path.join(b, "var", "shop.sqlite"))
    c.executescript("CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT NOT NULL, password TEXT NOT NULL,"
                    " role TEXT NOT NULL DEFAULT 'u', created_at TEXT NOT NULL);"
                    "CREATE TABLE carts (id INTEGER PRIMARY KEY, account_id INTEGER REFERENCES accounts(id), memo TEXT,"
                    " status TEXT);"
                    "CREATE TABLE items (id INTEGER PRIMARY KEY, cart_id INTEGER REFERENCES carts(id), sku TEXT);"
                    "CREATE TABLE catalog (id INTEGER PRIMARY KEY, title TEXT, price INTEGER);"
                    "CREATE TABLE sessions (token TEXT PRIMARY KEY, account_id INTEGER NOT NULL, created INTEGER NOT NULL);"
                    "INSERT INTO accounts VALUES (1, 'a@b.c', 'h', 'admin', '2024');")
    c.commit()
    c.close()
    _w(b, ".env", "SHOP_SECRET_KEY=topsecret\n")
    return b


def test_detect_heuristics(proj):
    d = detect.detect(proj)
    assert d["runtime"] == "python-asgi" and d["framework"] == "fastapi"
    assert d["asgi"] == "shop.api.server:api"          # tests/conftest.py's FastAPI() is ignored
    assert d["name"] == "mi-tienda"
    assert d["source_dirs"] == ["shop/api"]
    assert d["release_paths"] == ["requirements.txt", "shop", "tests"]   # var/ (the database) is excluded
    assert d["port"] == 9000 and "docker-compose.yml" in d["port_source"]
    assert d["db_env"] == "SHOP_DATABASE" and d["secret_envs"] == ["SHOP_SECRET_KEY"]
    assert d["time_env"] == "SHOP_NOW" and d["file_envs"] == ["SHOP_STATIC_DIR"]
    assert d["prod_db"] == "var/shop.sqlite"
    assert d["tests_command"] == "python -m pytest tests -q -p no:cacheprovider"
    dep = d["deploy"]
    assert dep["style"] == "compose" and dep["service"] == "web" and dep["ports"][0]["host"] == 8088
    assert dep["dockerfile"] == "Dockerfile"


def test_detect_builtin_victim_copy(tmp_path):
    shutil.copytree(os.path.join(ROOT, "victim"), str(tmp_path / "victim"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    d = detect.detect(str(tmp_path))
    assert d["asgi"] == "victim.app.main:app" and d["name"] == "tienda"
    assert d["db_env"] == "APP_DB" and d["secret_envs"] == ["APP_SECRET"] and d["time_env"] == "APP_NOW"
    assert d["tests_command"].startswith("python -m pytest victim/tests")
    assert d["deploy"]["style"] == "unknown"


def test_detect_no_app(tmp_path):
    _w(str(tmp_path), "main.go", "package main\n")
    d = detect.detect(str(tmp_path))
    assert d["runtime"] == "unknown" and d["problems"]


def test_column_and_marks_drafts_validate(proj):
    schema = shadowdata.dump_schema(os.path.join(proj, "var", "shop.sqlite"))
    doc = {"openapi": "3.0.3", "paths": {
        "/carts/{cart_id}": {"get": {"parameters": [{"name": "cart_id", "in": "path", "required": True}]}},
        "/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/L"}}}}}},
        "/me": {"get": {}}},
        "components": {"schemas": {"L": {"properties": {"email": {"type": "string"}, "password": {"type": "string"}}}}}}
    cols = drafts.columns_draft(schema, doc)
    assert cols["users_table"] == "accounts"
    assert cols["tables"]["carts"]["owner"] == "account_id" and cols["tables"]["carts"]["private"] == ["memo"]
    assert cols["tables"]["items"]["owner"] == {"via": "cart_id", "table": "carts"}
    assert cols["tables"]["catalog"] == {"public": True}
    assert cols["tables"]["sessions"]["secret"] == ["token"]
    assert cols["routes"]["cart_id"] == {"table": "carts", "column": "id"}
    assert shadowdata.validate_columns(cols, schema) == []
    marks = drafts.marks_draft(doc, cols)
    assert [m["op"] for m in marks["owner_scoped"]] == ["GET /carts/{cart_id}"]
    assert marks["sensitive"][0]["name"] == "password"
    assert oa.validate_marks(marks, doc) == []
    out = oa.apply_marks(doc, marks)
    assert out["paths"]["/carts/{cart_id}"]["get"]["x-owner-scoped"] is True
    assert out["components"]["schemas"]["L"]["properties"]["password"]["x-sensitive"] is True
    assert "x-owner-scoped" not in doc["paths"]["/carts/{cart_id}"]["get"]      # input not mutated
    bad = {"owner_scoped": ["GET /nope"], "sensitive": [{"op": "POST /login", "in": "body", "name": "pin"},
                                                        {"op": "POST /login", "in": "cookie2", "name": "x"}]}
    errs = oa.validate_marks(bad, doc)
    assert len(errs) == 3
    auth = drafts.auth_draft(proj, detect.detect(proj), schema, cols, doc)
    assert auth["auth"]["kind"] == "introspect" and auth["auth"]["path"] == "/me"


GOOD = '''
import json, os, sqlite3, secrets, hashlib
from shop.api import server
APP = "shop.api.server:api"
def allowed_file_roots(env):
    return [os.path.join(os.path.dirname(__file__), "static")]
def ensure_user(conn, uid, role):
    pass
def mint_token(env, uid, role):
    return secrets.token_hex(8)
def load_markers(env):
    with open(env["MARKERS_PATH"]) as f:
        return json.load(f)
def public_paths():
    return ["/health"]
'''


@pytest.mark.parametrize("snippet,needle", [
    ("import subprocess", "import subprocess is not allowed"),
    ("from socket import socket", "from socket import"),
    ("x = eval('1')", "eval() is not allowed"),
    ("open('/tmp/x', 'w')", "open() may only read"),
    ("os.system('id')", ".system() is not allowed"),
    ("from . import y", "relative imports"),
    ("o = open\no('/tmp/x', 'w')", "open may only be called"),            # aliasing a builtin
    ("getattr(os, 'sys' + 'tem')('id')", "getattr() is not allowed"),
    ("g = getattr", "getattr() is not allowed"),
    ("__import__('subprocess')", "__import__() is not allowed"),
    ("f = eval", "eval() is not allowed"),
    ("exec('1')", "exec() is not allowed"),
    ("import os as o\no.system('id')", ".system() is not allowed"),
    ("m = os\nm.system('id')", "module os may only be used as os.<name>"),
    ("f = os.system", ".system() is not allowed"),                        # not only when called
    ("from os import system", "from os import system is not allowed"),
    ("os.remove('/tmp/x')", ".remove() is not allowed"),
    ("os.open('/tmp/x', os.O_WRONLY)", ".open() is not allowed"),
    ("json.os.system('id')", "reaching module os through another object"),
    ("(1).__class__.__base__.__subclasses__()", ".__subclasses__ is not allowed"),
])
def test_profile_static_policy_rejects(snippet, needle):
    errs = validate.profile_static(GOOD + "\n" + snippet + "\n", "shop")
    assert any(needle in e for e in errs), errs


PLAIN_METHODS = """
def helper(env, conn, items):
    name = env["APP_STATIC"].replace("//", "/")
    items.remove(name)
    conn.execute("DELETE FROM sessions").fetchall()
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name).replace(os.sep, "/")
"""


def test_profile_static_policy_accepts():
    assert validate.profile_static(GOOD, "shop") == []
    # .replace() / .remove() of strings and lists are not file-system calls
    assert validate.profile_static(GOOD + PLAIN_METHODS, "shop") == []
    assert validate.profile_static("def f(:\n", "shop")[0].startswith("profile.py: syntax error")


def test_auth_validation(tmp_path):
    doc = {"paths": {"/auth/me": {"get": {}}, "/notes/{id}": {"get": {}}}}
    p = str(tmp_path / "auth.yaml")
    for auth, ok in (({"kind": "introspect", "path": "/auth/me", "uid_field": "id"}, True),
                     ({"kind": "introspect", "path": "/notes/{id}", "uid_field": "id"}, False),
                     ({"kind": "oauth"}, False), ({"kind": "jwt-hs256"}, False),
                     ({"kind": "none", "bogus": 1}, False)):
        with open(p, "w") as f:
            yaml.safe_dump({"auth": auth}, f)
        errs, _ = validate.auth(p, doc)
        assert (errs == []) == ok, (auth, errs)


def test_llm_workspace_hides_data_and_returns_only_expected_files(proj, tmp_path):
    seen = {}

    def fake(prompt, work, editable):
        seen["prompt"], seen["editable"] = prompt, editable
        seen["files"] = sorted(os.path.relpath(os.path.join(d, f), work) for d, _, fs in os.walk(work) for f in fs)
        with open(os.path.join(work, ".immune/shadow/columns.yaml"), "a") as f:
            f.write("# reviewed\n")
        with open(os.path.join(work, "shop/api/server.py"), "a") as f:   # a denied edit, simulated
            f.write("# injected\n")

        class R:
            ok, reason, text, denials = True, "", "done", []
        return R()

    res = llm.run_step("columns", proj, {".immune/context/schema.md": "# s"},
                       {".immune/shadow/columns.yaml": "users_table: accounts\n"}, "facts here", None, runner=fake)
    assert res.ok and list(res.files) == [".immune/shadow/columns.yaml"]
    assert res.files[".immune/shadow/columns.yaml"].endswith("# reviewed\n") and res.changed
    assert seen["editable"] == [".immune/shadow/columns.yaml"]
    assert not any(f.endswith((".sqlite", ".env")) for f in seen["files"])     # data and secrets never copied
    assert "shop/api/server.py" in seen["files"]
    assert "untrusted data" in seen["prompt"] and "FACTS-" in seen["prompt"]
    with open(os.path.join(proj, "shop/api/server.py")) as f:
        assert "# injected" not in f.read()                                  # the project itself is untouched
