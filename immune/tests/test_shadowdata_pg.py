"""immune.shadowdata_pg without Docker: catalog + rows (as read from Postgres) -> SQLite -> shadowdata.build_db -> SQL dump."""
import json
import re
import sqlite3

from immune import shadowdata, shadowdata_pg as sp

META = {
    "tables": ["sessions", "tasks", "users"],
    "columns": [
        {"table": "users", "name": "id", "type": "integer", "nullable": False, "default": "nextval('users_id_seq'::regclass)"},
        {"table": "users", "name": "email", "type": "text", "nullable": False, "default": None},
        {"table": "users", "name": "name", "type": "text", "nullable": False, "default": None},
        {"table": "users", "name": "password_hash", "type": "text", "nullable": False, "default": None},
        {"table": "users", "name": "role", "type": "text", "nullable": False, "default": "'user'::text"},
        {"table": "users", "name": "active", "type": "boolean", "nullable": True, "default": None},
        {"table": "sessions", "name": "token_hash", "type": "text", "nullable": False, "default": None},
        {"table": "sessions", "name": "user_id", "type": "integer", "nullable": False, "default": None},
        {"table": "tasks", "name": "id", "type": "integer", "nullable": False, "default": "nextval('tasks_id_seq'::regclass)"},
        {"table": "tasks", "name": "user_id", "type": "integer", "nullable": False, "default": None},
        {"table": "tasks", "name": "title", "type": "text", "nullable": False, "default": None},
        {"table": "tasks", "name": "notes", "type": "text", "nullable": False, "default": None},
        {"table": "tasks", "name": "due_date", "type": "date", "nullable": True, "default": None},
    ],
    "pks": [{"table": "users", "column": "id", "pos": 1}, {"table": "tasks", "column": "id", "pos": 1},
            {"table": "sessions", "column": "token_hash", "pos": 1}],
    "fks": [{"table": "tasks", "from": "user_id", "ref": "users", "to": "id"},
            {"table": "sessions", "from": "user_id", "ref": "users", "to": "id"}],
}
COLS = {"users_table": "users", "user_id_column": "id", "role_column": "role",
        "tables": {"users": {"owner": "id", "private": ["email", "name"], "secret": ["password_hash"]},
                   "sessions": {"owner": "user_id", "secret": ["token_hash"]},
                   "tasks": {"owner": "user_id", "private": ["title", "notes"]}},
        "routes": {"task_id": {"table": "tasks", "column": "id"}}}


def prod():
    users = [{"id": i, "email": "persona%d@correo.cl" % i, "name": "Persona Real %d" % i, "password_hash": "scrypt$ab$cd%d" % i,
              "role": "admin" if i == 1 else "user", "active": i % 2 == 0} for i in range(1, 6)]
    tasks = [{"id": 10 + i, "user_id": 1 + i % 5, "title": "Pagar arriendo O'Higgins %d" % i, "notes": "nota real %d" % i,
              "due_date": "2026-12-%02d" % (i + 1)} for i in range(12)]
    return {"meta": META, "pre": "CREATE TABLE public.users (...);\n", "post": "ALTER TABLE ONLY public.tasks ADD ...;\n",
            "rows": {"users": users, "tasks": tasks, "sessions": [{"token_hash": "deadbeef" * 8, "user_id": 2}]}}


def test_roundtrip_keeps_keys_and_replaces_private_values(tmp_path):
    p = prod()
    lite = str(tmp_path / "prod.db")
    sp.to_sqlite(p, lite)
    c = sqlite3.connect(lite)
    assert c.execute("SELECT count(*) FROM tasks").fetchone()[0] == 12
    assert c.execute("SELECT active FROM users WHERE id = 2").fetchone()[0] == 1
    c.close()
    rep = shadowdata.build_db(lite, COLS, str(tmp_path / "out"), seed=1)
    sql = sp.to_sql(p, rep["seed_db"])
    assert sql.index("CREATE TABLE") < sql.index('INSERT INTO public."users"') < sql.index('INSERT INTO public."tasks"') \
        < sql.index("setval(") < sql.index("ALTER TABLE ONLY")
    for real in ("persona3@correo.cl", "Persona Real 3", "nota real 4", "scrypt$ab$cd2", "deadbeef" * 8):
        assert real not in sql
    assert re.search(r"INSERT INTO public\.\"tasks\" .*VALUES \(11, 2, '[^']*MK[A-Z0-9]{10}", sql)
    assert "VALUES (2, " in sql and ", true);" in sql            # booleans back as true/false
    manifest = json.load(open(tmp_path / "out" / "manifest.json"))
    assert manifest["seed_max_uid"] == 5 and len(manifest["canaries"]["task_id"]) == 2
    assert all(int(k) in range(10, 22) or int(k) > 100000 for k in manifest["ownership"]["tasks"])


def test_helpers():
    assert sp.literal("O'Brien") == "'O''Brien'" and sp.literal(None) == "NULL" and sp.literal(True) == "true"
    assert sp.fk_order(META) == ["users", "sessions", "tasks"]
    dump = "\\restrict abc\nCREATE SCHEMA public;\nCREATE TABLE public.t (id int);\n\\unrestrict abc\n"
    assert sp._clean_dump(dump) == "CREATE TABLE public.t (id int);\n"
