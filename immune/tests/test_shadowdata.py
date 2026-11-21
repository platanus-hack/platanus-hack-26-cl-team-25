import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys

import pytest

from immune import shadowdata as sd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MK = re.compile(r"MK[A-Z0-9]{10}")

SCHEMA = """
CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT NOT NULL UNIQUE, full_name TEXT NOT NULL,
  phone TEXT, kind TEXT NOT NULL DEFAULT 'member', pw TEXT NOT NULL, prefs TEXT, created_at TEXT NOT NULL);
CREATE TABLE posts (id INTEGER PRIMARY KEY, author INTEGER NOT NULL REFERENCES accounts(id), title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0, updated_at TEXT);
CREATE TABLE comments (id INTEGER PRIMARY KEY, post_id INTEGER NOT NULL REFERENCES posts(id), text TEXT NOT NULL);
CREATE TABLE tags (id INTEGER PRIMARY KEY, label TEXT NOT NULL);
CREATE TABLE post_tags (post_id INTEGER NOT NULL, tag_id INTEGER NOT NULL, PRIMARY KEY (post_id, tag_id)) WITHOUT ROWID;
CREATE TABLE tokens (tok TEXT PRIMARY KEY, account_id INTEGER NOT NULL, issued INTEGER NOT NULL);
CREATE TABLE audit (id INTEGER PRIMARY KEY, what TEXT NOT NULL);
CREATE TRIGGER posts_touch AFTER UPDATE ON posts BEGIN INSERT INTO audit (what) VALUES ('touched'); END;
"""

COLUMNS = {
    "users_table": "accounts", "user_id_column": "id", "role_column": "kind",
    "login_column": "login", "secret_column": "pw",
    "tables": {
        "accounts": {"owner": "id", "private": ["login", "full_name", "phone", "prefs"], "secret": ["pw"]},
        "posts": {"owner": "author", "private": ["title", "body"]},
        "comments": {"owner": {"via": "post_id", "table": "posts"}, "private": ["text"]},
        "tags": {"public": True},
        "post_tags": {"public": True},
        "tokens": {"owner": "account_id", "secret": ["tok"]},
        "audit": {"public": True},
    },
    "routes": {"post_id": {"table": "posts", "column": "id"}, "account_id": {"table": "accounts", "column": "id"}},
}


def _make_prod(path):
    c = sqlite3.connect(path)
    c.executescript(SCHEMA)
    for i in range(1, 31):
        kind = "admin" if i == 1 else "member"
        c.execute("INSERT INTO accounts VALUES (?,?,?,?,?,?,?,?)",
                  (i, "real.person%d@corp.example" % i, "Realname Person%d O'Hara" % i,
                   None if i % 5 == 0 else "+1 202 555 %04d" % i, kind,
                   hashlib.sha256(b"pw%d" % i).hexdigest(), json.dumps({"nick": "realnick%d" % i, "n": i}),
                   "2024-01-%02dT10:00:00Z" % (i % 28 + 1)))
    for p in range(1, 81):
        c.execute("INSERT INTO posts VALUES (?,?,?,?,?,?)", (p, (p % 30) + 1, "Real title number %d" % p,
                                                             "Real body text of post %d with details" % p if p % 7 else "",
                                                             p * 3, None))
        c.execute("INSERT INTO comments (post_id, text) VALUES (?, ?)", (p, "real comment on %d" % p))
    for t in range(1, 6):
        c.execute("INSERT INTO tags VALUES (?, ?)", (t, "tag%d" % t))
    for p in range(1, 81, 3):
        c.execute("INSERT INTO post_tags VALUES (?, ?)", (p, p % 5 + 1))
    for i in range(1, 31):
        c.execute("INSERT INTO tokens VALUES (?,?,?)", ("%048x" % (i * 7919), i, 1700000000 + i))
    c.commit()
    c.close()


@pytest.fixture()
def prod(tmp_path):
    p = str(tmp_path / "prod.db")
    _make_prod(p)
    return p


def _rows(db, sql):
    c = sqlite3.connect(db)
    try:
        return c.execute(sql).fetchall()
    finally:
        c.close()


def _hasher(pws):
    return [hashlib.sha256(p.encode()).hexdigest() for p in pws]


def test_validate_columns_accepts_and_rejects(prod):
    schema = sd.dump_schema(prod)
    assert sd.validate_columns(COLUMNS, schema) == []
    bad = json.loads(json.dumps(COLUMNS))
    del bad["tables"]["audit"]
    bad["tables"]["posts"]["private"].append("author")
    bad["tables"]["nope"] = {"public": True}
    bad["routes"]["x_id"] = {"table": "posts", "column": "missing"}
    errs = "\n".join(sd.validate_columns(bad, schema))
    assert "'audit' is not classified" in errs
    assert "key/foreign-key" in errs or "owner column" in errs
    assert "nope: no such table" in errs
    assert "missing" in errs


def test_synthetic_schema_skeleton_markers_no_leak(prod, tmp_path):
    out = str(tmp_path / "out")
    rep = sd.build_db(prod, COLUMNS, out, seed=3, hash_password=_hasher)
    seed = rep["seed_db"]
    m = json.load(open(os.path.join(out, "manifest.json")))
    markers = json.load(open(os.path.join(out, "markers.json")))
    assert json.load(open(os.path.join(out, "shadow", "markers.json"))) == markers
    canary_u = set(m["canary_users"])
    # skeleton: same tables, same ids, same foreign keys (canaries are extra rows)
    assert _rows(prod, "SELECT id, kind FROM accounts ORDER BY id") == \
        _rows(seed, "SELECT id, kind FROM accounts WHERE id <= 30 ORDER BY id")
    assert _rows(prod, "SELECT id, author, score FROM posts ORDER BY id") == \
        _rows(seed, "SELECT id, author, score FROM posts WHERE id <= 80 ORDER BY id")
    assert _rows(prod, "SELECT id, post_id FROM comments") == _rows(seed, "SELECT id, post_id FROM comments")
    assert _rows(prod, "SELECT * FROM tags") == _rows(seed, "SELECT * FROM tags")
    assert _rows(prod, "SELECT * FROM post_tags") == _rows(seed, "SELECT * FROM post_tags")
    assert _rows(prod, "SELECT account_id, issued FROM tokens ORDER BY account_id") == \
        _rows(seed, "SELECT account_id, issued FROM tokens ORDER BY account_id")
    # triggers were not fired by the rewrite, and still exist
    assert _rows(seed, "SELECT COUNT(*) FROM audit") == [(0,)]
    assert _rows(seed, "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'") == [(1,)]
    # markers: every private value of an owned row carries its owner's marker
    inv = {v: k for k, v in markers.items()}
    assert len(inv) == len(markers)
    for uid, login, name, phone in _rows(seed, "SELECT id, login, full_name, phone FROM accounts"):
        mk = inv[uid]
        assert mk in login and mk in name and (phone is None or mk in phone)
    for pid, author, title, body in _rows(seed, "SELECT id, author, title, body FROM posts"):
        assert inv[author] in title and inv[author] in body
    for cid, post, text in _rows(seed, "SELECT c.id, p.author, c.text FROM comments c JOIN posts p ON p.id = c.post_id"):
        assert inv[post] in text
    # json private value stays json, with synthetic strings
    prefs = json.loads(_rows(seed, "SELECT prefs FROM accounts WHERE id = 2")[0][0])
    assert set(prefs) == {"nick", "n"} and "realnick" not in prefs["nick"]
    # NULL stays NULL
    assert _rows(seed, "SELECT phone FROM accounts WHERE id = 5") == [(None,)]
    # secrets: randomised, same shape
    for (a,), (b,) in zip(_rows(prod, "SELECT tok FROM tokens ORDER BY account_id"),
                          _rows(seed, "SELECT tok FROM tokens ORDER BY account_id")):
        assert a != b and len(a) == len(b) and re.fullmatch(r"[0-9a-f]+", b)
    # no MK in prod, no real value in shadow
    assert rep["prod_markers_found"] == 0
    assert sd.leak_check(prod, seed, COLUMNS) == []
    dump = "\n".join(map(str, _rows(seed, "SELECT * FROM accounts") + _rows(seed, "SELECT * FROM posts")))
    assert "real.person" not in dump and "Realname" not in dump and "Real title" not in dump
    # canaries
    assert len(canary_u) == 2 and all(u > 30 for u in canary_u)
    assert set(m["canaries"]["account_id"]) == canary_u
    assert len(m["canaries"]["post_id"]) == 2
    for cid in m["canaries"]["post_id"]:
        (author,) = _rows(seed, "SELECT author FROM posts WHERE id = %d" % cid)[0]
        assert author in canary_u
        assert m["ownership"]["posts"][str(cid)] == author
    assert m["seed_max_uid"] == 30
    assert m["ownership"]["posts"]["1"] == 2 and m["ownership"]["comments"]["1"] == 2
    assert all(u["id"] not in canary_u and u["role"] != "admin" for u in m["legit_users"])
    assert m["admin"]["id"] == 1
    # known passwords: the shadow hash matches the generated password
    u = m["legit_users"][0]
    (pw, login), = _rows(seed, "SELECT pw, login FROM accounts WHERE id = %d" % u["id"])
    assert pw == hashlib.sha256(u["password"].encode()).hexdigest() and login == u["email"]
    # prod untouched
    assert _rows(prod, "SELECT COUNT(*) FROM accounts") == [(30,)]


def test_deterministic_for_a_seed(prod, tmp_path):
    def dump(seed, d):
        out = str(tmp_path / d)
        rep = sd.build_db(prod, COLUMNS, out, seed=seed)
        c = sqlite3.connect(rep["seed_db"])
        try:
            return "\n".join(c.iterdump()), open(os.path.join(out, "manifest.json")).read()
        finally:
            c.close()
    a, b, c = dump(1, "a"), dump(1, "b"), dump(2, "c")
    assert a == b
    assert a[0] != c[0]


def test_leak_check_finds_a_misclassified_copy(prod, tmp_path):
    cols = json.loads(json.dumps(COLUMNS))
    cols["tables"]["posts"]["private"] = ["body"]          # title wrongly left out
    rep = sd.build_db(prod, cols, str(tmp_path / "o"), seed=1)
    # title is not private, so it is copied; it is not sampled either -> self-check passes...
    assert sd.leak_check(prod, rep["seed_db"], cols) == []
    # ...but with title declared private and the old shadow, the copy is found
    leaks = sd.leak_check(prod, rep["seed_db"], COLUMNS)
    assert leaks and leaks[0]["column"] == "posts.title" and leaks[0]["found_in"] == "posts.title"
    assert "Real" not in json.dumps(leaks)                 # the report never prints the value


def test_build_refuses_columns_that_do_not_match(prod, tmp_path):
    cols = json.loads(json.dumps(COLUMNS))
    cols["tables"]["accounts"]["private"].append("ghost")
    with pytest.raises(sd.ColumnsError):
        sd.build_db(prod, cols, str(tmp_path / "o"))


VICTIM_COLUMNS = {
    "users_table": "users", "user_id_column": "id", "role_column": "role", "login_column": "email",
    "secret_column": "password_hash",
    "tables": {"users": {"owner": "id", "private": ["email", "name", "address", "phone"], "secret": ["password_hash"]},
               "orders": {"owner": "user_id", "private": ["note", "shipping_address"]},
               "order_items": {"owner": {"via": "order_id", "table": "orders"}},
               "products": {"public": True}},
    "routes": {"order_id": {"table": "orders", "column": "id"}, "user_id": {"table": "users", "column": "id"}},
}


def test_builtin_victim_prod_database(tmp_path):
    d = tmp_path / "v"
    d.mkdir()
    subprocess.run([sys.executable, "-m", "victim.seed", "--out-prod", str(d / "prod.db"), "--out-shadow",
                    str(d / "x.db"), "--manifest", str(d / "m.json"), "--markers", str(d / "k.json")],
                   cwd=ROOT, check=True)
    prod = str(d / "prod.db")
    rep = sd.build_db(prod, VICTIM_COLUMNS, str(d / "out"), seed=1, hash_password=_hasher)
    seed = rep["seed_db"]
    for t, cols in (("users", "id, role, created_at"), ("orders", "id, user_id, status, total, created_at"),
                    ("order_items", "*"), ("products", "*")):
        assert _rows(prod, "SELECT %s FROM %s ORDER BY id" % (cols, t)) == \
            _rows(seed, "SELECT %s FROM %s WHERE id <= (SELECT MAX(id) FROM %s) - 0 AND id < 100000 ORDER BY id"
                  % (cols, t, t))
    markers = json.load(open(str(d / "out" / "markers.json")))
    inv = {v: k for k, v in markers.items()}
    for oid, uid, note, addr in _rows(seed, "SELECT id, user_id, note, shipping_address FROM orders"):
        assert inv[uid] in note and inv[uid] in addr
    for uid, email, name in _rows(seed, "SELECT id, email, name FROM users"):
        assert inv[uid] in email and inv[uid] in name
    assert not any(MK.search(str(v)) for r in _rows(prod, "SELECT * FROM users") for v in r)
    assert sd.leak_check(prod, seed, VICTIM_COLUMNS) == []
    prod_emails = {e for (e,) in _rows(prod, "SELECT email FROM users")}
    assert not prod_emails & {e for (e,) in _rows(seed, "SELECT email FROM users")}
    m = json.load(open(str(d / "out" / "manifest.json")))
    assert m["seed_max_uid"] == 60 and m["seed_max_order_id"] == 240
    assert m["ownership"]["orders"]["12"] == 7
    assert set(m["canaries"]) == {"order_id", "user_id"}
