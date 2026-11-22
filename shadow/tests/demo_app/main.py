import gzip, importlib, os, socket, sqlite3, subprocess, sys, traceback
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, Response
from immune_contracts import authtoken

app = FastAPI()
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
ORDER = {"cheap": "price ASC, id ASC", "name": "name ASC"}
_kept = []


def db():
    conn = sqlite3.connect(os.environ["APP_DB"])
    conn.row_factory = sqlite3.Row
    return conn


def who(authorization):
    ident = authtoken.verify(os.environ["APP_SECRET"], (authorization or "")[7:])
    if not ident:
        raise HTTPException(401, "unauthorized")
    return ident


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/search")
def search(q: str = ""):
    rows = db().execute("SELECT id, name FROM items WHERE name LIKE '%" + q + "%'").fetchall()
    return [dict(r) for r in rows]


@app.get("/safe")
def safe(q: str = ""):
    return [dict(r) for r in db().execute("SELECT id, name FROM items WHERE name LIKE ?", (f"%{q}%",)).fetchall()]


@app.get("/item/{item_id}")
def item(item_id: int):
    row = db().execute(f"SELECT id, name FROM items WHERE id = {item_id}").fetchone()
    if not row:
        raise HTTPException(404, "nf")
    return dict(row)


@app.get("/tag/{tag}")
def by_tag(tag: str):
    return [dict(r) for r in db().execute("SELECT id, name FROM items WHERE name = '" + tag + "'").fetchall()]


@app.get("/raw")
def raw(id: str):
    return [dict(r) for r in db().execute("SELECT id, name FROM items WHERE id = " + id).fetchall()]


@app.get("/sorted")
def sorted_items(sort: str = "name"):
    return [dict(r) for r in db().execute("SELECT id, name FROM items ORDER BY " + ORDER.get(sort, "id")).fetchall()]


@app.get("/col")
def col(c: str = "name"):
    return [dict(r) for r in db().execute("SELECT id FROM items ORDER BY " + c).fetchall()]


@app.get("/escaped")
def escaped(q: str = ""):
    lit = "'" + q.replace("'", "''") + "'"
    return [dict(r) for r in db().execute("SELECT id FROM items WHERE name = " + lit).fetchall()]


@app.get("/upper")
def upper(q: str = ""):
    return [dict(r) for r in db().execute("SELECT id FROM items WHERE name = '" + q.upper() + "'").fetchall()]


@app.post("/script")
def script(payload: dict):
    db().executescript("UPDATE items SET name = '" + payload.get("name", "") + "' WHERE id = 1;")
    return {"ok": True}


@app.get("/ping")
def ping(host: str = "x"):
    subprocess.run(["true"], check=False)
    return {"ok": True}


@app.get("/fetch")
def fetch(port: int = 9):
    s = socket.socket()
    try:
        s.settimeout(0.5)
        s.connect_ex(("127.0.0.1", port))
    finally:
        s.close()
    return {"ok": True}


@app.get("/file")
def file(name: str):
    with open(os.path.join(STATIC, name), "rb") as f:
        return Response(f.read(), media_type="text/plain")


@app.get("/send")
def send(name: str):
    return FileResponse(os.path.join(STATIC, name))


@app.get("/ls")
def ls(d: str = "."):
    return os.listdir(os.path.join(STATIC, d))


@app.post("/login")
def login(payload: dict):
    row = db().execute("SELECT id, name FROM users WHERE id = ?", (int(payload.get("uid", 0)),)).fetchone()
    if not row:
        raise HTTPException(401, "bad")
    return {"user": dict(row), "token": "t"}


@app.get("/dump")
def dump():
    return [dict(r) for r in db().execute("SELECT id, name FROM users").fetchall()]


@app.get("/note/{nid}")
def note(nid: int, authorization: str = Header(None)):
    who(authorization)
    row = db().execute("SELECT id, user_id, body FROM notes WHERE id = ?", (nid,)).fetchone()
    if not row:
        raise HTTPException(404, "nf")
    return dict(row)


@app.get("/gz")
def gz():
    return Response(gzip.compress(b"secret MKBBBBBBBBB2"), headers={"content-encoding": "gzip"})


@app.post("/note")
def add_note(payload: dict, authorization: str = Header(None)):
    ident = who(authorization)
    conn = db()
    cur = conn.execute("INSERT INTO notes (user_id, body) VALUES (?, ?)", (ident.uid, payload.get("body", "")))
    conn.commit()
    _kept.append(conn)  # a connection the app keeps open across requests
    return {"id": cur.lastrowid}


@app.get("/wall")
def wall(authorization: str = Header(None)):
    """Stored XSS sink: every note body dropped into an HTML page without escaping."""
    who(authorization)
    rows = db().execute("SELECT body FROM notes ORDER BY id").fetchall()
    html = "<html><body><h1>wall</h1>" + "".join("<div class=note>%s</div>" % r["body"] for r in rows) + "</body></html>"
    return Response(html, media_type="text/html")


@app.get("/note_search")
def note_search(authorization: str = Header(None)):
    """Second-order SQLi sink: the most recent note body is concatenated into a query."""
    who(authorization)
    body = db().execute("SELECT body FROM notes ORDER BY id DESC LIMIT 1").fetchone()["body"]
    rows = db().execute("SELECT id, name FROM items WHERE name = '" + body + "'").fetchall()
    return [dict(r) for r in rows]


@app.get("/boom")
def boom():
    raise RuntimeError("boom")


@app.get("/lazy")
def lazy():
    sys.modules.pop("tabnanny", None)
    importlib.import_module("tabnanny")
    traceback.format_stack()
    return {"ok": True}
