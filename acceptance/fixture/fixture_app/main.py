"""Tiny stand-in for the victim app. Same rules as contracts/README.md §4."""
import os, sqlite3
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from immune_contracts import authtoken

app = FastAPI()
STATIC = os.environ.get("APP_STATIC", os.path.join(os.path.dirname(__file__), "static"))


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
    conn = db()
    rows = conn.execute("SELECT id, name FROM items WHERE name LIKE '%" + q + "%' ORDER BY id").fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/safe-search")
def safe_search(q: str = ""):
    conn = db()
    rows = conn.execute("SELECT id, name FROM items WHERE name LIKE ? ORDER BY id", (f"%{q}%",)).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/download")
def download(name: str):
    path = os.path.join(STATIC, name)
    if not os.path.isfile(path):
        raise HTTPException(404, "not found")
    return FileResponse(path)


@app.get("/notes/{note_id}")
def note(note_id: int, authorization: str = Header(None)):
    who(authorization)
    row = db().execute("SELECT id, user_id, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    return dict(row)


@app.get("/safe-notes/{note_id}")
def safe_note(note_id: int, authorization: str = Header(None)):
    ident = who(authorization)
    row = db().execute("SELECT id, user_id, body FROM notes WHERE id = ? AND user_id = ?", (note_id, ident.uid)).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    return dict(row)


@app.post("/notes")
def add_note(payload: dict, authorization: str = Header(None)):
    ident = who(authorization)
    conn = db()
    cur = conn.execute("INSERT INTO notes (user_id, body) VALUES (?, ?)", (ident.uid, payload.get("body", "")))
    conn.commit()
    return {"id": cur.lastrowid}
