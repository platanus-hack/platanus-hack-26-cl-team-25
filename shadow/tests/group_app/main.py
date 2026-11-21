import os
import sqlite3

from fastapi import FastAPI, Header, HTTPException
from immune_contracts import authtoken

app = FastAPI()


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


@app.get("/teams/{team_id}/members")
def members(team_id: int, authorization: str = Header(None)):
    who(authorization)          # no membership check (the IDOR)
    conn = db()
    rows = conn.execute("SELECT u.name FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.team_id = ?",
                        (team_id,)).fetchall()
    return [r["name"] for r in rows]


@app.get("/teams/{team_id}/everyone")
def everyone(team_id: int, authorization: str = Header(None)):
    who(authorization)          # leaks every user, members or not
    return [r["name"] for r in db().execute("SELECT name FROM users ORDER BY id").fetchall()]


@app.get("/other/{gid}/members")
def other(gid: int, authorization: str = Header(None)):
    return members(gid, authorization)
