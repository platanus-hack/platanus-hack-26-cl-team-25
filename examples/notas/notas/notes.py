import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from .auth import current_user
from .db import connect, now

router = APIRouter()


class NoteIn(BaseModel):
    title: str
    body: str = ""
    team_id: Optional[int] = None


def check_team(conn, user, team_id):
    if team_id is None:
        return
    row = conn.execute(
        "SELECT 1 FROM memberships WHERE user_id = ? AND team_id = ?",
        (user["id"], team_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=403, detail="No perteneces a ese equipo")


@router.get("/notes")
def list_notes(
    q: Optional[str] = None,
    sort: str = Query("created", pattern="^(created|title)$"),
    user=Depends(current_user),
):
    sql = (
        "SELECT id, owner_id, team_id, title, body, created_at FROM notes "
        "WHERE owner_id = ?"
    )
    if q:
        sql += " AND (title LIKE '%" + q + "%' OR body LIKE '%" + q + "%')"
    if sort == "title":
        sql += " ORDER BY title COLLATE NOCASE, id"
    else:
        sql += " ORDER BY created_at DESC, id DESC"
    conn = connect()
    try:
        rows = conn.execute(sql, (user["id"],)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


@router.post("/notes", status_code=201)
def create_note(data: NoteIn, user=Depends(current_user)):
    conn = connect()
    try:
        check_team(conn, user, data.team_id)
        ts = now()
        cur = conn.execute(
            "INSERT INTO notes (owner_id, team_id, title, body, created_at) VALUES (?, ?, ?, ?, ?)",
            (user["id"], data.team_id, data.title, data.body, ts),
        )
        conn.commit()
        note_id = cur.lastrowid
    finally:
        conn.close()
    return {
        "id": note_id,
        "owner_id": user["id"],
        "team_id": data.team_id,
        "title": data.title,
        "body": data.body,
        "created_at": ts,
    }


@router.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user)):
    conn = connect()
    try:
        row = conn.execute(
            "SELECT id, owner_id, team_id, title, body, created_at FROM notes "
            "WHERE id = ? AND owner_id = ?",
            (note_id, user["id"]),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Nota no encontrada")
    return dict(row)


@router.put("/notes/{note_id}")
def update_note(note_id: int, data: NoteIn, user=Depends(current_user)):
    conn = connect()
    try:
        row = conn.execute(
            "SELECT id, created_at FROM notes WHERE id = ? AND owner_id = ?",
            (note_id, user["id"]),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Nota no encontrada")
        check_team(conn, user, data.team_id)
        conn.execute(
            "UPDATE notes SET title = ?, body = ?, team_id = ? WHERE id = ?",
            (data.title, data.body, data.team_id, note_id),
        )
        conn.commit()
        created_at = row["created_at"]
    finally:
        conn.close()
    return {
        "id": note_id,
        "owner_id": user["id"],
        "team_id": data.team_id,
        "title": data.title,
        "body": data.body,
        "created_at": created_at,
    }


@router.delete("/notes/{note_id}", status_code=204)
def delete_note(note_id: int, user=Depends(current_user)):
    conn = connect()
    try:
        cur = conn.execute(
            "DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, user["id"])
        )
        conn.commit()
        deleted = cur.rowcount
    finally:
        conn.close()
    if not deleted:
        raise HTTPException(status_code=404, detail="Nota no encontrada")


@router.get("/notes/{note_id}/export", response_class=PlainTextResponse)
def export_note(note_id: int, user=Depends(current_user)):
    conn = connect()
    try:
        row = conn.execute(
            "SELECT n.title, n.body, n.created_at, u.name FROM notes n "
            "JOIN users u ON u.id = n.owner_id WHERE n.id = ?",
            (note_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Nota no encontrada")
    fecha = time.strftime("%Y-%m-%d %H:%M", time.gmtime(row["created_at"]))
    return "%s\nAutor: %s\nFecha: %s\n\n%s\n" % (row["title"], row["name"], fecha, row["body"])
