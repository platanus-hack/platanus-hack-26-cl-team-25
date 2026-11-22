from fastapi import APIRouter, Depends, HTTPException

from .auth import current_user
from .db import connect

router = APIRouter()


@router.get("/teams/{team_id}/members")
def team_members(team_id: int, user=Depends(current_user)):
    conn = connect()
    try:
        team = conn.execute("SELECT id FROM teams WHERE id = ?", (team_id,)).fetchone()
        if team is None:
            raise HTTPException(status_code=404, detail="Equipo no encontrado")
        rows = conn.execute(
            "SELECT u.name, u.email FROM memberships m JOIN users u ON u.id = m.user_id "
            "WHERE m.team_id = ? ORDER BY u.name",
            (team_id,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


@router.get("/admin/users")
def admin_users(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Solo administradores")
    conn = connect()
    try:
        rows = conn.execute("SELECT id, email, name, role, phone FROM users ORDER BY id").fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]
