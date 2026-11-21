from fastapi import APIRouter, Header, HTTPException

from . import auth, db

router = APIRouter()


@router.get("/api/users/{user_id}/profile")
def profile(user_id: int, authorization: str = Header(None)):
    auth.current(authorization)
    row = db.fetch_one("SELECT id, name, email, address, phone FROM users WHERE id = ?", (user_id,))
    if not row:
        raise HTTPException(404, "not found")
    return row
