import hashlib
import secrets
import sqlite3
from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .db import connect, now

router = APIRouter()


class RegisterIn(BaseModel):
    email: str
    name: str
    password: str


class LoginIn(BaseModel):
    email: str
    password: str


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No autenticado")
    token = authorization[len("Bearer "):]
    conn = connect()
    try:
        row = conn.execute(
            "SELECT u.id, u.email, u.name, u.role FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.token = ?",
            (token,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="Sesion invalida")
    return dict(row)


@router.post("/auth/register", status_code=201)
def register(data: RegisterIn):
    conn = connect()
    try:
        cur = conn.execute(
            "INSERT INTO users (email, name, role, password_hash) VALUES (?, ?, 'member', ?)",
            (data.email, data.name, hash_password(data.password)),
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="El correo ya esta registrado")
    finally:
        conn.close()
    return {"id": user_id, "email": data.email, "name": data.name, "role": "member"}


@router.post("/auth/login")
def login(data: LoginIn):
    conn = connect()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE email = ? AND password_hash = ?",
            (data.email, hash_password(data.password)),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        token = secrets.token_hex(24)
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, row["id"], now()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"token": token, "token_type": "bearer"}


@router.get("/auth/me")
def me(authorization: Optional[str] = Header(None)):
    return current_user(authorization)
