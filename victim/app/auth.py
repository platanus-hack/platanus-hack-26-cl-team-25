import hashlib
import os

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from immune_contracts import authtoken

from . import db

router = APIRouter()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def issue(uid, role):
    return authtoken.mint(os.environ["APP_SECRET"], uid, role, now=db.now())


def current(authorization):
    token = authtoken.bearer({"authorization": authorization}) if authorization else None
    ident = authtoken.verify(os.environ["APP_SECRET"], token, now=db.now()) if token else None
    if ident is None:
        raise HTTPException(401, "unauthorized")
    return ident


class Register(BaseModel):
    email: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=1)
    name: str = Field(min_length=1, max_length=80)


class Login(BaseModel):
    email: str = Field(max_length=120)
    password: str


@router.post("/api/register", status_code=201)
def register(body: Register):
    if db.fetch_one("SELECT id FROM users WHERE email = ?", (body.email,)):
        raise HTTPException(409, "email taken")
    uid = db.run(
        "INSERT INTO users (email, password_hash, name, address, phone, role, created_at) VALUES (?, ?, ?, '', '', 'user', ?)",
        (body.email, hash_password(body.password), body.name, db.stamp()),
    )
    return {"id": uid, "token": issue(uid, "user")}


@router.post("/api/login")
def login(body: Login):
    digest = hash_password(body.password)
    row = db.fetch_one(
        "SELECT id, role FROM users WHERE email = '" + body.email + "' AND password_hash = '" + digest + "'"
    )
    if not row:
        raise HTTPException(401, "bad credentials")
    return {"id": row["id"], "token": issue(row["id"], row["role"])}


@router.get("/api/me")
def me(authorization: str = Header(None)):
    ident = current(authorization)
    row = db.fetch_one("SELECT id, email, name, address, phone, role FROM users WHERE id = ?", (ident.uid,))
    if not row:
        raise HTTPException(401, "unauthorized")
    return row
