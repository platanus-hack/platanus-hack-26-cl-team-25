"""Stateless session token of `auth.kind: immune-token`, used by the built-in demo app (prod and shadow).

Format:  base64url(json({"uid": int, "role": "user"|"admin", "exp": int})) + "." + hex(hmac_sha256(secret, payload_b64))
Header:  Authorization: Bearer <token>

Prod and shadow use DIFFERENT secrets. A token that verifies with the shadow
secret but arrives from the outside is a honeytoken (stolen inside a clone).
"""
from __future__ import annotations
import base64, hashlib, hmac, json, time
from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    uid: int
    role: str  # "user" | "admin"


def mint(secret: str, uid: int, role: str = "user", ttl: int = 86400, now: float | None = None) -> str:
    now = time.time() if now is None else now
    payload = base64.urlsafe_b64encode(
        json.dumps({"uid": uid, "role": role, "exp": int(now) + ttl}, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify(secret: str, token: str, now: float | None = None) -> Identity | None:
    """Return the Identity, or None if the token is malformed, forged or expired."""
    try:
        payload, sig = token.split(".", 1)
        want = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, sig):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if int(data["exp"]) < (time.time() if now is None else now):
            return None
        return Identity(uid=int(data["uid"]), role=str(data.get("role", "user")))
    except Exception:
        return None


def bearer(headers) -> str | None:
    """Extract the bearer token from a headers mapping (case-insensitive get)."""
    value = headers.get("authorization") or headers.get("Authorization")
    if not value or not value.lower().startswith("bearer "):
        return None
    return value[7:].strip() or None
