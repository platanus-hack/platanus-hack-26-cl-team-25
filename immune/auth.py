"""Identity resolution for the gateway and the pipeline (`auth` block of .immune/config.yaml).

Kinds
  immune-token  immune_contracts.authtoken with the prod secret (the built-in demo)
  jwt-hs256     `Authorization: Bearer <JWT>` signed HS256 with the secret in env `secret_env`
                (stdlib only: hmac + sha256; `alg` must be exactly HS256; exp/nbf honoured)
  introspect    the gateway asks PROD `<path>` with the client's Authorization and Cookie
                headers and reads `uid_field` / `role_field` from the JSON (see gateway.core)
  none          every client is anonymous

A uid is always an integer (it is compared with the manifest's seed_max_uid and sent to
clones as x-imm-uid); a non-integer subject is treated as anonymous.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from immune_contracts import authtoken


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    if not isinstance(s, str) or not s or any(c not in
                                              "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in s):
        raise ValueError("bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(secret: str, claims: dict, header: dict | None = None) -> str:
    h = {"alg": "HS256", "typ": "JWT", **(header or {})}
    seg = _b64e(json.dumps(h, separators=(",", ":")).encode()) + "." + \
        _b64e(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), seg.encode("ascii"), hashlib.sha256).digest()
    return seg + "." + _b64e(sig)


def jwt_decode(secret: str, token: str, now: float | None = None, leeway: float = 30.0) -> dict | None:
    """Claims of a valid HS256 token, else None. Never raises."""
    if not secret or not isinstance(token, str) or token.count(".") != 2 or len(token) > 8192:
        return None
    try:
        h64, p64, s64 = token.split(".")
        header = json.loads(_b64d(h64))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return None
        want = hmac.new(secret.encode(), (h64 + "." + p64).encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(want, _b64d(s64)):
            return None
        claims = json.loads(_b64d(p64))
    except (ValueError, UnicodeError, TypeError):
        return None
    if not isinstance(claims, dict):
        return None
    t = time.time() if now is None else now
    for k, bad in (("exp", lambda v: t > v + leeway), ("nbf", lambda v: t + leeway < v)):
        if k in claims:
            v = claims[k]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or bad(v):
                return None
    return claims


def as_uid(v) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if v >= 0 else None
    if isinstance(v, str) and v.isdigit() and len(v) <= 18:
        return int(v)
    return None


@dataclass
class Identity:
    uid: int | None = None
    role: str | None = None
    honeytoken: bool = False


def role_of(value, admin_values) -> str:
    vals = value if isinstance(value, list) else [value]
    return "admin" if any(str(x) in [str(a) for a in (admin_values or ["admin"])] for x in vals if x is not None) \
        else "user"


class Authenticator:
    """Local (no network) part of identity resolution. `kind == 'introspect'` is resolved by the caller."""

    def __init__(self, auth: dict | None, prod_secret: str = "", shadow_secret: str = ""):
        a = dict(auth or {})
        self.kind = a.get("kind") or "immune-token"
        self.uid_claim = a.get("uid_claim") or "sub"
        self.role_claim = a.get("role_claim") or ""
        self.admin_values = a.get("admin_values") or ["admin"]
        self.path = a.get("path") or "/api/me"
        self.uid_field = a.get("uid_field") or "id"
        self.role_field = a.get("role_field") or "role"
        self.cache_s = float(a.get("cache_s", 30) or 0)
        self.prod_secret, self.shadow_secret = prod_secret or "", shadow_secret or ""

    def from_token(self, token: str | None) -> Identity:
        if not token or self.kind in ("none", "introspect"):
            return Identity()
        if self.kind == "immune-token":
            ident = authtoken.verify(self.prod_secret, token) if self.prod_secret else None
            if ident is not None:
                return Identity(uid=ident.uid, role=ident.role)
            if self.shadow_secret and authtoken.verify(self.shadow_secret, token, now=0) is not None:
                return Identity(honeytoken=True)
            return Identity()
        if self.kind == "jwt-hs256":
            claims = jwt_decode(self.prod_secret, token)
            if claims is not None:
                uid = as_uid(claims.get(self.uid_claim))
                if uid is None:
                    return Identity()
                role = role_of(claims.get(self.role_claim), self.admin_values) if self.role_claim else "user"
                return Identity(uid=uid, role=role)
            # a token signed with the shadow secret (handed out by a clone) arriving from outside
            if self.shadow_secret and jwt_decode(self.shadow_secret, token, now=0, leeway=10 ** 10) is not None:
                return Identity(honeytoken=True)
            return Identity()
        return Identity()

    def from_introspection(self, status: int, body: bytes) -> Identity:
        if status != 200:
            return Identity()
        try:
            d = json.loads(body)
        except (ValueError, UnicodeError):
            return Identity()
        if not isinstance(d, dict):
            return Identity()
        uid = as_uid(_dig(d, self.uid_field))
        if uid is None:
            return Identity()
        role = role_of(_dig(d, self.role_field), self.admin_values) if self.role_field else "user"
        return Identity(uid=uid, role=role)

    def mint(self, uid: int, role: str = "user") -> str | None:
        """A prod credential for uid (pipeline verification). None when the kind cannot mint."""
        if self.kind == "immune-token" and self.prod_secret:
            return authtoken.mint(self.prod_secret, int(uid), role or "user")
        if self.kind == "jwt-hs256" and self.prod_secret:
            now = int(time.time())
            claims = {self.uid_claim: str(int(uid)), "iat": now, "exp": now + 600}
            if self.role_claim:
                claims[self.role_claim] = (self.admin_values[0] if role == "admin" else "user")
            return jwt_encode(self.prod_secret, claims)
        return None


def _dig(d: dict, dotted: str):
    cur = d
    for part in (dotted or "").split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def credential_key(authorization: str, cookie: str) -> str:
    return hashlib.sha256(("%s\n%s" % (authorization or "", cookie or "")).encode("utf-8", "replace")).hexdigest()


def prod_secret_for(auth: dict | None, env: dict) -> str:
    """The secret prod credentials are signed with: env[secret_env] for jwt-hs256, else PROD_APP_SECRET."""
    a = auth or {}
    if a.get("kind") == "jwt-hs256" and a.get("secret_env") and env.get(a["secret_env"]):
        return env[a["secret_env"]]
    return env.get("PROD_APP_SECRET", "")
