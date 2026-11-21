import json
import os

from immune_contracts import authtoken

APP = "victim.app.main:app"


def allowed_file_roots(env):
    return [env.get("APP_STATIC") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")]


def ensure_user(conn, uid, role):
    if not conn.execute("SELECT 1 FROM users WHERE id = ?", (uid,)).fetchone():
        conn.execute(
            "INSERT INTO users (id, email, password_hash, name, address, phone, role, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (uid, "user%d@shadow.invalid" % uid, "x", "User %d" % uid, "", "", role, "2025-01-01T00:00:00Z"),
        )
        conn.commit()


def mint_token(env, uid, role):
    now = float(env["APP_NOW"]) if env.get("APP_NOW") else None
    return authtoken.mint(env["APP_SECRET"], uid, role, now=now)


def load_markers(env):
    with open(env["MARKERS_PATH"]) as f:
        return json.load(f)


def public_paths():
    return ["/health", "/api/register", "/api/login", "/api/products", "/api/files"]
