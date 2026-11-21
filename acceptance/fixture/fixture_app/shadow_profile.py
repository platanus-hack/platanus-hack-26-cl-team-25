import os
from immune_contracts import authtoken
from . import seed

APP = "fixture_app.main:app"


def allowed_file_roots(env):
    return [env.get("APP_STATIC", os.path.join(os.path.dirname(__file__), "static"))]


def ensure_user(conn, uid, role):
    if not conn.execute("SELECT 1 FROM users WHERE id = ?", (uid,)).fetchone():
        conn.execute("INSERT INTO users VALUES (?,?,?)", (uid, f"user{uid}", role))
        conn.commit()


def mint_token(env, uid, role):
    return authtoken.mint(env["APP_SECRET"], uid, role)


def load_markers(env):
    return dict(seed.MARKERS)


def public_paths():
    return ["/health", "/search", "/safe-search", "/download"]
