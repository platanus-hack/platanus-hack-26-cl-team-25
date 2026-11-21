"""Sidecar profile for the demo apps (identity + markers). Loaded by path: ``profile: /…/profile.py``."""
import json
import os

from immune_contracts import authtoken


def mint_token(env, uid, role):
    return authtoken.mint(env["APP_SECRET"], uid, role)


def ensure_user(conn, uid, role):
    conn.execute("INSERT INTO users (id, name, role) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
                 (uid, f"user{uid}", role))


def load_markers(env):
    with open(env.get("MARKERS_PATH") or os.path.join(os.path.dirname(__file__), "markers.json")) as f:
        return {k: int(v) for k, v in json.load(f).items()}


def public_paths():
    return ["/health", "/search", "/safe-search", "/download", "/safe-download"]
