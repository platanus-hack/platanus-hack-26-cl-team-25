"""Synthetic canaries for `immune doctor` check 4 (contracts/product.md §5).

The shadow wrapper has no self-test endpoint, so the doctor wraps the target ASGI app in this
shim *inside the wrapped (instrumented) process*. Three routes, active only with env
``SHADOW_SELFTEST=1`` (set by the doctor's child process, never in normal clones):

    GET /__immune_selftest__/sql?q=<v>            executes a string-built SQL statement containing v
    GET /__immune_selftest__/file                 opens a file outside the allowed roots
    GET /__immune_selftest__/owner?exclude=<uid>  returns a private value of another owner, read from
                                                  the shadow database (columns.yaml users table)

Each must make the corresponding oracle (sql, file, owner) fire. Everything else goes to the app.
"""
from __future__ import annotations

import importlib
import json
import os
import sqlite3
from urllib.parse import parse_qs

PREFIX = "/__immune_selftest__/"
FILE_TARGETS = ("/etc/hostname", "/etc/passwd", "/etc/os-release")


class SelfTestApp:
    def __init__(self, app, owner: dict | None = None):
        self.app = app
        self.owner = owner or {}

    def __getattr__(self, name):  # openapi(), routes, etc. stay reachable
        return getattr(self.app, name)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not scope.get("path", "").startswith(PREFIX) \
                or os.environ.get("SHADOW_SELFTEST") != "1":
            return await self.app(scope, receive, send)
        qs = {k: v[0] for k, v in parse_qs(scope.get("query_string", b"").decode("latin-1")).items()}
        what = scope["path"][len(PREFIX):]
        status, body = 200, {}
        try:
            if what == "sql":
                conn = sqlite3.connect(os.environ["APP_DB"])
                try:
                    n = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = '" + qs.get("q", "") + "'").fetchone()[0]
                finally:
                    conn.close()
                body = {"count": n}
            elif what == "file":
                target = next((p for p in FILE_TARGETS if os.path.exists(p)), FILE_TARGETS[0])
                with open(target, "rb") as f:
                    body = {"file": target, "bytes": len(f.read(64))}
            elif what == "owner":
                o = self.owner
                q = 'SELECT "%s" FROM "%s" WHERE "%s" IS NOT ? AND "%s" IS NOT NULL ORDER BY "%s" LIMIT 1' % (
                    o["column"], o["table"], o["owner_col"], o["column"], o["owner_col"])
                conn = sqlite3.connect(os.environ["APP_DB"])
                try:
                    row = conn.execute(q, (int(qs.get("exclude", "0")),)).fetchone()
                finally:
                    conn.close()
                body = {"value": row[0] if row else None}
            else:
                status, body = 404, {"detail": "unknown self-test"}
        except Exception as e:  # noqa: BLE001
            status, body = 500, {"error": "%s: %s" % (e.__class__.__name__, e)}
        data = json.dumps(body, default=str).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
        await send({"type": "http.response.body", "body": data, "more_body": False})


def install(profile_module: str, opts: dict | None = None) -> None:
    """Replace the profile's APP object with the shim (before the Engine imports it)."""
    prof = importlib.import_module(profile_module)
    mod, _, attr = prof.APP.partition(":")
    m = importlib.import_module(mod)
    attr = attr or "app"
    real = getattr(m, attr)
    if not isinstance(real, SelfTestApp):
        setattr(m, attr, SelfTestApp(real, (opts or {}).get("owner")))
