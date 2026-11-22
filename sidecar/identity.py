"""Pluggable identity translation: ``x-imm-uid``/``x-imm-role`` -> app credentials.

Sources, first that applies:
1. ``profile`` (python module name or .py path) with any of:
   - ``identity_headers(env, uid, role) -> dict``   headers to set (replacing same-named client headers)
   - ``mint_token(env, uid, role) -> str``          becomes ``Authorization: Bearer <token>``
   - ``ensure_user(conn, uid, role)``               async-free hook; ``conn.execute(sql, params)`` runs on the
                                                    clone database (Postgres) before the request
   - ``identify(env, headers) -> (uid, role) | None``   requester of a request without x-imm-uid
   - ``load_markers(env) -> {marker: owner}``, ``public_paths() -> [prefix]``
   - ``rewrite_request(env, uid, role, query, headers, body) -> (query, body)``   session-bound values of the
                                                    client's request (CSRF tokens) replaced by the clone's
2. ``identity_command`` (shell): env ``IMM_UID``, ``IMM_ROLE``; stdout lines ``Header: value``, or one bare
   line taken as a bearer token.
3. nothing: the client's headers are left untouched.
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import json
import logging
import os
import subprocess

from immune_contracts import authtoken

log = logging.getLogger("sidecar.identity")


def load_profile(spec: str | None):
    if not spec:
        return None
    if spec.endswith(".py") or os.sep in spec:
        s = importlib.util.spec_from_file_location("sidecar_profile", spec)
        mod = importlib.util.module_from_spec(s)
        s.loader.exec_module(mod)
        return mod
    return importlib.import_module(spec)


class SyncPg:
    """``conn.execute(sql, params) -> rows`` facade over the async client, for profile hooks run in a thread."""

    def __init__(self, conn, loop):
        self.conn, self.loop = conn, loop

    def execute(self, sql, params=()):
        return asyncio.run_coroutine_threadsafe(self.conn.execute(sql, params), self.loop).result(10)

    def commit(self):
        pass  # every statement autocommits


class SyncMysql:
    """``conn.execute(sql, params) -> rows`` facade over the async MySQL client (``?`` placeholders), for profile
    hooks run in a thread. Every statement is reported to ``on_sql`` so the L1 reset rebuilds what it wrote."""

    def __init__(self, conn, loop, on_sql=None):
        self.conn, self.loop, self.on_sql = conn, loop, on_sql

    def execute(self, sql, params=()):
        if self.on_sql is not None:
            self.on_sql(sql)
        return asyncio.run_coroutine_threadsafe(self.conn.execute(sql, params), self.loop).result(10)

    def commit(self):
        pass  # every statement autocommits


class Identity:
    def __init__(self, profile=None, command: str | None = None):
        self.profile = profile
        self.command = command

    def has_mapping(self) -> bool:
        p = self.profile
        return bool(self.command) or (p is not None and (hasattr(p, "identity_headers") or hasattr(p, "mint_token")))

    def headers_for(self, env, uid: int, role: str) -> dict:
        p = self.profile
        if p is not None and hasattr(p, "identity_headers"):
            return {k.lower(): str(v) for k, v in p.identity_headers(env, uid, role).items()}
        if p is not None and hasattr(p, "mint_token"):
            return {"authorization": f"Bearer {p.mint_token(env, uid, role)}"}
        if self.command:
            e = dict(env, IMM_UID=str(uid), IMM_ROLE=role)
            out = subprocess.run(self.command, shell=True, env=e, capture_output=True, text=True, timeout=10)
            if out.returncode != 0:
                raise RuntimeError(f"identity_command failed: {out.stderr.strip()[:200]}")
            lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
            if len(lines) == 1 and ":" not in lines[0]:
                return {"authorization": f"Bearer {lines[0]}"}
            hdrs = {}
            for l in lines:
                k, _, v = l.partition(":")
                hdrs[k.strip().lower()] = v.strip()
            return hdrs
        return {}

    def rewrites(self) -> bool:
        return self.profile is not None and hasattr(self.profile, "rewrite_request")

    def rewrite_request(self, env, uid: int, role: str, query: str, headers: dict, body: bytes):
        try:
            q, b = self.profile.rewrite_request(env, uid, role, query, headers, body)
            return str(q), bytes(b)
        except Exception as e:  # noqa: BLE001 - the request is still judged as sent
            log.warning("rewrite_request failed: %r", e)
            return query, body

    def identify(self, env, headers: dict):
        p = self.profile
        if p is not None and hasattr(p, "identify"):
            r = p.identify(env, headers)
            return (int(r[0]), str(r[1])) if r else (None, None)
        secret = env.get("APP_SECRET")
        tok = authtoken.bearer(headers)
        if secret and tok:
            ident = authtoken.verify(secret, tok)
            if ident:
                return ident.uid, ident.role
        return None, None

    def markers(self, env, path: str | None) -> dict:
        p = self.profile
        try:
            if p is not None and hasattr(p, "load_markers"):
                return {str(k): int(v) for k, v in (p.load_markers(env) or {}).items()}
            if path:
                with open(path) as f:   # {marker: {"path": …}} entries are file markers (observer.load_file_markers)
                    return {str(k): int(v) for k, v in json.load(f).items() if not isinstance(v, dict)}
        except Exception as e:
            log.warning("markers not loaded (%r): owner oracle disabled", e)
        return {}

    def public_paths(self, configured) -> list:
        p = self.profile
        if p is not None and hasattr(p, "public_paths"):
            return list(p.public_paths())
        return list(configured or [])
