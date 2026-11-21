"""SQLite state handling. Always the backup API, never file copies.

Copying a live WAL database yields an empty/stale database, and replacing the file
leaves the app's already-open connections on the old inode; ``Connection.backup``
rewrites the pages in place under SQLite's own locking, so every connection sees
the new content.
"""
from __future__ import annotations

import gc
import os
import time

from .instrument import ORIG_CONNECT


def _open_source(path: str):
    try:
        return ORIG_CONNECT(f"file:{path}?mode=ro&immutable=1", uri=True)
    except Exception:
        return ORIG_CONNECT(path)


def _open_dest(path: str):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    return ORIG_CONNECT(path, timeout=10)


def _backup(src, dst_path: str, attempts: int = 5) -> None:
    last = None
    for i in range(attempts):
        dst = _open_dest(dst_path)
        try:
            src.backup(dst)
            return
        except Exception as e:  # locked by a lingering app connection: collect and retry
            last = e
            gc.collect()
            time.sleep(0.05 * (i + 1))
        finally:
            dst.close()
    raise last


def restore_from_file(seed_path: str, dst_path: str) -> None:
    src = _open_source(seed_path)
    try:
        _backup(src, dst_path)
    finally:
        src.close()


def restore_from_bytes(state: bytes, dst_path: str) -> None:
    src = ORIG_CONNECT(":memory:")
    try:
        src.deserialize(state)
        _backup(src, dst_path)
    finally:
        src.close()


def snapshot(path: str) -> bytes:
    src = ORIG_CONNECT(path, timeout=10)
    mem = ORIG_CONNECT(":memory:")
    try:
        src.backup(mem)
        return mem.serialize()
    finally:
        mem.close()
        src.close()


def ensure_user(profile, path: str, uid: int, role: str) -> None:
    conn = ORIG_CONNECT(path, timeout=10)
    try:
        profile.ensure_user(conn, uid, role)
        conn.commit()
    finally:
        conn.close()
