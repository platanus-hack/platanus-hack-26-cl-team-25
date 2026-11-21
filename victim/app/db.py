import os
import sqlite3
import time



def now():
    frozen = os.environ.get("APP_NOW")
    return float(frozen) if frozen else time.time()


def stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now()))


def connect():
    conn = sqlite3.connect(os.environ["APP_DB"])
    conn.row_factory = sqlite3.Row
    return conn


def fetch(sql, params=()):
    conn = connect()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def fetch_one(sql, params=()):
    rows = fetch(sql, params)
    return rows[0] if rows else None


def run(sql, params=()):
    conn = connect()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()
