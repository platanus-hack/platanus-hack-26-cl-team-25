"""Shadow data from a production PostgreSQL database (generic runtime; contracts/product.md §4 semantics).

    from immune import shadowdata_pg
    rep = shadowdata_pg.build(cfg, prod_url, network)

Same `columns.yaml` semantics as `immune.shadowdata` (it is reused unchanged): ids and foreign keys
preserved, private values synthetic with the owner's marker, secrets randomised, canaries, manifest,
markers, leak self-check. How:

1. one throw-away `postgres:16-alpine` container on `network` reads prod **read-only** (a
   `default_transaction_read_only` session): catalog (tables, columns, primary/foreign keys), the
   `pg_dump --schema-only` pre-data and post-data sections, and every row as JSON;
2. the rows go into a temporary SQLite copy with the same keys, on which `shadowdata.build_db` runs;
3. the synthetic SQLite seed is written back as a SQL dump: pre-data, INSERTs (foreign-key order),
   sequence positions, post-data (indexes, constraints).

Outputs (under the runtime dir):
    data/shadow/seed.sql          the dump every clone Postgres loads into its template database `seed`
    data/shadow/pginit/01-seed.sh /docker-entrypoint-initdb.d script: role `app`, database `seed`, load
    data/shadow/pginit/seed.dump  (a copy of seed.sql, read by the script)
    data/manifest.json, data/markers.json, data/shadow/markers.json
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile

from . import shadowdata

PG_IMAGE = "postgres:16-alpine"
INT_TYPES = {"integer", "bigint", "smallint"}
REAL_TYPES = {"numeric", "real", "double precision"}

META_SQL = r"""
SELECT json_build_object(
 'tables', (SELECT coalesce(json_agg(table_name ORDER BY table_name), '[]') FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'),
 'columns', (SELECT coalesce(json_agg(json_build_object('table', table_name, 'name', column_name, 'type', data_type,
             'nullable', is_nullable = 'YES', 'default', column_default) ORDER BY table_name, ordinal_position), '[]')
             FROM information_schema.columns WHERE table_schema = 'public'),
 'pks', (SELECT coalesce(json_agg(json_build_object('table', tc.table_name, 'column', kcu.column_name,
         'pos', kcu.ordinal_position)), '[]')
         FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu
           ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
         WHERE tc.table_schema = 'public' AND tc.constraint_type = 'PRIMARY KEY'),
 'fks', (SELECT coalesce(json_agg(json_build_object('table', tc.table_name, 'from', kcu.column_name,
         'ref', ccu.table_name, 'to', ccu.column_name)), '[]')
         FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu
           ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
         JOIN information_schema.constraint_column_usage ccu
           ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema
         WHERE tc.table_schema = 'public' AND tc.constraint_type = 'FOREIGN KEY'))
"""

INIT_SH = r"""#!/bin/sh
# written by immune.shadowdata_pg: template database `seed` (owned by role app) loaded from seed.dump
set -e
psql -v ON_ERROR_STOP=1 -q --username postgres --dbname postgres \
  -c "CREATE ROLE app LOGIN PASSWORD '${APP_DB_PASSWORD}'" -c "CREATE DATABASE seed OWNER app"
psql -v ON_ERROR_STOP=1 -q --username app --dbname seed -f /docker-entrypoint-initdb.d/seed.dump
"""


class PgShadowError(RuntimeError):
    pass


def literal(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, bytes):
        return "'\\x%s'::bytea" % v.hex()
    return "'%s'" % str(v).replace("'", "''")


# ------------------------------------------------------------------ reading prod
def run_psql(url: str, network: str, script: str, timeout: float = 120) -> str:
    """Run `script` (sh) in a throw-away postgres client container on `network`; $URL holds the prod URL."""
    cmd = ["docker", "run", "--rm", "-i", "--network", network, "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--user", "70:70", "-e", "URL", "-e",
           "PGOPTIONS=-c default_transaction_read_only=on", "--label", "immune.component=shadowdata",
           PG_IMAGE, "sh", "-e", "-s"]
    p = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=timeout,
                       env=dict(os.environ, URL=url))
    if p.returncode != 0:
        raise PgShadowError("reading prod failed (exit %d): %s" % (p.returncode, p.stderr.strip()[-600:]))
    return p.stdout


def read_prod(url: str, network: str) -> dict:
    """-> {"meta": catalog, "pre": sql, "post": sql, "rows": {table: [dict]}}"""
    dump = "pg_dump \"$URL\" --schema-only --no-owner --no-privileges --no-comments --schema=public"
    out = run_psql(url, network, "\n".join([
        "echo '@@META'", "psql \"$URL\" -X -At -v ON_ERROR_STOP=1 <<'EOSQL'", META_SQL, "EOSQL",
        "echo '@@PRE'", dump + " --section=pre-data", "echo '@@POST'", dump + " --section=post-data", ""]))
    parts = _split(out, ["@@META", "@@PRE", "@@POST"])
    meta = json.loads(parts["@@META"].strip())
    lines = ["echo '@@T %s'" % t + "\n" + "psql \"$URL\" -X -At -v ON_ERROR_STOP=1 -c " +
             _shq("SELECT row_to_json(t) FROM public.%s t" % shadowdata._q(t)) for t in meta["tables"]]
    rows = {t: [] for t in meta["tables"]}
    if lines:
        data = run_psql(url, network, "\n".join(lines) + "\n", timeout=600)
        cur = None
        for line in data.splitlines():
            if line.startswith("@@T "):
                cur = line[4:]
            elif line.strip() and cur is not None:
                rows[cur].append(json.loads(line))
    return {"meta": meta, "pre": _clean_dump(parts["@@PRE"]), "post": _clean_dump(parts["@@POST"]), "rows": rows}


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _split(text: str, marks: list) -> dict:
    out, cur = {m: "" for m in marks}, None
    for line in text.splitlines(keepends=True):
        if line.strip() in marks:
            cur = line.strip()
        elif cur:
            out[cur] += line
    return out


def _clean_dump(sql: str) -> str:
    """Drop psql meta-commands (pg_dump >= 16.10 emits \\restrict / \\unrestrict)."""
    return "".join(l for l in sql.splitlines(keepends=True)
                   if not l.lstrip().startswith("\\") and l.strip() != "CREATE SCHEMA public;")


# ------------------------------------------------------------------ SQLite bridge
def columns_of(meta: dict) -> dict:
    out = {t: [] for t in meta["tables"]}
    for c in meta["columns"]:
        if c["table"] in out:
            out[c["table"]].append(c)
    return out


def pks_of(meta: dict) -> dict:
    out = {}
    for p in sorted(meta["pks"], key=lambda p: p["pos"]):
        out.setdefault(p["table"], []).append(p["column"])
    return out


def to_sqlite(prod: dict, path: str) -> None:
    """The prod rows in a SQLite file with the same keys (what shadowdata.build_db reads)."""
    meta = prod["meta"]
    cols, pks = columns_of(meta), pks_of(meta)
    conn = sqlite3.connect(path)
    try:
        for t in meta["tables"]:
            pk = pks.get(t, [])
            defs = []
            for c in cols[t]:
                ty = "INTEGER" if c["type"] in INT_TYPES or c["type"] == "boolean" else \
                    "REAL" if c["type"] in REAL_TYPES else "TEXT"
                d = "%s %s" % (shadowdata._q(c["name"]), ty)
                if pk == [c["name"]]:
                    d += " PRIMARY KEY"
                if not c["nullable"]:
                    d += " NOT NULL"
                defs.append(d)
            if len(pk) > 1:
                defs.append("PRIMARY KEY (%s)" % ", ".join(shadowdata._q(x) for x in pk))
            for f in meta["fks"]:
                if f["table"] == t:
                    defs.append("FOREIGN KEY (%s) REFERENCES %s (%s)" % (shadowdata._q(f["from"]), shadowdata._q(f["ref"]), shadowdata._q(f["to"])))
            conn.execute("CREATE TABLE %s (%s)" % (shadowdata._q(t), ", ".join(defs)))
            names = [c["name"] for c in cols[t]]
            kinds = {c["name"]: c["type"] for c in cols[t]}
            for r in prod["rows"][t]:
                vals = []
                for n in names:
                    v = r.get(n)
                    if kinds[n] == "boolean" and v is not None:
                        v = 1 if v else 0
                    elif isinstance(v, (dict, list)):
                        v = json.dumps(v, ensure_ascii=False)
                    vals.append(v)
                conn.execute("INSERT INTO %s (%s) VALUES (%s)" % (shadowdata._q(t), ", ".join(shadowdata._q(n) for n in names),
                                                                  ", ".join("?" * len(names))), vals)
        conn.commit()
    finally:
        conn.close()


def fk_order(meta: dict) -> list:
    """Tables so that every referenced table comes first (self references ignored)."""
    deps = {t: {f["ref"] for f in meta["fks"] if f["table"] == t and f["ref"] != t} for t in meta["tables"]}
    out, seen = [], set()

    def visit(t, stack=()):
        if t in seen or t in stack:
            return
        for d in sorted(deps.get(t, ())):
            visit(d, stack + (t,))
        seen.add(t)
        out.append(t)
    for t in sorted(meta["tables"]):
        visit(t)
    return out


def to_sql(prod: dict, shadow_sqlite: str) -> str:
    """The synthetic seed as one SQL script: pre-data, data, sequence positions, post-data."""
    meta = prod["meta"]
    cols = columns_of(meta)
    conn = sqlite3.connect("file:%s?mode=ro" % shadow_sqlite, uri=True)
    out = ["-- shadow seed written by immune.shadowdata_pg (synthetic data; no real private value)\n",
           prod["pre"], "\nSET search_path = public;\n"]
    try:
        for t in fk_order(meta):
            names = [c["name"] for c in cols[t]]
            kinds = {c["name"]: c["type"] for c in cols[t]}
            cur = conn.execute("SELECT %s FROM %s" % (", ".join(shadowdata._q(n) for n in names), shadowdata._q(t)))
            for r in cur:
                vals = []
                for n, v in zip(names, r):
                    if kinds[n] == "boolean" and v is not None:
                        v = bool(v)
                    vals.append(literal(v))
                out.append("INSERT INTO public.%s (%s) VALUES (%s);\n" % (shadowdata._q(t), ", ".join(shadowdata._q(n) for n in names),
                                                                         ", ".join(vals)))
        for c in meta["columns"]:
            if str(c.get("default") or "").startswith("nextval("):
                out.append("SELECT setval(pg_get_serial_sequence(%s, %s), coalesce((SELECT max(%s) FROM public.%s), 0) + 1, "
                           "false);\n" % (literal("public." + shadowdata._q(c["table"])), literal(c["name"]), shadowdata._q(c["name"]),
                                          shadowdata._q(c["table"])))
    finally:
        conn.close()
    out.append(prod["post"])
    return "".join(out)


# ------------------------------------------------------------------ entry
def load_hasher(cfg):
    """profile.hash_password from <project>/.immune/<shadow.profile>.py, or None."""
    if not cfg.shadow.profile:
        return None
    path = os.path.join(cfg.dot_immune, cfg.shadow.profile.replace(".", os.sep) + ".py")
    if not os.path.isfile(path):
        return None
    spec = importlib.util.spec_from_file_location("immune_profile_%s" % cfg.name, path)
    mod = importlib.util.module_from_spec(spec)
    import sys
    keep, sys.dont_write_bytecode = sys.dont_write_bytecode, True   # no __pycache__ in the project's .immune/
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = keep
    return getattr(mod, "hash_password", None)


def build(cfg, prod_url: str, network: str, *, seed: int = 1) -> dict:
    from . import _cfg
    columns = _cfg.columns_path(cfg)
    if not os.path.isfile(columns):
        raise PgShadowError("%s not found (columns.yaml is required to derive shadow data)" % columns)
    prod = read_prod(prod_url, network)
    work = tempfile.mkdtemp(prefix="immune-pgshadow-")
    try:
        lite = os.path.join(work, "prod.db")
        to_sqlite(prod, lite)
        rep = shadowdata.build_db(lite, columns, work, seed=seed, admin_values=cfg.auth.admin_values,
                                  hash_password=load_hasher(cfg), insert_canaries=False)
        sql = to_sql(prod, rep["seed_db"])
        shadow = cfg.shadow_dir
        os.makedirs(os.path.join(shadow, "pginit"), exist_ok=True)
        with open(os.path.join(shadow, "seed.sql"), "w", encoding="utf-8") as f:
            f.write(sql)
        shutil.copyfile(os.path.join(shadow, "seed.sql"), os.path.join(shadow, "pginit", "seed.dump"))
        with open(os.path.join(shadow, "pginit", "01-seed.sh"), "w") as f:
            f.write(INIT_SH)
        for name in ("manifest.json", "markers.json"):
            shutil.copyfile(os.path.join(work, name), os.path.join(os.path.dirname(shadow), name))
        shutil.copyfile(os.path.join(work, "markers.json"), os.path.join(shadow, "markers.json"))
        sharing = shadowdata.SHARING_FILE
        if os.path.exists(os.path.join(work, "shadow", sharing)):
            shutil.copyfile(os.path.join(work, "shadow", sharing), os.path.join(shadow, sharing))
        rep = {k: v for k, v in rep.items() if k not in ("seed_db",)}
        rep.update(seed_sql=os.path.join(shadow, "seed.sql"), tables={t: len(r) for t, r in prod["rows"].items()},
                   bytes=len(sql))
        return rep
    finally:
        shutil.rmtree(work, ignore_errors=True)
