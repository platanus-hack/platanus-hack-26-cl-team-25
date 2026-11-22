"""Shadow data from a production MySQL / MariaDB database (generic runtime; contracts/product.md §4 semantics).

    from immune import shadowdata_mysql
    rep = shadowdata_mysql.build(cfg, prod_url, network)

Twin of ``immune.shadowdata_pg``, with the same ``columns.yaml`` semantics (``immune.shadowdata`` reused
unchanged): ids and foreign keys preserved, private values synthetic with the owner's marker, secrets
randomised, canaries, manifest, markers, leak self-check. How:

1. throw-away containers of the pinned MariaDB image on ``network`` read prod in **read-only** sessions
   (``SET SESSION TRANSACTION READ ONLY``; dumps in one consistent snapshot): catalog from
   ``information_schema``, ``mariadb-dump --no-data`` for the schema, every row of the tables columns.yaml
   rewrites (owner / private / secret) as JSON, and ``mariadb-dump --no-create-info`` for the public tables
   (copied verbatim by definition: large reference tables never take the SQLite detour);
2. the rewritten tables go into a temporary SQLite copy with the same keys, on which
   ``shadowdata.build_db`` runs (with the classification of those tables only);
3. the result is one SQL script: schema, public data, the synthetic rows of the rewritten tables.

Outputs (under the runtime dir):
    data/shadow/seed.sql             the dump every clone database loads into its template database `seed`
    data/shadow/myinit/01-seed.sh    /docker-entrypoint-initdb.d script: user `app`, databases `seed`, `clone`
    data/shadow/myinit/seed.dump     (a copy of seed.sql, read by the script)
    data/manifest.json, data/markers.json, data/shadow/markers.json
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile

import yaml

from . import dbkind, shadowdata
from .shadowdata_pg import load_hasher

INT_TYPES = {"tinyint", "smallint", "mediumint", "int", "integer", "bigint", "year", "bit"}
REAL_TYPES = {"decimal", "numeric", "float", "double", "real"}
BLOB_TYPES = {"binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "geometry", "point"}

INIT_SH = r"""#!/bin/sh
# written by immune.shadowdata_mysql: user `app`, template database `seed` loaded from seed.dump, and the
# database `clone` the observer rebuilds from it (sidecar: full copy on start, written tables after L1)
set -e
mariadb --protocol=socket -uroot -p"${MARIADB_ROOT_PASSWORD}" <<EOSQL
CREATE DATABASE IF NOT EXISTS seed CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE DATABASE IF NOT EXISTS clone CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY '${APP_DB_PASSWORD}';
GRANT ALL PRIVILEGES ON clone.* TO 'app'@'%';
FLUSH PRIVILEGES;
EOSQL
mariadb --protocol=socket -uroot -p"${MARIADB_ROOT_PASSWORD}" --max-allowed-packet=256M seed \
  < /docker-entrypoint-initdb.d/seed.dump
"""


class MysqlShadowError(RuntimeError):
    pass


def qi(name: str) -> str:
    return "`%s`" % name.replace("`", "``")


def literal(v) -> str:
    from sidecar.mysqlclient import literal as lit
    return lit(v)


# ------------------------------------------------------------------ reading prod
def run_client(url: str, network: str, script: str, timeout: float = 600) -> str:
    """Run `script` (sh) in a throw-away MariaDB client container on `network`. $H $P $U $D hold the prod
    host/port/user/database, MYSQL_PWD its password; `mc` is a read-only mariadb client, `md` mariadb-dump."""
    kind = dbkind.of("mysql")
    p = kind.parse(url)
    prelude = ("mc() { mariadb -h \"$H\" -P \"$P\" -u \"$U\" --protocol=tcp --skip-ssl "
               "--init-command='SET SESSION TRANSACTION READ ONLY' -N -B --raw \"$@\"; }\n"
               "md() { mariadb-dump -h \"$H\" -P \"$P\" -u \"$U\" --protocol=tcp --skip-ssl --single-transaction "
               "--skip-lock-tables --no-tablespaces --skip-comments --hex-blob \"$@\"; }\n")
    cmd = ["docker", "run", "--rm", "-i", "--network", network, "--read-only", "--tmpfs", "/tmp",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "999:999",
           "-e", "H", "-e", "P", "-e", "U", "-e", "D", "-e", "MYSQL_PWD",
           "--label", "immune.component=shadowdata", "--entrypoint", "sh", kind.image, "-e", "-s"]
    env = dict(os.environ, H=p["host"], P=str(p["port"]), U=p["user"], D=p["database"], MYSQL_PWD=p["password"])
    # bytes, not text mode: the script must reach the container with LF line endings on any host
    r = subprocess.run(cmd, input=(prelude + script).encode("utf-8"), capture_output=True, timeout=timeout, env=env)
    if r.returncode != 0:
        raise MysqlShadowError("reading prod failed (exit %d): %s" % (
            r.returncode, r.stderr.decode("utf-8", "replace").strip()[-800:]))
    return r.stdout.decode("utf-8", "replace")


CATALOG_SQL = r"""
SELECT JSON_OBJECT('kind','table','table',table_name) FROM information_schema.tables
 WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE';
SELECT JSON_OBJECT('kind','column','table',table_name,'name',column_name,'type',data_type,
                   'nullable',is_nullable = 'YES','pos',ordinal_position,'extra',extra)
  FROM information_schema.columns WHERE table_schema = DATABASE();
SELECT JSON_OBJECT('kind','pk','table',table_name,'column',column_name,'pos',seq_in_index)
  FROM information_schema.statistics WHERE table_schema = DATABASE() AND index_name = 'PRIMARY';
SELECT JSON_OBJECT('kind','fk','table',table_name,'from',column_name,'ref',referenced_table_name,
                   'to',referenced_column_name)
  FROM information_schema.key_column_usage
 WHERE table_schema = DATABASE() AND referenced_table_name IS NOT NULL;
"""


def read_catalog(url: str, network: str) -> dict:
    out = run_client(url, network, "mc \"$D\" <<'EOSQL'\n" + CATALOG_SQL + "\nEOSQL\n")
    meta = {"tables": [], "columns": [], "pks": [], "fks": []}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        k = row.pop("kind")
        if k == "table":
            meta["tables"].append(row["table"])
        elif k == "column":
            meta["columns"].append(row)
        elif k == "pk":
            meta["pks"].append(row)
        else:
            meta["fks"].append(row)
    meta["tables"].sort()
    meta["columns"].sort(key=lambda c: (c["table"], c["pos"]))
    return meta


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


def rows_query(table: str, cols: list) -> str:
    parts = []
    for c in cols:
        expr = qi(c["name"])
        if c["type"] in BLOB_TYPES:
            expr = "TO_BASE64(%s)" % expr
        elif c["type"] in ("date", "datetime", "timestamp", "time"):
            expr = "CAST(%s AS CHAR)" % expr
        parts.append("%s, %s" % (literal(c["name"]), expr))
    # chunked JSON_OBJECT keeps every row on one line (newlines inside values are escaped by JSON)
    return "SELECT JSON_OBJECT(%s) FROM %s;" % (", ".join(parts), qi(table))


def read_rows(url: str, network: str, meta: dict, tables: list) -> dict:
    cols = columns_of(meta)
    rows = {t: [] for t in tables}
    if not tables:
        return rows
    script = []
    for t in tables:
        script.append("echo '@@T %s'" % t)
        script.append("mc \"$D\" <<'EOSQL'\n%s\nEOSQL" % rows_query(t, cols[t]))
    out = run_client(url, network, "\n".join(script) + "\n")
    cur = None
    blobs = {t: {c["name"] for c in cols[t] if c["type"] in BLOB_TYPES} for t in tables}
    for line in out.splitlines():
        if line.startswith("@@T "):
            cur = line[4:].strip()
        elif line.strip() and cur is not None:
            r = json.loads(line)
            for b in blobs[cur]:
                if r.get(b) is not None:
                    r[b] = base64.b64decode(r[b])
            rows[cur].append(r)
    return rows


def dump_schema(url: str, network: str) -> str:
    return run_client(url, network, "md --no-data --routines --triggers \"$D\"\n")


def dump_data(url: str, network: str, tables: list) -> str:
    if not tables:
        return ""
    names = " ".join("'%s'" % t.replace("'", "") for t in tables)
    return run_client(url, network, "md --no-create-info --skip-triggers --complete-insert \"$D\" %s\n" % names,
                      timeout=1800)


# ------------------------------------------------------------------ SQLite bridge
def to_sqlite(meta: dict, rows: dict, tables: list, path: str) -> None:
    cols, pks = columns_of(meta), pks_of(meta)
    keep = set(tables)
    conn = sqlite3.connect(path)
    try:
        for t in tables:
            pk = pks.get(t, [])
            defs = []
            for c in cols[t]:
                ty = "INTEGER" if c["type"] in INT_TYPES else "REAL" if c["type"] in REAL_TYPES else \
                    "BLOB" if c["type"] in BLOB_TYPES else "TEXT"
                d = "%s %s" % (qi(c["name"]), ty)
                if pk == [c["name"]] and ty == "INTEGER":
                    d += " PRIMARY KEY"
                if not c["nullable"]:
                    d += " NOT NULL"
                defs.append(d)
            if pk and not (len(pk) == 1 and any(c["name"] == pk[0] and c["type"] in INT_TYPES for c in cols[t])):
                defs.append("PRIMARY KEY (%s)" % ", ".join(qi(x) for x in pk))
            for f in meta["fks"]:
                if f["table"] == t and f["ref"] in keep:
                    defs.append("FOREIGN KEY (%s) REFERENCES %s (%s)" % (qi(f["from"]), qi(f["ref"]), qi(f["to"])))
            conn.execute("CREATE TABLE %s (%s)" % (qi(t), ", ".join(defs)))
            names = [c["name"] for c in cols[t]]
            for r in rows[t]:
                vals = [json.dumps(r[n], ensure_ascii=False) if isinstance(r.get(n), (dict, list)) else r.get(n)
                        for n in names]
                conn.execute("INSERT INTO %s (%s) VALUES (%s)" % (qi(t), ", ".join(qi(n) for n in names),
                                                                  ", ".join("?" * len(names))), vals)
        conn.commit()
    finally:
        conn.close()


def to_sql(meta: dict, tables: list, shadow_sqlite: str) -> str:
    cols = columns_of(meta)
    conn = sqlite3.connect("file:%s?mode=ro" % shadow_sqlite, uri=True)
    out = []
    try:
        for t in tables:
            names = [c["name"] for c in cols[t]]
            cur = conn.execute("SELECT %s FROM %s" % (", ".join(qi(n) for n in names), qi(t)))
            batch = []
            for r in cur:
                batch.append("(%s)" % ", ".join(literal(v) for v in r))
                if len(batch) >= 200:
                    out.append("INSERT INTO %s (%s) VALUES %s;\n" % (qi(t), ", ".join(qi(n) for n in names),
                                                                     ",\n".join(batch)))
                    batch = []
            if batch:
                out.append("INSERT INTO %s (%s) VALUES %s;\n" % (qi(t), ", ".join(qi(n) for n in names),
                                                                 ",\n".join(batch)))
    finally:
        conn.close()
    return "".join(out)


# ------------------------------------------------------------------ entry
def rewritten_tables(cols: dict, meta: dict) -> list:
    """Tables columns.yaml rewrites (owner / private / secret), plus the users table; the rest is public."""
    spec = cols.get("tables") or {}
    out = {cols.get("users_table")}
    for t, s in spec.items():
        if isinstance(s, dict) and not s.get("public") and (s.get("owner") or s.get("private") or s.get("secret")):
            out.add(t)
            o = s.get("owner")
            if isinstance(o, dict) and o.get("table"):
                out.add(o["table"])
    return sorted(t for t in out if t in meta["tables"])


def build(cfg, prod_url: str, network: str, *, seed: int = 1) -> dict:
    from . import _cfg
    columns = _cfg.columns_path(cfg)
    if not os.path.isfile(columns):
        raise MysqlShadowError("%s not found (columns.yaml is required to derive shadow data)" % columns)
    with open(columns, encoding="utf-8") as fh:
        cols = yaml.safe_load(fh) or {}
    meta = read_catalog(prod_url, network)
    missing = [t for t in meta["tables"] if t not in (cols.get("tables") or {})]
    if missing:
        raise MysqlShadowError("columns.yaml does not classify %d table(s) of the prod database: %s"
                               % (len(missing), ", ".join(missing[:20])))
    rewrite = rewritten_tables(cols, meta)
    public = [t for t in meta["tables"] if t not in rewrite]
    rows = read_rows(prod_url, network, meta, rewrite)
    schema = dump_schema(prod_url, network)
    public_data = dump_data(prod_url, network, public)
    sub = dict(cols)
    sub["tables"] = {t: s for t, s in (cols.get("tables") or {}).items() if t in rewrite}
    sub["routes"] = {k: v for k, v in (cols.get("routes") or {}).items()
                     if isinstance(v, dict) and v.get("table") in rewrite}
    work = tempfile.mkdtemp(prefix="immune-myshadow-")
    try:
        lite = os.path.join(work, "prod.db")
        to_sqlite(meta, rows, rewrite, lite)
        rep = shadowdata.build_db(lite, sub, work, seed=seed, admin_values=cfg.auth.admin_values,
                                  hash_password=load_hasher(cfg), insert_canaries=False)
        data = to_sql(meta, rewrite, rep["seed_db"])
        sql = "".join([
            "-- shadow seed written by immune.shadowdata_mysql (synthetic private data; public tables verbatim)\n",
            "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\nSET UNIQUE_CHECKS=0;\nSET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n",
            schema, "\n", public_data, "\n", data, "\nSET FOREIGN_KEY_CHECKS=1;\n"])
        shadow = cfg.shadow_dir
        init = os.path.join(shadow, dbkind.of("mysql").init_dir)
        os.makedirs(init, exist_ok=True)
        with open(os.path.join(shadow, "seed.sql"), "w", encoding="utf-8", newline="\n") as f:
            f.write(sql)
        shutil.copyfile(os.path.join(shadow, "seed.sql"), os.path.join(init, "seed.dump"))
        with open(os.path.join(init, "01-seed.sh"), "w", newline="\n") as f:
            f.write(INIT_SH)
        os.chmod(os.path.join(init, "01-seed.sh"), 0o755)
        for name in ("manifest.json", "markers.json"):
            shutil.copyfile(os.path.join(work, name), os.path.join(os.path.dirname(shadow), name))
        shutil.copyfile(os.path.join(work, "markers.json"), os.path.join(shadow, "markers.json"))
        sharing = os.path.join(work, "shadow", getattr(shadowdata, "SHARING_FILE", "sharing.json"))
        if os.path.exists(sharing):
            shutil.copyfile(sharing, os.path.join(shadow, os.path.basename(sharing)))
        rep = {k: v for k, v in rep.items() if k not in ("seed_db",)}
        rep.update(seed_sql=os.path.join(shadow, "seed.sql"), tables=len(meta["tables"]), rewritten=rewrite,
                   bytes=len(sql))
        return rep
    finally:
        shutil.rmtree(work, ignore_errors=True)
