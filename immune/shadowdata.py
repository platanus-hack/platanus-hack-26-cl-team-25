"""Shadow data from a production SQLite database (contracts/product.md §4).

    from immune import shadowdata
    rep = shadowdata.build(cfg)                       # cfg: immune.config.Config (or a project dir)
    rep = shadowdata.build_db(prod_db, columns, out_dir, seed=1)   # lower level, no config

Reads the production database **read-only** and writes, under ``out_dir``:

    shadow/seed.db        same schema, same ids, same foreign keys; private values synthetic and
                          carrying the owner's marker (MK + 10 [A-Z0-9]); secrets random with the
                          same shape; public tables copied; 2 canary users + 2 canary rows per
                          owner-scoped table
    manifest.json         seed_max_uid, seed_max_<table>_id, legit_users, admin, canaries, ownership
    markers.json          marker -> owner uid (also shadow/markers.json)

Everything is deterministic for a given ``seed``. ``leak_check`` (also used by ``immune doctor``)
verifies that no sampled real private/secret value survives anywhere in the shadow database.

``columns.yaml`` (contracts/product.md §4, plus optional keys this generator understands):

    users_table: users
    user_id_column: id
    role_column: role                 # optional
    login_column: email               # optional: column used to log in (for manifest legit_users)
    secret_column: password_hash      # optional: password hash column (needs profile.hash_password)
    tables:
      users:  {owner: id, private: [email, name], secret: [password_hash]}
      orders: {owner: user_id, private: [note]}
      order_items: {owner: {via: order_id, table: orders}}     # owner through a foreign key
      products: {public: true}
    routes:
      order_id: {table: orders, column: id}
    why: {"users.email": "...", ...}  # optional justifications (report only)
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import random
import re
import shutil
import sqlite3
import string
import tempfile

import yaml

MARKER_RE = re.compile(r"MK[A-Z0-9]{10}")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
CANARY_GAP = 100000          # canary ids = max id + CANARY_GAP + k: far from ids prod will hand out soon
LEGIT_COUNT = 8
SAMPLE = 200

# Synthetic vocabulary: deliberately unusual, so it never collides with real data.
FIRST = ["Aurelio", "Brisa", "Casimiro", "Dafne", "Eulalio", "Fermina", "Gaspar", "Hortensia", "Ildefonso",
         "Jacinta", "Leoncio", "Melisenda", "Nemesio", "Olimpia", "Pancracio", "Quiteria", "Rosendo", "Sinforosa",
         "Tranquilino", "Ursulina", "Vitaliano", "Wenceslada", "Zoilo", "Ximena"]
LAST = ["Arandelo", "Berrocal", "Cienfuegos", "Dorrego", "Espinel", "Fontecilla", "Garmendia", "Hurtado-Lis",
        "Iturbe", "Jaramago", "Lastarria", "Montenebro", "Nogaleda", "Olavarrieta", "Pezoa", "Quintanal",
        "Riquelmo", "Santelices", "Terrazino", "Ugarteche", "Valdivieso", "Zañartu"]
STREETS = ["Calle Sintetica", "Pasaje Ficticio", "Avenida Inventada", "Camino Simulado", "Callejon Sombra",
           "Paseo Imaginario"]
CITIES = ["Villa Sombra", "Puerto Ficcion", "San Simulado", "Ciudad Espejo"]
WORDS = ["informe", "revision", "pendiente", "propuesta", "reunion", "detalle", "entrega", "borrador", "plan",
         "seguimiento", "registro", "resumen", "acuerdo", "consulta", "solicitud", "observacion"]
SENTENCES = ["Texto sintetico de prueba.", "Contenido generado para la copia sombra.", "Registro ficticio sin datos reales.",
             "Borrador simulado con fines de verificacion.", "Detalle inventado para el entorno espejo.",
             "Nota artificial creada por el generador."]

_PRIVATE_KINDS = (
    ("email", ("email", "mail", "correo")),
    ("phone", ("phone", "tel", "mobile", "movil", "celular", "fono", "fax")),
    ("first", ("first_name", "firstname", "given_name", "nombre_pila")),
    ("last", ("last_name", "lastname", "surname", "family_name", "apellido")),
    ("name", ("name", "nombre", "full_name", "fullname", "display_name", "username", "user_name", "author")),
    ("address", ("address", "addr", "street", "direccion", "domicilio", "calle")),
    ("city", ("city", "ciudad", "comuna", "commune", "town", "region", "state", "country", "pais")),
    ("zip", ("zip", "postal", "postcode")),
    ("url", ("url", "website", "link", "avatar")),
    ("ip", ("ip", "ip_address", "remote_addr")),
)


class ColumnsError(ValueError):
    pass


# ------------------------------------------------------------------------------------------ schema
def _ro(path: str) -> sqlite3.Connection:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    conn = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(path), uri=True)
    return conn


def _q(name: str) -> str:
    return '"%s"' % name.replace('"', '""')


def dump_schema(db_path: str, conn: sqlite3.Connection | None = None) -> dict:
    """{"tables": {name: {"columns": [{name,type,pk,notnull}], "fks": [...], "pk": [...], "rowid_alias": str|None,
    "rows": n, "sql": str}}}"""
    own = conn is None
    conn = conn or _ro(db_path)
    try:
        out = {"tables": {}}
        rows = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                            "ORDER BY name").fetchall()
        for name, sql in rows:
            cols = [{"name": r[1], "type": (r[2] or "").upper(), "notnull": bool(r[3]), "pk": int(r[5])}
                    for r in conn.execute("PRAGMA table_info(%s)" % _q(name))]
            fks = [{"from": r[3], "table": r[2], "to": r[4]} for r in conn.execute("PRAGMA foreign_key_list(%s)" % _q(name))]
            pk = [c["name"] for c in sorted((c for c in cols if c["pk"]), key=lambda c: c["pk"])]
            without_rowid = bool(sql and re.search(r"WITHOUT\s+ROWID", sql, re.I))
            alias = pk[0] if (len(pk) == 1 and not without_rowid and
                              next(c for c in cols if c["name"] == pk[0])["type"] == "INTEGER") else None
            n = conn.execute("SELECT COUNT(*) FROM %s" % _q(name)).fetchone()[0]
            out["tables"][name] = {"columns": cols, "fks": fks, "pk": pk, "rowid_alias": alias,
                                   "without_rowid": without_rowid, "rows": n, "sql": sql}
        return out
    finally:
        if own:
            conn.close()


# ------------------------------------------------------------------------------------------ columns.yaml
def load_columns(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    if not isinstance(doc, dict):
        raise ColumnsError("%s: top level must be a mapping" % path)
    return doc


def _owner_spec(spec):
    o = spec.get("owner") if isinstance(spec, dict) else None
    return o


def validate_columns(cols: dict, schema: dict) -> list[str]:
    """Mechanical validation against the real schema. [] = valid."""
    errs = []
    tables = schema["tables"]
    if not isinstance(cols, dict):
        return ["columns.yaml: top level must be a mapping"]
    ut = cols.get("users_table")
    uc = cols.get("user_id_column", "id")
    if not isinstance(ut, str) or ut not in tables:
        errs.append("users_table: %r is not a table of the database (tables: %s)" % (ut, ", ".join(tables)))
    else:
        names = [c["name"] for c in tables[ut]["columns"]]
        if uc not in names:
            errs.append("user_id_column: %r is not a column of %s" % (uc, ut))
        for key in ("role_column", "login_column", "secret_column"):
            v = cols.get(key)
            if v not in (None, "") and v not in names:
                errs.append("%s: %r is not a column of %s" % (key, v, ut))
    t = cols.get("tables")
    if not isinstance(t, dict):
        errs.append("tables: must be a mapping table -> classification")
        t = {}
    for name in tables:
        if name not in t:
            errs.append("tables: table %r is not classified (every table needs public: true, or owner/private/secret)"
                        % name)
    for name, spec in t.items():
        if name not in tables:
            errs.append("tables.%s: no such table in the database" % name)
            continue
        if spec is None or not isinstance(spec, dict):
            errs.append("tables.%s: must be a mapping" % name)
            continue
        colnames = [c["name"] for c in tables[name]["columns"]]
        unknown = set(spec) - {"owner", "private", "secret", "public", "why"}
        if unknown:
            errs.append("tables.%s: unknown keys %s" % (name, sorted(unknown)))
        if spec.get("public"):
            if spec.get("private") or spec.get("secret"):
                errs.append("tables.%s: public: true cannot also list private/secret columns" % name)
            continue
        for key in ("private", "secret"):
            v = spec.get(key) or []
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                errs.append("tables.%s.%s: must be a list of column names" % (name, key))
                continue
            for c in v:
                if c not in colnames:
                    errs.append("tables.%s.%s: %r is not a column of %s (columns: %s)"
                                % (name, key, c, name, ", ".join(colnames)))
        both = set(spec.get("private") or []) & set(spec.get("secret") or [])
        if both:
            errs.append("tables.%s: columns both private and secret: %s" % (name, sorted(both)))
        keys = set(tables[name]["pk"]) | {f["from"] for f in tables[name]["fks"]}
        referenced = {(f["table"], f["to"]) for i in tables.values() for f in i["fks"]}
        for c in (spec.get("private") or []) + (spec.get("secret") or []):
            ctype = next((x["type"] for x in tables[name]["columns"] if x["name"] == c), "")
            if c in (spec.get("secret") or []) and tables[name]["pk"] == [c] and tables[name]["rowid_alias"] != c \
                    and (name, c) not in referenced and (name, None) not in referenced and "INT" not in ctype:
                continue  # an opaque text key nobody references (e.g. a session token): randomised like any secret
            if c in keys or (tables[name]["rowid_alias"] == c):
                errs.append("tables.%s: %r is a key/foreign-key column; keys are never rewritten (skeleton must stay)"
                            % (name, c))
        o = spec.get("owner")
        if o is None:
            if spec.get("private") and isinstance(ut, str) and name != ut:
                pass  # private without owner: allowed (no marker possible), reported as a warning
        elif isinstance(o, str):
            if o in (spec.get("private") or []) or o in (spec.get("secret") or []):
                errs.append("tables.%s.owner: the owner column %r cannot be private/secret" % (name, o))
            if o not in colnames:
                errs.append("tables.%s.owner: %r is not a column of %s" % (name, o, name))
            if name == ut and o != uc:
                errs.append("tables.%s.owner: the users table's owner must be its id column %r" % (name, uc))
        elif isinstance(o, dict):
            via, tt = o.get("via"), o.get("table")
            if via not in colnames:
                errs.append("tables.%s.owner.via: %r is not a column of %s" % (name, via, name))
            if tt not in tables:
                errs.append("tables.%s.owner.table: %r is not a table" % (name, tt))
            elif not tables[tt]["rowid_alias"] and not tables[tt]["pk"]:
                errs.append("tables.%s.owner.table: %r has no primary key to follow" % (name, tt))
            elif not _owner_spec(t.get(tt) or {}):
                errs.append("tables.%s.owner.table: %r has no owner itself" % (name, tt))
        else:
            errs.append("tables.%s.owner: must be a column name or {via: <fk column>, table: <table>}" % name)
    if isinstance(ut, str) and ut in t and not _owner_spec(t.get(ut) or {}):
        errs.append("tables.%s: the users table must have owner: %s" % (ut, uc))
    r = cols.get("routes") or {}
    if not isinstance(r, dict):
        errs.append("routes: must be a mapping path-parameter -> {table, column}")
        r = {}
    for p, m in r.items():
        if not isinstance(m, dict) or m.get("table") not in tables:
            errs.append("routes.%s: table %r does not exist" % (p, (m or {}).get("table") if isinstance(m, dict) else m))
            continue
        if m.get("column") not in [c["name"] for c in tables[m["table"]]["columns"]]:
            errs.append("routes.%s: column %r is not a column of %s" % (p, m.get("column"), m["table"]))
    return errs


def warnings_for(cols: dict, schema: dict) -> list[str]:
    """Non-fatal findings for human review (likely misclassification)."""
    out = []
    t = cols.get("tables") or {}
    hint = re.compile(r"(email|mail|phone|tel|name|nombre|address|direcc|street|note|body|comment|message|ssn|dni|"
                      r"rut|birth|token|secret|password|hash|key|salary|card|iban|content|text|descr)", re.I)
    for name, info in schema["tables"].items():
        spec = t.get(name) or {}
        classified = set(spec.get("private") or []) | set(spec.get("secret") or [])
        keys = set(info["pk"]) | {f["from"] for f in info["fks"]}
        strong = re.compile(r"(email|mail|phone|tel|address|direcc|ssn|dni|rut|birth|token|secret|password|"
                            r"passwd|hash|salary|card|iban)", re.I)
        for c in info["columns"]:
            if c["name"] in classified or c["name"] in keys:
                continue
            pat = strong if spec.get("public") else hint
            if pat.search(c["name"]) and (c["type"] in ("TEXT", "", "BLOB") or "CHAR" in c["type"]):
                out.append("%s.%s is copied verbatim to the shadow (%s); its name suggests it may be private"
                           % (name, c["name"], "public table" if spec.get("public") else "not listed as private"))
        if spec.get("private") and not spec.get("owner"):
            out.append("%s has private columns but no owner: its synthetic values carry no marker "
                       "(the owner oracle cannot see leaks of this table)" % name)
    return out


# ------------------------------------------------------------------------------------------ synthesis
def _rng(seed, *parts) -> random.Random:
    h = hashlib.sha256(("|".join(str(p) for p in (seed,) + parts)).encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def make_markers(seed, uids) -> dict:
    rng = _rng(seed, "markers")
    alphabet = string.ascii_uppercase + string.digits
    out, seen = {}, set()
    for uid in uids:
        while True:
            mk = "MK" + "".join(rng.choice(alphabet) for _ in range(10))
            if mk not in seen:
                seen.add(mk)
                break
        out[uid] = mk
    return out


def _kind(col: str, value) -> str:
    c = col.lower()
    if isinstance(value, str):
        v = value.strip()
        if v[:1] in "{[":
            try:
                json.loads(v)
                return "json"
            except ValueError:
                pass
        if EMAIL_RE.match(v):
            return "email"
    for kind, keys in _PRIVATE_KINDS:
        if any(k == c or k in c for k in keys):
            if kind == "ip" and not (c == "ip" or c.endswith("_ip") or c.startswith("ip_") or "ip_addr" in c
                                     or c == "remote_addr"):
                continue
            return kind
    if isinstance(value, str):
        if DATE_RE.match(value.strip()):
            return "date"
        if IP_RE.match(value.strip()):
            return "ip"
        if value.startswith(("http://", "https://")):
            return "url"
    return "text"


def _shape_random(value: str, rng: random.Random) -> str:
    if value and HEX_RE.match(value) and len(value) >= 8:
        alpha = "0123456789abcdef" if value == value.lower() else "0123456789ABCDEF"
        return "".join(rng.choice(alpha) for _ in value)
    out = []
    for ch in value:
        if ch.isdigit():
            out.append(rng.choice(string.digits))
        elif ch.isascii() and ch.islower():
            out.append(rng.choice(string.ascii_lowercase))
        elif ch.isascii() and ch.isupper():
            out.append(rng.choice(string.ascii_uppercase))
        elif ch.isalpha():
            out.append(rng.choice(string.ascii_letters))
        else:
            out.append(ch)
    s = "".join(out)
    if s == value and value:      # e.g. only punctuation: still must differ
        s = "".join(rng.choice(string.ascii_letters) for _ in value)
    return s


def secret_value(value, rng: random.Random):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        n = max(1, len(str(abs(value))))
        return rng.randrange(10 ** (n - 1) if n > 1 else 0, 10 ** n)
    if isinstance(value, float):
        return round(rng.uniform(0, max(1.0, abs(value) * 2)), 4)
    if isinstance(value, bytes):
        return bytes(rng.randrange(256) for _ in value)
    return _shape_random(str(value), rng)


def _mk_part(mk):
    return mk or ""


def private_value(col: str, value, mk: str | None, rng: random.Random):
    """A plausible synthetic value for one private cell, embedding the owner's marker when there is one."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return secret_value(value, rng)
    if isinstance(value, bytes):
        return bytes(rng.randrange(256) for _ in value)
    kind = _kind(col, value)
    m = _mk_part(mk)
    first, last = rng.choice(FIRST), rng.choice(LAST)
    if kind == "json":
        try:
            doc = json.loads(value)
        except ValueError:
            doc = None
        if doc is not None:
            return json.dumps(_synth_json(doc, mk, rng), ensure_ascii=False)
        kind = "text"
    if kind == "email":
        local = "%s.%s" % (first.lower(), m or "x%d" % rng.randrange(10 ** 6))
        return "%s%s@shadow.example" % (local, "" if m else "")
    if kind == "phone":
        return "+00 %d %04d %04d%s" % (rng.randrange(1, 9), rng.randrange(10000), rng.randrange(10000),
                                        (" x" + m) if m else "")
    if kind == "first":
        return ("%s %s" % (first, m)).strip()
    if kind == "last":
        return ("%s %s" % (m, last)).strip()
    if kind == "name":
        return ("%s %s %s" % (first, m, last)).replace("  ", " ")
    if kind == "address":
        return ("%s %d, %s%s" % (rng.choice(STREETS), rng.randrange(1, 9999), rng.choice(CITIES),
                                 (" Apt " + m) if m else ""))
    if kind == "city":
        return ("%s %s" % (rng.choice(CITIES), m)).strip()
    if kind == "zip":
        return ("%05d %s" % (rng.randrange(100000), m)).strip()
    if kind == "url":
        return "https://shadow.example/%s/%d" % (m or "x", rng.randrange(10 ** 6))
    if kind == "ip":
        return "10.%d.%d.%d" % (rng.randrange(256), rng.randrange(256), rng.randrange(1, 255))
    if kind == "date":
        base = _dt.datetime(2000, 1, 1) + _dt.timedelta(days=rng.randrange(9000), seconds=rng.randrange(86400))
        v = value.strip()
        if len(v) == 10:
            return base.strftime("%Y-%m-%d")
        sep = "T" if "T" in v else " "
        s = base.strftime("%Y-%m-%d" + sep + "%H:%M:%S")
        return s + ("Z" if v.endswith("Z") else "")
    # free text
    if value.strip() == "":
        return ("Ref %s" % m) if m else value
    words = max(1, min(12, len(value.split())))
    if len(value) <= 24:
        body = " ".join(rng.choice(WORDS) for _ in range(max(1, min(3, words)))).capitalize()
    else:
        body = " ".join(rng.choice(SENTENCES) for _ in range(max(1, min(4, len(value) // 60 + 1))))
    return ("%s (%s)" % (body, m)) if m else body


def _synth_json(doc, mk, rng):
    if isinstance(doc, dict):
        return {k: _synth_json(v, mk, rng) if not isinstance(v, str) else private_value(k, v, mk, rng)
                for k, v in doc.items()}
    if isinstance(doc, list):
        return [_synth_json(v, mk, rng) if not isinstance(v, str) else private_value("item", v, mk, rng) for v in doc]
    if isinstance(doc, (int, float)) and not isinstance(doc, bool):
        return secret_value(doc, rng)
    return doc


# ------------------------------------------------------------------------------------------ build
class _Ctx:
    def __init__(self, conn, schema, cols, seed):
        self.conn, self.schema, self.cols, self.seed = conn, schema, cols, seed
        self.tables = cols.get("tables") or {}
        self.ut = cols["users_table"]
        self.uc = cols.get("user_id_column") or "id"
        self._owner_cache = {}

    def keyexpr(self, table):
        info = self.schema["tables"][table]
        if not info["without_rowid"]:
            return ["rowid"]
        return info["pk"] or [c["name"] for c in info["columns"]]

    def owners(self, table) -> dict:
        """{pk value (rowid alias or first pk) -> owner uid} for an owner-scoped table."""
        if table in self._owner_cache:
            return self._owner_cache[table]
        spec = self.tables.get(table) or {}
        o = spec.get("owner")
        info = self.schema["tables"][table]
        pkcol = info["rowid_alias"] or (info["pk"][0] if info["pk"] else None)
        out = {}
        if isinstance(o, str) and pkcol:
            for pk, ov in self.conn.execute("SELECT %s, %s FROM %s" % (_q(pkcol), _q(o), _q(table))):
                out[pk] = _as_uid(ov)
        elif isinstance(o, dict) and pkcol:
            parent = self.owners(o["table"])
            for pk, via in self.conn.execute("SELECT %s, %s FROM %s" % (_q(pkcol), _q(o["via"]), _q(table))):
                out[pk] = parent.get(via if via in parent else _as_uid(via))
        self._owner_cache[table] = out
        return out

    def row_owner_sql(self, table):
        """(select list for the owner of each row, resolver(row_value) -> uid)."""
        spec = self.tables.get(table) or {}
        o = spec.get("owner")
        if isinstance(o, str):
            return o, _as_uid
        if isinstance(o, dict):
            parent = self.owners(o["table"])
            return o["via"], (lambda v, parent=parent: parent.get(v if v in parent else _as_uid(v)))
        return None, None


def _as_uid(v):
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


def _triggers(conn):
    return conn.execute("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND sql IS NOT NULL").fetchall()


def _update(conn, table, keycols, keyvals, changes):
    sets = ", ".join("%s = ?" % _q(c) for c in changes)
    where = " AND ".join(("rowid = ?" if k == "rowid" else "%s IS ?" % _q(k)) for k in keycols)
    conn.execute("UPDATE %s SET %s WHERE %s" % (_q(table), sets, where), list(changes.values()) + list(keyvals))


def _rewrite_table(ctx: _Ctx, table: str, markers: dict, overrides: dict | None = None):
    spec = ctx.tables.get(table) or {}
    private = list(spec.get("private") or [])
    secret = list(spec.get("secret") or [])
    if spec.get("public") or not (private or secret):
        return 0
    keycols = ctx.keyexpr(table)
    ocol, resolve = ctx.row_owner_sql(table)
    sel = [*keycols, *private, *secret] + ([ocol] if ocol else [])
    rows = ctx.conn.execute("SELECT %s FROM %s" % (", ".join(c if c == "rowid" else _q(c) for c in sel), _q(table))).fetchall()
    n = 0
    for row in rows:
        kv = row[:len(keycols)]
        pv = row[len(keycols):len(keycols) + len(private)]
        sv = row[len(keycols) + len(private):len(keycols) + len(private) + len(secret)]
        owner = resolve(row[-1]) if ocol else None
        mk = markers.get(owner)
        changes = {}
        for c, v in zip(private, pv):
            changes[c] = private_value(c, v, mk, _rng(ctx.seed, table, c, *kv))
        for c, v in zip(secret, sv):
            changes[c] = secret_value(v, _rng(ctx.seed, "secret", table, c, *kv))
        if overrides and owner in overrides.get(table, {}):
            changes.update(overrides[table][owner])
        try:
            _update(ctx.conn, table, keycols, kv, changes)
        except sqlite3.IntegrityError:
            for c in changes:
                if isinstance(changes[c], str):
                    changes[c] = "%s-%s" % (changes[c], "-".join(str(x) for x in kv))
            _update(ctx.conn, table, keycols, kv, changes)
        n += 1
    return n


def _insert_copy(conn, table, schema, template: dict, changes: dict):
    row = dict(template)
    row.update(changes)
    cols = [c["name"] for c in schema["tables"][table]["columns"]]
    vals = [row.get(c) for c in cols]
    sql = "INSERT INTO %s (%s) VALUES (%s)" % (_q(table), ", ".join(_q(c) for c in cols), ", ".join("?" * len(cols)))
    for attempt in range(3):
        try:
            conn.execute(sql, vals)
            return
        except sqlite3.IntegrityError:
            keys = set(changes)
            vals = [("%s-c%d" % (v, attempt + 1)) if (isinstance(v, str) and c not in keys) else v
                    for c, v in zip(cols, vals)]
    conn.execute(sql, vals)


def _template_row(conn, table, where="", params=()):
    cur = conn.execute("SELECT * FROM %s %s ORDER BY rowid LIMIT 1" % (_q(table), where), params)
    r = cur.fetchone()
    if r is None:
        return None
    return {d[0]: v for d, v in zip(cur.description, r)}


def _admin_values(cols, admin_values):
    return [str(x) for x in (admin_values or cols.get("admin_values") or ["admin"])]


def build_db(prod_db: str, columns, out_dir: str, *, seed: int = 1, admin_values=None,
             hash_password=None, insert_canaries: bool = False, legit_count: int = LEGIT_COUNT,
             sample: int = SAMPLE) -> dict:
    """Write out_dir/shadow/seed.db, out_dir/manifest.json, out_dir/markers.json (+ shadow/markers.json).

    ``columns``: dict or path. ``hash_password``: optional callable(list[str]) -> list[str] (the app's own
    password hashing, from the generated profile) used to give a few shadow users known passwords.
    Returns a report dict; raises ColumnsError when columns.yaml does not match the database, and
    RuntimeError when the leak self-check finds a real value in the shadow.
    """
    cols = load_columns(columns) if isinstance(columns, str) else dict(columns)
    schema = dump_schema(prod_db)
    errs = validate_columns(cols, schema)
    if errs:
        raise ColumnsError("columns.yaml does not match %s:\n  - %s" % (prod_db, "\n  - ".join(errs)))
    shadow_dir = os.path.join(out_dir, "shadow")
    os.makedirs(shadow_dir, exist_ok=True)
    seed_path = os.path.join(shadow_dir, "seed.db")
    fd, tmp = tempfile.mkstemp(prefix=".seed-", suffix=".db", dir=shadow_dir)
    os.close(fd)
    src = _ro(prod_db)
    dst = sqlite3.connect(tmp)
    try:
        src.backup(dst)
    finally:
        src.close()
    dst.execute("PRAGMA journal_mode=DELETE")
    ctx = _Ctx(dst, schema, cols, seed)
    ut, uc = ctx.ut, ctx.uc
    role_col = cols.get("role_column") or None
    admins = _admin_values(cols, admin_values)

    try:
        prod_markers = _scan_markers(dst)
        uids = sorted(_as_uid(r[0]) for r in dst.execute("SELECT %s FROM %s" % (_q(uc), _q(ut))) if r[0] is not None)
        int_uids = [u for u in uids if isinstance(u, int)]
        seed_max_uid = max(int_uids) if int_uids else 0
        canary_uids = [seed_max_uid + CANARY_GAP + k for k in (1, 2)]
        markers = make_markers(seed, uids + canary_uids)

        # owner-scoped tables (direct or via) and row counts per owner
        owned_tables = [t for t, s in (cols.get("tables") or {}).items() if isinstance(s, dict) and s.get("owner")]
        counts = {}
        for t in owned_tables:
            if t == ut:
                continue
            for _, o in ctx.owners(t).items():
                counts[o] = counts.get(o, 0) + 1
        roles = {}
        if role_col:
            for uid, role in dst.execute("SELECT %s, %s FROM %s" % (_q(uc), _q(role_col), _q(ut))):
                roles[_as_uid(uid)] = role
        admin_ids = [u for u in uids if str(roles.get(u)) in admins]
        plain_role = _most_common([r for u, r in roles.items() if str(r) not in admins]) if roles else None

        # known-password users (legit + admin), when the app's hashing is available
        login_col = cols.get("login_column") or None
        secret_col = cols.get("secret_column") or None
        non_admin = [u for u in uids if u not in admin_ids]
        legit = sorted(non_admin, key=lambda u: (-counts.get(u, 0), str(u)))[:legit_count]
        legit = sorted(legit, key=lambda u: (isinstance(u, str), u if isinstance(u, int) else 0, str(u)))
        admin_id = admin_ids[0] if admin_ids else None
        passwords = {}
        overrides = {}
        if hash_password and login_col and secret_col:
            prng = _rng(seed, "passwords")
            for u in legit + ([admin_id] if admin_id is not None else []):
                passwords[u] = "Shadow-%s-%04d" % (prng.choice(WORDS), prng.randrange(10000))
            order = list(passwords)
            hashes = hash_password([passwords[u] for u in order])
            if not isinstance(hashes, list) or len(hashes) != len(order):
                raise RuntimeError("hash_password returned %r" % (type(hashes),))
            overrides = {ut: {u: {secret_col: h} for u, h in zip(order, hashes)}}

        trig = _triggers(dst)
        for name, _ in trig:
            dst.execute("DROP TRIGGER %s" % _q(name))
        rewritten = {}
        for t in schema["tables"]:
            rewritten[t] = _rewrite_table(ctx, t, markers, overrides)

        # canaries: 2 users, 2 rows per directly owner-scoped table with an integer key
        canary_rows = {}
        tmpl = _template_row(dst, ut, "WHERE %s IS NOT ?" % _q(role_col), (admins[0],)) if role_col else \
            _template_row(dst, ut)
        if tmpl is not None:
            uspec = cols["tables"][ut]
            for k, cu in enumerate(canary_uids):
                ch = {uc: cu}
                for c in uspec.get("private") or []:
                    ch[c] = private_value(c, tmpl.get(c) if tmpl.get(c) is not None else "x", markers[cu],
                                          _rng(seed, "canary", ut, c, k))
                for c in uspec.get("secret") or []:
                    ch[c] = secret_value(tmpl.get(c), _rng(seed, "canary-secret", ut, c, k))
                if role_col and plain_role is not None:
                    ch[role_col] = plain_role
                _insert_copy(dst, ut, schema, tmpl, ch)
        for t in owned_tables:
            spec = cols["tables"][t]
            info = schema["tables"][t]
            if t == ut or not isinstance(spec.get("owner"), str) or not info["rowid_alias"]:
                continue
            pk = info["rowid_alias"]
            row = _template_row(dst, t)
            if row is None:
                continue
            mx = dst.execute("SELECT MAX(%s) FROM %s" % (_q(pk), _q(t))).fetchone()[0] or 0
            ids = []
            for k, cu in enumerate(canary_uids):
                cid = mx + CANARY_GAP + k + 1
                ch = {pk: cid, spec["owner"]: cu}
                for c in spec.get("private") or []:
                    ch[c] = private_value(c, row.get(c) if row.get(c) is not None else "x", markers[cu],
                                          _rng(seed, "canary", t, c, k))
                for c in spec.get("secret") or []:
                    ch[c] = secret_value(row.get(c), _rng(seed, "canary-secret", t, c, k))
                _insert_copy(dst, t, schema, row, ch)
                ids.append(cid)
            canary_rows[t] = ids
        for name, sql in trig:
            dst.execute(sql)
        dst.commit()

        # manifest
        ctx._owner_cache.clear()
        ownership = {}
        for t in owned_tables:
            if t == ut:
                continue
            own = ctx.owners(t)
            if own:
                ownership[t] = {str(k): v for k, v in sorted(own.items(), key=lambda kv: str(kv[0]))}
        canaries = {}
        for param, m in (cols.get("routes") or {}).items():
            if m["table"] == ut and m["column"] == uc:
                canaries[param] = list(canary_uids)
            elif m["table"] in canary_rows and m["column"] == schema["tables"][m["table"]]["rowid_alias"]:
                canaries[param] = list(canary_rows[m["table"]])
            # the gateway looks ownership up by <param minus _id> + "s"
            if param.endswith("_id") and m["table"] in ownership and param[:-3] + "s" not in ownership \
                    and m["column"] == schema["tables"][m["table"]]["rowid_alias"]:
                ownership[param[:-3] + "s"] = ownership[m["table"]]
        login_vals = {}
        if login_col:
            for uid, lv in dst.execute("SELECT %s, %s FROM %s" % (_q(uc), _q(login_col), _q(ut))):
                login_vals[_as_uid(uid)] = lv

        def cred(u, role):
            d = {"id": u, "role": role}
            if u in passwords:
                d.update({"email": login_vals.get(u), "login": login_vals.get(u), "password": passwords[u]})
            return d
        manifest = {
            "generated_by": "immune.shadowdata", "seed": seed,
            "seed_max_uid": seed_max_uid,
            "legit_users": [cred(u, str(roles.get(u, plain_role or "user"))) for u in legit],
            "admin": cred(admin_id, str(roles.get(admin_id))) if admin_id is not None else None,
            "canaries": canaries,
            "canary_users": list(canary_uids),
            "canary_rows": canary_rows,
            "ownership": ownership,
        }
        for t in owned_tables:
            info = schema["tables"][t]
            if t != ut and info["rowid_alias"]:
                mx = src_max(prod_db, t, info["rowid_alias"])
                single = t[:-1] if t.endswith("s") else t
                manifest["seed_max_%s_id" % single] = mx
        dst.close()
        dst = None
        os.replace(tmp, seed_path)
    except BaseException:
        if dst is not None:
            dst.close()
        if os.path.exists(tmp):
            os.remove(tmp)
        raise

    inv = {mk: uid for uid, mk in markers.items()}
    _write_json(os.path.join(out_dir, "manifest.json"), manifest)
    _write_json(os.path.join(out_dir, "markers.json"), inv)
    _write_json(os.path.join(shadow_dir, "markers.json"), inv)
    if insert_canaries:
        _insert_prod_canaries(prod_db, seed_path, cols, schema, canary_uids, canary_rows)
    leaks = leak_check(prod_db, seed_path, cols, sample=sample, seed=seed)
    if leaks:
        raise RuntimeError("leak self-check failed: %d real value(s) found in the shadow, e.g. %s"
                           % (len(leaks), leaks[0]))
    return {"seed_db": seed_path, "manifest": os.path.join(out_dir, "manifest.json"),
            "markers": os.path.join(out_dir, "markers.json"), "users": len(uids), "canary_users": canary_uids,
            "canary_rows": canary_rows, "rewritten": rewritten, "legit_with_password": len(passwords),
            "prod_markers_found": prod_markers, "warnings": warnings_for(cols, schema)}


def src_max(db, table, col):
    c = _ro(db)
    try:
        return c.execute("SELECT MAX(%s) FROM %s" % (_q(col), _q(table))).fetchone()[0] or 0
    finally:
        c.close()


def _most_common(vals):
    best = None
    counts = {}
    for v in vals:
        counts[v] = counts.get(v, 0) + 1
    for v, n in sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0]))):
        best = v
        break
    return best


def _scan_markers(conn) -> int:
    n = 0
    for (t,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
        for row in conn.execute("SELECT * FROM %s" % _q(t)):
            for v in row:
                if isinstance(v, str) and MARKER_RE.search(v):
                    n += 1
    return n


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=False, default=str)
    os.replace(tmp, path)


def _insert_prod_canaries(prod_db, seed_path, cols, schema, canary_uids, canary_rows):
    """data.insert_canaries: copy the canary rows into prod with their markers stripped."""
    ut = cols["users_table"]
    uc = cols.get("user_id_column") or "id"
    s = sqlite3.connect("file:%s?mode=ro" % seed_path, uri=True)
    p = sqlite3.connect(prod_db, timeout=10)
    try:
        def copy(table, keycol, ids):
            cur = s.execute("SELECT * FROM %s WHERE %s IN (%s)" % (_q(table), _q(keycol), ",".join("?" * len(ids))), ids)
            names = [d[0] for d in cur.description]
            for r in cur.fetchall():
                vals = [MARKER_RE.sub("C%06d" % (i * 7 % 999999), v) if isinstance(v, str) else v
                        for i, v in enumerate(r)]
                p.execute("INSERT OR IGNORE INTO %s (%s) VALUES (%s)" % (_q(table), ", ".join(_q(n) for n in names),
                                                                          ", ".join("?" * len(names))), vals)
        copy(ut, uc, canary_uids)
        for t, ids in canary_rows.items():
            copy(t, schema["tables"][t]["rowid_alias"], ids)
        p.commit()
    finally:
        s.close()
        p.close()


# ------------------------------------------------------------------------------------------ leak check
def _sample(conn, table, col, n, seed):
    vals = [r[0] for r in conn.execute("SELECT DISTINCT %s FROM %s WHERE %s IS NOT NULL" % (_q(col), _q(table), _q(col)))]
    vals = [v for v in vals if (isinstance(v, str) and v.strip()) or (isinstance(v, (int, float)) and not isinstance(v, bool))]
    vals.sort(key=lambda v: str(v))
    if len(vals) > n:
        vals = _rng(seed, "sample", table, col).sample(vals, n)
    return vals


def leak_check(prod_db: str, shadow_db: str, columns, sample: int = SAMPLE, seed: int = 1) -> list[dict]:
    """Sample up to ``sample`` distinct real values per private/secret column; report any that appears in the
    shadow database (exact cell match for short values, substring for values of 6+ characters).
    Values that also occur in public tables of prod are not private information and are skipped."""
    cols = load_columns(columns) if isinstance(columns, str) else columns
    p = _ro(prod_db)
    s = _ro(shadow_db)
    try:
        public_cells = set()
        for t, spec in (cols.get("tables") or {}).items():
            if isinstance(spec, dict) and spec.get("public"):
                for row in p.execute("SELECT * FROM %s" % _q(t)):
                    public_cells.update(str(v) for v in row if v is not None)
        cells = []   # (table, column, text)
        for (t,) in s.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
            cur = s.execute("SELECT * FROM %s" % _q(t))
            names = [d[0] for d in cur.description]
            for row in cur:
                for n, v in zip(names, row):
                    if v is not None and not isinstance(v, bytes):
                        cells.append((t, n, str(v)))
        exact = {}
        for t, n, v in cells:
            exact.setdefault(v, (t, n))
        big = "\x00".join(c[2] for c in cells)
        found = []
        for t, spec in (cols.get("tables") or {}).items():
            if not isinstance(spec, dict) or spec.get("public"):
                continue
            for kind in ("private", "secret"):
                for c in spec.get(kind) or []:
                    for v in _sample(p, t, c, sample, seed):
                        sv = str(v)
                        if sv in public_cells:
                            continue
                        hit = exact.get(sv)
                        if hit is None and isinstance(v, str) and len(sv) >= 6 and sv in big:
                            hit = next(((tt, nn) for tt, nn, vv in cells if sv in vv), ("?", "?"))
                        if hit is not None and isinstance(v, (int, float)) and len(sv) < 6:
                            continue  # short numbers collide by chance
                        if hit is not None:
                            found.append({"column": "%s.%s" % (t, c), "kind": kind, "found_in": "%s.%s" % hit,
                                          "value": sv[:3] + "..." if len(sv) > 3 else "***"})
        return found
    finally:
        p.close()
        s.close()


# ------------------------------------------------------------------------------------------ config entry
def build(cfg=None, *, seed: int = 1, hash_password="profile", **kw) -> dict:
    """§4 entry: derive the shadow data of a configured project.

    ``cfg``: an ``immune.config.Config`` or a project directory. ``hash_password``: "profile" (use the
    generated profile's optional ``hash_password``, run in a subprocess), None, or a callable.
    """
    from immune import _cfg
    if cfg is None or isinstance(cfg, str):
        cfg = _cfg.load(cfg)
    columns = _cfg.columns_path(cfg)
    out_dir = os.path.dirname(cfg.manifest_path)
    hasher = None
    if hash_password == "profile":
        hasher = profile_hasher(cfg)
    elif callable(hash_password):
        hasher = hash_password
    rep = build_db(cfg.data.prod_db, columns, out_dir, seed=seed, admin_values=cfg.auth.admin_values,
                   hash_password=hasher, insert_canaries=cfg.data.insert_canaries, **kw)
    if os.path.abspath(cfg.shadow_seed) != os.path.abspath(rep["seed_db"]):
        os.makedirs(os.path.dirname(cfg.shadow_seed), exist_ok=True)
        shutil.copyfile(rep["seed_db"], cfg.shadow_seed)
    return rep


def profile_hasher(cfg):
    """callable(list[str]) -> list[str] using <profile>.hash_password in a clean subprocess, or None."""
    from immune.initsteps import sandbox
    if not sandbox.profile_has(cfg, "hash_password"):
        return None

    def run(passwords):
        out = sandbox.call_profile(cfg, "hash_password", passwords)
        return out
    return run
