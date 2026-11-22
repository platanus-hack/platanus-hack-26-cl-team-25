"""Identity profile of OpenEMR 8.2.0 for the generic runtime (hand-written; contracts/product.md §6).

Run by the observer (sidecar) inside every shadow clone:

  ensure_user(conn, uid, role)   on the clone's MySQL (admin connection, outside the observation window):
                                 make sure OpenEMR user `uid` exists (an unknown uid becomes a new user in the
                                 ACL group of its role) and give it this process's random password
                                 (users_secure, SHA-512 crypt: OpenEMR verifies `$6$rounds=` hashes natively)
  identity_headers(env, uid, role)
                                 logs in to the clone exactly like a browser (main_screen.php?auth=login) and
                                 returns the clone session: Cookie OpenEMR=<id> and the session's APICSRFTOKEN
                                 (OpenEMR's local REST/FHIR API), cached per uid
  rewrite_request(...)           the client's csrf_token_form (bound to its prod session) -> the clone
                                 session's token, so forms are judged as the real request would run
  public_paths()                 responses the owner oracle never judges alone
  hash_password(passwords)       SHA-512 crypt, for shadow users with known passwords

Passwords and sessions are random per clone process: nothing minted here works on prod.
"""
import base64
import hashlib
import http.client
import json
import re
import secrets
import urllib.parse

APP_HOST = "127.0.0.1"
_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ROLE_GROUP = {"admin": "admin", "user": "doc"}     # gacl_aro_groups.value: Administrators / Physicians


# ---------------------------------------------------------------------------- SHA-512 crypt ($6$)
def sha512_crypt(password: str, salt: str | None = None, rounds: int = 5000) -> str:
    """Ulrich Drepper's SHA-crypt (the $6$ of crypt(3) and PHP's password_verify)."""
    pw = password.encode()
    salt = (salt or "".join(secrets.choice(_B64) for _ in range(16)))[:16]
    s = salt.encode()
    b = hashlib.sha512(pw + s + pw).digest()
    a = hashlib.sha512(pw + s)
    n = len(pw)
    while n > 64:
        a.update(b); n -= 64
    a.update(b[:n])
    n = len(pw)
    while n:
        a.update(b if n & 1 else pw); n >>= 1
    a = a.digest()
    dp = hashlib.sha512(pw * len(pw)).digest()
    p = (dp * (len(pw) // 64 + 1))[:len(pw)]
    ds = hashlib.sha512(s * (16 + a[0])).digest()
    sb = (ds * (len(s) // 64 + 1))[:len(s)]
    c = a
    for i in range(rounds):
        h = hashlib.sha512()
        h.update(p if i & 1 else c)
        if i % 3:
            h.update(sb)
        if i % 7:
            h.update(p)
        h.update(c if i & 1 else p)
        c = h.digest()
    order = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48),
             (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
             (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41)]
    out = []
    for x, y, z in order:
        v = (c[x] << 16) | (c[y] << 8) | c[z]
        for _ in range(4):
            out.append(_B64[v & 0x3F]); v >>= 6
    v = c[63]
    for _ in range(2):
        out.append(_B64[v & 0x3F]); v >>= 6
    return "$6$rounds=%d$%s$%s" % (rounds, salt, "".join(out))


_PASSWORD = "Sombra-" + secrets.token_urlsafe(18)
_HASH = sha512_crypt(_PASSWORD)
_users = {}       # uid -> username
_sessions = {}    # uid -> {"headers": {...}, "form": csrf_token_form}


def hash_password(passwords):
    return [sha512_crypt(p) for p in passwords]


# ---------------------------------------------------------------------------- clone database
def ensure_user(conn, uid, role):
    uid = int(uid)
    rows = conn.execute("SELECT username FROM users WHERE id = ?", (uid,))
    if rows and rows[0][0]:
        username = rows[0][0]
        conn.execute("UPDATE users SET active = 1 WHERE id = ?", (uid,))
    else:
        username = "sombra%d" % uid
        conn.execute(
            "INSERT INTO users (id, username, password, authorized, fname, lname, active, facility_id, calendar,"
            " see_auth, abook_type) VALUES (?, ?, 'NoLongerUsed', 1, 'Cuenta', ?, 1, 3, 1, 1, '')",
            (uid, username, "Sombra %d" % uid))
        conn.execute("INSERT INTO `groups` (name, user) VALUES ('Default', ?)", (username,))
        conn.execute("UPDATE gacl_aro_seq SET id = LAST_INSERT_ID(id + 1)")
        aro = int(conn.execute("SELECT LAST_INSERT_ID()")[0][0])
        conn.execute("INSERT INTO gacl_aro (id, section_value, value, order_value, name, hidden)"
                     " VALUES (?, 'users', ?, 10, ?, 0)", (aro, username, "Cuenta Sombra %d" % uid))
        conn.execute("INSERT INTO gacl_groups_aro_map (group_id, aro_id) SELECT id, ? FROM gacl_aro_groups"
                     " WHERE value = ?", (aro, ROLE_GROUP.get(role or "user", "doc")))
    conn.execute(
        "REPLACE INTO users_secure (id, username, password, last_update_password, login_fail_counter,"
        " total_login_fail_counter) VALUES (?, ?, ?, NOW(), 0, 0)", (uid, username, _HASH))
    if _users.get(uid) != username:
        _sessions.pop(uid, None)
    _users[uid] = username


# ---------------------------------------------------------------------------- clone session
def _port(env) -> int:
    return int((env or {}).get("IMMUNE_APP_PORT") or 8080)


def _request(env, method, path, headers=None, body=None):
    c = http.client.HTTPConnection(APP_HOST, _port(env), timeout=30)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.getheaders(), r.read()
    finally:
        c.close()


def _login(env, uid):
    username = _users.get(int(uid))
    if not username:
        return None
    form = urllib.parse.urlencode({"new_login_session_management": "1", "authUser": username,
                                   "clearPass": _PASSWORD, "languageChoice": "1"})
    st, hdrs, _ = _request(env, "POST", "/interface/main/main_screen.php?auth=login&site=default",
                           {"content-type": "application/x-www-form-urlencoded", "host": "localhost"}, form)
    sid, location = None, None
    for k, v in hdrs:
        if k.lower() == "set-cookie":
            m = re.match(r"\s*OpenEMR=([^;]+)", v)
            if m:
                sid = m.group(1)
        elif k.lower() == "location":
            location = v
    if st != 302 or not sid or not location or "token_main" not in location:
        return None
    cookie = "OpenEMR=" + sid
    # the session's CSRF tokens from immune-runtime/whoami.php (answered only inside a clone): the main UI
    # page that also carries them is far heavier to render
    st, _, body = _request(env, "GET", "/_immune/whoami?tokens=1", {"cookie": cookie, "host": "localhost"})
    try:
        info = json.loads(body)
    except ValueError:
        info = {}
    if st != 200 or info.get("id") != int(uid):
        return None
    headers = {"cookie": cookie}
    if info.get("csrf_api"):
        headers["apicsrftoken"] = info["csrf_api"]
    return {"headers": headers, "form": info.get("csrf_form")}


def identity_headers(env, uid, role):
    uid = int(uid)
    s = _sessions.get(uid)
    if s is None or not _alive(env, s):
        s = _login(env, uid)
        if s is None:
            return {}
        _sessions[uid] = s
    return dict(s["headers"])


def _alive(env, s) -> bool:
    try:
        st, _, body = _request(env, "GET", "/_immune/whoami", {"cookie": s["headers"]["cookie"], "host": "localhost"})
        return st == 200 and b'"id":null' not in body
    except OSError:
        return False


_FORM_FIELD = re.compile(r"(^|&)(csrf_token_form=)[^&]*")
_MULTIPART_FIELD = re.compile(rb'(name="csrf_token_form"\r\n(?:[^\r\n]+\r\n)*\r\n)[^\r\n]*')


def rewrite_request(env, uid, role, query, headers, body):
    s = _sessions.get(int(uid))
    token = (s or {}).get("form")
    if not token:
        return query, body
    if query and "csrf_token_form=" in query:
        query = _FORM_FIELD.sub(lambda m: m.group(1) + m.group(2) + urllib.parse.quote(token), query)
    ctype = (headers or {}).get("content-type", "")
    if body and b"csrf_token_form" in body:
        if "multipart/form-data" in ctype:
            body = _MULTIPART_FIELD.sub(lambda m: m.group(1) + token.encode(), body)
        elif "x-www-form-urlencoded" in ctype:
            body = _FORM_FIELD.sub(lambda m: m.group(1) + m.group(2) + urllib.parse.quote(token),
                                   body.decode("latin-1")).encode("latin-1")
    return query, body


def public_paths():
    return ["/meta/health", "/interface/login", "/apis/default/fhir/metadata", "/apis/default/fhir/.well-known",
            "/_immune/whoami", "/public", "/portal/index.php"]


def _b64(data: bytes) -> str:  # kept for symmetry with other profiles' token helpers
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# ---------------------------------------------------------------- oráculos extra (perfil OpenEMR)
#
# `extra_oracles(ctx)` — el sidecar la llama después de los oráculos base (sidecar/server.py), con:
#   env, conn (conexión admin MySQL del clon, async), database, method, path, query, headers, body,
#   status, resp_headers, resp_body, uid, role, statements, failed, bound.
# Tres verificaciones que miran lo que el app HIZO (SQL observado + respuesta) y lo que el app DEBIÓ
# haber autorizado, usando las tablas del propio clon. Devuelven eventos con la misma forma que los
# oráculos base, así que heredan todo el mecanismo: veredicto, evidencia, incidente y regla.

_BILL_GROUPS = {"admin", "back", "breakglass"}   # gacl_aro_groups.value con el ACO acct/bill en 8.2.0
_BILLING_PATH = re.compile(r"^/interface/billing/sl_eob_(invoice|search)\.php$")
_BILLING_TABLE = re.compile(r"\b(billing|form_encounter|ar_activity|payments)\b", re.I)
_ACTIVE_MARKUP = re.compile(
    r"\bon(error|load|click|mouseover|focus|toggle|animationstart)\s*=|javascript\s*:"
    r"|<\s*script\b|<\s*iframe\b|srcdoc\s*=", re.I)
_acl_cache: dict = {}      # uid -> set de valores de gacl_aro_groups del usuario
_mfa_cache: dict = {}      # username -> bool (tiene TOTP registrado en el clon)
_stored_active: dict = {}  # contenido activo guardado en el clon -> docid (estado del proceso clon)


def _ev(oracle: str, detail: dict) -> dict:
    return {"oracle": oracle, "detail": detail, "stack": []}


def _form_fields(body: bytes) -> dict:
    try:
        return {k: (v[0] if v else "") for k, v in
                urllib.parse.parse_qs(body.decode("latin-1"), keep_blank_values=True).items()}
    except Exception:
        return {}


async def _acl_groups(ctx, uid: int) -> set:
    """Grupos gacl del usuario, según el clon (público/copiado verbatim del prod). Cacheado por proceso."""
    if uid in _acl_cache:
        return _acl_cache[uid]
    groups: set = set()
    conn = ctx.get("conn")
    if conn is not None:
        try:
            rows = await conn.query(
                "SELECT g.value FROM gacl_aro a"
                " JOIN gacl_groups_aro_map m ON m.aro_id = a.id"
                " JOIN gacl_aro_groups g ON g.id = m.group_id"
                " WHERE a.section_value = 'users'"
                " AND a.value = (SELECT username FROM users WHERE id = %d)" % int(uid))
            groups = {r[0] for r in rows if r and r[0]}
        except Exception:
            groups = set()
    _acl_cache[uid] = groups
    return groups


async def _has_totp(ctx, username: str) -> bool:
    """¿El usuario tiene un TOTP registrado en el clon? (login_mfa_registrations, tabla reescrita del seed)."""
    if username in _mfa_cache:
        return _mfa_cache[username]
    ok = False
    conn, db = ctx.get("conn"), ctx.get("database") or "clone"
    if conn is not None and username.replace("_", "").isalnum():
        try:
            rows = await conn.query(
                "SELECT COUNT(*) FROM `%s`.`login_mfa_registrations` r"
                " JOIN `%s`.`users` u ON u.id = r.user_id"
                " WHERE r.method = 'TOTP' AND u.username = '%s'" % (db, db, username))
            ok = bool(rows and rows[0] and rows[0][0] not in (None, "", "0"))
        except Exception:
            ok = False
    _mfa_cache[username] = ok
    return ok


_grant_probe_cache: dict = {}   # resultado de la sonda del password grant, cacheado por proceso de clon


async def _grant_probe(ctx) -> bool:
    """Sonda por ejecución (una vez por clon): ¿el app emite un token por password grant sin mfa_token
    para un usuario CON TOTP registrado? El clon no conoce las contraseñas de prod (los hashes del seed
    son aleatorios), así que la sonda usa un usuario del propio clon: le fija una contraseña sintética
    vía la conexión admin (fuera de la ventana de observación) y canjea el grant contra el app del clon.
    Si el token sale sin segundo factor, el bypass está confirmado — no adivinado."""
    if "result" in _grant_probe_cache:
        return _grant_probe_cache["result"]
    ok = False
    conn, db = ctx.get("conn"), ctx.get("database") or "clone"
    try:
        if conn is not None:
            rows = await conn.query(
                "SELECT u.id, u.username FROM `%s`.`login_mfa_registrations` r"
                " JOIN `%s`.`users` u ON u.id = r.user_id"
                " WHERE r.method = 'TOTP' ORDER BY u.id LIMIT 1" % (db, db))
            if rows:
                uid, username = int(rows[0][0]), str(rows[0][1])
                pw = "Sonda-" + secrets.token_urlsafe(12)
                await conn.query("UPDATE `%s`.`users_secure` SET password = '%s', last_update_password = NOW()"
                                 " WHERE id = %d" % (db, sha512_crypt(pw), uid))
                form = _form_fields(ctx.get("body") or b"")
                client_id = form.get("client_id") or ""
                if not client_id.replace("-", "").isalnum():
                    rows = await conn.query("SELECT client_id FROM `%s`.`oauth_clients`"
                                            " WHERE grant_types LIKE '%%password%%' LIMIT 1" % db)
                    client_id = str(rows[0][0]) if rows else ""
                if client_id:
                    body = urllib.parse.urlencode({"grant_type": "password", "client_id": client_id,
                                                   "username": username, "password": pw})
                    st, _, rb = _request(ctx.get("env") or {}, "POST", "/oauth2/default/token",
                                         {"content-type": "application/x-www-form-urlencoded",
                                          "host": "localhost"}, body)
                    ok = st == 200 and b"access_token" in rb
    except Exception:
        ok = False
    _grant_probe_cache["result"] = ok
    return ok


async def extra_oracles(ctx) -> list:
    out: list = []
    method, path, status = ctx["method"], ctx["path"], ctx["status"]
    resp_body = ctx.get("resp_body") or b""

    # ---- acl: lectura de facturación sin acct/bill (CVE-2026-124471). El app no chequea nada; el
    # oráculo replayea la autorización contra el gacl del clon: admin/back leen sin ruido, front/doc
    # y anónimos detonan.
    if _BILLING_PATH.match(path) and status and status < 400 and ctx.get("statements"):
        tables = {m.group(0).lower() for s in ctx["statements"] for m in _BILLING_TABLE.finditer(s)}
        if tables:
            uid = ctx.get("uid")
            if uid is None:
                out.append(_ev("acl", {"route": path, "why": "anonymous billing read", "tables": sorted(tables)}))
            else:
                groups = await _acl_groups(ctx, uid)
                if not (groups & _BILL_GROUPS):
                    out.append(_ev("acl", {"route": path, "user": uid, "groups": sorted(groups),
                                           "required": "acct/bill", "tables": sorted(tables)}))

    # ---- mfa: token por password grant sin segundo factor (CVE-2026-67611). El login web exige el
    # código TOTP; UserRepository.php:111 solo lo valida si el request trae mfa_token. El clon no puede
    # autenticar la contraseña del atacante (los hashes del seed son aleatorios), así que el oráculo
    # confirma el bypass con la sonda por ejecución (_grant_probe) sobre el app del clon, y dispara
    # cuando el request canjea credenciales de un usuario con TOTP registrado sin mandar el código.
    if method == "POST" and path == "/oauth2/default/token":
        form = _form_fields(ctx.get("body") or b"")
        if form.get("grant_type") == "password" and "mfa_token" not in form:
            username = form.get("username") or ""
            if username and await _has_totp(ctx, username) and await _grant_probe(ctx):
                out.append(_ev("mfa", {"user": username, "why": "token issued without mfa_token",
                                       "scope": form.get("scope") or ""}))

    # ---- xss: marcado activo guardado en una plantilla del portal (CVE-2026-67612). El save es el
    # momento de la inyección: mode=save acepta todo salvo el literal "<?php" (import_template.php:125),
    # y el contenido se devuelve sin codificar a cualquier víctima. El oráculo dispara en el clon
    # durante el save, así que el gateway retiene la respuesta y el payload nunca llega a prod.
    if method == "POST" and path == "/portal/import_template.php":
        form = _form_fields(ctx.get("body") or b"")
        if form.get("mode") == "save":
            content = form.get("content") or ""
            if _ACTIVE_MARKUP.search(content):
                out.append(_ev("xss", {"stored": True, "docid": form.get("docid") or "",
                                       "sample": content[:160]}))
            if content:
                import hashlib
                _stored_active[hashlib.sha1(content.encode("latin-1", "replace")).hexdigest()] = \
                    (content, form.get("docid") or "")
        # eco diferido (L2/sesiones con estado): el contenido guardado devuelto tal cual
        for content, docid in list(_stored_active.values()):
            if content.encode("latin-1", "replace") in resp_body:
                out.append(_ev("xss", {"echoed": True, "docid": docid, "sample": content[:160]}))
    return out
