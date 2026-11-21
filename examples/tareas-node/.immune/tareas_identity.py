"""Identity profile of the Tareas app for the generic runtime (hand-written; contracts/product.md §6).

Run by the observer (sidecar) inside every shadow clone, and on the host by the pipeline:

  ensure_user(conn, uid, role)  on the clone's Postgres (admin connection, outside the observation window):
                                make sure user `uid` exists and owns a session for the token below
  mint_token(env, uid, role)    the opaque bearer token the app accepts for that session
  public_paths()                responses never checked by the owner oracle
  hash_password(passwords)      the app's password hash (scrypt, same parameters as src/auth.js), so the
                                shadow seed can give a few users known passwords

The app stores sha256(token) in sessions.token_hash; tokens are random per clone process, so a token
handed out by a clone is worthless on prod.
"""
import hashlib
import hmac
import secrets

_SALT = secrets.token_bytes(16)


def _token(uid: int) -> str:
    return hmac.new(_SALT, str(int(uid)).encode(), hashlib.sha256).hexdigest()


def ensure_user(conn, uid, role):
    uid = int(uid)
    conn.execute(
        "INSERT INTO users (id, email, name, password_hash, role) VALUES ($1, $2, $3, $4, $5) "
        "ON CONFLICT (id) DO NOTHING",
        (uid, "cuenta-%d@sombra.invalid" % uid, "Cuenta %d" % uid, "scrypt$00$00", role or "user"))
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '1 day') "
        "ON CONFLICT (token_hash) DO NOTHING",
        (hashlib.sha256(_token(uid).encode()).hexdigest(), uid))


def mint_token(env, uid, role):
    return _token(uid)


def public_paths():
    return ["/health", "/api/register", "/api/login", "/api/files"]


def hash_password(passwords):
    out = []
    for p in passwords:
        salt = secrets.token_bytes(16)
        key = hashlib.scrypt(p.encode(), salt=salt, n=16384, r=8, p=1, dklen=64, maxmem=64 * 1024 * 1024)
        out.append("scrypt$%s$%s" % (salt.hex(), key.hex()))
    return out

