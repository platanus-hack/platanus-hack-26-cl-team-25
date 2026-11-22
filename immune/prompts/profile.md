## Step: write the shadow profile (`.immune/profile.py`) and the auth block (`.immune/shadow/auth.yaml`)

The profile is the only app-specific code the shadow wrapper loads. It runs inside the shadow copy,
whose database path is in the environment variable named by `DB_ENV` (see the facts). Read the
authentication code of the app (how users log in, how a request is authenticated, how roles work), the
schema in `.immune/context/schema.md` and the classification in `.immune/shadow/columns.yaml`.

`profile.py` must define exactly this interface (keep the draft's structure):

```python
APP = "<module>:<attribute>"          # the ASGI app, exactly as in the facts
def allowed_file_roots(env: dict) -> list[str]   # absolute directories the app legitimately serves files from
                                                 # (honour the app's own env var for them if it has one; never "/",
                                                 # a system directory or the repository root)
def ensure_user(conn, uid: int, role: str) -> None  # conn: sqlite3 connection to the shadow db. If no user with id
                                                 # uid exists, INSERT one (synthetic values, the given role, every
                                                 # NOT NULL column filled). Never update existing rows.
def mint_token(env: dict, uid: int, role: str) -> str  # a credential the app accepts for that user, sent by the
                                                 # wrapper as "Authorization: Bearer <value>". If the app stores
                                                 # sessions in a table (opaque tokens), INSERT a session row for
                                                 # uid into the shadow db (sqlite3.connect(env[DB_ENV])) and return
                                                 # its token. If the app signs tokens, sign one the same way with the
                                                 # secret from env.
def load_markers(env: dict) -> dict[str, int]    # json.load(open(env["MARKERS_PATH"]))  - keep as drafted
def public_paths() -> list[str]                  # path prefixes whose responses are never owner-checked: health,
                                                 # login/register and data that is the same for everyone. Never "/".
def hash_password(password: str) -> str          # OPTIONAL: only if the app stores password hashes with a
                                                 # deterministic function you can import or reproduce exactly
                                                 # (it lets the installer give shadow users known passwords).
```

Allowed imports: the stdlib modules json, os, sqlite3, secrets, hashlib, hmac, base64, time, datetime, uuid,
string, random, re, binascii, functools, math; `immune_contracts.authtoken`; and the app's own package.
No subprocess, sockets, eval/exec, file writes or deletes.

`auth.yaml` tells the gateway how to identify a client on production:

```yaml
auth:
  kind: introspect        # immune-token | jwt-hs256 | introspect | none
  path: /auth/me          # introspect: a parameter-free GET that returns the caller (called with the client's headers)
  uid_field: id           # field of that JSON holding the user id
  role_field: role
  admin_values: [admin]   # role values that mean administrator
  # jwt-hs256: secret_env, uid_claim, role_claim
why: one or two lines on how the app authenticates (file:line)
```
Use `introspect` for opaque session tokens stored server-side; `immune-token` only if the app uses
`immune_contracts.authtoken`.
