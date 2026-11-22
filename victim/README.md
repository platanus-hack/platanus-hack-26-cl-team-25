# victim

## Purpose

`victim/` is the demo application "Tienda": a small online shop written with FastAPI on SQLite. It is the app
behind the built-in demo project `tienda`, which Immune protects when `immune up` runs from the repository root.
The app is written without any knowledge of Immune; it reads four environment variables and nothing else.

Tienda contains planted defects, put there on purpose so the demo has something to detect and patch. They were
planted, not discovered. Their list is kept outside this directory, in `docs/demo/respuestas/tienda.md`: this
directory is a release path, so every file in it is copied into each release and into the workspace the patch
generator reads. A description of the defects here would be an answer key inside that workspace.

## How it runs

The repository's own `.immune/config.yaml` declares this app as project `tienda`:
`app.release_paths: [victim]`, `app.source_dirs: [victim/app]`, `app.asgi: victim.app.main:app`, port 8000,
health route `/health`, `shadow.profile: victim.shadow_profile`, OpenAPI document `contracts/openapi.yaml`.

Under Immune the app never runs from this directory. `immune up` copies `victim/` into
`runtime/releases/t0/`, and the fleet starts that release as the production container and, wrapped by
`shadow.run`, as each clone. See [`fleet/README.md`](../fleet/README.md) and
[`shadow/README.md`](../shadow/README.md).

To run it alone, from the repository root:

```
.venv/bin/python -m victim.seed --out-prod /tmp/tienda.db --out-shadow /tmp/tienda-shadow.db \
    --manifest /tmp/tienda-manifest.json --markers /tmp/tienda-markers.json --seed 1
APP_DB=/tmp/tienda.db APP_SECRET=dev-secret .venv/bin/python -m uvicorn victim.app.main:app --port 8000
```

## Layout

| File | Role |
|---|---|
| `app/main.py` | FastAPI instance, routers, `GET /health`, handler that turns `sqlite3.Error` into a 500 |
| `app/db.py` | SQLite helpers (`fetch`, `fetch_one`, `run`), clock (`now`, `stamp`) |
| `app/auth.py` | Register, login, `GET /api/me`; token issue and verification with `immune_contracts.authtoken` |
| `app/products.py` | Catalogue listing with search, category, sort and paging; product detail |
| `app/files.py` | Manual download and product image, served from the static directory |
| `app/orders.py` | Orders: list, create, detail, plain-text invoice, admin listing |
| `app/users.py` | User profile |
| `seed.py` | Builds the production database, the shadow database, the manifest and the markers file |
| `shadow_profile.py` | Shadow profile: `APP`, `allowed_file_roots`, `ensure_user`, `mint_token`, `load_markers`, `public_paths` |
| `static/manuals/`, `static/images/` | Files served by `app/files.py` |
| `tests/` | The app's own test suite |

## Configuration

Environment variables read by the app:

| Variable | Required | Meaning |
|---|---|---|
| `APP_DB` | yes | Path of the SQLite database |
| `APP_SECRET` | yes | HMAC secret of the session tokens |
| `APP_STATIC` | no | Directory holding `manuals/` and `images/`. Default: `victim/static` |
| `APP_NOW` | no | Fixed Unix time used for token expiry and timestamps. Default: the system clock |

`python -m victim.seed` arguments: `--out-prod`, `--out-shadow`, `--manifest`, `--markers` (all required) and
`--seed N` (default 1).

## Behaviour

### Routes

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | none | `{"ok": true}` |
| POST | `/api/register` | none | Creates a user with role `user`; returns `id` and `token` |
| POST | `/api/login` | none | Returns `id` and `token` |
| GET | `/api/me` | token | The caller's own record |
| GET | `/api/products` | none | Listing; query `q`, `category`, `sort` (`name`, `price`, `newest`), `page`; 10 per page |
| GET | `/api/products/{product_id}` | none | One product |
| GET | `/api/products/{product_id}/image` | none | Image file named by query `file` |
| GET | `/api/files/download` | none | Manual named by query `name` |
| GET | `/api/orders` | token | The caller's orders |
| POST | `/api/orders` | token | Creates an order from `items` and an optional `note` |
| GET | `/api/orders/{order_id}` | token | One order |
| GET | `/api/orders/{order_id}/invoice` | token | Invoice as plain text |
| GET | `/api/users/{user_id}/profile` | token | A user's profile |
| GET | `/api/admin/orders` | token, role `admin` | Every order |

The wire-level description is `contracts/openapi.yaml`.

### Authentication

Tokens are stateless: `immune_contracts/authtoken.py` signs `{uid, role, exp}` with HMAC-SHA256 and `APP_SECRET`.
The client sends `Authorization: Bearer <token>`. Production and clones run with different secrets, which is what
lets the gateway recognise a token issued inside a clone when it comes back from outside.

### Seed data

`victim.seed` is deterministic for a given `--seed`. It writes 60 users (id 1 is the admin; ids 2, 3, 4, 5, 6, 8,
9, 10 are the manifest's `legit_users`, with known passwords), 40 products in 4 categories and 240 orders. The
production and the shadow database have the same ids and structure. In the shadow database, names, emails,
addresses, phones and order notes carry the owner's marker (`MK` plus 10 characters of `[A-Z0-9]`). Users 7 and 19
and orders 12 and 31 are the canaries. The manifest holds `seed_max_uid`, `seed_max_order_id`, `legit_users`,
`admin`, `canaries` and the `ownership` of every order; the markers file maps each marker to its owner's uid.

### Shadow profile

`shadow_profile.py` allows file access under `APP_STATIC` (default `victim/static`), creates a missing user with
synthetic values, mints tokens with the clone's `APP_SECRET` (honouring `APP_NOW`) and declares `/health`,
`/api/register`, `/api/login`, `/api/products` and `/api/files` as public paths.

## Tests

```
.venv/bin/pytest victim/tests -q
```

No Docker and no LLM. These tests are also the project's `tests.command`
(`python -m pytest victim/tests -q -p no:cacheprovider`), which the `tests` gate runs on every patched release.
Acceptance tests that exercise the app's HTTP contract are under `acceptance/`.

## Limits

- This is a demo target with planted defects. Do not deploy it.
- Passwords are stored as unsalted SHA-256 (`app/auth.py`). That is a simplification of the demo app, not one of
  the planted defects, and it is out of the demo's scope.
- Sessions cannot be revoked: a token is valid until its `exp`.
- Results obtained on this app and their conditions are in [`docs/resultados.md`](../docs/resultados.md); limits of
  the system as a whole are in [`docs/limites.md`](../docs/limites.md).
