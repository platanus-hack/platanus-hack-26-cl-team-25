# tareas-node

## Purpose

"Tareas" is the third demo application: a personal task manager written in Node.js (`http` module and `pg`, no
framework) on PostgreSQL. It exists to exercise the generic runtime (`app.runtime: generic`), where the app
runs unmodified from its own image and the oracles work from outside the process
([`sidecar/`](../../sidecar/README.md)). It has three planted defects, and a hand-written `.immune/` profile
because `immune init` supports Python ASGI apps only.

## How it runs

Under Inmune, from the repository root (needs the images built by `install.sh`, including `immune-sidecar:1`):

```bash
immune up --project examples/tareas-node
immune status --project examples/tareas-node
immune down --project examples/tareas-node
```

`immune up` copies the release paths into `.immune/runtime/releases/t0`, builds the image
`immune-tareas-app:t0` from it, starts a demo Postgres on the production network and seeds it with
`node db/seed.js`, derives the shadow data from that database, and starts the stack (`cmd_up` in
`immune/generic.py`). Ports, all on 127.0.0.1: gateway 8180, gateway admin 8181, dashboard 8190, fleet 8170.
To use an existing database instead of the demo one, export `TAREAS_DATABASE_URL` with a URL reachable from
the stack's production network.

Standalone, without Inmune:

```bash
cd examples/tareas-node
docker compose up -d --build                  # app on port 3000, Postgres as service db
docker compose exec app node db/seed.js       # sample data
```

`docker-compose.yml` publishes port 3000 on every host interface.

## Layout

| Path | Role |
|---|---|
| `server.js` | Entry point; listens on `HOST` (default `0.0.0.0`) and `PORT` (default 3000) |
| `src/app.js` | Router |
| `src/auth.js` | Registration, login, opaque session tokens (SHA-256 of the token stored in `sessions`), scrypt password hashes |
| `src/tasks.js` | Task CRUD and search |
| `src/exporter.js` | Task export as Markdown or JSON |
| `src/files.js` | Listing and download of shared files under `files/` |
| `src/db.js`, `src/http.js` | Connection pool; HTTP helpers |
| `db/schema.sql`, `db/seed.js` | Schema (`users`, `sessions`, `tasks`) and sample data |
| `test/api.test.js` | The app's test suite (`node --test`) |
| `Dockerfile` | Installs dependencies from `package-lock.json` one level above `/app`, so they stay in place when a release directory is mounted over `/app` |
| `.immune/config.yaml` | Project configuration for Inmune |
| `.immune/openapi.yaml` | Hand-written OpenAPI with the `x-owner-scoped` and `x-sensitive` marks |
| `.immune/tareas_identity.py` | Identity profile loaded by the sidecar: `ensure_user`, `mint_token`, `public_paths`, `hash_password` |
| `.immune/shadow/columns.yaml` | Which columns are owner keys, private or secret, for the shadow data |

`node_modules` is not in the repository; the image installs the single dependency (`pg` 8.13.1) from the
lockfile.

Routes: `GET /health`, `POST /api/register`, `POST /api/login`, `POST /api/logout`, `GET /api/me`,
`GET|POST /api/tasks`, `GET|PUT|DELETE /api/tasks/{id}`, `GET /api/tasks/search?q=&status=`,
`GET /api/tasks/{id}/export?format=md|json`, `GET /api/files`, `GET /api/files/download?name=`.
`POST /api/login` returns an opaque token, sent as `Authorization: Bearer <token>`.

## Configuration

App environment: `DATABASE_URL` (required), `PORT` (3000), `HOST` (`0.0.0.0`), `SESSION_HOURS` (72),
`DB_POOL_SIZE` (5), `FILES_DIR` (`files/` next to `src/`).

`.immune/config.yaml`, the keys that matter for the generic runtime (reference:
[`contracts/product.md`](../../contracts/product.md)):

| Key | Value | Effect |
|---|---|---|
| `app.runtime` | `generic` | Clone triples with the sidecar; image built per release |
| `app.release_paths` | `server.js`, `package.json`, `package-lock.json`, `src`, `db`, `files`, `test`, `Dockerfile`, `.dockerignore` | What a release contains. This README and `.immune/` are not part of it. |
| `app.source_dirs` | `src` | The only files a patch may edit |
| `app.build` | `{context: ., dockerfile: Dockerfile}` | Image `immune-tareas-app:<release>` |
| `app.bind_env` | `HOST` | `0.0.0.0` in production, `127.0.0.1` in clones |
| `app.allowed_file_roots` | `/app/files` | Opens outside it fire the `file` oracle |
| `app.warmup_paths` | `/api/files` | Extra warm-up request for the sidecar |
| `database.kind`, `database.url_env` | `postgres`, `DATABASE_URL` | The sidecar proxies this connection |
| `data.prod_url_env` | `TAREAS_DATABASE_URL` | Real database, if exported |
| `data.demo_postgres` | database and user `tareas`, `seed_command: node db/seed.js` | Demo database otherwise |
| `auth` | `kind: introspect`, `path: /api/me`, `uid_field: id`, `role_field: role`, `cache_s: 30` | The gateway resolves the identity by calling the app |
| `tests.command` | `node --test "test/**/*.test.js"` | The `tests` gate |
| `autopatch`, `mode`, `pool_size` | `merge`, `enforce`, 3 | |

## Behaviour

The three planted defects, by file (the answer key is `docs/demo/respuestas/tareas-node.md`, kept outside the
app tree):

| Class | File | Oracle that observes it |
|---|---|---|
| SQL injection | `src/tasks.js` | `sql`, through the sidecar's Postgres proxy |
| Path traversal | `src/files.js` | `file`, through `strace` |
| Missing owner check (IDOR) | `src/exporter.js` | `owner`, markers in the response body |

They are planted, not discovered. The rest of the app (owner checks on the task routes, parameterised queries
elsewhere) is intended to be correct.

Inside a clone the gateway's `x-imm-uid` is translated by `.immune/tareas_identity.py`: `ensure_user` inserts
the user and a session row into the clone's database, and `mint_token` returns the bearer token of that
session. The token is derived from a salt that is random per sidecar process, so a token obtained from a clone
is not valid in production.

Patches for this runtime are proposed by `pipeline/generic_patch.py` and validated on ephemeral clone triples
(`pipeline/generic.py`); the policy gate is lexical for JavaScript. There are no fallback diffs. The legit gate
has no scripted scenarios for this app and replays recorded clean GETs; when no recorded request covers the
patched route, the gate soft-fails and the fix stays as an open pull request instead of being merged. The
observed outcome per defect is in [`docs/resultados.md`](../../docs/resultados.md), and the gates are described
in [`docs/validaciones.md`](../../docs/validaciones.md).

## Tests

The app's own suite needs a PostgreSQL database with the schema of `db/schema.sql`:

```bash
cd examples/tareas-node
npm ci
DATABASE_URL=postgres://tareas:tareas@127.0.0.1:5432/tareas npm test
```

(The compose file does not publish the database port; point `DATABASE_URL` at any reachable Postgres.) The
suite exercises every route with legitimate input. Under Inmune the same command runs as the `tests` gate in
the app image against a fresh copy of the shadow seed. The repository's `pytest` does not run this suite.

## Limits

- No `immune init`: the profile, the OpenAPI marks and `columns.yaml` are hand-written.
- No smoke request on deploy: the OpenAPI has no public parameterless `GET` other than the health path, so the
  fleet skips the step and reports it (see [`fleet/README.md`](../../fleet/README.md)).
- The limits of the out-of-process oracles apply (see [`sidecar/README.md`](../../sidecar/README.md)); evidence
  has no stack, so the files to edit are located by scoring the source against the route, parameter and
  observed sink.
- The demo production database keeps its data in tmpfs; it is recreated and reseeded by every fresh start
  (`immune reset`, or `immune up` when there is no run to resume, which is always the case after `immune down`).

The project-wide list is in [`docs/limites.md`](../../docs/limites.md); operation of a second project next to
the built-in demo is in [`docs/operacion.md`](../../docs/operacion.md).
