# examples/notas

## Purpose

Notas is a small note-taking service for teams, written with FastAPI on SQLite. It is the second demo application
of Inmune and the one used to exercise `immune init`: unlike the built-in shop it ships without a `.immune/`
directory, uses opaque session tokens stored in a table, and has group-shared data (teams). The app has no
dependency on Inmune.

Notas contains four planted defects. Their list is kept outside this directory, in
`docs/demo/respuestas/notas.md`, because `immune init` copies this project tree for the LLM steps; an answer key
here would be visible to them.

## How it runs

Standalone, from this directory:

```
pip install -r requirements.txt
python scripts/init_db.py --db data/notas.db
NOTAS_DB=data/notas.db uvicorn notas.main:app --port 8000
```

With Docker: `docker compose up --build`. The container listens on 8000 and creates the database in the volume
`notas-data` on first start.

Under Inmune, from the repository root, after creating `data/notas.db` as above:

```
immune init --project examples/notas --yes
immune up --project examples/notas
```

`init` writes `examples/notas/.immune/` and ends with `READY:` or `NEEDS ATTENTION:`. The generated config uses
the default ports (8080, 8081, 8090, 8070); change `ports:` in `.immune/config.yaml` when another stack is using
them. The steps of `init` are described in [`immune/README.md`](../../immune/README.md); running a second project is
covered in [`docs/operacion.md`](../../docs/operacion.md).

## Layout

| File | Role |
|---|---|
| `notas/main.py` | FastAPI instance (`title="Notas"`), routers, `GET /health` |
| `notas/db.py` | Schema, connection, `db_path`, `files_dir`, `now` |
| `notas/auth.py` | Register, login, `GET /auth/me`; session lookup `current_user` |
| `notas/notes.py` | Notes: list with search and sort, create, read, replace, delete, plain-text export |
| `notas/attachments.py` | Template listing and download |
| `notas/teams.py` | Team members; admin user listing |
| `notas/files/` | The read-only templates served by `notas/attachments.py` |
| `scripts/init_db.py` | Creates the database with sample data |
| `tests/` | The app's test suite |
| `Dockerfile`, `docker-compose.yml`, `requirements.txt`, `pytest.ini` | Packaging and test configuration |
| `data/` | Location of the SQLite file; ignored by git |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `NOTAS_DB` | `data/notas.db` | Path of the SQLite database |
| `NOTAS_FILES` | `notas/files` | Directory of the templates |
| `NOTAS_NOW` | system clock | Fixed Unix time for every timestamp |

`scripts/init_db.py` takes `--db PATH` (required) and `--seed N` (default 1). It does nothing when the database
already has users.

## Behaviour

### Routes

| Method | Path | Description |
|---|---|---|
| GET | `/health` | `{"status": "ok"}` |
| POST | `/auth/register` | Creates a user (`email`, `name`, `password`) with role `member` |
| POST | `/auth/login` | Returns `{"token", "token_type"}` |
| GET | `/auth/me` | `{"id", "email", "name", "role"}` |
| GET | `/notes` | The caller's notes; `q` searches title and body, `sort` is `created` or `title` |
| POST | `/notes` | Creates a note (`title`, `body`, optional `team_id`) |
| GET | `/notes/{note_id}` | One note |
| PUT | `/notes/{note_id}` | Replaces a note |
| DELETE | `/notes/{note_id}` | Deletes a note |
| GET | `/notes/{note_id}/export` | The note as plain text with the author's name |
| GET | `/templates` | Names of the available templates |
| GET | `/templates/download?name=` | Downloads a template |
| GET | `/teams/{team_id}/members` | Name and email of the team's members |
| GET | `/admin/users` | Every user; role `admin` only |

Every route except `/health`, `/auth/register` and `/auth/login` requires `Authorization: Bearer <token>`.
FastAPI serves the OpenAPI document at `/openapi.json` and `/docs`.

### Authentication

`POST /auth/login` inserts a random token (`secrets.token_hex(24)`) into the `sessions` table and returns it.
`current_user` in `notas/auth.py` resolves a request by looking that token up. Tokens are opaque: nothing can be
verified without the database. For an app with a session table and a route that returns the caller, the
heuristic draft of `immune init` (`auth_draft` in `immune/initsteps/drafts.py`) proposes `auth.kind: introspect`
with `path: /auth/me`: the gateway asks production who the caller is.

### Sample data

`scripts/init_db.py` creates 25 users, 4 teams and 80 notes, deterministically for a given `--seed`.

- Admin: `admin@notas.example`, password `admin123`.
- Members (for example `valentina.munoz@notas.example`): password `notas1234`.

Every user belongs to at least one team; a note may be attached to one of its owner's teams.

## Tests

From this directory. The suite has its own `pytest.ini` and is not part of the repository's `testpaths`:

```
python -m pytest tests -q
```

With the repository's virtualenv: `../../.venv/bin/python -m pytest tests -q`. No Docker and no LLM.

## Limits

- This is a demo target with planted defects. Do not deploy it.
- Passwords are stored as unsalted SHA-256 (`notas/auth.py`). That is a simplification of the demo app, not one of
  the planted defects, and it is out of the demo's scope.
- Sessions never expire and there is no logout route.
- `immune init` on this app was run end to end; the result and its conditions are in
  [`docs/resultados.md`](../../docs/resultados.md). The heuristics of `init` were tuned on this app and on the
  built-in shop, so success here says little about other apps; see [`docs/limites.md`](../../docs/limites.md).
