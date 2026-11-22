# Product contract

Reference for running Inmune on a project: the `.immune/` directory, the schema of `config.yaml`, the `immune`
command line, the generic runtime for apps that are not Python ASGI, and the behaviour of a stack under
failure. The wire protocols between the processes are in `contracts/README.md`. Every entry describes the code
as it is; the truth for `config.yaml` is the loader, `immune/config.py` (`from_dict`).

## 1. Layout

| Name | Meaning |
|---|---|
| Inmune home | this repository. Mounted read-only at `/opt/immune` in every container that runs Inmune code |
| project | the repository of the protected app, any path. The built-in demo uses this repository itself as its project (app in `victim/`, config in `.immune/config.yaml`) |
| `<project>/.immune/config.yaml` | the only source of app-specific facts (section 2) |
| `<runtime>` | all state of the stack: `runtime_dir` of `config.yaml`, default `<project>/.immune/runtime`. The built-in demo sets it to `runtime` at the repository root. Layout: `contracts/README.md` section 2 |
| release | a full copy of the paths in `app.release_paths`, at `<runtime>/releases/<id>/`. `t0` is the release a stack starts from. Mounted read-only at `/app` in production, clone and runner containers |

The project a command acts on is, in this order: `--project DIR`; the environment variable `IMMUNE_PROJECT`;
the nearest directory at or above the current one that holds `.immune/config.yaml`; the Inmune home
(`immune/config.py`, `find_project`). One command differs: `--project` of `immune init` defaults to the current
directory.

Files of a project's `.immune/` directory:

| File | Written by | Purpose |
|---|---|---|
| `config.yaml` | `immune init`, or by hand | section 2 |
| `openapi.yaml` | `immune init` | the app's OpenAPI document with the `x-owner-scoped` and `x-sensitive` marks |
| `profile.py` | `immune init` | shadow profile (`contracts/README.md` section 4.4) |
| `scenarios.py` | `immune init` | generated legitimate journeys for the `legit` gate |
| `shadow/columns.yaml` | `immune init`, or by hand | column classification for the shadow data (section 4) |
| `shadow/auth.yaml`, `shadow/marks.yaml`, `shadow/detect.yaml`, `shadow/schema.json`, `shadow/openapi.base.json` | `immune init` | intermediate results of init |
| `context/schema.md` | `immune init` | the database schema and the shapes of its values (never the values), given to the LLM steps as context |
| `deploy/`, `DEPLOY.md` | `immune init` | artefacts of the experimental `immune deploy` (section 5) |
| `report.md` | `immune init` | what init found, assumed and could not verify |
| `.gitignore` | `immune init` | ignores `runtime/` and `deploy/immune.env`; an existing file is kept |
| `runtime/` | `immune up` | `<runtime>` when `runtime_dir` is not set |

## 2. `config.yaml`

Example (the built-in demo, `.immune/config.yaml`):

```yaml
version: 1
name: tienda
runtime_dir: runtime
app:
  runtime: python-asgi
  release_paths: [victim]
  source_dirs: [victim/app]
  asgi: victim.app.main:app
  port: 8000
  health: /health
  static: victim/static
  env:
    APP_DB: "{db}"
    APP_STATIC: "{static}"
    APP_SECRET: "{secret}"
  frozen_time_env: APP_NOW
database:
  kind: sqlite
  path_env: APP_DB
data:
  prod_db: runtime/data/prod/app.db
  seed_command: "python -m victim.seed --out-prod {prod_db} --out-shadow {shadow_db} --manifest {manifest} --markers {markers} --seed {seed}"
auth:
  kind: immune-token
openapi: contracts/openapi.yaml
shadow:
  profile: victim.shadow_profile
tests:
  command: "python -m pytest victim/tests -q -p no:cacheprovider"
scenarios: sim.scenarios
repo:
  target: local
  t0_tag: victim-t0
autopatch: merge
mode: enforce
pool_size: 4
ports: {gateway: 8080, admin: 8081, dashboard: 8090, fleet: 8070}
```

Relative paths are resolved against the project directory. An invalid file is rejected with every error
listed, each with its key (`ConfigError`); the CLI then exits with status 2.

### Top level

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `version` | integer | 1 | only `1` is accepted |
| `name` | string | required | lower-case slug `[a-z0-9][a-z0-9-]{0,30}`. Containers, networks and units are named `immune-<name>-...` |
| `runtime_dir` | path | `.immune/runtime` | may not overlap any `app.release_paths` entry |
| `openapi` | path | required | the file must exist |
| `scenarios` | Python module name | empty | module with `SCENARIOS` (`contracts/interfaces.md`). Empty: the `legit` gate replays recorded requests (section 3) |
| `autopatch` | `off` \| `pr` \| `merge` | `merge` | `off`: rule only. `pr`: open the pull request and stop. `merge`: merge and deploy. Capped at `pr` without `tests.command` |
| `mode` | `observe` \| `enforce` | `enforce` | initial gateway mode (`contracts/README.md` section 6.5) |
| `pool_size` | integer | 4 | 0 to 32; number of clones |
| `aftercheck` | boolean | `false` | section 3b |
| `ports` | mapping | `{gateway: 8080, admin: 8081, dashboard: 8090, fleet: 8070}` | only these four keys; each 1 to 65535; all distinct. Every port is bound on `127.0.0.1` |

### `app`

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `runtime` | `python-asgi` \| `generic` | `python-asgi` | `generic`: section 6 |
| `release_paths` | list of relative paths | required | files and directories copied into a release. Each must exist in the project; `.immune` and `.git` are refused |
| `source_dirs` | list of relative paths | required | where an automatic fix may edit; each must be inside a `release_paths` entry |
| `asgi` | `module:attribute` | required for `python-asgi` | ASGI entry of the app |
| `port` | integer | 8000 | port the app listens on in its container |
| `health` | path | `/health` | must start with `/` |
| `env` | mapping of name to scalar | empty | environment of the app. Values may use `{db}`, `{static}` and `{secret}`; any other placeholder is an error |
| `static` | relative path | empty | release-relative directory that `{static}` expands to; required when `{static}` is used |
| `frozen_time_env` | variable name | empty | variable that freezes the app's clock (unix seconds); set in runner jobs |
| `image` | string | empty | generic runtime; accepted by the loader, but a project without `app.build` is refused by `immune/generic.py` |
| `build` | `{context, dockerfile}` | empty | generic runtime: how the app image is built from a release. `context` is release-relative |
| `command` | list or string | empty | generic runtime, required: the app's command |
| `allowed_file_roots` | list of paths | empty | generic runtime: directories, as seen by the app, that it may open files in |
| `workdir` | path | `/app` | generic runtime: where the image keeps the release |
| `bind_env` | variable name | empty | generic runtime: variable carrying the bind address (`0.0.0.0` in production, `127.0.0.1` in clones) |
| `warmup_paths` | list of paths | empty | generic runtime: extra harmless `GET`s for the observer's warm-up |

Placeholders in `app.env`: `{db}` is the database path (or the Postgres URL for the generic runtime),
`{secret}` is `PROD_APP_SECRET` in production and `SHADOW_APP_SECRET` in clones, `{static}` is
`/app/<app.static>`.

### `database` and `data`

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `database.kind` | `sqlite` \| `postgres` | `sqlite` | `postgres` only with `app.runtime: generic`; the generic runtime accepts only `postgres` |
| `database.path_env` | variable name | `APP_DB` | variable through which the app receives its SQLite path |
| `database.url_env` | variable name | `DATABASE_URL` (generic) | variable through which the app receives its Postgres URL |
| `data.prod_db` | path | required for `sqlite` | the live database file; its directory is mounted read-write at `/data` in production |
| `data.seed_command` | shell command | empty | builds production and shadow data. Placeholders: `{prod_db}`, `{shadow_db}`, `{manifest}`, `{markers}`, `{seed}`. Empty: the shadow data is derived from `data.prod_db` (section 4) |
| `data.insert_canaries` | boolean | `false` | also insert the canary rows into the production database (section 4) |
| `data.prod_url_env` | variable name | empty | generic runtime: variable of `immune up` holding the real production Postgres URL, as reachable from the production network |
| `data.demo_postgres` | `{database, user, seed_command}` | empty | generic runtime: without that variable, a Postgres container on the production network, seeded once by `seed_command` run in the app image. One of the two is required |

### `auth`

How the gateway resolves the identity of a request (`immune/auth.py`).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `kind` | `immune-token` \| `jwt-hs256` \| `introspect` \| `none` | `immune-token` | see below |
| `secret_env` | variable name | required for `jwt-hs256` | variable holding the HS256 secret of production tokens |
| `uid_claim`, `role_claim` | string | `sub`, empty | `jwt-hs256`: claims holding the user id and the role |
| `admin_values` | list | `[admin]` | role values that mean admin |
| `path` | path | `/api/me` | `introspect`: route of production that answers who the caller is |
| `uid_field`, `role_field` | string | `id`, `role` | `introspect`: fields of that JSON answer (dotted paths allowed) |
| `cache_s` | number | 30 | `introspect`: how long an answer is cached per credential |

| Kind | Resolution |
|---|---|
| `immune-token` | `Authorization: Bearer <token>` in the format of `immune_contracts/authtoken.py`, verified with `PROD_APP_SECRET` |
| `jwt-hs256` | `Authorization: Bearer <JWT>`, `alg` exactly `HS256`, `exp` and `nbf` honoured |
| `introspect` | the gateway calls `path` on production with the client's `Authorization` and `Cookie` headers (opaque server-side sessions) |
| `none` | every client is anonymous |

A user id is always an integer; a non-integer subject is treated as anonymous.

### `shadow`, `tests`, `repo`, `audit`

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `shadow.profile` | Python module name | required for `python-asgi` | shadow profile, importable from `/app` or from `<project>/.immune` (`contracts/README.md` section 4.4). For the generic runtime: a module in `.immune/` with the identity hooks the observer loads |
| `shadow.columns` | path | `.immune/shadow/columns.yaml` | section 4 |
| `tests.command` | shell command | empty | run in the runner with the release as working directory; exit status 0 passes |
| `repo.target` | `local` \| `github` | `local` | where fixes become pull requests (`contracts/README.md` section 9) |
| `repo.github` | `owner/name` | empty | required when `repo.target` is `github` |
| `repo.t0_tag` | tag name | `immune-t0` | tag of the `t0` tree in the repository target |
| `audit.enabled` | boolean | `true` for `python-asgi`, `false` for `generic` | class audit after a closed incident (section 8) |
| `audit.max_jobs` | integer | 40 | 0 to 1000; judge jobs per audit |
| `audit.max_seconds` | integer | 120 | 0 to 3600; time budget per audit |

Loader: `immune.config.load(project_dir) -> Config` (validated dataclass, absolute paths). Every component
takes its app-specific facts from that object. `immune mode` and `immune autopatch` rewrite one top-level key
in place and keep the comments (`set_key`).

## 3. Behaviour that depends on the configuration

| Configuration | Behaviour | Source |
|---|---|---|
| no `tests.command` | the `tests` gate is published as passed with detail `skipped: ...` and `skipped: true`; autopatch is capped at `pr` | `pipeline/gates.py`, `gate_tests`; `immune/config.py`, `effective_autopatch` |
| no `scenarios` | the `legit` gate replays the gateway recording instead: clean `GET` requests forwarded to production with status 200, the most recent per path, query and uid, at most 200, from the last 8 MB of the recording. Status and body must be identical on the unpatched and the patched release. With no recorded request, or none covering the patched route, the gate reports "no coverage" and autopatch is capped at `pr`; the patch is not rejected | `pipeline/gates.py`, `gate_legit_replay` |
| `scenarios` set, module cannot be imported | the `legit` gate fails | `pipeline/runner_entry.py`, `job_scenarios` |
| `scenarios` set, patched route not covered | the gate rejects the patch, unless the module declares `PARTIAL_COVERAGE = True` (the modules `immune init` generates do): then autopatch is capped at `pr` | `pipeline/gates.py`, `gate_legit` |
| `mode: observe` | the gateway classifies and detonates as in `enforce`; every response comes from production; events carry `observe: true`; `immune report` summarises what `enforce` would have done | `contracts/README.md` section 6.5 |
| `autopatch: pr` | the pipeline stops after the gates and the pull request; the incident closes `rule_only` with `outcome_detail: pr_open`; the rule stays | `pipeline/orchestrator.py` |
| `autopatch: off` | the pipeline stops after the rule; the incident closes `rule_only` with `outcome_detail: autopatch_off` | `pipeline/orchestrator.py` |

The `policy` gate allows edits only under `app.source_dirs`. Stack frames in evidence are relative to the
release root and limited to `app.release_paths`. The pipeline re-reads `config.yaml` at the start of each
incident, so a change of `autopatch` applies to the next incident.

## 3b. After-check (`aftercheck: true`)

A second net for requests the classifier calls clean. Off by default; active in `enforce` mode only
(`gateway/core.py`, `_after_enqueue`, `_aftercheck`). `immune up` passes the setting as `GW_AFTERCHECK`.

- The request goes to production and the client gets production's answer. The first request is not stopped.
- After the response is sent, the gateway replays the same request in a clone in mode `L1`. One worker does
  this, so at most one clone is busy with after-checks.
- If an oracle fires: the clone pushes evidence as for any detonation (`oracle.fired`); the session is
  captive from its next request (`session.captured`, reason `aftercheck`) unless the identity is trusted;
  `GET /_admin/prodlog` gains `"aftercheck": "oracle"`; and a line is appended to the recording that removes
  that path, query and uid from the recorded-request corpus of the `legit` gate.
- Budget: identical requests (method, target, body, uid) are checked once per release (the last 4096 are
  remembered); at most 256 are pending, further ones are dropped; a check that finds no free clone within
  2 s is given up. Requests answered 502 or 504 are not checked. Counters:
  `aftercheck: {queued, checked, oracle, duplicate, dropped, no_clone}` in `GET /_admin/stats`.
- Limits: the effects of the first request on production are not undone; a request that depends on objects
  created after the seed may not reproduce in the clone; under load, coverage is what the budget allows.

## 4. Shadow data without a seed command

When `data.seed_command` is empty, `immune.shadowdata.build(config)` derives the shadow data from
`data.prod_db`, which it opens read-only, guided by `columns.yaml`:

```yaml
users_table: users            # table holding identities
user_id_column: id
role_column: role             # optional
login_column: email           # optional: column used to log in (manifest legit_users)
secret_column: password_hash  # optional: password hash column
tables:
  users:   {owner: id,      private: [email, name, address, phone], secret: [password_hash]}
  orders:  {owner: user_id, private: [note, shipping_address]}
  order_items: {owner: {via: order_id, table: orders}}   # owner through a foreign key
  products: {public: true}
routes:                       # OpenAPI path parameter -> table and column
  order_id: {table: orders, column: id}
  user_id:  {table: users, column: id}
```

| Output | Content |
|---|---|
| `<runtime>/data/shadow/seed.db` | same schema, ids and foreign keys. `private` values replaced by synthetic text carrying the owner's marker; `secret` values replaced by random strings of the same shape; `public` tables copied; 2 canary users and 2 canary rows per owner-scoped table |
| `<runtime>/data/manifest.json` | `seed_max_uid`, `seed_max_<table>_id`, `legit_users`, `admin`, `canaries`, `ownership`, and `groups` and `group_routes` when declared (`contracts/README.md` section 4.3) |
| `<runtime>/data/markers.json` | marker to owner uid; also written as `<runtime>/data/shadow/markers.json` |

The output is deterministic for a given seed. With `data.insert_canaries: true` the canary rows are also
inserted into the production database, the only case in which it is written. `immune doctor` check 6 samples
200 values per private or secret column and fails if any appears in the shadow seed.

For Postgres (generic runtime) the equivalent is `immune/shadowdata_pg.py`, which writes the dump
`<runtime>/data/shadow/seed.sql` and, under `<runtime>/data/shadow/pginit/`, a copy of it (`seed.dump`) and the
init script that loads it into each clone database (`01-seed.sh`).

Limit: manifest keys assume English plural table names (`<x>_id` maps to table `<x>s`).

## 5. Command line

`bin/immune` runs `python -m immune` with the repository's virtual environment. `install.sh` creates that
environment, builds the images and links `bin/immune` into `~/.local/bin`; installation is described in
`docs/operacion.md`.

| Command | Options | Behaviour | Exit status |
|---|---|---|---|
| `immune up` | `--project DIR` | start the stack; if the project has a run on disk, resume it (section 11) | 0; 1 on failure; 2 on invalid config |
| `immune reset` | `--project DIR` | back to `t0`: fresh data, `t0` in production, no incidents, new run id | same |
| `immune down` | `--project DIR` | stop host processes and remove the stack's containers | 0 |
| `immune status` | `--project DIR` | health summary | 0 when healthy; 1 when anything is unhealthy, including an unreachable fleet |
| `immune report` | `--project DIR`, `--json` | summary from the bus store and the recording: classes, routes, detonations, verdicts, oracles, incidents, what `enforce` would have done in observe mode | 0 |
| `immune mode observe\|enforce` | `--project DIR` | rewrite `mode` in `config.yaml` and switch the running gateway | 0 |
| `immune autopatch off\|pr\|merge` | `--project DIR` | rewrite `autopatch` in `config.yaml`; read by the pipeline at the start of each incident | 0 |
| `immune rollback` | `--project DIR`, `--to RELEASE`, `--keep-autopatch` | fleet `/deploy` of the previous release (or RELEASE); `autopatch merge` -> `pr` unless `--keep-autopatch`; rules kept | 0; 1 deploy not completed |
| `immune init` | `--project DIR` (default: current directory), `--yes`, `--no-llm`, `--prod-db PATH`, `--seed N` | analyse a project and write its `.immune/` | 0 `READY`; 1 `NEEDS ATTENTION` |
| `immune doctor` | `--project DIR`, `--json`, `--only 1,2` | run the verification checks | 0 when all pass; 1 otherwise |
| `immune doctor --prereqs` | `--json` | check host prerequisites only | 0 when every required one is present |
| `immune deploy` | `--project DIR`, `--dry-run`, `--experimental` | experimental; see below | see below |
| `immune anticipate` | `list`; `check TARGET`; `run TARGET [--model M] [--out DIR]`; `recheck RESULT_DIR` | same as `python -m anticipate` | |

### `immune up`, `reset`, `down`, `status`

`immune up` on a `python-asgi` project without a run (`immune/__main__.py`, `cmd_up`): generate or read the secrets
(section 7), stop anything left of the stack, check that the four ports are free on `127.0.0.1` (it fails
with the port and its config key otherwise), seed (`seed`: data, shadow data, release `t0`, run id), start the
compose services, start the fleet, `POST /reset` with `t0` and `pool_size`, set the gateway mode, start the
pipeline. Environment variables: `POOL_SIZE` overrides `pool_size` for this start, `NO_PIPELINE=1` skips the
pipeline, `T0_REF` builds `t0` from a git ref instead of the working tree, `IMMUNE_NO_SYSTEMD=1` disables
systemd units. The generic runtime starts through `immune/generic.py` (`cmd_up`), which also builds the app
image and the databases and does not check that the ports are free.

`immune reset` never deletes a production database it cannot regenerate: when there is no
`data.seed_command` and `data.prod_db` lies under `<runtime>/data`, that file and its SQLite journal files are
kept and everything else under `data/` is rebuilt. When `data.seed_command` exists and `data.prod_db` lies
outside `<runtime>` and already exists, the seed command writes its production output to a temporary file
that is discarded.

`immune status` prints the containers, the host processes, the gateway and dashboard health, the release in
production, the size of the clone pool and the number of active rules. It reports `NOT HEALTHY` and exits 1
when a host process is not running or is restarting, the gateway, the dashboard or the fleet is unreachable,
no release is in production, or the clone pool is below its size.

### `immune init`

Supported scope: Python ASGI apps that expose `openapi()` (FastAPI) and keep their data in one SQLite file.
For any other app there is no `init`; the profile is written by hand (`examples/tareas-node/.immune/`).

| Step | What it does | LLM |
|---|---|---|
| 1 | detect runtime, framework, ASGI entry, port, tests command and deploy style | no |
| 2 | dump the OpenAPI document by importing the app; find the health route | no |
| 3 | find the SQLite database and dump its schema | no |
| 4 | classify columns: `shadow/columns.yaml` | yes |
| 5 | write `profile.py` and the `auth` block | yes |
| 6 | mark `x-owner-scoped` and `x-sensitive` in `openapi.yaml` | yes |
| 7 | build the shadow data (section 4) and the generated scenarios | no |
| 8 | run the doctor; failing checks are fed back to the step that owns them, up to 3 rounds | on failures |
| 9 | write `deploy/`, `DEPLOY.md` and `report.md` | no |
| 10 | print `READY: immune up --project <dir>` or `NEEDS ATTENTION:` with a list | no |

`--no-llm` keeps the heuristic drafts of steps 4 to 6. Init switches to it by itself, with a message, when
the `claude` CLI is not found. When the LLM fails on a step and the heuristic draft validates, init can still
end `READY` and prints `NOTE: LLM unavailable for step(s) ...`. LLM steps use the confined CLI of
`patcher/claude_cli.py`.

Where init runs code of the project:

- The OpenAPI dump (`immune/initsteps/openapi.py`, `dump`) imports the app and calls `openapi()` in a
  `--network none` container when `docker` and the image `immune-base:1` are available. When they are not, or
  when that container run returns no document, it does the same in a separate host process as the invoking
  user. When that fails too, or the app is not FastAPI, it reads a spec file from the project (`openapi.yaml`,
  `openapi.yml`, `openapi.json`, `swagger.yaml`, `swagger.json`).
- The generated `profile.py` is checked against a static deny-list and then imported on the host as the
  invoking user; the profile validation and doctor checks 2 to 5 run on the host in a separate process
  (`immune/initsteps/hostrun.py`).
- Doctor checks 1, 7 and 8 run in containers with `--network none`.

The host process is process separation, not a sandbox.

### `immune doctor`

| Check | Passes when | Runs in |
|---|---|---|
| 1 config, release, clone health | the config is valid, the release is complete and the app answers its health path inside a clone container | container |
| 2 profile identity | `ensure_user` and `mint_token` produce an identity the app accepts on an authenticated route | host process |
| 3 legitimate GETs are clean | legitimate `GET`s on the parameter-free routes get a clean or expected verdict | host process |
| 4 synthetic canaries | a string-built SQL statement, an open outside the allowed roots and a foreign marker each fire their oracle, through self-test routes that exist only with `SHADOW_SELFTEST=1` | host process |
| 5 L1 reset | after an `L2` write, the next `L1` request restores the database to the seed state | host process |
| 6 no real data in the shadow | no sampled real private value appears in the shadow seed; skipped when the data comes from `data.seed_command` and the project has no `columns.yaml` | the CLI process (reads the two databases, runs no project code) |
| 7 tests in a container | `tests.command` exits 0 in a `--network none` container of `immune-base:1` with the release mounted read-only (`immune/initsteps/docker.py`, not the pipeline's runner); without one the check warns "autopatch capped at pr" | container |
| 8 legit scenarios deterministic | two runs of the `scenarios` module in the pipeline's runner give identical output and cover at least one route; without one the check warns | container |

`--json` prints `{"ok", "checks": [{"id", "name", "ok", "status", "reason", "owner", "detail"}]}`, where
`status` is `pass`, `fail`, `warn` or `skip`. `--prereqs --json` prints `{"ok", "prereqs": [...]}`.

### `immune deploy`

Experimental and not a working protection path (`immune/deploycmd.py`). It reads the compose override that
`immune init` wrote under `.immune/deploy/` and:

| Invocation | Behaviour |
|---|---|
| `immune deploy --dry-run` | prints the `docker compose` command and exits 0 |
| `immune deploy` | prints the command and what does not work, starts nothing, exits 2 |
| `immune deploy --experimental` | runs the command and returns its exit status |
| any of the above when init wrote no compose override | prints `DEPLOY.md` (manual steps) and exits 0; exits 1 when there are no deploy artefacts at all |

The gateway that command starts has no clone pool and no event bus: it proxies requests to the app. No request
is detonated, no incident is opened, no rule is written and no patch is produced from the traffic it sees.
The working path is `immune up`, which runs production itself from releases. Placing the gateway in front of
a service that is already deployed is not built.

## 6. Generic runtime (`app.runtime: generic`)

For apps in any language. The app runs unmodified from its own image; the oracles observe it from outside the
process (`sidecar/`). Full example: `examples/tareas-node/.immune/config.yaml`; the keys specific to this
runtime, abridged from it:

```yaml
app:
  runtime: generic
  release_paths: [server.js, package.json, src, Dockerfile]
  source_dirs: [src]
  build: {context: ., dockerfile: Dockerfile}
  command: [node, server.js]
  port: 3000
  health: /health
  allowed_file_roots: [/app/files]
  bind_env: HOST
database: {kind: postgres, url_env: DATABASE_URL}
data:
  demo_postgres: {database: tareas, user: tareas, seed_command: [node, db/seed.js]}
```

Requirements checked by `immune/generic.py` (`facts`): `app.build` is present, `database.kind` is `postgres`,
and `data.prod_url_env` or `data.demo_postgres` is set.

The observer speaks the clone protocol of `contracts/README.md` section 5: one request at a time, buffered
response, verdict headers, signed evidence push.

| Oracle | Observed through | Fires when |
|---|---|---|
| `file` | `strace` on the app's processes | a successful open outside `allowed_file_roots`, after a warm-up allowlist |
| `proc` | `strace` | a successful `execve`, or a fork whose child does not `execve`, during the request |
| `net` | `strace` | a connection outside loopback that was not seen during warm-up (loopback covers the database proxy), or a DNS lookup |
| `sql` | a Postgres wire-protocol proxy between the app and the per-clone database | the same taint check as the in-process oracle, on the statement text of `Q` (simple query) and `Parse` messages |
| `owner` | the response body | another owner's marker, as in-process |

`strace` follows `openat`, `openat2`, `open`, `creat`, `execve`, `execveat`, `connect`, `sendto`, `sendmsg`,
`fork`, `vfork`, `clone` and `clone3` (`sidecar/tracer.py`, `SYSCALLS`). The proxy answers `SSLRequest` and
`GSSENCRequest` with `N`, so TLS between the app and its database is refused inside a clone; `Bind` parameters
are not taint-checked.

Fail-closed rules of the observer (`sidecar/server.py`, `sidecar/identity.py`):

| Condition | Behaviour |
|---|---|
| the tracer is not running when a request arrives | the request is not sent to the app; the observer answers 503 with verdict `inconclusive` |
| the tracer dies while a request is in flight | the verdict is `inconclusive`, never `clean` |
| markers are configured (a profile `load_markers` or a markers path) but cannot be loaded | the observer refuses to start |
| no markers are configured | the observer starts with the owner oracle off and logs a warning |
| the app does not answer (connection error or timeout) | 502, verdict `inconclusive` |

Differences from the in-process runtime: evidence has an empty `stack` and the incident has no sink file, so
the patch generator locates the defect from route, parameter and the observed statement or path;
`pre_state_b64` is `null`; an `L1` reset recreates the clone database from the template `seed`; there are no
fallback diffs; the class audit is off by default; and the `policy` gate is lexical for non-Python sources.
Not observed: reads on already-open file descriptors, `rename`, `unlink`, `mmap`, `io_uring`, in-process
databases. See `sidecar/README.md`.

## 7. Secrets

`immune/__main__.py`, `stack_secrets`. Every project, the built-in demo included, gets its own secrets.

| Fact | Value |
|---|---|
| File | `<runtime>/secrets.env`, mode 0600 |
| Keys | `PROD_APP_SECRET`, `SHADOW_APP_SECRET`, `ADMIN_TOKEN`, `BUS_TOKEN` |
| Generated | on the first `immune up`, `immune reset` or `immune status`, each as 16 random bytes in hex |
| Override | a variable of the same name in the environment of `immune` wins over the file |
| Stack started before the file existed | the values its containers run with are taken from `<runtime>/stack/containers.env` |
| `jwt-hs256` | the HS256 secret is read from the variable named by `auth.secret_env`, or from the same key in `secrets.env`; `immune up` fails without it |
| Copies | `<runtime>/stack/containers.env` (env file of the compose services, 0600) and `<runtime>/stack/fleet.supervise.json`, `<runtime>/stack/pipeline.supervise.json` (0600) |
| Generic runtime | the demo database password is in `<runtime>/stack/demo-db.env` (0600); each clone database gets random passwords |

`deploy/demo.env` holds placeholders; when they are still read is stated in `contracts/README.md` section 3.
`immune init` writes `.immune/.gitignore` so that `runtime/` and `deploy/immune.env` stay out of git.

## 8. Class audit and corpus

`pipeline/audit.py`, `pipeline/corpus.py`. Config block `audit: {enabled, max_jobs, max_seconds}` (section 2).

When an incident of class `sqli`, `traversal` or `idor` closes `patched` or `rule_only`, the pipeline probes
the other operations and parameters of the OpenAPI document that the class could affect, on the release in
production, inside the runner only (never production, never the live clones). The probes are the inputs of
the `properties` gate plus the class corpus.

| Fact | Value |
|---|---|
| Candidates for `sqli`, `traversal` | query, path and form parameters and JSON string leaves whose schema is a string; enum, integer, number and boolean schemas are skipped |
| Candidates for `idor` | path parameters and integer or `*id` query parameters, probed as a new user above `seed_max_uid` |
| Selection | by schema shape; no route names are involved |
| Frequency | one audit per class per release |
| Finding | an incident with `origin: audit` and `parent`, which follows the normal flow |
| Events | `audit.started`, `audit.finding`, `audit.done` |
| Budget | `max_jobs` judge jobs and `max_seconds` per audit |

Corpus: `<runtime>/corpus/<class>.jsonl` holds the parameter values an oracle confirmed (the PoC value and
each variant that fired on the unpatched release), deduplicated, at most 500 per class, values of at most 1000
characters. Only the value of the affected parameter is stored. It is kept across `immune reset`.

## 9. Group-shared access

For resources that several users may legitimately read (a team's notes).

| Where | Declaration |
|---|---|
| `columns.yaml`, table | `tables.<t>.shared_via: {table, member, group}`: the membership table, its member column and its group column |
| `columns.yaml`, route | `routes.<param>.access: members`: every member of the addressed group may read |

Effects: the manifest carries `groups` and `group_routes`, which the gateway uses for
`owner_scoped:mismatch` (`contracts/README.md` section 6.2); `<runtime>/data/shadow/sharing.json` tells the
owner oracle not to fire for markers of members of the addressed group when the requester belongs to it
(`shadow/core.py`, `co_members`, read from the clone's own database). Without a declaration nothing changes.

## 10. Generic runtime: containers

`fleet/generic.py`. Per clone `<n>`, three containers on the clone network:

| Container | Image | Settings |
|---|---|---|
| `immune-<name>-clone-<n>-db` | `postgres:16-alpine` | data on tmpfs, `fsync` off, `--cap-drop ALL`, read-only root; its init script creates role `app` and the template database `seed` from the shadow dump; random passwords per clone |
| `immune-<name>-clone-<n>` | `immune-<name>-app:<release>` | the unmodified app, `--cap-drop ALL`, read-only root, bound to `127.0.0.1` through `app.bind_env`, database URL pointing at `127.0.0.1:5432` (the proxy) |
| `immune-<name>-clone-<n>-obs` | `immune-sidecar:1` | shares the app's network and PID namespaces; `--cap-drop ALL --cap-add SYS_PTRACE`, the only added capability in the system; serves the clone protocol on port 8000 and runs the proxy |

The gateway addresses the clone as `immune-<name>-clone-<n>:8000`. A clone whose observer or database is not
running is replaced as a whole. Production is the same image on the production network. Each release is a
new image tag, built by `immune up` for `t0` and by the fleet on `/deploy`. `immune down` removes the app
images, the demo database and the stack's networks.

The pipeline judges patches for this runtime on throw-away triples of the same shape
(`pipeline/generic.py`), each on its own internal network.

## 11. Operation: restarts, failures, limits

### Resume

`immune up` does not go back to `t0` when the project has a run on disk. A run can be resumed when
`<runtime>/run_id` and `<runtime>/stack/fleet-state.json` agree and the recorded release directory exists
(`immune/__main__.py`, `existing_run`). The resumed stack keeps the release in production, the rules and the
open incidents. Only `immune reset` returns to `t0`. For the generic runtime a run is resumed only while its
production container still exists, because `immune down` removes that runtime's images and demo database.

Nothing starts the stack at boot. After a host reboot, `immune up` resumes it.

### Supervised host processes

`fleet` and `pipeline` run under `python -m immune.supervise <spec.json>` (`immune/supervise.py`), which
restarts its child when it exits: after 1 s, doubling up to 30 s, back to 1 s once the child has stayed up for a minute. On
`SIGTERM` it stops the child (`SIGKILL` after 10 s) and exits.

| Host | How the supervisor runs |
|---|---|
| with a systemd user manager | transient unit `immune-<name>-fleet.service` or `immune-<name>-pipeline.service` (`systemd-run --user`, `Restart=on-failure`) |
| without one, or with `IMMUNE_NO_SYSTEMD=1` | a detached process in its own session |

Either way the processes outlive the terminal or SSH session that ran `immune up`. Files:
with `<process>` being `fleet` or `pipeline`: `<runtime>/stack/<process>.supervise.json` (0600),
`<runtime>/logs/<process>.pid` (supervisor), `<runtime>/logs/<process>.pid.child` (process),
`<runtime>/logs/<process>.log` (appended within a run; deleted by `immune reset` for `python-asgi`).

### State that survives a restart

All under `<runtime>`, valid only for the run that wrote it:

| Process | File | Holds | On start |
|---|---|---|---|
| gateway | `stack/gateway-state.json` | upstream, mode, rules with absolute expiry | restored before the first request; expired rules are dropped |
| fleet | `stack/fleet-state.json` | live colour, release, pool size, clone counter | `Fleet.adopt`: keeps the running production container and clones (clone keys are read back from the containers), starts production again if it is absent; if both colours run, the gateway's upstream decides |
| pipeline | `pipeline/state.json` | incidents, queue, last bus sequence number | an incident left open is redone from the start |
| dashboard | `bus/events.jsonl`, `bus/events.jsonl.1` | every event | both files are loaded into memory, up to `DASH_MAX_EVENTS` |

### Fleet reconcile loop

Every `RECONCILE_S` (1 s), `Fleet.reconcile_once`: the live production container is recreated if it was
removed (Docker restarts a crashed one: restart policy `unless-stopped`); the `gateway` and `dashboard`
containers are started if found stopped; clones that are not running, and clones the gateway reports as
`retired`, are destroyed and replaced; the pool is registered again when it changed; the gateway upstream is
corrected if it does not point at the live colour.

### Pipeline under failure

- A `POST /deploy` that loses its connection is not a failed deploy: the client waits up to 90 s for the
  fleet, reads `GET /state`, and either confirms the release is live or asks again, 3 attempts in total
  (`pipeline/clients.py`, `Fleet.deploy`).
- An incident closed for a reason that may not hold later gets `outcome_detail: transient`: the patch
  generator was unavailable or proposed nothing on every attempt, the repository target or the merge was
  unavailable, the fleet was unreachable for the deploy, or the pipeline raised an internal error. It is
  queued again after `PIPELINE_RETRY_COOLDOWN_S` (60 seconds) multiplied by 4 per retry, capped at 1 h, at most
  `PIPELINE_MAX_RETRIES` (5) times. A patch rejected by the gates is not transient.
- An internal error after the rule was posted closes `rule_only`; before any rule it closes `error`, because
  nothing contains the incident.
- The rule of an incident closed `rule_only` is renewed when a quarter of its TTL remains, and posted again
  if the gateway lost it (`Pipeline.keep_rules`). `seconds_to_rule` is the first time the rule was active,
  across retries.
- Events the bus could not take are kept and sent again (`contracts/README.md` section 10.4).

### Deploy watch

A new release is rolled back when, since the switch, production served at least `DEPLOY_MIN_REQUESTS` (20)
requests, at least one was answered 5xx, and the 5xx rate is above
`max(2 x rate of the release it replaced, that rate + 0.02)`. With fewer requests the deploy stands and is
reported `traffic_validated: false`. Requests the gateway refuses itself (below) are not production errors.
The full rule and the result fields are in `contracts/README.md` section 8.

### Gateway input limits

Answered by the gateway, never forwarded, never counted as production errors: a target that does not start
with `/` is 400; a `Content-Length` above 10 MiB or a body growing past it is 413; a body not completed within
30 s is 408; a request that cannot be put on the wire as sent is 400. To production, a refused connection is
retried once for any method; a pooled connection the upstream had closed is retried once for `GET`, `HEAD`
and `OPTIONS` only.

### Bounded disk and memory

| What | Bound |
|---|---|
| recording `recordings/requests.jsonl` | rotates to `requests.jsonl.1` at `RECORD_MAX_MB` (256); the `legit` gate reads the tail of both |
| bus store `bus/events.jsonl` | rotates to `events.jsonl.1` at `DASH_STORE_MAX_MB` (256); one old generation kept |
| bus memory | `DASH_MAX_EVENTS` (50000) |
| releases | after a deploy only `t0`, the live one, any still mounted by a container and the 5 newest are kept |
| corpus | 500 values per class |
| not bounded | `pipeline/events.jsonl` (the pipeline's own copy of its events) and the logs under `logs/` within a run |

### Measured behaviour under injected failures

Measured on 2026-11-21 on the built-in demo, one run per row, under 20 requests per second of legitimate
traffic. No raw data is stored in the repository and the table has not been re-measured since that date. The
row "release answering 500" depends on the rollback rule above: at 20 requests per second the minimum of 20
requests is reached in about 1 s.

| Failure injected | Back to healthy | Requests failed |
|---|---|---|
| `kill -9` of fleet / pipeline / fleet supervisor | 2.0 s / 1.3 s / 3.3 s | 0 |
| gateway process crash; gateway container killed by hand | 2.0 s; 1.5 s | about 1.3 s of refused connections |
| production process crash; production container removed | 1.3 s; 1.3 s | about 1.2 s of 502 |
| clone crash or removal; dashboard crash | 1.5 to 1.8 s | 0 |
| pipeline killed when an incident opens | incident patched (55 s) | 0 |
| fleet killed during the deploy | incident patched (57 s) | 0 |
| gateway crashed with a rule active | rule back on restart; incident patched (49 s) | 0.6 s |
| release that does not start; release answering 500 | never takes traffic; rolled back | 0; 1.1 s of 500 |
| patch generator down, no fallback | 3 defects contained by rules, retried, patched when it returned | 0 |
| `immune down` then `immune up` | 4 s, patched release in production | not applicable |

### Not covered

- Loss of the host or of Docker itself. Nothing starts the stack at boot.
- The demo Postgres of the generic example: it keeps its data in memory and is not supervised. It stands in
  for the customer's database.
- A client that holds thousands of slow connections. A reverse proxy in front of the gateway is needed.
- A release that fails only after the watch window, or that answers wrong content with a non-5xx status.
- A deploy during which fewer than `DEPLOY_MIN_REQUESTS` requests arrive: it is not judged by traffic.
- Events published by the fleet while the bus is down are lost.
