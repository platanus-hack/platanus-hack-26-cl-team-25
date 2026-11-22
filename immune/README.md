# immune

## Purpose

`immune` is the command-line interface of Inmune and the code that adapts Inmune to one application. It reads
the project's `.immune/config.yaml`, starts and stops the stack of that project (gateway and dashboard containers,
the `fleet` and `pipeline` host processes), and reports what the stack saw. `immune init` writes the `.immune/`
directory for a Python ASGI app; `immune doctor` verifies it.

Operating instructions (install, ports, recovery) are in [`docs/operacion.md`](../docs/operacion.md). The config
schema and the stack's processes are specified in [`contracts/product.md`](../contracts/product.md). This file is
the reference for the code in this directory.

## How it runs

| Entry point | What it is |
|---|---|
| `bin/immune` | Bash wrapper: `exec .venv/bin/python -m immune "$@"` with `PYTHONPATH` set to the checkout. Fails with a message when `.venv` is missing. `install.sh` links it into `~/.local/bin` (`IMMUNE_BIN_DIR`). |
| `python -m immune` | `immune/__main__.py`, function `main`. |
| `python -m immune.init`, `python -m immune.doctor`, `python -m immune.deploycmd` | The modules behind `immune init`, `immune doctor`, `immune deploy`. |
| `python -m immune.supervise <spec.json>` | Supervisor of one host process; started by `immune up`, not by hand. |
| `python -m immune.metrics --bus URL [--recording PATH] [--json]` | Time-to-patch and detection figures computed from the event bus. |

The CLI runs on the host as the invoking user. It talks to Docker through the `docker` CLI and to the gateway,
fleet and dashboard over HTTP on `127.0.0.1`.

### Project selection

Every subcommand takes `--project DIR`. Without it, `up`, `down`, `status`, `reset`, `report`, `mode`,
`autopatch`, `doctor` and `deploy` use the environment variable `IMMUNE_PROJECT`, else the nearest directory at or above the current one
that holds `.immune/config.yaml`, else the Inmune checkout itself (`find_project` in `immune/config.py`). The
checkout's own `.immune/config.yaml` describes the built-in demo project `tienda` (app in `victim/`).
`immune init` defaults to the current directory.

## Commands

Flags are the ones declared with `argparse` in `immune/__main__.py`, `immune/init.py`, `immune/doctor.py`,
`immune/deploycmd.py` and `anticipate/__main__.py`.

| Command | Flags | Exit status |
|---|---|---|
| `immune up` | `--project DIR` | 0 started or resumed; 1 on a stack error (`CliError`); 2 on an invalid config |
| `immune reset` | `--project DIR` | as `up` |
| `immune down` | `--project DIR` | 0 |
| `immune status` | `--project DIR` | 0 healthy; 1 when anything is unhealthy, including an unreachable fleet |
| `immune report` | `--project DIR`, `--json` | 0 |
| `immune mode observe\|enforce` | `--project DIR` | 0; 2 on an invalid config |
| `immune autopatch off\|pr\|merge` | `--project DIR` | 0; 2 on an invalid config |
| `immune init` | `--project DIR` (default `.`), `--yes`, `--no-llm`, `--prod-db PATH`, `--seed N` (default 1) | 0 after `READY:`; 1 after `NEEDS ATTENTION:` |
| `immune doctor` | `--project DIR`, `--json`, `--only 1,2` | 0 all checks pass; 1 otherwise |
| `immune doctor --prereqs` | `--json` | 0 when every required prerequisite is present; 1 otherwise |
| `immune deploy` | `--project DIR`, `--dry-run`, `--experimental` | see [immune deploy](#immune-deploy-experimental) |
| `immune anticipate list` | | 0 |
| `immune anticipate check TARGET` | | 0 |
| `immune anticipate run TARGET` | `--model NAME`, `--out DIR` | 0 when the suggested patch compiles and passes every vector; 1 otherwise |
| `immune anticipate recheck RESULT_DIR` | | as `run` |

`immune anticipate ...` runs the `anticipate` package with the same arguments (`dispatch` in `immune/__main__.py`);
see [`anticipate/README.md`](../anticipate/README.md).

### immune up

`cmd_up` in `immune/__main__.py`. Two paths:

**Resume** (`cmd_resume`), taken when `existing_run` finds a stack that already ran: `<runtime>/run_id` exists,
`<runtime>/stack/fleet-state.json` belongs to that run and names a release whose directory exists (for the generic
runtime, a production container must also still exist). Resume never goes back to `t0`:

1. Load or create the secrets, rewrite `<runtime>/stack/containers.env`.
2. Check that the ports of the services that are not running are free on `127.0.0.1`.
3. `docker compose -p immune-<name> -f deploy/compose.yaml up -d`.
4. Wait for the dashboard `/health` and the gateway `/_admin/health`.
5. Start the fleet under the supervisor and wait until it reports production active, the clone pool at its size
   and the gateway link up (`wait_fleet`, 180 s). If production serves but the pool is short, it prints a warning
   and continues; if production is not active it fails and points to `<runtime>/logs/fleet.log`.
6. Start the pipeline under the supervisor (skipped when `NO_PIPELINE` is set).

The release in production, the containment rules and the open incidents are kept: the gateway and the fleet
restore their own state files.

**Fresh start**, when there is nothing to resume (and always for `immune reset`):

1. Load or create the secrets; stop the host processes; remove this project's containers (label
   `immune.project=<name>`); `docker compose down --remove-orphans`.
2. Check that the four ports are free (`check_ports`).
3. `seed`: delete `data/`, `recordings/`, `bus/`, `releases/` and `pipeline/` under the runtime directory and the
   `*.log` files; run `data.seed_command` (or, without one, `immune.shadowdata.build` on `data.prod_db`); copy
   `app.release_paths` into `releases/t0` (from the working tree, or from `git archive $T0_REF` when `T0_REF` is
   set); write a new `run_id` (`MMDD-HHMMSS`).
4. `docker compose up -d --force-recreate`; wait for dashboard and gateway.
5. Start the fleet under the supervisor; `POST /reset {"release": "t0", "pool_size": N}` to it (`N` is `POOL_SIZE`
   from the environment, else `pool_size` from the config).
6. If `mode` is not `enforce`, `POST /_admin/mode` to the gateway.
7. Start the pipeline under the supervisor (skipped when `NO_PIPELINE` is set).

`seed` never deletes a production database it cannot regenerate: with no `data.seed_command` and `data.prod_db`
under `<runtime>/data`, that file and its SQLite journal files are kept (`_clear_except`). With a `seed_command`
and a `data.prod_db` that exists outside the runtime directory, the command writes its production output to a
scratch file that is then discarded, so the live database is not overwritten.

For `app.runtime: generic` the fresh start is `immune/generic.py` `cmd_up`: copy the `t0` release, start the
compose services, build the image `immune-<name>-app:t0` from the release, take the production database URL from
the environment variable named by `data.prod_url_env` or start and seed a `postgres:16-alpine` demo database
(`data.demo_postgres`), build the shadow seed from production with `immune/shadowdata_pg.py`, then fleet reset
and pipeline as above. `check_ports` covers the four ports on `immune reset` and the fleet port on `immune up`
(the compose services of this stack may already hold the other three).

### immune down

Stops the supervised host processes (systemd unit stop, then `SIGTERM`, `SIGKILL` after 15 s), removes the
project's containers and runs `docker compose down --remove-orphans`. The runtime directory is kept, so a later
`immune up` resumes. For the generic runtime it also removes the project's networks and app images, which is why
such a stack cannot be resumed after `down`.

### immune reset

`immune up` forced onto the fresh-start path: back to release `t0`, new run id, events, recordings, releases and
incident state deleted.

### immune status

Prints the project's containers, the state of `fleet` and `pipeline` (`running`, `RESTARTING`, `NOT RUNNING`),
gateway and dashboard reachability, the fleet's view (active colour, release, clones against pool size, gateway
link) and the gateway upstream with the number of containment rules. It ends with `healthy` (exit 0) or
`NOT HEALTHY: ...` (exit 1). A missing pipeline is not a problem when `NO_PIPELINE` is set.

### immune report

Reads `<runtime>/bus/events.jsonl.1` and `<runtime>/bus/events.jsonl` (the dashboard's event store) and the gateway
recording. Prints requests by class and by route, detonations by verdict, oracle events by kind, incidents with
outcome and times, and, for observe mode, what enforce would have routed (`would_route`). `--json` prints the same
data as one object. It reads files only and works with the stack down.

### immune mode, immune autopatch

Both rewrite one top-level key of `.immune/config.yaml` in place, keeping comments (`set_key` in
`immune/config.py`; the result is validated before the file is replaced).

- `mode` also posts the new mode to the running gateway (`POST /_admin/mode`). If the gateway is unreachable the
  change applies on the next `immune up`.
- `autopatch` is read by the pipeline at the start of each incident. The command prints the effective value when
  it differs: without `tests.command`, `merge` is capped at `pr` (`effective_autopatch`).

### immune init

`immune/init.py`, class `Init`. Scope: a Python ASGI app whose source contains a `FastAPI(...)` or
`Starlette(...)` instance, with a SQLite database file. An app without an importable `openapi()` needs a spec file
(`openapi.yaml`, `openapi.json`, `swagger.yaml`, ...) in the project. There is no `init` for other runtimes: the
profile of `examples/tareas-node` is hand-written.

With an existing `.immune/config.yaml`, `init` asks before overwriting; `--yes` skips the question, and without a
terminal and without `--yes` it exits 1.

| Step (as printed) | What it does | Code |
|---|---|---|
| 1 detect | Static detection, no import of the app: ASGI entry, package, release paths, source directory, port (compose file or Dockerfile, else 8000), environment variables and which one carries the database path, a secret or a frozen clock, tests command, deploy style, SQLite files | `initsteps/detect.py` |
| 2 openapi | Imports the app and calls `openapi()` in a `--network none` container; falls back to a host subprocess when Docker or the container run fails; else reads a spec file. Writes `.immune/openapi.yaml` and picks the health route | `initsteps/openapi.py`, `initsteps/probe.py` |
| 3 database | Locates the production SQLite file (`--prod-db`, the default of the database variable, or the SQLite file found) and reads its schema read-only. Writes `shadow/schema.json` and `context/schema.md` (column shapes, no values) | `shadowdata.dump_schema`, `initsteps/report.py` |
| (config) | Writes `.immune/config.yaml` (with `autopatch: pr`) and `.immune/.gitignore` (`runtime/`, `deploy/immune.env`; an existing file is kept) | `Init.write_config`, `Init.write_gitignore` |
| 4 columns | Classifies every table and column as owner-scoped, private, secret or public: `shadow/columns.yaml` | `initsteps/drafts.py`, LLM |
| 5 profile + auth | Writes `.immune/profile.py` (the shadow profile) and `shadow/auth.yaml` (the `auth` block, merged into `config.yaml` when valid) | `initsteps/drafts.py`, LLM |
| 6 marks | Writes `shadow/marks.yaml` and applies `x-owner-scoped` / `x-sensitive` to `.immune/openapi.yaml` | `initsteps/openapi.py`, LLM |
| 7 shadow data | Builds the shadow seed, `manifest.json` and `markers.json`, runs the leak self-check, and generates `.immune/scenarios.py` (sets `scenarios:` in the config when at least one GET route is covered) | `shadowdata.build`, `initsteps/scenarios.py` |
| 8 doctor | Runs the doctor. Failing checks owned by `columns`, `profile` or `marks` are sent back to the LLM step with the failure as feedback, the shadow data is rebuilt and the doctor runs again, up to 3 repair rounds | `Init.step8_doctor` |
| 9 deploy | Writes `.immune/deploy/`, `.immune/DEPLOY.md`, `shadow/detect.yaml` and `.immune/report.md` | `deploycmd.generate`, `initsteps/report.py` |

The last lines are `init: <seconds>s, <n> LLM call(s)`, then `READY: immune up --project <dir>` (exit 0) or
`NEEDS ATTENTION:` with a list (exit 1).

**LLM steps.** Steps 4, 5 and 6 each start from a heuristic draft, so the minimum is 3 LLM calls; 5 and 6 run in
parallel. Each call (`initsteps/llm.py`):

1. copies the project to a temporary directory, leaving out `.git`, virtualenvs, caches, `.immune/`, database
   files (by extension and by SQLite header), `.env*` files, key files, symlinks and files over 512 KiB;
2. adds the context files (schema without values, OpenAPI summary, detected facts) and the draft outputs;
3. runs the `claude` CLI through `patcher/claude_cli.py` with Read on the copy and Edit only on the step's output
   files; the prompt (`immune/prompts/*.md`) declares the repository content untrusted and fences the facts and the
   feedback with a per-call nonce;
4. reads back only the expected output files, which are then validated mechanically (`initsteps/validate.py`).

A step retries up to 3 times, feeding validation errors back. If every call fails and the heuristic draft
validates, the draft is kept, init can still end `READY` and prints `NOTE: LLM unavailable for step(s) ...`.
`--no-llm` keeps the drafts (with `TODO(immune)` markers) and makes no call; init switches to it by itself, with a
message, when the `claude` CLI is not found. Model and timeout: `IMMUNE_INIT_MODEL` (default: the patcher's model,
`PATCHER_MODEL`), `IMMUNE_INIT_TIMEOUT_S` (default 420).

**The profile.** `.immune/profile.py` is the only app-specific code a clone loads. It defines `APP`,
`allowed_file_roots(env)`, `ensure_user(conn, uid, role)`, `mint_token(env, uid, role)`, `load_markers(env)`,
`public_paths()` and optionally `hash_password(password)`. Validation (`validate.profile`) is a static AST policy
(import allow-list; no `eval`, `exec`, `getattr`, `__import__`; no process or file-changing calls on `os`,
`shutil`, `subprocess`, `pathlib`, `sys`) followed by an import in a separate interpreter that checks the
interface, that `public_paths()` does not contain `/`, and that the allowed file roots are existing, absolute,
non-system directories.

### immune doctor

`immune/doctor.py`. Builds a fresh copy of the release (`app.release_paths` plus the profile and scenarios
modules) and runs eight checks. Each result has `id`, `name`, `ok`, `status` (`pass`, `fail`, `warn`, `skip`),
`reason` and `owner` (the init step that owns the failing artefact).

| # | Name | What it verifies | Runs |
|---|---|---|---|
| 1 | config, release, clone health | The config loads, the release is complete, the shadow seed exists, and a clone (`python -m shadow.run`) answers the health route | `--network none` container (`initsteps/clone_probe.py`) |
| 2 | profile identity | On a parameter-free GET that answers 401/403 anonymously, an identity created by `ensure_user` + `mint_token` gets 2xx (with `auth.kind: introspect`, the introspection path must return that uid) | host subprocess |
| 3 | legitimate GETs are clean | Every parameter-free GET, anonymous and as a seeded user, gets verdict `clean` (or `inconclusive` with 401/404) | host subprocess |
| 4 | synthetic canaries | Three self-test routes added around the app (`immune/doctor_selftest.py`: string-built SQL, a file outside the allowed roots, another owner's private value) each fire their oracle (`sql`, `file`, `owner`) | host subprocess |
| 5 | L1 reset | A write made in L2 mode changes the database and the next L1 request restores the seed state. `warn` when `ensure_user` wrote nothing, so no write was undone | host subprocess |
| 6 | no real data in the shadow | Up to 200 sampled real values per private or secret column do not appear in the shadow seed (`shadowdata.leak_check`). `skip` when the shadow comes from `data.seed_command` and there is no `columns.yaml` | CLI process, reads the two databases |
| 7 | tests in the runner | `tests.command` passes on the release. `warn` without a tests command (autopatch capped at `pr`) | `--network none` container |
| 8 | legit scenarios deterministic | The `scenarios` module runs twice in the pipeline's runner with identical output, covers at least one route and hits no 5xx. `warn` without scenarios | pipeline runner container (`pipeline/runner.py`) |

"Host subprocess" means `python -I` with a clean `sys.path`, run as the invoking user by
`initsteps/hostrun.py` and driving `shadow.harness` through `initsteps/harness_runner.py`. The containers of
checks 1 and 7 are `docker run --rm --network none --read-only --cap-drop ALL` on `immune-base:1`, named
`immunedoctor-<hex>`.

`immune doctor --prereqs` needs no project. It reports Docker, the Compose plugin, the image `immune-base:1` and
`git` as required, and the images `immune-sidecar:1` and `immune-cbuild:1`, the `claude` CLI and the `gh` CLI as
optional, each with what it is needed for and how to fix it. `install.sh` runs it at the end.

### immune deploy (experimental)

`immune/deploycmd.py`. `immune init` writes `.immune/deploy/compose.immune.yaml`, an override for the project's
own compose file that stops publishing the app and publishes a gateway container (`immune-<name>-front`) on the
app's host port, plus `.immune/deploy/immune.env` (0600) and `DEPLOY.md`.

| Invocation | Behaviour | Exit |
|---|---|---|
| `immune deploy --dry-run` | Prints the `docker compose ... up -d` command | 0 |
| `immune deploy` | Prints the command and the list of what does not work, then refuses | 2 |
| `immune deploy --experimental` | Runs the command | that of `docker compose` |
| no compose override was generated | Prints `DEPLOY.md` (manual steps) | 0, or 1 when there are no deploy artefacts |

The gateway this starts has no clone pool, no event bus and none of the project's gateway settings (`LIMITS` in
`deploycmd.py`): it proxies requests. Protection in front of a service that is already deployed is not built. The
working path is `immune up`, which runs production itself from releases.

## Layout

| File | Role |
|---|---|
| `__main__.py` | CLI: argument parsing, secrets, compose and host-process control, `up` / `down` / `status` / `report` / `mode` / `autopatch` |
| `config.py` | Loader and validator of `.immune/config.yaml`; runtime paths; `set_key` |
| `_cfg.py` | Path conventions shared by init, doctor and deploy (`columns_path`, `shadow_markers_path`) |
| `supervise.py` | Supervisor of one host process |
| `generic.py` | `app.runtime: generic`: facts read from the config, `up` and `down` for such a project |
| `auth.py` | Identity resolution used by the gateway and the pipeline: `immune-token`, `jwt-hs256`, `introspect`, `none`; honeytoken detection |
| `init.py` | `immune init` |
| `initsteps/detect.py` | Step 1: static detection |
| `initsteps/openapi.py` | Step 2 and the mechanical half of step 6 |
| `initsteps/drafts.py` | Heuristic drafts of `columns.yaml`, `profile.py`, `auth.yaml`, `marks.yaml` |
| `initsteps/llm.py` | The confined LLM call of steps 4 to 6 |
| `initsteps/validate.py` | Mechanical validation of the four LLM-owned files |
| `initsteps/scenarios.py` | Generator of `.immune/scenarios.py` |
| `initsteps/hostrun.py` | Runs project code in a separate host interpreter |
| `initsteps/docker.py` | `docker run --network none` wrapper for init and doctor |
| `initsteps/probe.py`, `initsteps/harness_runner.py`, `initsteps/clone_probe.py` | Child programs run by `initsteps/hostrun.py` and `initsteps/docker.py` |
| `initsteps/report.py` | `context/schema.md` and `report.md` |
| `prompts/` | Prompt templates of the init LLM steps (`common.md`, `columns.md`, `profile.md`, `marks.md`, `feedback.md`) |
| `doctor.py`, `doctor_selftest.py` | `immune doctor` and the self-test routes of check 4 |
| `deploycmd.py` | Deploy artefacts and `immune deploy` |
| `shadowdata.py` | Shadow seed, manifest and markers from a production SQLite database; `leak_check` |
| `shadowdata_pg.py` | The same from a production Postgres database (generic runtime) |
| `legit.py` | Runtime of the generated `.immune/scenarios.py` |
| `metrics.py` | Time-to-patch and detection figures from bus events |
| `tests/` | Unit and integration tests |

## Configuration

### `.immune/config.yaml`

Keys and defaults as validated by `from_dict` in `immune/config.py`. Relative paths resolve against the project
directory. The full schema, with examples, is in [`contracts/product.md`](../contracts/product.md).

| Key | Default | Notes |
|---|---|---|
| `version` | `1` | Only 1 is accepted |
| `name` | required | Lower-case slug `[a-z0-9-]`, at most 31 characters. Names the stack `immune-<name>` |
| `runtime_dir` | `.immune/runtime` | |
| `app.runtime` | `python-asgi` | `python-asgi` or `generic` |
| `app.release_paths` | required | Files and directories that make a release; may not include `.immune`, `.git` or the runtime directory |
| `app.source_dirs` | required | Inside `release_paths`; the only area a patch may edit |
| `app.asgi` | required for `python-asgi` | `package.module:attribute` |
| `app.port` | `8000` | |
| `app.health` | `/health` | |
| `app.env` | `{}` | Values may use `{db}`, `{static}`, `{secret}` |
| `app.frozen_time_env` | empty | Variable through which the app accepts a fixed clock |
| `app.static` | empty | Release-relative directory behind `{static}` |
| `app.image`, `app.build`, `app.command` | empty | Generic runtime. The loader requires `command` and `build`: the fleet builds one image per release, so `image` alone is rejected |
| `app.allowed_file_roots` | `[]` | Generic runtime |
| `database.kind` | `sqlite` | `sqlite` or `postgres`; `postgres` only with `app.runtime: generic` |
| `database.path_env` | `APP_DB` | Variable carrying the SQLite path |
| `database.url_env` | empty | Variable carrying the Postgres URL (generic); when empty the generic runtime uses `DATABASE_URL` |
| `data.prod_db` | required for `sqlite` | The production database file |
| `data.seed_command` | empty | May use `{prod_db}`, `{shadow_db}`, `{manifest}`, `{markers}`, `{seed}` |
| `data.insert_canaries` | `false` | Also insert the canary rows into the production database |
| `auth.kind` | `immune-token` | `immune-token`, `jwt-hs256`, `introspect`, `none` |
| `auth.secret_env` | empty | Required for `jwt-hs256` |
| `auth.uid_claim`, `auth.role_claim`, `auth.admin_values` | `sub`, empty, `[admin]` | `jwt-hs256` |
| `auth.path`, `auth.uid_field`, `auth.role_field`, `auth.cache_s` | `/api/me`, `id`, `role`, `30` | `introspect` |
| `openapi` | required | Path to the OpenAPI document |
| `shadow.profile` | required for `python-asgi` | Python module name |
| `shadow.columns` | empty (`.immune/shadow/columns.yaml`) | |
| `tests.command` | empty | Without it autopatch is capped at `pr` |
| `scenarios` | empty | Python module with `SCENARIOS` for the `legit` gate |
| `repo.target` | `local` | `local` or `github` |
| `repo.github` | empty | `owner/name`, required for `github` |
| `repo.t0_tag` | `immune-t0` | |
| `autopatch` | `merge` | `off`, `pr`, `merge` (`immune init` writes `pr`) |
| `mode` | `enforce` | `observe` or `enforce` |
| `pool_size` | `4` | 0 to 32 |
| `aftercheck` | `false` | |
| `audit.enabled` | `true` for `python-asgi`, `false` for `generic` | |
| `audit.max_jobs`, `audit.max_seconds` | `40`, `120` | |
| `ports.gateway`, `ports.admin`, `ports.dashboard`, `ports.fleet` | `8080`, `8081`, `8090`, `8070` | Must be distinct |

The generic runtime also reads `app.workdir`, `app.bind_env`, `app.warmup_paths`, `data.prod_url_env` and
`data.demo_postgres` from the raw file (`facts` in `immune/generic.py`). `config.py` does not validate these five
keys, so a misspelt one is ignored.

### Environment variables read by the CLI

| Variable | Effect |
|---|---|
| `IMMUNE_PROJECT` | Project directory when `--project` is absent |
| `PROD_APP_SECRET`, `SHADOW_APP_SECRET`, `ADMIN_TOKEN`, `BUS_TOKEN` | Override the values of `<runtime>/secrets.env` |
| `POOL_SIZE` | Overrides `pool_size` on a fresh start |
| `T0_REF` | Build `releases/t0` from `git archive <ref>` instead of the working tree |
| `NO_PIPELINE` | Do not start the pipeline |
| `IMMUNE_NO_SYSTEMD` | Do not use systemd user units for the host processes |
| `IMMUNE_INIT_MODEL`, `IMMUNE_INIT_TIMEOUT_S` | Model and timeout (default 420 s) of the init LLM steps |
| `IMMUNE_BASE_IMAGE` | Image used by init and doctor containers (default `immune-base:1`) |
| `CLAUDE_BIN` | Path of the `claude` CLI (`patcher/claude_cli.py`) |

### Secrets

`stack_secrets` in `immune/__main__.py`. Every project, the built-in demo included, gets random
`PROD_APP_SECRET`, `SHADOW_APP_SECRET`, `ADMIN_TOKEN` and `BUS_TOKEN` in `<runtime>/secrets.env` (mode 0600), created
by the first `up`, `reset` or `status`. Environment variables override them. A stack that was started before that
file existed keeps the values its containers run with, read from `<runtime>/stack/containers.env`. With
`auth.kind: jwt-hs256`, the variable named by `auth.secret_env` must be exported or present in `secrets.env`.
`deploy/demo.env` holds placeholders; the CLI uses it only as the `env_file` of `docker compose down` when no
stack was ever started.

### Files written

Under the project's `.immune/` (by `immune init`; `config.yaml`, `openapi.yaml`, `profile.py`, `scenarios.py` and
`shadow/*.yaml` are meant to be committed):

| Path | Content |
|---|---|
| `config.yaml`, `openapi.yaml`, `profile.py`, `scenarios.py` | Config, marked OpenAPI, shadow profile, generated legit journeys |
| `shadow/columns.yaml`, `shadow/auth.yaml`, `shadow/marks.yaml` | The three LLM-owned classifications |
| `shadow/schema.json`, `shadow/openapi.base.json`, `shadow/detect.yaml`, `context/schema.md` | Detection results and LLM context |
| `deploy/`, `DEPLOY.md`, `report.md` | Deploy artefacts and the report for human review |
| `.gitignore` | Ignores `runtime/` and `deploy/immune.env` |

Under the runtime directory (`runtime_dir`; `runtime/` at the checkout root for the built-in demo):

| Path | Written by | Content |
|---|---|---|
| `secrets.env` | CLI | The four secrets, 0600 |
| `run_id` | CLI | Id of the current run |
| `stack/containers.env` | CLI | `env_file` of the compose services, 0600 |
| `stack/fleet.supervise.json`, `stack/pipeline.supervise.json` | CLI | Supervisor specs; they carry the secrets, 0600 |
| `stack/fleet-state.json`, `stack/gateway-state.json` | fleet, gateway | State restored on resume |
| `stack/demo-db.env` | CLI (generic runtime) | Password and URL of the demo Postgres, 0600 |
| `data/manifest.json`, `data/markers.json`, `data/shadow/` | seed | Manifest, markers, shadow seed |
| `data/prod/` (demo) | seed | The demo's production database |
| `releases/<release>/` | CLI (`t0`), pipeline | Release trees |
| `recordings/requests.jsonl` | gateway | Request recording |
| `bus/events.jsonl` | dashboard | Event store |
| `pipeline/` | pipeline | Incident state |
| `logs/<name>.log`, `logs/<name>.pid`, `logs/<name>.pid.child` | supervisor | Output and pids of `fleet` and `pipeline` |

## Behaviour

### Supervision of host processes

`fleet` and `pipeline` run on the host, not in containers. `start_host` writes a spec
(`<runtime>/stack/<name>.supervise.json`: argv, environment, log, pid file) and starts
`python -m immune.supervise <spec>`:

- with a systemd user manager (`systemctl --user is-system-running` answers `running`, `degraded` or `starting`,
  and `IMMUNE_NO_SYSTEMD` is unset), as the transient unit `immune-<name>-fleet` or `immune-<name>-pipeline`
  (`systemd-run --user --collect`, `Restart=on-failure`, `RestartSec=2`, `KillMode=mixed`). A process started
  from a terminal or an SSH session shares that session's cgroup and dies with it; the unit does not;
- otherwise as a detached process in a new session.

The supervisor (`immune/supervise.py`) restarts its child whenever it exits, with a backoff of 1 s doubling to
30 s and back to 1 s after 60 s of uptime. `SIGTERM` stops the child (`SIGKILL` after 10 s) and then the
supervisor. Nothing starts the stack at boot: transient units do not survive a reboot, and `immune up` then
resumes the run.

### Shadow data

`shadowdata.build` reads the production SQLite database read-only and writes `data/shadow/seed.db` with the same
schema, ids and foreign keys. Private values are synthetic and carry the owner's marker (`MK` plus 10 characters of
`[A-Z0-9]`); secret values are random with the same shape; public tables are copied. It adds 2 canary users and 2
canary rows per owner-scoped table, and writes `manifest.json` (`seed_max_uid`, `legit_users`, `admin`, `canaries`,
`ownership`, and `groups` / `group_routes` for group-shared access) and `markers.json` (marker to owner uid).
Output is deterministic for a given `--seed`. `leak_check` verifies that no sampled real private or secret value
appears in the shadow. With `data.insert_canaries: true`, the canary rows are also inserted into the production
database; this is the only write to production.

For Postgres (`shadowdata_pg.build`), a throw-away `postgres:16-alpine` container reads production in a read-only
session, the rows pass through a temporary SQLite copy and the same generator, and the result is written as
`data/shadow/seed.sql`, with a copy and an init script under `data/shadow/pginit/`, the directory each clone
database loads at start.

### Generated scenarios

`initsteps/scenarios.py` derives a plan from the OpenAPI (every GET operation), `columns.yaml` and the manifest;
`immune/legit.py` runs it. A seeded user reads its own resources, its groups and itself; parameter-free routes
are also read by the admin. A GET is covered when each path parameter maps to something the user legitimately
addresses and each required query parameter has legitimate values. Uncovered operations are listed in the
generated module; for them the `legit` gate reports no coverage and autopatch stays capped at `pr` (see
[`docs/validaciones.md`](../docs/validaciones.md)).

### Identity resolution

`immune/auth.py` `Authenticator` is used by the gateway and the pipeline. A uid is always an integer; a
non-integer subject is anonymous. A token that verifies with the shadow secret and not with the production secret
is reported as a honeytoken (`immune-token` and `jwt-hs256`). `introspect` is resolved by the gateway with a GET to
`auth.path` on production; see [`gateway/README.md`](../gateway/README.md).

## Tests

```
.venv/bin/pytest immune/tests -q
```

Tests marked `docker` (`test_deploy_init.py`, `test_feedback_live.py`) need Docker and the image `immune-base:1`.
One test in `test_feedback_live.py` is marked `live` and calls the LLM. To leave both out:

```
.venv/bin/pytest immune/tests -q -m "not live and not docker"
```

Repository-wide test results are in [`docs/resultados.md`](../docs/resultados.md).

## Limits

- **Generated code runs on the host.** `profile.py` is written by an LLM, checked by a static deny-list
  (`initsteps/validate.py`) and then imported in a separate interpreter on the host, as the invoking user, with
  that user's file and network access. The app itself is imported the same way for profile validation and doctor
  checks 2 to 5 (and for the OpenAPI dump when the container run fails). This is process separation, not a
  sandbox. Only doctor checks 1, 7 and 8 and the first attempt of the OpenAPI dump run in `--network none`
  containers. `report.md` asks for human review of the generated files.
- **`init` supports one shape of app:** Python ASGI (FastAPI or Starlette instance found by a regular expression)
  with a SQLite database file. Other runtimes need a hand-written `.immune/` directory.
- **Heuristics tuned to the demo apps.** The auth draft detection (`initsteps/drafts.py`), the file-like parameter
  pattern `FILE_PARAM_RE` (`initsteps/scenarios.py`), the table and column name patterns of the column draft, and
  the manifest's ownership keys, which are derived from English plural table names (`shadowdata.py`). On another
  app the drafts may be wrong; the LLM steps and the doctor are what corrects them.
- **Column classification decides what leaves production.** A private column classified as public is copied into
  the shadow seed. `leak_check` samples at most 200 values per classified column and cannot see a column that was
  never classified as private.
- **`immune deploy` is a stub** (see above).
- **No start at boot.** After a reboot the stack is down until `immune up` is run.
- **`immune down` on a generic project** removes its app images and networks; the next `up` is a fresh start.

The complete list of limits for all components is [`docs/limites.md`](../docs/limites.md).
