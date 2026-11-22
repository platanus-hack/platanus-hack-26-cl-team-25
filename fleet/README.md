# fleet

## Purpose

The fleet manages every container that runs application code: the production container (blue or green) and the
pool of shadow clones. It is the only component that creates and removes those containers; the pipeline (runner
containers) and the `immune` CLI (compose services, `init` and `doctor` containers) also use Docker, and no
container has the Docker socket. It keeps the clone pool at its
configured size, replaces clones the gateway has retired, and performs blue/green deploys with a health check, a
smoke request and an automatic rollback.

The gateway and the dashboard are started by `deploy/compose.yaml`, not by the fleet; the fleet only restarts
them if they were stopped (see [Reconcile loop](#reconcile-loop)).

## How it runs

```
python -m fleet
```

A host process (FastAPI under uvicorn) bound to `127.0.0.1:$FLEET_PORT` (default port 8070, from `ports.fleet`
of `.immune/config.yaml`). `immune up` starts it under `immune.supervise`, as the transient systemd user unit
`immune-<project>-fleet` or, on a host without a systemd user manager, as a detached process, and passes
its whole environment (`host_env` in `immune/__main__.py`). The project it serves is selected by `IMMUNE_PROJECT` (else `PROJECT_DIR`, else the repository itself, which is the built-in
demo).

The process does not start without `ADMIN_TOKEN` in its own environment (`Config.from_env` in
`fleet/config.py` raises). The token is never read from a file in the repository.

## Layout

| File | Role |
|---|---|
| `__main__.py` | Entry point: builds the config and serves the API on 127.0.0.1 |
| `app.py` | HTTP API, token check, starts the reconcile thread |
| `config.py` | `Config.from_env` (environment plus `.immune/config.yaml`), `derive_smoke_path`, the app's container environment |
| `manager.py` | `Fleet`: containers, clone pool, reset, deploy, rollback, state persistence, adoption, reconcile loop, release pruning |
| `generic.py` | `GenericFleet` for `app.runtime: generic`: image build per release, clone triple (app, Postgres, observer), demo production database |
| `tests/` | Docker-backed tests and unit tests of the deploy logic |

## API

Every route requires the header `x-admin-token` equal to `ADMIN_TOKEN` (compared with `hmac.compare_digest`);
otherwise the answer is 401.

| Route | Body | Effect |
|---|---|---|
| `POST /reset` | `{"release": "<id>", "pool_size": 4}` | Removes every container of this run, starts `prod-blue` on the release, creates the pool, registers it with the gateway, sets the upstream, resets the gateway. `pool_size` 0 to 32 (default 4). |
| `POST /deploy` | `{"release": "<id>"}` | Blue/green deploy of the release (see [Deploy](#deploy)). 409 when there is no active production container. |
| `GET /state` | | `{prod: {active, release}, ready, pool_size, gateway_ok, run_id, clones: [{id, name, addr, release, state}]}`. `ready` is true once the start-up adoption has finished. The generic runtime adds `runtime` and `image`. |

A release id must match `^[A-Za-z0-9][A-Za-z0-9._-]*$` and exist as `<runtime>/releases/<id>` containing every
path of `app.release_paths`; otherwise the answer is 400.

`POST /reset` reports gateway failures in `gateway_errors` instead of failing: the reconcile loop registers the
pool later. It always puts the given release in production, so calling it on a running stack with `t0` puts the
unpatched release back. `immune up` and `immune reset` are the callers; a restarted fleet does not need it (see
[State and restart](#state-and-restart)).

The fleet publishes `deploy.started`, `deploy.done` and `pool.state` to the event bus. Publishing is best
effort (one attempt, 1 s timeout, errors ignored).

## Configuration

Environment variables read by `Config.from_env`. "Project" means the value comes from `.immune/config.yaml`
when the variable is unset.

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_TOKEN` | none (required) | Token of this API; also sent to the gateway admin API |
| `IMMUNE_PROJECT` | repository root | Project directory whose `.immune/config.yaml` is loaded |
| `REPO_DIR` | repository root | Mounted read-only at `/opt/immune` in the containers |
| `RUNTIME_DIR` | project runtime dir | Releases, data, persisted state |
| `RUN_ID` | `deploy/demo.env`, then `<runtime>/run_id`, then `dev` | Value of the `immune.run` label |
| `FLEET_PORT` | project `ports.fleet` (8070) | Listen port on 127.0.0.1 |
| `GATEWAY_ADMIN_URL` | `http://127.0.0.1:<ports.admin>` | Gateway admin API |
| `BUS_URL_HOST`, else `FLEET_BUS_URL` | `http://127.0.0.1:<ports.dashboard>` | Event bus as reachable from the host. `BUS_URL` is the in-container address and is not read. |
| `BUS_TOKEN` | `deploy/demo.env` | Bus token |
| `PROD_APP_SECRET` | `deploy/demo.env` | Secret given to the production app (or the variable named by `auth.secret_env`) |
| `SHADOW_APP_SECRET` | `deploy/demo.env` | Secret given to the clones |
| `IMMUNE_IMAGE` | `immune-base:1` | Image of production and clone containers (Python runtime) |
| `NAME_PREFIX` | `immune-<project>` | Container name prefix |
| `PRODNET`, `CLONENET` | `<compose project>_prodnet`, `<compose project>_clonenet` | Docker networks created by the compose stack |
| `SHADOW_PROFILE` | project `shadow.profile` | Profile module passed to `shadow.run` |
| `CLONE_CMD` | `python -m shadow.run --profile <profile> --port 8000` | Overrides the clone command |
| `COLLECTOR_URL` | `http://gateway:9000` | Where clones push signed evidence |
| `EXTRA_PYTHONPATH` | empty | Appended to the containers' `PYTHONPATH` |
| `SMOKE_PATH` | derived from the OpenAPI | Smoke request path; set it empty to skip the step |
| `DEPLOY_WATCH_S` | 20 | Length of the watch window after the switch |
| `DEPLOY_MIN_REQUESTS` | 20 | Requests needed before the 5xx rate is judged |
| `WATCH_POLL_S` | 0.25 | Poll interval during the watch |
| `HEALTH_TIMEOUT_S` | 40 | Time a container has to pass its health check |
| `RECONCILE_S` | 1 | Reconcile interval |

`deploy/demo.env` holds placeholders. It is only a fallback for `RUN_ID`, `BUS_TOKEN`, `PROD_APP_SECRET` and
`SHADOW_APP_SECRET` when `python -m fleet` is run by hand; `immune up` always passes real values. `ADMIN_TOKEN`
has no fallback.

From `.immune/config.yaml` the fleet takes `app.release_paths`, `app.asgi`, `app.port`, `app.health`, `app.env`,
`app.static`, `database.path_env`, the production data directory and database file name, `shadow.profile`, the
ports and the project name. The reference for the file is [`contracts/product.md`](../contracts/product.md).

## Behaviour

### Containers (Python ASGI runtime)

`Fleet._create` in `manager.py` starts every container with: read-only root filesystem, `cap_drop: ALL`,
`no-new-privileges`, a pids limit, a memory limit with swap set to the same value, the host user's uid and gid
(so a container without capabilities can still write the bind-mounted data directory), and working directory
`/app`.

| Container | Network | Command | Mounts | Limits |
|---|---|---|---|---|
| `<prefix>-prod-<colour>` (alias `prod-<colour>`) | prodnet | `uvicorn <app.asgi> --host 0.0.0.0 --port <app.port>` | repository at `/opt/immune` (ro), release at `/app` (ro), production data at `/data` (rw), tmpfs `/tmp` | 256 pids, 512 MB |
| `<prefix>-clone-<n>` | clonenet | `python -m shadow.run --profile <profile> --port 8000` | repository at `/opt/immune` (ro), release at `/app` (ro), `<runtime>/data/shadow` at `/seed` (ro), `markers.json` at `/markers/markers.json` (ro, if present), tmpfs `/tmp` and `/data` | 128 pids, 256 MB |

When the project has a `.immune` directory it is mounted read-only at `/app/.immune`. Inside the read-only
mounts, the runtime directory, `.git` and the project's `.immune/runtime` are covered by small tmpfs mounts
(`Fleet._masks`), so application code in a container cannot read host state, recordings or secrets through
them. `PYTHONPATH` is `/app`, `/app/.immune` (if mounted), `/opt/immune`.

Production containers have the Docker restart policy `unless-stopped`. Clones have none: the reconcile loop
replaces them.

Every container carries the labels `immune.run=<RUN_ID>`, `immune.role` (`prod`, `clone`, and for the generic
runtime `clone-db`, `clone-obs`), `immune.release` and `immune.project`. `Fleet.destroy` reloads a container
and refuses to remove it unless its `immune.run` label matches. Creating a container first removes any
container with the same name under that rule, so a same-named container without the label aborts the
operation.

### Clone pool

Each clone gets a sequential number and a random 16-byte key (`CLONE_KEY`), which the gateway uses to verify
the evidence the clone pushes. The fleet registers the pool with `PUT /_admin/pool` on the gateway, as
`{id: clone-<n>, addr: <prefix>-clone-<n>:8000, key, release}`. Clones are created in parallel; one that fails
its health check is removed and not registered.

### Reconcile loop

`Fleet.loop` first adopts an existing run (below), then runs `reconcile_once` every `RECONCILE_S`. A pass is
skipped while a reset or deploy holds the lock. One pass:

1. Starts the gateway or dashboard container if it is `exited`, `dead` or `created` (a crash is already covered
   by Docker's restart policy; a container stopped by hand is not).
2. Starts the live production colour again if its container is gone or not running.
3. Reads the gateway pool. Removes clones whose container is not running and clones the gateway marked
   `retired` (a clone whose captive session ended or was evicted, or that failed a request).
4. Creates clones on the current release until the pool has `pool_size` members, registers the new set, then
   removes the old containers.
5. Sets the gateway upstream again if it differs from the live colour.
6. Publishes `pool.state` when the counts changed.

An unreachable gateway is tolerated: `gateway_ok` is false in `/state` and the pass continues with what Docker
reports.

### Deploy

`Fleet.deploy` and `Fleet._deploy`, under the same lock as reset and reconcile:

1. Validate the release id and directory.
2. Start the idle colour on the new release, with the same production data directory.
3. Wait for its health check (`app.health`, up to `HEALTH_TIMEOUT_S`). On failure the new container is removed
   and the deploy ends with `ok: false`.
4. Send one smoke request (see below). On failure the new container is removed and the deploy ends with
   `ok: false`.
5. Read the 5xx rate of the release being replaced from the gateway (`prod_5xx / prod_requests` of
   `GET /_admin/stats`).
6. Switch the gateway upstream (`POST /_admin/upstream`). The gateway drains in-flight requests and zeroes its
   production counters on the switch.
7. Watch the counters for `DEPLOY_WATCH_S`.
8. Without a regression: remove the old colour, replace every free clone that is not on the new release (busy
   and captive clones are left on theirs), prune old release directories.

Steps 3 and 4 fail before the switch, so production never points at a release that did not pass them.

The health check and the smoke request are made from inside a container, with `python -c
"urllib.request.urlopen(...)"`; any HTTP error status fails them.

**Smoke path.** `SMOKE_PATH` if the variable is set; otherwise `derive_smoke_path` picks the first `GET` of the
project's OpenAPI that has no path parameter, no required parameter and no `security`, and is not the health
path. If there is none, or the path equals the health path, the step is skipped and the result says so in
`smoke` (`skipped: no request distinct from the health check ...`). For the built-in demo the derived path is
`GET /api/products`; for `examples/tareas-node` the step is skipped.

**Rollback rule** (`Fleet._watch`). During the watch the fleet polls the gateway counters. It rolls back when
all three hold:

- at least `DEPLOY_MIN_REQUESTS` requests reached production since the switch,
- at least one of them was answered with a 5xx,
- the 5xx rate since the switch is above `max(2 x old rate, old rate + 0.02)`, where the old rate is the one
  read in step 5.

On rollback the upstream is switched back, the new container is removed, and the result is `ok: false,
rolled_back: true, detail: "prod_5xx grew after switch; rolled back"`.

With fewer than `DEPLOY_MIN_REQUESTS` requests in the window, the deploy succeeds with
`traffic_validated: false` and the detail `deployed; not validated by traffic (...)`. The result of a deploy
that reached the watch (success or rollback) carries `smoke` and
`watch: {seconds, requests, prod_5xx, min_requests}`; a deploy that failed before the switch carries neither.

Comparing against the old release's rate means errors the old release already produced do not undo a deploy.

**Release pruning.** After a successful deploy `_prune_releases` keeps `t0`, the release in production, every
release a container of this run still mounts, and the five newest of the rest; older directories are removed.

### State and restart

After every change the fleet writes `<runtime>/stack/fleet-state.json`: run id, live colour, release, pool
size, clone counter. On start, `Fleet.adopt` reads it and takes over the running containers instead of
starting from nothing:

- The file is ignored if it belongs to another run id or is malformed; the fleet then stays idle until a
  `/reset`.
- If the other colour is running, healthy, and the gateway's upstream points at it, the fleet follows the
  gateway: the process died between the switch and recording it.
- If the production container is missing or does not pass its health check, the recorded release is started
  again.
- A leftover container of the other colour is removed.
- Running clones on the recorded release are adopted with their keys, up to `pool_size`; the others are
  removed and the reconcile loop refills the pool.

So a restarted fleet keeps the release that was in production. `POST /reset` is not needed after a restart and
would put the release given in its body back in production.

### Generic runtime (`app.runtime: generic`)

`make_fleet` returns `GenericFleet` (`generic.py`) when the project config says `app.runtime: generic`. The app
runs unmodified from its own image; the oracles run outside the process, in the sidecar (see
[`sidecar/README.md`](../sidecar/README.md)).

- **Image per release.** `build_image` runs `docker build` on the release directory (`app.build.context`,
  `app.build.dockerfile`) and tags it `immune-<project>-app:<release>`. `immune up` builds `t0`; `/deploy`
  builds the new release before starting the normal deploy sequence and returns `build_s`. A failed build ends
  the deploy with `ok: false` and no container started.
- **Production.** The image on prodnet as `prod-<colour>`, with the database URL from the variable named by
  `data.prod_url_env`, or the demo database below. Read-only, `cap_drop: ALL`, `no-new-privileges`, 256 pids,
  512 MB.
- **Clone triple.** Each clone is three containers on clonenet:

  | Container | Image | Notes |
  |---|---|---|
  | `<prefix>-clone-<n>-db` | `postgres:16-alpine` | tmpfs data, `fsync=off`, uid 70, random passwords per clone; its init script (`<runtime>/data/shadow/pginit`) creates role `app` and the template database `seed` from the shadow dump |
  | `<prefix>-clone-<n>` | `immune-<project>-app:<release>` | the app, bound to 127.0.0.1 through the variable named by `app.bind_env`, database URL pointing at `127.0.0.1:5432` (the sidecar's proxy) |
  | `<prefix>-clone-<n>-obs` | `immune-sidecar:1` | `python -m sidecar --config /cfg/sidecar.json`, sharing the app container's network and PID namespaces, with `SYS_PTRACE` as the only added capability |

  All three are read-only with `cap_drop: ALL` and `no-new-privileges`. The gateway's clone address is
  `<prefix>-clone-<n>:8000`, the sidecar's port in the app's network namespace. The sidecar's config file is
  written to `<runtime>/stack/clones/<clone>.json` and contains the clone database's superuser password. If
  any of the three fails to start, the whole triple is removed. The reconcile loop replaces a triple whose
  observer or database is not running.
- **Health checks.** A clone is healthy when a request to the sidecar on port 8000 succeeds (the fleet execs
  into the observer container); production is checked from the gateway container against `prod-<colour>`.
- **Demo production database.** Without a value in the variable named by `data.prod_url_env`, `immune up`
  starts `<prefix>-proddb` (`postgres:16-alpine` on prodnet, alias `proddb`, tmpfs data) and runs
  `data.demo_postgres.seed_command` once in the `t0` image. It is labelled with the project only, so `/reset`
  does not remove it. Its data lives in tmpfs and is lost when the container is removed.

## Tests

```
.venv/bin/pytest fleet/tests -q
```

`fleet/tests/test_fleet.py` needs Docker and the `immune-base:1` image: it starts real containers with a
test-only name prefix, label and networks against a fake gateway, in a temporary runtime directory, and removes
them afterwards. These tests are not marked `docker`, so `-m "not docker"` does not deselect them.
`fleet/tests/test_deploy_unit.py` runs without Docker: the watch and rollback rule, the smoke step, smoke path
derivation, the required token and the constant-time comparison. The generic fleet has no tests in this
directory.

## Limits

- The rollback rule sees only 5xx answers during the watch window. It does not see a release that answers 200
  with wrong content, and it sees nothing after the window.
- A deploy with little traffic is not validated by traffic (`traffic_validated: false`); only the health check
  and one smoke request stand between that release and production. When the smoke step is skipped, only the
  health check does.
- If the gateway is unreachable during the watch, the polls fail silently and the deploy finishes with
  `traffic_validated: false`.
- If the rollback switch itself fails, the fleet logs the error and records the old colour as live; the
  reconcile loop then sets the upstream again.
- The production database is shared by both colours. A release that changes the schema or the data is not
  undone by a rollback.
- One project per fleet process; `/reset`, `/deploy` and reconcile are serialised by one lock.
- The fleet does not start at boot by itself; see [`docs/operacion.md`](../docs/operacion.md).
- The generic runtime supports Postgres only and needs `app.build` (an image without a build context is
  rejected by `immune/generic.py`).

The project-wide list is in [`docs/limites.md`](../docs/limites.md).
