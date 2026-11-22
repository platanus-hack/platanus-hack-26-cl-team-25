# System contract

Reference for the running system of Immune: which processes exist, where they listen, how they talk to each
other, and the exact shape of every message between them. Every entry describes the code as it is; the file
that implements it is named next to it.

| Document | Covers |
|---|---|
| `contracts/README.md` (this file) | Processes, ports, networks, environment, clone protocol, gateway decisions and admin API, recording format, fleet API, pipeline flow, event bus |
| `contracts/product.md` | The `.immune/` directory of a project, `config.yaml`, the CLI, the generic runtime, behaviour under failure |
| `contracts/interfaces.md` | Python interfaces between `pipeline/`, `patcher/` and scenario modules; the runner |
| `contracts/openapi.yaml` | API of the built-in demo app (Tienda), with the `x-owner-scoped` and `x-sensitive` marks |
| `contracts/schemas/evidence.schema.json` | Evidence a clone pushes to the gateway; also the data of `oracle.fired` |
| `contracts/schemas/poc.schema.json` | Regression case (PoC) of an incident |
| `contracts/schemas/rule.schema.json` | Gateway rule |
| `immune_contracts/` | The same contracts as code: `authtoken.py`, `grammar.py`, `wire.py`, `events.py` |

Terms used throughout: **clone** (a copy of the app running on synthetic data), **oracle** (a mechanical
observation that proves an attack worked), **detonation** (running a request in a clone to read its verdict),
**captive** (a session served only by a clone), **rule** (a gateway containment rule), **gate** (one of the five
validations of a patch), **canary** (a share of production traffic sent to a new release before the upstream
switch). Design reasons are in `docs/arquitectura.md`; limits are in `docs/limites.md`.

Scope. This file describes the stack that `immune up` starts. Three things in the repository run outside it,
with their own processes, and are described where they live: the FUXA runtime (`immune fuxa`,
`immune/README.md`), the Grafana lab (`labs/grafana-cve-2021-43798/README.md`) and the ScadaBR lab
(`labs/scadabr-cve-2026-8602/README.md`). They reuse the clone protocol (section 5), the gateway and the event
types (section 10.3).

`<name>` is the `name` of `.immune/config.yaml`; `<runtime>` is its `runtime_dir` (`contracts/product.md` section 1).

## 1. Processes, ports, networks

| Component | Package | Runs as | Listens | Entry point |
|---|---|---|---|---|
| gateway | `gateway/` | container `immune-<name>-gateway` | 8080 data, 8081 admin, 9000 clone ingest | `python -m gateway` |
| event bus and dashboard | `dashboard/` | container `immune-<name>-dashboard` | 8090 | `python -m dashboard` |
| production app (`python-asgi`) | the project's code | container `immune-<name>-prod-<blue\|green>` | `app.port` (default 8000) | `uvicorn <app.asgi> --host 0.0.0.0 --port <app.port>` |
| clone (`python-asgi`) | `shadow/` wrapping the project's code | container `immune-<name>-clone-<n>` | 8000 | `python -m shadow.run --profile <shadow.profile> --port 8000` |
| clone (`generic`) | project image + `sidecar/` + a database (Postgres or MariaDB) | three containers per clone (`contracts/product.md` section 10) | 8000 (observer) | `python -m sidecar --config /cfg/sidecar.json` |
| fleet | `fleet/` | supervised host process (`contracts/product.md` section 11), unit `immune-<name>-fleet` | `127.0.0.1:8070` | `python -m fleet` |
| pipeline | `pipeline/` | supervised host process, unit `immune-<name>-pipeline` | none | `python -m pipeline` |
| runner | `pipeline/runner.py` | one container per job, `immune-<name>-runner-<pid>-<n>` | none (`--network none`) | `python -m pipeline.runner_entry` |
| patch generator | `patcher/` | library inside the pipeline process; spawns the `claude` CLI | none | `patcher.propose` |
| legitimate traffic generator (demo) | `sim/` | host process, started by hand | none | `python -m sim.legit` |

Host ports. `deploy/compose.yaml` publishes three container ports, each on `127.0.0.1` only; the fleet binds
`127.0.0.1` itself (`fleet/__main__.py`). The numbers come from `ports:` in `config.yaml`.

| Key in `ports:` | Default | Container port | Serves |
|---|---|---|---|
| `gateway` | 8080 | gateway 8080 | client traffic |
| `admin` | 8081 | gateway 8081 | gateway admin API (section 6.6) |
| `dashboard` | 8090 | dashboard 8090 | event bus and panel (section 10) |
| `fleet` | 8070 | host process | fleet API (section 8) |

The clone ingest port 9000 is not published; clones reach it as `http://gateway:9000` on the clone network.

Docker networks, created by `deploy/compose.yaml` under the compose project `immune-<name>` (so their Docker
names are `immune-<name>_prodnet` and so on):

| Network | Internal | Members |
|---|---|---|
| `prodnet` | yes | gateway (alias `gateway`), production containers (alias `prod-<colour>`), demo database of the generic runtime (alias `proddb`) |
| `clonenet` | yes | gateway (alias `gateway`), clones |
| `ctrlnet` | yes | gateway (alias `gateway`), dashboard |
| `edge` | no | gateway, dashboard; carries the published ports |

A clone is attached to `clonenet` only: the gateway is the only other member it can address. Nothing in a
container calls the fleet or the pipeline; host processes call the containers through the published ports.

Images:

| Image | Built from | Used by |
|---|---|---|
| `immune-base:1` | `deploy/Dockerfile.base` | gateway, dashboard, production and clones of `python-asgi`, runner |
| `immune-sidecar:1` | `deploy/Dockerfile.sidecar` | observer of generic clones and of the generic judge |
| `immune-cbuild:1` | `deploy/Dockerfile.cbuild` | `immune anticipate` |
| `immune-<name>-app:<release>` | the project's Dockerfile (`fleet/generic.py`, `build_image`) | production and clones of the generic runtime |
| `immune-<name>-app:<release>-trace` | the release image plus Xdebug (`fleet/generic.py`, `build_trace_image`) | clones of a generic project with `shadow.tracer`; never production |
| `postgres:16-alpine` | Docker Hub | per-clone database and demo database of the generic runtime, `database.kind: postgres` |
| `mariadb:11.8.8`, pinned by digest (`immune/dbkind.py`, `MARIADB_IMAGE`) | Docker Hub | the same, `database.kind: mysql` |
| `immune-strace:1` | `deploy/Dockerfile.strace` | tracer container of the sidecar's `docker` mode (Grafana lab) |
| `immune-bpftrace:1` | `deploy/Dockerfile.bpftrace` | tracer container of `python -m sidecar.prodwatch` (Grafana lab) |
| `immune-gobuild:1` | `deploy/Dockerfile.gobuild` | build and test sandbox of `pipeline/extfix.py` (Grafana lab) |
| `immune-waf:1` | `waf/Dockerfile` | detection service of `waf/` (started by `immune up` with `IMMUNE_WAF=1`, and by the ScadaBR lab) |

`install.sh` builds `immune-base:1` and `immune-sidecar:1`, `immune-cbuild:1` with `IMMUNE_WITH_ANTICIPATE=1`,
and pulls the images of the OpenEMR example with `IMMUNE_WITH_OPENEMR=1`. The app images are built by
`immune up` and by the fleet. The last four rows are built by the lab scripts
(`labs/grafana-cve-2021-43798/lab.sh`, `labs/scadabr-cve-2026-8602/lab.sh`).

Mounts inside containers:

| Path in the container | Content | Where |
|---|---|---|
| `/opt/immune` (read-only) | this repository | every container that runs Immune code; `PYTHONPATH` includes it |
| `/app` (read-only) | one release (`<runtime>/releases/<id>`); working directory | production, clones, runner (`python-asgi`) |
| `/app/.immune` (read-only) | the project's `.immune/` directory, when it exists | production, clones, runner |
| `/runtime` | `<runtime>` | gateway, dashboard |
| `/config/openapi.yaml` (read-only) | the project's OpenAPI document | gateway |
| `/data` | production: the directory of `data.prod_db` (read-write); clone: a tmpfs | production, clones |
| `/seed` (read-only) | `<runtime>/data/shadow` | clones; runner when the project has no `data.seed_command` |
| `/markers/markers.json` (read-only) | `<runtime>/data/markers.json` | clones |

Inside `/opt/immune` and `/app/.immune`, the runtime directory and `.git` are covered by an empty tmpfs
(`fleet/manager.py`, `_masks`; `pipeline/runner.py`, `docker_cmd`), and the runner also masks `.env`.

Container hardening applied by the code:

| Container | Settings | Source |
|---|---|---|
| gateway, dashboard | read-only root, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`, runs as the host user, restart `unless-stopped` | `deploy/compose.yaml` |
| production | read-only root, `cap_drop ALL`, `no-new-privileges`, 256 pids, 512 MB, restart `unless-stopped` | `fleet/manager.py`, `start_prod` |
| clone (`python-asgi`) | read-only root, `cap_drop ALL`, `no-new-privileges`, 128 pids, 256 MB, tmpfs `/tmp` and `/data`, no restart policy | `fleet/manager.py`, `start_clone` |
| runner | `--network none`, read-only root, `--cap-drop ALL`, `no-new-privileges`, tmpfs `/tmp`, pids, memory and CPU limits (256, 1 GB, 2 by default) | `pipeline/runner.py`, `docker_cmd` |

Every container the fleet creates carries the labels `immune.run=<run id>`, `immune.role`, `immune.release` and
`immune.project=<name>`. The fleet removes a container only if it carries `immune.run` of its own run
(`fleet/manager.py`, `destroy`).

## 2. Runtime directory

All state of a stack lives under `<runtime>`. For the built-in demo that is `runtime/` at the repository root;
for any other project the default is `.immune/runtime/` inside the project.

| Path under `<runtime>` | Content | Written by |
|---|---|---|
| `run_id` | id of the current run (`MMDD-HHMMSS`) | `immune up` / `immune reset` |
| `secrets.env` | the four stack secrets, mode 0600 (section 3) | `immune/__main__.py`, `stack_secrets` |
| `stack/containers.env` | env file of the compose services | `immune/__main__.py`, `write_stack_env` |
| `stack/gateway-state.json` | upstream, mode, rules with their absolute expiry (infinite for a rule without TTL) | gateway |
| `stack/fleet-state.json` | live colour, release, pool size, clone counter | fleet |
| `stack/fleet.supervise.json`, `stack/pipeline.supervise.json` | supervisor spec of each host process, mode 0600 (holds the secrets) | `immune up` |
| `stack/clones/<clone>.json` | generic runtime: observer configuration of one clone, including that clone's database passwords | fleet (`fleet/generic.py`) |
| `stack/demo-db.env` | generic runtime: password and URL of the demo database, mode 0600 | `immune up` |
| `releases/<release>/` | immutable copy of `app.release_paths` for one release; `t0` is the first | `immune up`, pipeline |
| `data/` | production database (when `data.prod_db` is under it), `manifest.json`, `markers.json` | seed |
| `data/shadow/` | `seed.db`, `markers.json`, optional `sharing.json`; for Postgres `seed.sql` and `pginit/` (`seed.dump`, `01-seed.sh`); for MySQL `seed.sql` and `myinit/` (same two files) | seed |
| `recordings/requests.jsonl` | gateway request log (section 7); rotated to `requests.jsonl.1` | gateway |
| `bus/events.jsonl` | event bus store; rotated to `events.jsonl.1` | dashboard |
| `pipeline/state.json` | incidents, queue, last bus sequence number | pipeline |
| `pipeline/events.jsonl` | copy of every event the pipeline published | pipeline |
| `pipeline/PAUSE` | while this file exists the pipeline starts no new incident | operator |
| `corpus/<class>.jsonl` | confirmed parameter values per class, at most 500 per class | pipeline |
| `repo/` | local git repository used when `repo.target` is `local` | pipeline |
| `logs/fleet.log`, `logs/fleet.pid`, `logs/fleet.pid.child` and the same for `pipeline` | log and pid files of the two host processes | supervisor |

`immune anticipate` is not tied to a project: it keeps its cache and reports under `anticipate/` in the directory
named by the environment variable `RUNTIME_DIR`, by default `runtime/` at the repository root (`anticipate/core.py`).

`immune reset` deletes `data/`, `recordings/`, `bus/`, `releases/`, `pipeline/` and `logs/*.log`; it keeps `corpus/`,
`secrets.env` and, in the case described in `contracts/product.md` section 5, the production database. The two
runtimes differ in one point: `python-asgi` keeps `repo/` (`immune/__main__.py`, `seed`) and `generic` deletes
it (`immune/generic.py`, `cmd_up`).

## 3. Environment variables

Secrets. `immune up` generates four random values (`secrets.token_hex(16)`) into `<runtime>/secrets.env` and
passes them to every component. A variable of the same name in the environment of `immune` overrides the file.

| Variable | Used by | Meaning |
|---|---|---|
| `PROD_APP_SECRET` | production, gateway, pipeline | secret of production tokens (`{secret}` in `app.env` of production) |
| `SHADOW_APP_SECRET` | clones, gateway | secret of tokens minted inside clones; a token signed with it that arrives from outside is a honeytoken |
| `ADMIN_TOKEN` | gateway admin API, fleet API, pipeline | value of the header `x-admin-token` |
| `BUS_TOKEN` | dashboard, every publisher | value of the header `x-bus-token` |

`deploy/demo.env` holds placeholder values. No stack started by `immune up` uses them. They are read in two
cases: as the env file of `docker compose down` when no stack was ever started, and as the fallback of a
hand-run `python -m pipeline` for unset secrets (`pipeline/config.py`, `_demo_env`) and of a hand-run
`python -m fleet` for every secret except `ADMIN_TOKEN` (`fleet/config.py`, `Config.from_env`).

Per-component variables. Each component's own variables, with their defaults, are listed once, in the
component's README, next to the code that reads them:

| Component | Read by | Reference |
|---|---|---|
| gateway | `gateway/core.py`, `Config.from_env` | `gateway/README.md`, "Configuration" |
| dashboard and bus | `dashboard/__main__.py`, `dashboard/server.py` | `dashboard/README.md`, "Configuration" |
| fleet | `fleet/config.py`, `Config.from_env` | `fleet/README.md`, "Configuration" |
| pipeline | `pipeline/config.py`, `Config.from_env` | `pipeline/README.md`, "Configuration" |
| patch generator | `patcher/claude_cli.py`, `patcher/core.py` | `patcher/README.md`, "Configuration" |

The variables an operator is expected to change are summarised in `docs/operacion.md`.

Clone (`fleet/manager.py`, `start_clone`; read by `shadow/run.py` and `shadow/core.py`):

| Variable | Meaning |
|---|---|
| `CLONE_ID`, `CLONE_KEY` | clone id (`clone-<n>`) and the HMAC key of its evidence pushes (random per clone) |
| `COLLECTOR_URL` | base URL of the gateway ingest listener |
| `SHADOW_SEED_DB` | seed database the clone restores from (`/seed/seed.db`) |
| `SHADOW_DB_ENV` | name of the variable through which the app receives its database path (`database.path_env`) |
| `SHADOW_RELEASE_ROOT`, `SHADOW_RELEASE_PATHS` | release root (`/app`) and `app.release_paths`, used to select stack frames |
| `MARKERS_PATH` | markers file, set only when `<runtime>/data/markers.json` exists |
| `RELEASE` | release id, copied into evidence |
| the `app.env` entries | with `{db}` = `/data/app.db`, `{secret}` = `SHADOW_APP_SECRET`, `{static}` = `/app/<app.static>` |


## 4. Application contract

What Immune needs from the protected application. The built-in demo, Tienda (`victim/`), is the reference
instance; a project's own values live in its `config.yaml` (`contracts/product.md` section 2).

### 4.1 OpenAPI extensions

Read by `gateway/spec.py` from the project's OpenAPI document:

| Extension | Where | Effect |
|---|---|---|
| `x-owner-scoped: true` | operation | the resource belongs to one user; see the `owner_scoped:*` reasons in section 6.2 |
| `x-sensitive: true` | parameter, or schema of a parameter or JSON property | the value is never schema- or grammar-checked and is replaced by `<redacted>` in the recording |
| `x-owner-id: true` | query parameter of an `x-owner-scoped` operation | the parameter's value identifies the addressed object for the `enumeration` reason, for apps that carry the object id in the query string instead of the path (`gateway/classifier.py`, `classify`) |

The gateway reads this subset of OpenAPI 3.0: local `$ref`, path templates (including catch-all `{name*}`),
query, path and header parameters, JSON and form request bodies.

### 4.2 Demo app

| Fact | Value | Source |
|---|---|---|
| Framework and storage | FastAPI, synchronous `sqlite3`, all mutable state in one SQLite file | `victim/app/db.py` |
| Environment | `APP_DB` (database path), `APP_SECRET` (token secret), `APP_STATIC` (static directory), `APP_NOW` (optional frozen unix time) | `victim/app/db.py`, `victim/app/auth.py`, `victim/app/files.py` |
| Authentication | `immune_contracts/authtoken.py`: `Authorization: Bearer <token>` | `victim/app/auth.py` |
| API | `contracts/openapi.yaml` | |
| Tests | `victim/tests/`, run with `python -m pytest victim/tests -q -p no:cacheprovider` | `.immune/config.yaml` |
| Planted defects | seven; the list is kept outside every release path, in `docs/demo/respuestas/` | |

Token format (`immune_contracts/authtoken.py`):
`base64url(json({"uid": int, "role": "user"|"admin", "exp": int})) + "." + hex(hmac_sha256(secret, payload))`.

Seed command of the demo:

```
python -m victim.seed --out-prod <db> --out-shadow <db> --manifest <json> --markers <json> [--seed 1]
```

Production and shadow databases share the key skeleton (same ids, same owner relations, same public data).
Every private value in the shadow database embeds its owner's marker: `MK` followed by 10 characters of
`[A-Z0-9]`, unique per owner.

### 4.3 `manifest.json` and `markers.json`

`<runtime>/data/manifest.json`, read by the gateway (`gateway/classifier.py`, `Manifest`) and by the pipeline:

| Key | Type | Used for |
|---|---|---|
| `seed_max_uid` | integer | identity trust: `uid <= seed_max_uid` is trusted (section 6.1) |
| `canaries` | `{path parameter name: [values]}` | a non-admin, non-owner request addressing a canary value is evidence |
| `ownership` | `{table: {object id: owner uid}}` | `owner_scoped:mismatch` and canary ownership; the table for parameter `<x>_id` is `<x>s` |
| `groups` | `{group table: {group id: [member uids]}}` | group-shared access (`contracts/product.md` section 9) |
| `group_routes` | `{path parameter name: group table}` | same |
| `legit_users`, `admin` | credentials of seeded users | scenarios, `sim/legit.py`, class audit |
| `seed_max_<table>_id` | integer | scenarios (for the demo: `seed_max_order_id`) |

Each event: `{"oracle": kind, "detail": {...}, "stack": [{"file": "<path relative to the release>", "line": n, "func": "..."}]}` with only frames inside the victim package. Out-of-process oracles (`sidecar/`) fill `stack` when a frame source is configured (native `strace -k` frames resolved with `addr2line`, the servlet entry point of a Java app, PHP Xdebug traces: `sidecar/README.md` *Where in the app's code*); without one it is `[]`. `detail` for `sql`: `{statement, input, param}`; `file`: `{path, realpath}`; `owner`: `{marker_owner, requester}`.

`<runtime>/data/markers.json` maps each marker to its owner uid: `{"MK4F7Q2ZP0XA": 3, ...}`.
The gateway reloads the manifest when the file's modification time changes.

### 4.4 Shadow profile

A Python module named by `shadow.profile`, importable inside the clone from `/app` or `/app/.immune`. It is
the only application-specific code the wrapper runs. For the demo: `victim/shadow_profile.py`.

```python
APP = "victim.app.main:app"                               # ASGI entry, "module:attribute"
def allowed_file_roots(env: dict) -> list[str]: ...        # directories the app may open files in
def ensure_user(conn, uid: int, role: str) -> None: ...    # insert a synthetic user row if uid is missing
def mint_token(env: dict, uid: int, role: str) -> str: ... # a credential the app accepts for uid
def load_markers(env: dict) -> dict[str, int]: ...         # marker -> owner uid
def public_paths() -> list[str]: ...                       # path prefixes exempt from the owner oracle
def identify(env: dict, headers: dict): ...                # optional: (uid, role) or None from client headers
```

`load_markers` raising stops the clone from starting. Returning an empty mapping turns the owner oracle off
and logs a warning (`shadow/core.py`, `Engine.__init__`).

## 5. Clone protocol

How the gateway talks to a clone. Three implementations exist, and the gateway cannot tell them apart:

| Implementation | For | Source |
|---|---|---|
| in-process wrapper | Python ASGI apps (`app.runtime: python-asgi`) | `shadow/core.py`, `Engine.handle`, `Engine.finish` |
| sidecar | any other app: clones of the generic runtime, and the Grafana lab in the sidecar's `docker` mode | `sidecar/server.py`, `Sidecar.handle` |
| ScadaBR proxy | the ScadaBR lab only | `sidecar/httpds/core.py` |

### 5.1 Headers (`immune_contracts/wire.py`)

| Header | Direction | Value |
|---|---|---|
| `x-imm-rid` | gateway to clone | request id minted by the gateway |
| `x-imm-mode` | gateway to clone | `L1`: reset to the seed after the request. `L2`: captive, keep state. The sidecar also accepts `learn` from `python -m sidecar.learn`, signed with the clone key; the gateway never sends it |
| `x-imm-uid` | gateway to clone | user id resolved from the production credential; absent means "use the client's own headers" |
| `x-imm-role` | gateway to clone | `user` or `admin`; only with `x-imm-uid` |
| `x-imm-verdict` | clone to gateway | `clean`, `oracle` or `inconclusive` |
| `x-imm-events` | clone to gateway | number of oracle events of this request |
| `x-imm-clone` | clone to gateway ingest | clone id of an evidence push |
| `x-imm-signature` | clone to gateway ingest | `hex(hmac_sha256(clone key, raw body bytes))` |

The gateway removes every header starting with `x-imm-` from client requests (`gateway/core.py`, `_read`) and
from responses sent to clients (`_clean_resp_headers`). A response without a valid `x-imm-verdict` is treated
as `inconclusive`.

### 5.2 One request in a clone

A clone handles one request at a time (a lock in `shadow/run.py`). For each request:

1. Read and remove the `x-imm-*` request headers.
2. If `x-imm-uid` is present: call `ensure_user`, then replace `Authorization` with `mint_token(uid, role)`.
   Otherwise the identity is what the profile's `identify` returns or, by default, what the bearer token
   verifies to with the clone's `APP_SECRET`.
3. In mode `L2`: snapshot the database before the request.
4. Run the app and buffer the whole response.
5. Evaluate the oracles (section 5.3).
6. Verdict: `oracle` if any oracle fired; else `inconclusive` if the status is 401, 404 or 500 and above;
   else `clean`.
7. If the verdict is `oracle`: POST the evidence to `<COLLECTOR_URL>/_clone/evidence`, signed, before the
   response is released (2 s timeout). A failed push is logged and does not change the response.
8. Send the response with `x-imm-verdict` and `x-imm-events`.
9. In mode `L1`: restore the database from the seed.

Evidence body: `contracts/schemas/evidence.schema.json`. `pre_state_b64` carries the SQLite snapshot of step 3
in `L2` and is `null` in `L1` and for Postgres. The body is serialised with `wire.dumps` (sorted keys, compact
separators) and signed over those bytes.

### 5.3 Oracles

Kinds are the constants `wire.ORACLE_SQL`, `wire.ORACLE_FILE`, `wire.ORACLE_PROC`, `wire.ORACLE_NET` and
`wire.ORACLE_OWNER`. `contracts/schemas/evidence.schema.json` and `contracts/schemas/poc.schema.json` also
accept the kinds `acl`, `mfa` and `xss`. They have no constant in `immune_contracts/wire.py` and no
implementation in `shadow/` or `sidecar/`: only a profile's `extra_oracles` hook in the sidecar can emit them,
and the only profile that does is `examples/openemr/overlay/.immune/openemr_identity.py`. The pipeline maps
them to the class `other` (section 9).

In-process implementation (`shadow/`):

| Kind | Fires when | Does not fire when | Source |
|---|---|---|---|
| `sql` | a request input of length 2 or more appears in a statement executed through `sqlite3` and is not exactly inside one literal token, or touches a comment | the statement failed; the value arrived as a bound parameter; the occurrence is a verbatim part of a string constant of the app's own code | `shadow/sqltaint.py` |
| `file` | the app opens or lists a path whose real path is outside the profile's allowed roots and outside the warm-up allowlist | the file was opened during warm-up (interpreter and library files) | `shadow/instrument.py` |
| `proc` | a process is spawned during the request | | `shadow/instrument.py` |
| `net` | an outbound connection or name resolution happens during the request | the wrapper's own evidence push | `shadow/instrument.py` |
| `owner` | the response body carries the marker of an owner other than the requester, and the requester is not admin | the path is under `public_paths()`, unless markers of two or more foreign owners appear or another oracle fired in the same request; the marker owner shares a group with the requester on a members-scoped route | `shadow/core.py`, `owner_events` |

Each event is `{"oracle": kind, "detail": {...}, "stack": [{"file", "line", "func"}]}`. `stack` holds only
frames inside `app.release_paths`, with paths relative to the release root, outermost first and the sink last.
`detail` is `{statement, input, param, location, reason}` for `sql` (`reason` is `comment`, `token` or
`structure`), `{path, realpath}` for `file` (plus `op` for a directory listing), `{event, args}` for `proc`,
`{event, address}` for `net` and `{marker_owner, requester}` for `owner`. The sidecar implementation and what
it observes are described in `contracts/product.md` section 6 and `sidecar/README.md`; its events have an empty
`stack`, except for a clone with `shadow.tracer`, where `sidecar/phptrace.py` fills it from the PHP call trace
of the request. The ScadaBR proxy emits `owner` events with detail `{route, consumed, observed, expected}` and
an empty `stack`.

Limits of each oracle are listed in `shadow/README.md` and `docs/limites.md`.

### 5.4 In-process harness

The runner judges patches with the same engine, without a network (`shadow/harness.py`):

```python
from shadow.harness import Harness
h = Harness(profile="victim.shadow_profile", seed_db="/path/seed.db", state=None)  # state: SQLite bytes, or None for the seed
r = h.send("GET", "/api/products", query="q=x", headers={}, body=b"", uid=None, role="user", mode="L1")
r.status, r.headers, r.body, r.verdict, r.events, r.evidence
h.snapshot()   # -> bytes
h.close()
```

The app is imported from `sys.path`, so the caller chooses the release. Evidence is built but never pushed.

## 6. Gateway

`gateway/core.py` (`Gateway`), `gateway/classifier.py` (`classify`), `gateway/spec.py`, `gateway/pool.py`,
`gateway/l0.py`, `gateway/waf.py`.

### 6.1 Reading a request

| Step | Behaviour | Function |
|---|---|---|
| Target | a target that does not start with `/` is answered 400 | `_read` |
| Body | `Content-Length` above 10 MiB, or a body growing past it: 413. Body not complete within 30 s: 408. Invalid `Content-Length`: 400 | `_read` |
| Client disconnect | a request whose client disconnects before its body is complete is dropped: not forwarded, not answered, not recorded | `data_app` |
| Internal headers | every `x-imm-*` request header is removed | `_read` |
| Session cookie | cookie `gwsid`, accepted if it matches `[A-Za-z0-9_-]{16,64}`; otherwise a new one is issued with `Set-Cookie: gwsid=<value>; Path=/; HttpOnly; SameSite=Lax` | `_read`, `_send` |
| Identity | per `auth.kind` (`immune/auth.py`): `immune-token` and `jwt-hs256` are verified locally; `introspect` asks production `auth.path` with the client's `Authorization` and `Cookie` (without `gwsid`) and caches the answer by credential hash for `auth.cache_s` (5 s at most for an anonymous answer); `none` makes every client anonymous | `resolve`, `identify` |
| Trust | `trusted` is `uid <= seed_max_uid`. Anonymous clients and newer uids are untrusted | `identify` |
| Honeytoken | a bearer token that verifies with `SHADOW_APP_SECRET` and not with the production secret | `immune/auth.py`, `Authenticator.from_token` |
| Session key | `uid:<n>` when identified, else `gwsid:<cookie value>`. Never the IP address | `_read` |

The `gwsid` cookie is supplied by the client and is not signed.

Requests the gateway refuses in this step are answered by the gateway, never forwarded and never counted as
production errors.

### 6.2 Classification

`classify` returns a class and a list of reasons. The class is `evidence` if any reason is `honeytoken` or
`canary:*`, else `suspect` if there is any reason, else `clean`. In `enforce` mode a `clean` result may then be
turned into `suspect` by the detection service (reason `waf:<rule id>`, section 6.8).

Path matching. Routes and rules are matched on two readings of the raw path (`gateway/spec.py`,
`path_readings`): decoded once and then split on `/` (how uvicorn and Starlette route), and split first with
each segment decoded afterwards (how servers that route on the raw path behave). A route or a rule applies if
either reading matches; the first reading wins when both match. The readings differ only when the path carries
an encoded slash (`%2F`). `%252F` decodes to the text `%2F` and `%5C` to a backslash: neither is a separator.

| Reason | Condition | Applies off-spec |
|---|---|---|
| `path:encoded_slash` | the two readings route to different operations (or only one of them routes) | needs at least one reading to match an operation |
| `honeytoken` | the credential is a honeytoken | yes |
| `dup_query:<name>` | a query parameter appears more than once | yes |
| `traversal:path` | a path segment equals `..` under any of up to four rounds of percent-decoding, with overlong UTF-8 forms and backslashes folded | yes |
| `traversal:query.<name>` | a query value contains `../`, ends in `/..` or equals `..` under the same decodings (`<name>` is `?` when the key is not `[A-Za-z0-9_-]{1,64}`) | yes |
| `grammar:query.key` | a query key is not `[A-Za-z0-9_-]{1,64}` | no |
| `schema:<where>.<name>:<kind>` | a query, path, declared header or form value violates its schema; `<kind>` is `type`, `enum`, `bounds`, `length` or `pattern` | no |
| `grammar:<where>.<name>` | the value does not match `grammar.SAFE_DEFAULT` (`grammar.PATH_SAFE` for a catch-all path parameter) | no |
| `schema:json:invalid`, `schema:form:invalid` | the body cannot be parsed | no |
| `schema:json.<path>:<kind>`, `grammar:json.<path>`, `grammar:json.key` | a JSON leaf violates its schema, a JSON string is outside `SAFE_DEFAULT`, a JSON key is not `[A-Za-z0-9_-]{1,64}` | no |
| `owner_scoped:anonymous`, `owner_scoped:untrusted` | the operation is `x-owner-scoped` and the client is anonymous, or identified with `uid > seed_max_uid` | no |
| `owner_scoped:mismatch:<param>` | the operation is `x-owner-scoped`, the identity is trusted and not admin, and the manifest attributes the object addressed by path parameter `<param>` to someone else | no |
| `canary:<param>` | a path parameter equals a canary value, the role is not admin and the requester is not its owner | no |
| `enumeration` | more than 8 distinct parameter sets on one owner-scoped route from one session within 30 s (`EnumTracker`). A parameter set is the path parameters; the query parameters marked `x-owner-id` are counted the same way | no |
| `rule:<id>` | an active rule matches (section 6.4) | yes |
| `waf:<rule id>` | added by `gateway/core.py` (`_waf_upgrade`), not by `classify`: the detection service reported an anomaly for a request classified `clean` (section 6.8) | yes |
| `scanner` | the path is in the fixed scanner list and no operation matches it (section 6.3 step 4) | only off-spec |
| `captive` | the session is captive; prefixed to the other reasons, class `captive` | yes |

Ownership lookup for `owner_scoped:mismatch` and canaries (`_owns`): a parameter in `group_routes` is owned by
every member of the addressed group; `user_id` is owned by the uid equal to its value; `<x>_id` is owned by
`ownership["<x>s"][value]`. When the manifest has no entry (another parameter name, or an object created
after the seed) the lookup is undetermined and the request is not flagged.

Not inspected: values marked `x-sensitive`, headers the operation does not declare, cookies. A route missing
from the OpenAPI document is `clean` unless one of the "applies off-spec" reasons fires.

`grammar.SAFE_DEFAULT` is `[A-Za-z0-9 _.,@:+\-]{0,128}`; `grammar.PATH_SAFE` adds `/` and allows 512
characters; a value containing `..` never matches any grammar (`immune_contracts/grammar.py`, `matches`).

### 6.3 Decision in `enforce` mode

`Gateway.handle`. The step numbers are stable: code comments refer to them.

1. **Read** the request (section 6.1).
2. **Session key** (section 6.1).
3. **Captive session.** If the identity is not trusted and the session (or, for an identified client, its
   cookie session) is captive: serve it from its clone in mode `L2` (step 8). Route `shadow_l2`.
4. **Scanner path.** If the path is in `SCANNER_PATHS` or under `/wp-admin/` or `/phpmyadmin/`
   (`gateway/l0.py`, `is_scanner_path`) and no operation of the OpenAPI
   matches: answer with a deterministic decoy generated from a hash of path and session. Route `l0`.
5. **Classify** (section 6.2). With `WAF_URL` set, a request classified `clean` is then checked by the
   detection service (section 6.8), which may make it `suspect`.
6. `clean`: forward to production. Route `prod`.
7. `suspect`: **detonate** (`_detonation`). The gateway takes a free clone, waiting at most 0.3 s, sends the
   request with `x-imm-mode: L1` (and `x-imm-uid`, `x-imm-role` when identified), reads the whole response
   and its verdict. The first matching row applies:

   | Outcome of the detonation | Decision |
   |---|---|
   | verdict `oracle`, trusted identity | deny |
   | verdict `oracle`, any other identity | return the clone's response (route `shadow_l1`) and mark the session captive |
   | reason `traversal:path` present, verdict not `oracle` | deny, whatever the verdict |
   | verdict `clean` | forward the same bytes to production |
   | verdict `inconclusive` | deny if an active rule matched strictly (section 6.4); else forward to production |
   | no clone available, or the clone failed (verdict recorded as `no_clone`) | deny if the request fails closed; else forward to production |

   A request **fails closed** when an active rule matched (strictly or not), or a reason starts with
   `schema:`, `grammar:`, `dup_query:` or `traversal:`. A `waf:` reason does not make a request fail closed.
   When no clone is free the gateway also retires the clone of the oldest clone-bound captive session, so the
   fleet replaces it. `_detonation` returns `prod`, `deny`, `rule_deny` or `shadow_l1`; `rule_deny` is a deny
   decided without an oracle (no clone, or an inconclusive verdict on a strict match). It is recorded with
   route `deny` and counted in the `denied` counter of each rule that matched.
8. **Confirmed attack and captivity** (`gateway/pool.py`).
   - Class `evidence` (honeytoken, canary): a trusted identity is denied. Any other session is marked
     captive, a clone is bound to it now and the request is replayed there in `L2`. Without a clone: deny.
   - A session marked captive after an `L1` detonation holds no clone; the clone returns to the pool. On the
     session's next request the gateway binds a clone to it (retiring the oldest bound one if none is free)
     and uses `L2` from then on.
   - A captive request that cannot get a clone is denied; it never reaches production.
   - A captive session is released after `GW_CAPTIVE_TTL_S` (900 s) without requests; its clone is retired.
   - At most 50000 captive sessions are tracked (`max_sessions`); beyond that the oldest unbound one is
     dropped. There is no per-origin limit.
   - A trusted identity is never captive and is never served synthetic data.
9. **Deny** is `404` with body `{"detail":"Not Found"}`. A handler error is also answered with a deny.

Consequences that follow from the table: a rule is as strong as the oracle behind it, because a rule hit
whose detonation is `clean` goes to production; and an `inconclusive` verdict goes to production unless a rule
matched strictly.

Forwarding (`to_prod`, `to_clone`, `_out_headers`): the request target is sent byte for byte. Hop-by-hop
headers (`connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `trailers`,
`transfer-encoding`, `upgrade`, `host`, `content-length`, `proxy-connection`) are not forwarded, and `gwsid`
is removed from the forwarded `Cookie` header, to production and to clones. From upstream responses the same
headers plus `content-encoding`, `date`, `server` and every `x-imm-*` header are dropped. A refused connection
to production is retried once for any method; a pooled connection the upstream had closed is retried once for
`GET`, `HEAD` and `OPTIONS`. A production timeout (30 s) is answered 504, any other failure 502; both count
as production 5xx. A request that cannot be put on the wire as sent is answered 400 and is not counted. While
a canary is active, `to_prod` sends a share of these requests to the canary release (section 6.9).

### 6.4 Rules

A rule (`contracts/schemas/rule.schema.json`; `gateway/classifier.py`, `Rule`) marks a point confirmed
vulnerable. Its scope is a route, a parameter and a grammar, optionally limited to untrusted identities; it
never refers to an IP address, a fingerprint or a user agent.

| Field | Meaning |
|---|---|
| `id` | unique id; posting an existing id replaces the rule |
| `incident` | incident it belongs to, or `null` |
| `method` | HTTP method; `*` or `ANY` match every method; a `GET` rule also matches `HEAD` |
| `route` | OpenAPI path template, matched on both path readings; it may be a route that is not in the OpenAPI |
| `scope` | `param`, `param_present` or `all` (table below) |
| `param` | `{"in": "query"\|"path"\|"json"\|"form"\|"header", "name": ...}`; for `json` a dotted path. Required unless the scope is `all` |
| `grammar` | full-match regular expression over the decoded value; `null` or absent with a scope other than `all` means `SAFE_DEFAULT` |
| `identity` | optional; the only value is `untrusted`: the rule is skipped for a trusted identity. Absent: the rule applies to every identity, trusted included |
| `ttl_s` | lifetime in seconds, at least 1; `null` or absent: no expiry, the rule lives until it is deleted |
| `created`, `expires_in`, `stats` | set by the gateway. `expires_in` (seconds left, `null` without TTL) and `stats: {hits, oracle, denied}` appear in responses and in `rule.active` |

| Scope | The rule matches when | Strict match |
|---|---|---|
| `all` | any request on the route | always |
| `param` | a value of `param` is outside `grammar` | always |
| `param_present` | the request carries `param`, whatever its value | only when a value is outside `grammar` |

A matching rule adds the reason `rule:<id>`, which forces a detonation and makes the request fail closed
(section 6.3). A strict match also denies the request when the clone's verdict is `inconclusive`; a non-strict
match lets it through to production in that case. The distinction exists because a clone holds synthetic
credentials, so a legitimate login is a 401, hence `inconclusive`, in the clone.

Counters (`stats`, in memory only): `hits` is the number of detonations the rule caused, `oracle` those in
which an oracle fired, `denied` the requests denied without an oracle. They are not updated in observe mode.

A rule ends by TTL when it has one (`rule.expired`, reason `ttl`), by `DELETE` (reason `deleted`) or by a
gateway reset (reason `reset`). Rules survive a gateway restart within the same run
(`<runtime>/stack/gateway-state.json`). The rules the pipeline posts carry no TTL unless `PIPELINE_RULE_TTL_S`
is set (section 9).

### 6.5 Modes

| Mode | Behaviour |
|---|---|
| `enforce` | section 6.3 |
| `observe` | classifies and detonates as `enforce`, but every response comes from production. Nothing is denied, diverted, evicted or captured. `request.classified`, `request.routed` and `oracle.fired` carry `"observe": true`, and `request.routed` carries `would_route`: the route `enforce` would have taken (`prod`, `deny`, `shadow_l1`, `shadow_l2` or `l0`), computed by the same function |
| `passthrough` | classifies for the record and forwards everything to production; no detonation, and no `request.classified` event |

The initial mode comes from `GW_MODE`; `POST /_admin/mode` changes it and the change is persisted. The
detection service (section 6.8) is consulted in `enforce` mode only.

### 6.6 Admin API

Port 8081, header `x-admin-token`. A missing or wrong token, or a gateway started without `ADMIN_TOKEN`, is
answered `403 {"detail":"forbidden"}`.

| Method and path | Request body | Response |
|---|---|---|
| `GET /_admin/health` | | `{"ok", "mode", "upstream": {"addr", "release"}, "pool": {"free", "busy", "captive", "retired", "sessions"}}` |
| `GET /_admin/pool` | | `{"clones": [{"id", "state": "free"\|"busy"\|"captive"\|"retired", "session", "release", "addr", "since"}]}` |
| `PUT /_admin/pool` | `{"clones": [{"id", "addr", "key", "release"}]}`, the full set | same as `GET`; 422 on a malformed body. Clones missing from the set are forgotten and their sessions released |
| `GET /_admin/rules` | | `{"rules": [rule + "expires_in" + "stats"]}` |
| `POST /_admin/rules` | one rule or a list | 201 with the rule or the list; 422 `{"detail": "invalid rule: ..."}` |
| `DELETE /_admin/rules/{id}` | | `{"ok": true, "id"}`; 404 if unknown |
| `GET /_admin/upstream` | | `{"addr", "release"}` |
| `POST /_admin/upstream` | `{"addr": "prod-green:8000", "release": "..."}` | waits up to 30 s for in-flight production requests, ends a running canary, switches, zeroes the statistics; returns the new upstream. 422 without `addr` |
| `GET /_admin/canary` | | `{"canary": <view>}`, `null` when none is running. View: `{"addr", "release", "weight", "since", "canary": {"requests", "5xx", "4xx", "conn_errors"}, "stable": {...}}` |
| `POST /_admin/canary` | `{"addr": "prod-green:8000", "release": "...", "weight": 0.2}` | starts (or replaces) the canary and returns `{"canary": <view>}`; 422 unless `addr` is a non-empty string and `0 < weight <= 1` |
| `DELETE /_admin/canary` | | stops the canary; returns `{"canary": <last view or null>}` |
| `GET /_admin/sessions` | | `{"captive": [{"session", "clone", "since"}]}`; `clone` is `null` until bound |
| `POST /_admin/mode` | `{"mode": "enforce"\|"observe"\|"passthrough"}` | `{"mode"}`; 422 otherwise |
| `GET /_admin/prodlog?rid=<rid>` | | `{"forwarded": bool, "status": int\|null}`, plus `"aftercheck": "oracle"` when the after-check fired; the last 50000 requests are kept |
| `GET /_admin/stats` | | counters since the last upstream switch: `prod_requests`, `prod_5xx`, `prod_conn_errors`, `requests`, `by_class`, `by_route`, `since`, `release`, `addr`, `aftercheck`, plus `pool`, `captive`, `rules` (a count), `mode`, `bus_dropped` and `canary` (the view above, or `null`) |
| `POST /_admin/reset` | | clears captive sessions, rules, a running canary, enumeration counters, the in-memory production log, after-check memory and statistics, and reloads the manifest; the recording file is not truncated; `{"ok": true}` |

### 6.7 Clone ingest

Port 9000, `POST /_clone/evidence` with headers `x-imm-clone` and `x-imm-signature`. The gateway verifies the
signature with the key registered for that clone (403 otherwise; 400 for a body that is not a JSON object),
adds `session` and `uid` of the request it minted that `rid` for, and publishes `oracle.fired`.

### 6.8 Detection service (WAF)

Optional. When the gateway's environment has `WAF_URL`, `Gateway._waf_upgrade` sends each request that
`classify` called `clean`, in `enforce` mode, to `POST <WAF_URL>/eval` (`gateway/waf.py`, `WafClient.check`):

```json
{"method": "GET", "path": "/search", "query": "q=1", "headers": {"host": "..."}, "body_b64": ""}
```

The service (`waf/main.go`, OWASP Core Rule Set on Coraza) answers `{"anomalous": bool, "rule_id", "status",
"msg"}`. On `anomalous: true` the request becomes `suspect` with the reason `waf:<rule_id>` (`waf:crs` when the
id is missing) and is detonated as in section 6.3. The service never causes a deny by itself. Any error,
timeout (1.5 s), non-200 answer or invalid JSON leaves the request `clean`. Captive sessions, scanner paths
and the `observe` and `passthrough` modes do not consult it.

`deploy/compose.yaml` has the service under the Compose profile `waf`. `immune up` enables the profile and sets
`WAF_URL=http://waf:8080` for the gateway only when `IMMUNE_WAF=1` is in its environment (`compose_env`,
`ensure_waf_image` in `immune/__main__.py`); otherwise the stack does not use it. Checked on 2026-11-22: the Compose
configuration, and the image running with the service's restrictions answering `gateway/waf.py`; not a full
stack with the WAF. The ScadaBR lab also starts the service. Reference: `waf/README.md`.

### 6.9 Canary

`Gateway.start_canary`, `to_prod`. While a canary is active, each request bound for production goes to the
canary address with probability `weight` and to the stable upstream otherwise. The side is drawn per request,
not per session. The fleet starts one before the upstream switch of a deploy (section 8).

| Aspect | Behaviour |
|---|---|
| Counters | per side, `{requests, 5xx, 4xx, conn_errors}`. Canary requests are not counted in `prod_requests`, `prod_5xx` or `prod_conn_errors` |
| Refused connection to the canary | counted against the canary (one request, one 5xx, one connection error); the request is sent to the stable upstream and the client gets that answer |
| Recording | a request answered by the canary carries the canary's release id in `release` (section 7) |
| End | `DELETE /_admin/canary` (`canary.done`, reason `aborted`); `POST /_admin/upstream` (reason `promoted` when the new upstream is the canary address, else `superseded`); `POST /_admin/reset` (no event) |
| Persistence | none: a restarted gateway serves the stable upstream only |

## 7. Recording format

`<runtime>/recordings/requests.jsonl`, one JSON line per client request (`gateway/core.py`, `_record`):

```json
{"rid": "...", "ts": 1.0, "session": "uid:3", "uid": 3, "trusted": true, "method": "GET",
 "path": "/api/products", "query": "q=usb", "headers": {"content-type": "..."}, "body_b64": "",
 "class": "clean", "reasons": [], "route": "prod", "verdict": null, "status": 200, "ms": 4.2,
 "release": "t0", "mode": "enforce"}
```

| Field | Values |
|---|---|
| `class` | `clean`, `suspect`, `evidence`, `captive` |
| `route` | `prod`, `shadow_l1`, `shadow_l2`, `l0`, `deny` |
| `verdict` | `clean`, `oracle`, `inconclusive`, `no_clone`, or `null` when there was no detonation |
| `release` | release id of the stable upstream, or of the canary when the canary answered |
| `observe`, `would_route` | present in observe mode |

Redaction: the values of `authorization`, `cookie` and `proxy-authorization`, and every value marked
`x-sensitive` (path and header parameters, query, JSON, URL-encoded and multipart form fields), are replaced by
`<redacted>`.

The after-check appends a second line for a request it found to be an attack:
`{"rid", "ts", "aftercheck": "oracle", "method", "path", "query", "uid", "session"}`.

The file rotates to `requests.jsonl.1` when it reaches `RECORD_MAX_MB` (256); one old generation is kept.

## 8. Fleet API

`fleet/app.py`, `fleet/manager.py`. Bound to `127.0.0.1:<ports.fleet>`. Every route requires the header
`x-admin-token`, compared in constant time; otherwise `401`. The fleet does not start without `ADMIN_TOKEN` in
its own environment. No container has the Docker socket. Three host processes use Docker: the fleet, which is
the only one that creates and removes production and clone containers; the pipeline, which starts runner
containers (`pipeline/runner.py`); and the `immune` CLI (`docker compose`, and the containers of `init` and
`doctor`).

| Method and path | Body | Behaviour |
|---|---|---|
| `POST /reset` | `{"release": "t0", "pool_size": 4}` | removes every container of the run, starts `prod-blue` on the release, creates the pool, registers it with the gateway (`PUT /_admin/pool`), sets the upstream and resets the gateway |
| `POST /deploy` | `{"release": "<id>"}` | blue/green deploy (below) |
| `GET /state` | | `{"prod": {"active", "release"}, "ready", "pool_size", "gateway_ok", "run_id", "clones": [{"id", "name", "addr", "release", "state"}]}`; the generic runtime adds `runtime` and `image` |

`fleet/fuxa.py` (`FuxaFleet`) is not part of this API: it is the container manager of `immune fuxa`.

Errors: `400` for a release id that does not match `[A-Za-z0-9][A-Za-z0-9._-]*`, a release directory that is
missing or incomplete, or a `pool_size` outside 0 to 32; `409` for `/deploy` before any `/reset`; `500` when
`prod-blue` fails its health check in `/reset`.

`POST /reset` returns `{"ok": true, "prod": {"active": "blue", "release"}, "clones": [ids], "gateway_errors": [...]}`.

### Deploy sequence

`Fleet._deploy`:

1. Validate the release directory. The generic runtime builds the image first (and the trace image, with
   `shadow.tracer`).
2. Start the idle colour on the release and wait for its health path (`HEALTH_TIMEOUT_S`, 40 s).
3. Smoke request: one `GET` on the smoke path, from inside the new container. The smoke path is `SMOKE_PATH`
   if set; otherwise the first `GET` of the project's OpenAPI document that has no path parameter, no
   required parameter and no `security`, and is not the health path (`fleet/config.py`, `derive_smoke_path`).
   When there is none the step is skipped and the result says so.
4. Read the 5xx rate of the release being replaced from `GET /_admin/stats`.
5. Canary (`Fleet._canary`): `POST /_admin/canary` with `CANARY_WEIGHT` (0.2), then poll `canary` of
   `GET /_admin/stats` for up to `CANARY_S` (8 s). Verdicts below. A verdict `worse` stops the deploy here.
6. Switch the gateway upstream, which also ends the canary.
7. Watch `GET /_admin/stats` for `DEPLOY_WATCH_S` (20 s). After a canary with verdict `ok` the time the canary
   took is subtracted, with a floor of 2 s.
8. Remove the old colour, replace the free clones that are not on the new release, prune old release
   directories (kept: `t0`, the live one, any still mounted by a container, and the 5 newest).

Canary verdict (`Fleet._canary`, `Fleet._worse`):

| Verdict | Condition | Effect |
|---|---|---|
| `worse` | the canary side has at least `CANARY_MIN_REQUESTS` (20) requests and either at least one 5xx with a 5xx rate above `max(2 x stable rate, stable rate + 0.02)`, or at least five 4xx with a 4xx rate above `max(2 x stable rate, stable rate + 0.10)`. Checked on every poll | `DELETE /_admin/canary`; the new container is removed; `ok: false`, `rolled_back: false` |
| `ok` | the window ended with at least `CANARY_MIN_REQUESTS` canary requests and no `worse` condition | the deploy continues; `traffic_validated` is `true` |
| `skipped` | `CANARY_WEIGHT` or `CANARY_S` is 0; the gateway refused the canary; the gateway no longer reports a canary for this release; or fewer than `CANARY_MIN_REQUESTS` requests reached it (with no production request at all, the wait ends after `min(2, CANARY_S)` seconds) | the deploy continues with the plain switch and the full watch |

Rollback rule (`Fleet._watch`). During the watch the new release is rolled back when all three hold:

- at least `DEPLOY_MIN_REQUESTS` (20) requests reached production since the switch;
- at least one of them was answered 5xx;
- the 5xx rate is above `max(2 x rate of the old release, rate of the old release + 0.02)`.

With fewer requests than the minimum and no canary verdict `ok`, the deploy succeeds with
`traffic_validated: false`. A failed start, health check, smoke request or canary stops the deploy before the
switch; nothing is rolled back because nothing was switched. Neither rule sees responses that are wrong but
carry a 2xx or 3xx status, nor anything after its window.

### Deploy result

| Field | Present | Value |
|---|---|---|
| `ok` | always | `true` when the release is live |
| `rolled_back` | always | `true` only when the upstream was switched and switched back |
| `release`, `active` | always, except on an image build failure | release and colour in production after the call |
| `detail` | always | `deployed`; `deployed; not validated by traffic (<n> request(s) in the <s>s watch, minimum <m>; canary: <detail>)`; `prod_5xx grew after switch; rolled back`; `canary: <reason>; the release never took the full traffic`; `start failed: ...`; `new release failed health check`; `smoke request <path> failed`; `gateway upstream switch failed: ...`; `image build failed: ...` |
| `canary` | when the canary step was reached and the upstream switch did not fail | `{"verdict": "ok"\|"worse"\|"skipped", "detail", "weight", "seconds", "canary": {"requests", "5xx", "4xx", "conn_errors"}, "stable": {...}}`; the two counter objects are empty when the gateway reported none |
| `smoke` | when the watch ran | `GET <path> ok`, or `skipped: no request distinct from the health check <path> (set SMOKE_PATH)` |
| `watch` | when the watch ran | `{"seconds", "requests", "prod_5xx", "min_requests"}` |
| `traffic_validated` | on success | `true` when `watch.requests >= min_requests` or the canary verdict is `ok` |
| `clones_replaced` | on success | number of clones moved to the new release |
| `build_s` | generic runtime | seconds spent in the image step |

The fleet publishes `deploy.started` and `deploy.done`; the gateway publishes `canary.started` and
`canary.done`. The fleet's variables and defaults are in `fleet/README.md`, "Configuration". The reconcile loop
and what it restores after a crash are described in `contracts/product.md` section 11.

## 9. Pipeline

`pipeline/orchestrator.py` (`Pipeline._flow`). The pipeline follows `GET /events/stream` and opens an incident
for each `oracle.fired` event. Incidents are processed one at a time; the others wait in a persisted queue.

Deduplication key (`pipeline/incident.py`, `dedupe_key`): oracle kind, method, route template and parameter.
A second event with the same key increments the incident's hit count. An incident closed `patched` or
`rule_only` is never reopened by a new event, with one exception: one closed `rule_only` with
`outcome_detail: escalated` may reopen after `PIPELINE_REOPEN_COOLDOWN_S` (300 s). One closed `error` may
reopen after the same delay once its retries are spent.

Flow of one incident:

1. Publish `incident.opened`. Class by oracle: `sql` is `sqli`, `file` is `traversal`, `owner` is `idor`,
   anything else is `other`. An `owner` event on a request without an identity sets the incident's `anon`
   flag (`pipeline/incident.py`).
2. **Reproduction.** Build the PoC (`contracts/schemas/poc.schema.json`) from the evidence and run it three
   times in the runner on the release in production, together with its variants. It reproduces when all three
   runs fire the incident's oracle kind with the incident's sink file in the stack; the sink check is skipped
   when the incident has no sink file (generic runtime without a tracer). Publish `poc.ready`. With fewer
   than three of three (zero included: the oracle did fire once, on the live request) the incident is
   **escalated** (`Pipeline.escalate`): the built-in rule of `pipeline/rules.py` is posted, no fix is attempted
   and the incident closes `rule_only` with `outcome_detail: escalated`.
3. **Rule.** `patcher.derive_rule`, validated against `contracts/schemas/rule.schema.json`; if it is invalid or
   targets another route, the built-in rule of `pipeline/rules.py` is used. `POST /_admin/rules`. The rule has
   no TTL unless `PIPELINE_RULE_TTL_S` is set. For an incident with the `anon` flag, a rule of scope `all`
   gets `identity: untrusted` (`pipeline/rules.py`, `finalize`, `default_rule`).
4. **Autopatch policy.** `autopatch: off` closes `rule_only` with detail `autopatch_off`.
5. **Fix loop.** Up to `PIPELINE_MAX_ATTEMPTS` (3) calls to `patcher.propose`, each followed by the five
   gates in order: `policy`, `properties`, `poc`, `tests`, `legit` (`pipeline/gates.py`, `GATES`; reference in
   `docs/validaciones.md`). The detail of a rejecting gate is fed back to the next attempt. Each attempt
   publishes `patch.attempt`, `patch.diff` and one `gate.result` per gate that ran. The pull request is opened
   once `policy` passes (`pr.opened`).
6. **Merge.** With `autopatch: pr`, or when a gate capped autopatch (no `tests.command`, missing legit
   coverage), the pull request stays open and the incident closes `rule_only` with detail `pr_open`. Otherwise
   the pull request is merged (`pr.merged`) and the merged tree becomes `<runtime>/releases/<sha[:12]>/`.
7. **Deploy.** `POST /deploy` on the fleet. A failed or rolled-back deploy reverts the merge and closes
   `rule_only`.
8. **Verification.** The rule is deleted. The PoC and its counted variants must fire no oracle on the
   deployed release in the runner, and the same request, sent through the gateway from a fresh identity, must
   be forwarded to production: the gateway's `GET /_admin/prodlog` must answer `forwarded: true`
   (`pipeline/verify.py`). Publish `verify.result`. If either check fails the rule is posted again and the
   incident closes `rule_only`.
9. Publish `incident.closed`. After a `patched` or `rule_only` close the class audit may run
   (`contracts/product.md` section 8).

Incident outcomes (`incident.closed`, field `outcome`):

| Outcome | Meaning |
|---|---|
| `patched` | the fix is deployed and verified; the rule was removed |
| `rule_only` | a rule was posted and stays active; there is no deployed fix |
| `error` | the flow failed before any rule was posted; nothing contains the incident. It is retried |
| `not_reproducible` | not produced by the current code. The value is still listed in `immune_contracts/events.py` and still read by the reopen check, for state written by earlier versions |

Optional field `outcome_detail`:

| Value | With outcome | Meaning |
|---|---|---|
| `escalated` | `rule_only` | the PoC fired in fewer than three of three replays: rule posted, no fix attempted, no class audit; a person decides |
| `autopatch_off` | `rule_only` | `autopatch: off` |
| `pr_open` | `rule_only` | the pull request is open and was not merged |
| `transient` | `rule_only`, `error` | closed for a reason that may not hold later; retried (`contracts/product.md` section 11) |

`seconds_to_rule` is the time from the first `oracle.fired` to the first time the rule was posted, across
retries. `seconds_to_patch` is the time from the first `oracle.fired` to the end of verification, set only for
`patched`.

Patch source. `patch.attempt` carries `source`: `llm` (the diff was written by the model), `fallback` (a
pre-written diff from `patcher/fallbacks/`) or `unknown` (the generator returned no `source`, or another
value). An unknown source is never reported as `llm` (`pipeline/orchestrator.py`, `patch_source`). The pull
request body and each commit message state the source.

Repository target (`repo.target` in `config.yaml`; `pipeline/repo.py`):

| Target | Behaviour |
|---|---|
| `local` | a git repository at `<runtime>/repo`; pull requests are JSON records inside it. Used by the demo |
| `github` | the `gh` CLI against `repo.github`; verified only against a simulated `gh` |

Branches: `run/<run>/base` (created from the tag `repo.t0_tag`) and `run/<run>/fix-<incident>`. Each gate is
reported as a commit status `immune/<gate>`.

Other flows. For `app.runtime: generic` the pipeline runs the same flow with its jobs on throw-away clone
triples (`pipeline/external.py`, `pipeline/generic.py`; `contracts/interfaces.md` section 3). With `REPRO_URL`
set (the two labs), `pipeline/external.py` replays the PoC against one reserved clone instead of the runner,
posts the built-in rule, and closes `rule_only` unless `EXTERNAL_TARGET` names a target file; then
`pipeline/extfix.py` runs its own patch stage, with the gates `policy`, `build`, `tests`, `poc`, `legit`, a
local branch as pull request and its own blue/green switch without the fleet. Both are described in
`pipeline/README.md`.

Configuration: the variables read by `pipeline/config.py` (`Config.from_env`) and their defaults are listed in
`pipeline/README.md`, "Configuration".

Command line (`pipeline/__main__.py`): `python -m pipeline` runs until stopped; `--once [--idle S]` processes
what is queued and exits; `--replay FILE` enqueues a saved `oracle.fired` event; `--status` prints the
persisted state.

## 10. Event bus

`dashboard/server.py`. One Starlette application serves the bus and the panel.

### 10.1 Envelope

```json
{"type": "<type>", "ts": 1763750000.0, "run": "<run id>", "src": "<component>",
 "rid": "<request id or null>", "incident": "<incident id or null>", "data": {}}
```

The bus adds `seq`, a strictly increasing integer. `immune_contracts/events.py` (`make`) builds the envelope
and rejects a type that is not in `TYPES`.

### 10.2 HTTP API

| Method and path | Auth | Behaviour |
|---|---|---|
| `POST /events` | `x-bus-token` | body: one event or a JSON list. Returns `{"ok": true, "seqs": [...], "next": <last seq>}`. `401` without a valid token, and always when the dashboard has no token configured; `400` for invalid JSON, an unknown `type`, a non-object `data` or a non-numeric `ts`; `413` for a body above `DASH_MAX_BODY_MB` |
| `GET /events?since=<seq>&type=<prefix>&limit=<n>` | none | one page of events with `seq > since`, optionally filtered by type prefix: `{"events": [...], "next": <seq>}`. See pagination below |
| `GET /events/stream?since=<seq>` | none | Server-Sent Events; also honours `Last-Event-ID`. Messages: `id: <seq>` with the event as data; `event: hello` with `{"gen", "seq"}`; `event: reset` after the store was cleared; `event: hb` after 15 seconds without events. `503` above `DASH_MAX_STREAMS` |
| `POST /admin/clear` | `x-bus-token` | empties memory and the store; `seq` keeps counting |
| `GET /health` | none | `{"ok": true, "events": <in memory>, "seq": <last>}` |
| `GET /`, `GET /static/<file>` | none | the panel |

Pagination of `GET /events`. The response is always a page: `limit` events at most, where `limit` defaults to
`DASH_EVENTS_LIMIT` (1000) and is capped at `DASH_EVENTS_LIMIT_MAX` (5000). `next` is the `seq` of the last
event returned, or the bus's last `seq` when the page is empty. A reader repeats the call with
`since=<next>` until a page comes back empty.

Redaction. A reader that sends the bus token gets events as stored. Any other reader, the panel included,
gets a redacted copy unless `DASH_REDACT=0` (`dashboard/server.py`, `redact`):

| Field | Published as |
|---|---|
| values of headers whose name matches `authorization`, `cookie`, `token`, `secret`, `api-key`, `passw`, `session`, `credential` or `signature` | `[redacted]`, keeping an authentication scheme word such as `Bearer` |
| `body_b64`, `pre_state_b64`, oracle `statement` | `[redacted: <n> chars]` |
| values of query parameters with such a name, in `query`, `path`, `url` and `target` fields | `[redacted]` |
| strings starting with `file:///` (pull request URLs of the local repository) | `file:///[redacted]/<last path component>` |
| session keys starting with `gwsid:` | `gwsid:~<12 hex>`, a keyed hash that is stable within one dashboard process |

Not redacted: method, path, other query parameters, `uid:<n>` session keys, stack frames, diffs, gate details,
rule grammars, timings. The JSONL store is never redacted.

Bounds:

| Bound | Default | Behaviour at the limit |
|---|---|---|
| `DASH_MAX_EVENTS` | 50000 in memory | evicts events of earlier runs first, then `request.*` events of the current run, then the oldest |
| `DASH_STORE_MAX_MB` | 256 | the store becomes `events.jsonl.1`; one old generation is kept; `0` disables rotation |
| `DASH_MAX_BODY_MB` | 32 | `413` |

### 10.3 Event types

`immune_contracts/events.py`. `data` fields as published by the code of the stack that `immune up` starts:

| Type | Publisher | `data` |
|---|---|---|
| `request.classified` | gateway | `{class: clean\|suspect\|captive\|evidence, reasons, method, path, session, uid}`; `observe: true` in observe mode. Not published in `passthrough` mode |
| `request.routed` | gateway | `{route: prod\|shadow_l1\|shadow_l2\|l0\|deny, status, verdict, ms}`; in observe mode also `observe: true` and `would_route` |
| `oracle.fired` | gateway | the evidence object (`contracts/schemas/evidence.schema.json`) with `clone`, `session` and `uid` set by the gateway |
| `session.captured` | gateway | `{session, clone, reason}`. `clone` is `null` when the session is marked and the clone id when one is bound. `reason`: `oracle`, `aftercheck`, `bound`, or the first classification reason (`honeytoken`, `canary:<param>`) |
| `session.released` | gateway | `{session, clone, reason: ttl\|evicted\|clone_gone\|reset}` |
| `rule.active` | gateway | the rule object plus `expires_in` and `stats` |
| `rule.expired` | gateway | `{id, reason: ttl\|deleted\|reset}` |
| `upstream.switched` | gateway | `{release, addr}` |
| `canary.started` | gateway | `{release, addr, weight}` |
| `canary.done` | gateway | `{release, reason: promoted\|aborted\|superseded, canary: {requests, 5xx, 4xx, conn_errors}, stable: {...}}` |
| `pool.state` | fleet | `{l1_free, l2_busy, size}`, published when it changes |
| `deploy.started` | fleet | `{release}` |
| `deploy.done` | fleet | `{release, ok, rolled_back, detail, canary}`; `canary` is the canary object of the deploy result (section 8) or `null` |
| `incident.opened` | pipeline | `{incident, vuln_class: sqli\|traversal\|idor\|other, method, route, param, sink: {file, line}, evidence_rid, request: {method, path, query, body_b64}}`; optional `origin: live\|audit` (set by the incident flow of `pipeline/orchestrator.py`) and, for an audit finding, `parent` |
| `poc.ready` | pipeline | `{incident, reproducible, runs, poc}` |
| `patch.attempt` | pipeline | `{incident, attempt, source: llm\|fallback\|unknown}` |
| `patch.diff` | pipeline | `{incident, attempt, diff}` |
| `gate.result` | pipeline | `{incident, attempt, gate, ok, detail}`; `skipped: true` when the gate was skipped. `gate` is `policy`, `properties`, `poc`, `tests` or `legit` in the main flow, and `policy`, `build`, `tests`, `poc` or `legit` in `pipeline/extfix.py` |
| `pr.opened` | pipeline | `{incident, url, branch}` |
| `pr.merged` | pipeline | `{incident, url, sha}` |
| `verify.result` | pipeline | `{incident, exploit_blocked_on_prod}` |
| `incident.closed` | pipeline | `{incident, outcome: patched\|rule_only\|error, seconds_to_rule, seconds_to_patch}`; optional `outcome_detail: escalated\|autopatch_off\|pr_open\|transient` (section 9) |
| `audit.started` | pipeline | `{incident, vuln_class, candidates}` |
| `audit.finding` | pipeline | `{incident, parent, route, param}` |
| `audit.done` | pipeline | `{incident, checked, findings, seconds}` |
| `prod.alert` | `python -m sidecar.prodwatch` (`src: prodwatch`), started by the Grafana lab only | `{container, oracle: file\|proc\|net, detail, candidates, confirmed: [{method, path, query}], note}`. `candidates` is the number of recorded requests around the instant of the system call; `confirmed` lists those whose replay on the clone fired an oracle. An alert never blocks |
| `attack.attempt` | `sim/attacker.py` (`src: sim`), run by hand | `{vuln, ok, saw_real_data}`. `ok`: the response looks like the exploit worked; `saw_real_data`: it carried production values (scored against the production database and container). `dashboard/demo_events.py` also posts invented ones with `run: demo` |

The pipeline rejects, before sending, an event whose `data` keys differ from this table (`pipeline/bus.py`,
`FIELDS` and `OPTIONAL`). `immune_contracts/events.py` lists every type of this section in `TYPES`.

FUXA runtime. `immune fuxa dashboard` (`immune/fuxa_dashboard.py`) serves its own instance of the dashboard,
with no bus token and no store, and feeds it in-process with events of `src: fuxa` and `run: fuxa-v1.2.9`.
Two types exist only there, and it reuses others with different `data`; a consumer must not assume the shapes
of the table above for these events:

| Type | `data` in the FUXA runtime |
|---|---|
| `fuxa.status` | `{active, enforced, protected, persistent, validation, legitimate, coverage, coverage_audit, pending, partial, patch_mode, monitor}` |
| `fuxa.review` | `{}`; the envelope's `incident` names the incident whose candidate passed its checks and waits for `immune fuxa approve` |
| `session.restricted` | `{session, operations, reason, expires}` |
| `session.released` | `{session, reason}` (no `clone`) |
| `request.classified` | `{class, method, path, status, reason}` and optionally `verdict`. `class` is `clean`, `suspect`, `uninspected`, `blocked`, `authorized` or `unavailable`; and `{class: evidence\|simulation, method, path}` when an incident starts |
| `incident.opened` | `{vuln_class, route, method, evidence_rid, sink: {file, line}, fuxa: {synthetic, role, timed}}` |
| `oracle.fired`, `gate.result`, `patch.attempt`, `patch.diff`, `rule.active` | built from the incident records of `fleet/fuxa.py`; `patch.attempt.source` is a fixed text, not `llm` or `fallback` |
| `rule.expired` | `{id, reason: patched}` |
| `deploy.done` | `{release, ok, rolled_back, detail}` |
| `incident.closed` | `{outcome: patched\|rolled_back\|rejected}` |

### 10.4 Delivery

Publishing never blocks a request path. Delivery is at-most-once per attempt and differs per publisher:

| Publisher | Timeout | When the bus does not accept an event |
|---|---|---|
| gateway (`gateway/bus.py`) | 1.0 s, connect 0.3 s; batches of up to 200 | `request.*` events are dropped. Every other event is kept and retried for 120 s (at most 2000 kept), then dropped. A 4xx answer counts as accepted. Drops are counted in `bus_dropped` of `GET /_admin/stats` |
| pipeline (`pipeline/bus.py`, `Publisher`) | 2.0 s | the event stays pending (at most 2000) and is sent again before the next one and on every idle pass; an event the bus answers with a 3xx or 4xx status is dropped (a 5xx answer or a transport error keeps it). Every event is also appended to `<runtime>/pipeline/events.jsonl` |
| fleet (`fleet/manager.py`, `publish`) | 1.0 s | the event is lost; no retry |

A subscriber that reconnects resumes from its last `seq`. The pipeline persists the last `seq` it handled in
`<runtime>/pipeline/state.json`.
