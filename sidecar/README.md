# sidecar/ — language-agnostic shadow observer (P4)

Runs next to an **unmodified** app (any language, its own image) in a shadow clone and gives the same
per-request verdicts as the Python wrapper (`shadow/`, contract `contracts/README.md` §5), observing
from outside the process:

| Oracle | Source | Fires when |
|---|---|---|
| `sql` | Postgres wire-protocol proxy (`pgproxy.py`), or the shadow database's statement log (`sqllog.py`: Postgres, MySQL) | a request input (from `shadow.inputs`) breaks out of a literal in a **successfully executed** statement (`shadow.sqltaint`, imported unchanged); or the statement has a structure outside the learnt baseline (`reason: new_structure`) |
| `file` | strace `openat/openat2/open/creat`; the response body | a **successful** open whose kernel path is outside `allowed_file_roots` and the warm-up allowlist; with `protected_paths`: only an open of a protected path, failed attempts included; a marker planted in a protected file appears in the response |
| `proc` | strace `execve/execveat`, non-thread `clone/clone3/fork/vfork` | any process spawned during the request |
| `net` | strace `connect/sendto/sendmsg` | an attempt to a non-loopback address, any DNS query (port 53), or a unix socket not seen in warm-up |
| `owner` | response body | marker of another owner (same rule as `shadow.core.Engine.owner_events`) |

Evidence `stack` is `[]` unless a source of frames is configured (see *Where in the app's code* below); `detail` is `{statement,input,param,location,reason}`,
`{path,realpath}`, `{path,argv}` / `{syscall,child}`, `{family,address,port,syscall}`, `{marker_owner,requester}`.

One sidecar, three placements (`mode`), and the pieces around it:

| | |
|---|---|
| `mode: attach` | sidecar container shares the app's PID and network namespaces (fleet clones, pipeline judge) |
| `mode: launch` | sidecar starts the app as a traced child, one container |
| `mode: docker` | sidecar runs outside (host); a tracer container (`immune-strace:1`, no network, `SYS_PTRACE`+`KILL` only) joins `container`'s PID namespace. Nothing is added to the app's container; it re-attaches and warms up again when the container is replaced, failing closed meanwhile. Used by `labs/grafana-cve-2021-43798` |
| `python -m sidecar.learn` | replays the gateway's clean recordings in learn mode (signed with the clone key) to teach the sql structure baseline |
| `python -m sidecar.prodwatch` | the same file/proc/net rules, from the same config file, on **production** containers with eBPF, alert only (`prod.alert`); candidates are replayed on the clone |

Added rules (all optional, config keys in `config.py`):
- `protected_paths` (globs) switches the `file` rule from "outside the allowed roots" to "a protected path was
  opened or attempted", for apps that legitimately read all over the disk. Paths of file markers are protected.
- Markers file: `{marker: uid}` entries feed `owner`; `{marker: {"path": …}}` entries are secrets planted in that
  file: seen in a response → `file` event (`observed: response`, or `response+syscall` when the open was seen too).
- `exec_allow` / `net_allow`: globs that never fire. `learn_background`: what the app does with no request in
  flight (and none finished in the last second) stops firing.
- `sql_log: {cmd, dialect}`: statements from the database log instead of the proxy. The log reports statements
  that failed (`STATEMENT:`), and with this source those are checked too (error-based injection fails on purpose).
- Without string constants of the app (no `source_dirs`, e.g. docker mode) or with MySQL, a taint match on a single
  token is dropped: it cannot be told from an identifier the app wrote (`?sort=name` in `ORDER BY name`).
- Structure rule: statements whose fingerprint is not in the baseline fire once a request has been learnt
  (`sql_baseline` persists it). Covers input that never appears verbatim (base64, second order).

## Where in the app's code (evidence `stack`)

The sidecar sees the app from outside, so by default evidence carries no frames. Three optional sources fill the
evidence `stack` (`[{file, line, func}]`, outermost first, the innermost app frame last = the incident's sink,
`pipeline/incident.py`); none of them can change a verdict, a failure just leaves a shorter or empty stack:

| Source | Apps | How | Config |
|---|---|---|---|
| `native_stack` (`nativestack.py`) | compiled: C, C++, Rust, Go with symbols | `strace -k` prints the native call stack of every traced syscall (`file`/`proc`/`net` events, and the open behind a response marker); frames of libc, the loader and interpreters/VMs are dropped; `addr2line` gives `file:line` when the binary has debug info (`-g`), otherwise the frame keeps its function name. strace reports the ELF *file offset*, so it is mapped through the binary's `PT_LOAD` segments first (PIE: identical; non-PIE and static: `p_vaddr - p_offset`) | `native_stack: {frame_limit, include, exclude, path_map, addr2line}` |
| servlet entry point (`servlets.py`) | Java servlets on Tomcat | static, not a runtime stack: `WEB-INF/web.xml` says which servlet class serves the URL (exact, longest `/*` prefix, `*.ext`, default, Servlet spec 12.1) and the compiled class's `SourceFile` + `LineNumberTable` give the file and the first line of the HTTP entry method (`doGet`/`doPost`/...). A servlet that is not in `WEB-INF/classes` (a library's) gives no frame | `HTTPDS_WEB_XML`, `HTTPDS_CLASSES`, `HTTPDS_CONTEXT`, `HTTPDS_SRC_ROOT` (`sidecar/httpds`, the ScadaBR lab) |
| `tracer` (`phptrace.py`) | PHP | Xdebug function traces of a shadow-only image | `tracer: {kind: php-xdebug, dir}` |

`path_map` turns the build path DWARF recorded (`/src/app.c`) into the repo path the patcher edits
(`sidecar/examples/c/app.c`). The image needs `addr2line` (`binutils`, in `deploy/Dockerfile.sidecar`).

Limits, measured: `strace -k` unwinds **dynamically** linked glibc binaries fully, but loses the frames of a **static**
glibc (the demo `examples/c` built `-static` yields a single `__internal_syscall_cancel` frame, which is dropped, so
`stack` stays `[]`: build the shadow image dynamically, `DYNAMIC=1 sidecar/examples/c/build.sh`). In `mode: docker`
the sidecar cannot read the app's binaries, so frames keep function names but have no line. A stripped binary has no
function names either. `strace -k` adds the cost of unwinding to every traced syscall. A JVM has no native frames
worth reading: the servlet entry point names the file the handler lives in, not the line of the sink inside it.

## How it works

```
gateway ──HTTP :8000──► sidecar (immune-sidecar:1)          app container (its own image, unmodified)
                        ├─ wire protocol (lock, buffer,      ┌──────────────────────────────────┐
                        │  verdict, signed evidence)  ──────►│ app on 127.0.0.1:3000             │
                        ├─ strace -f -y -p <app pids> ◄──────│ (shared PID + network namespace)  │
                        └─ pg proxy 127.0.0.1:5432 ◄─────────│ DATABASE_URL=…@127.0.0.1:5432/clone│
                               │                             └──────────────────────────────────┘
                               └──► per-clone Postgres: database "clone" = CREATE DATABASE … TEMPLATE seed
```

Per request (one at a time, under a lock): strip `x-imm-*` → identity hook (`x-imm-uid` → `ensure_user` on the
clone DB + app credentials) → open the observation window → forward to the app on loopback (own minimal
HTTP/1.1 client, raw bytes, `Connection: close`) and buffer the whole response → keep the window open
`grace_ms` → oracles → verdict (`oracle` / `inconclusive` for 401, 404, ≥ 500 / `clean`) → signed evidence
push (2 s timeout, failures only logged) **before** the response is released → response with
`x-imm-verdict`/`x-imm-events` → L1: recreate the clone database.

- **Attach** (default): the sidecar shares the app container's PID and network namespaces and attaches to every
  process of the app's mount namespace (`/proc/*/ns/mnt` = that of PID 1), so its own processes (uvicorn, proxy,
  evidence push) are never traced. Paths come from strace `-y`: for a successful open the return value is
  decorated with the kernel's path of the new fd (resolved in the app's namespace, symlinks and `..` already
  resolved); otherwise the `AT_FDCWD</cwd>`/dirfd decoration or `/proc/<pid>/cwd` is joined and normalised.
- **Launch** (`mode: launch`): the sidecar starts `command` as a traced child (`strace -f --seccomp-bpf --`),
  for when app and sidecar share one container (contracts/product.md §6). Needs no capability at all.
- **Warm-up**: after attaching, `health`, `warmup_paths` and a 404 are requested `warmup_rounds` times with the
  window in *learning* mode; every file (and non-DNS net destination) seen is allowlisted. Opens made before the
  attach (startup) are not seen at all.
- **SQL constants** (taint rule 3, e.g. input `notes` inside `"… FROM notes"`): string literals scraped from
  `source_dirs` (read through `/proc/<pid>/root`) plus printable strings of the app's executables
  (`/proc/<pid>/exe`, ≤ `scan_executable_max_mb`; printf specifiers split like template interpolation). The node
  binary itself (≈ 120 MB) is skipped by the size cap; the static C demo's SQL text comes from its `.rodata`.
- **pg proxy**: forwards bytes unchanged; answers `SSLRequest`/`GSSENCRequest` with `N` itself; authentication
  passes through. Statement text = `Q` string or `P` (Parse) text; `B` (Bind) values are never recorded, so bound
  parameters can never fire. A `Q` counts as executed iff ≥ 1 `CommandComplete`/`EmptyQueryResponse` precedes its
  `ReadyForQuery` (Postgres parses the whole multi-statement string first, so a syntax error means nothing ran);
  an `Execute` iff `CommandComplete`/`EmptyQueryResponse`/`PortalSuspended` answers it, and an `ErrorResponse` fails
  it and every later `Execute` up to `Sync`. The startup phase has its own `ReadyForQuery` (handled: a client
  that pipelines a query before auth completes is attributed correctly — a bug the unit test caught).
- **Reset (L1)**: the proxy ends every proxied session itself (sends `Terminate` upstream, closes the app side),
  the sidecar waits (≤ 500 ms, 2 ms polls) until `pg_stat_activity` shows none, then
  `DROP DATABASE clone WITH (FORCE)` + `CREATE DATABASE clone TEMPLATE seed`. New app connections wait in the
  proxy until the database exists again. The app's pool must tolerate its idle connections being closed
  (node-pg: `pool.on("error", …)`); the first query after a reset pays for a new connection (≈ 20 ms with SCRAM).
- **Fail closed**: if strace is gone, every request gets `503` + `inconclusive` (never a false `clean`).

## Running

Exact lines used by the tests (`sidecar/tests/dockerenv.py`), Node demo:

```
docker network create --internal p4-net
docker run -d --name p4-pg  --network p4-net -e POSTGRES_PASSWORD=pw postgres:16-alpine \
       -c fsync=off -c synchronous_commit=off -c full_page_writes=off
#   seed: CREATE ROLE app LOGIN PASSWORD 'apppw'; CREATE DATABASE seed OWNER app; then sidecar/examples/node/seed.sql in "seed"
docker run -d --name p4-app --network p4-net --read-only -v $REPO/sidecar/examples/node:/app:ro -w /app \
       -e DATABASE_URL=postgres://app:apppw@127.0.0.1:5432/clone -e APP_SECRET=shadowsecret \
       -e APP_STATIC=/app/static -e PORT=3000 node:22-alpine node /app/server.js
docker run -d --name p4-sc --network container:p4-app --pid container:p4-app --cap-add SYS_PTRACE \
       -v $REPO:/opt/immune:ro -v $CFG_DIR:/cfg:ro -e PYTHONPATH=/opt/immune \
       -e APP_SECRET=shadowsecret -e CLONE_ID=c1 -e CLONE_KEY=k1 -e COLLECTOR_URL=http://p4-col:9000 -e RELEASE=t0 \
       -e MARKERS_PATH=/opt/immune/sidecar/examples/node/markers.json \
       immune-sidecar:1 python -m sidecar --config /cfg/sidecar.json
```

`/cfg/sidecar.json`:

```json
{"listen_port": 8000, "app_port": 3000, "health": "/health",
 "allowed_file_roots": ["/app/static"], "source_dirs": ["/app"], "warmup_paths": ["/"],
 "profile": "/opt/immune/sidecar/examples/node/profile.py",
 "postgres": {"listen": "127.0.0.1:5432", "upstream": "p4-pg:5432",
              "admin_url": "postgres://postgres:pw@p4-pg:5432/postgres", "database": "clone", "template": "seed"}}
```

Launch mode, no capabilities (test `test_launch_mode_without_capabilities`):

```
docker run -d --name p4-launch --network p4-lnet --cap-drop ALL --read-only -v $REPO:/opt/immune:ro \
       -v $CFG_DIR:/cfg:ro -e PYTHONPATH=/opt/immune immune-sidecar:1 python -m sidecar --config /cfg/sidecar.json
#   config: {"mode": "launch", "command": ["python3", "/opt/immune/sidecar/examples/pyhttp/app.py"], ...}
```

All config keys: docstring of `config.py` (YAML or JSON; a product `config.yaml` with `app:` + `sidecar:` is
accepted too). Identity: `profile` (module or `.py` path) with `mint_token` / `identity_headers` / `ensure_user(conn, uid, role)`
(`conn.execute(sql, params)` with `$n` placeholders, on the clone DB, outside the observation window) / `identify` /
`load_markers` / `public_paths`; or `identity_command` (env `IMM_UID`, `IMM_ROLE`; stdout `Header: value` lines or a
bare token); default: client headers untouched. Without `identify`, the requester of a request without `x-imm-uid`
is taken from an immune-token bearer verified with `APP_SECRET` if that env is set, else anonymous.

## Demo apps (`examples/`)

- `node/` — plain `http` + `pg@8.13.1`. `npm install` works from this host, so `node_modules/` (13 packages,
  900 KB) is **vendored** (installed with `node:22-alpine`, `npm install --omit=dev`; `package-lock.json` included).
  Routes: `/health`, `/search` (concatenated, simple query), `/safe-search` (`$1`, extended protocol), `/download`
  (`path.join`, no containment), `/safe-download`, `/notes/:id` (no owner check), `/safe-notes/:id`, `POST /notes`,
  plus `/lookup` (shell injection → `proc`), `/fetch` (SSRF → `net`), `/deferred` (opens a file *after*
  responding, for the grace-period test). Auth: immune-token (HMAC, `APP_SECRET`).
- `c/` — the compiled-language demo: no Go/Rust/.NET/Java toolchain image is present, but `immune-cbuild:1` has
  gcc 14, so this is C, **statically linked** (`build.sh` compiles it at test time; no binary is committed), with its
  own minimal Postgres client (simple + extended protocol, trust auth only — the test adds a `trust` line for
  role `capp`). Same routes (no POST); identity from an `x-user` header filled by `identity_command`.
  It runs from `node:22-alpine` only because that image is present; any image works for a static binary.
- `pyhttp/` — stdlib Python app used only for the launch-mode test (it has to live in the sidecar's image).

No image was built or pulled.

## Measured (this host: arm64, Docker 29, no KVM)

`python -m sidecar.tests.bench 200 30` (Node demo, L2 so no reset between requests, ms, median/p95).
`app` = time until the app's full response as seen by the sidecar (where ptrace cost lands);
`client` = end-to-end, includes the 30 ms grace period.

| route | app, no tracer | app, traced | client, no tracer | client, traced |
|---|---|---|---|---|
| `/health` | 0.90 / 1.30 | 1.10 / 1.60 | 32.77 / 34.17 | 33.00 / 34.48 |
| `/download` (1 open) | 1.50 / 3.40 | 2.00 / 3.50 | 33.67 / 36.67 | 33.89 / 35.52 |
| `/safe-search` (pg) | 1.80 / 2.50 | 2.40 / 4.60 | 33.77 / 34.83 | 34.42 / 37.18 |
| `/lookup` (fork+exec sh) | 3.10 / 3.90 | 6.20 / 8.20 | 35.00 / 36.10 | 42.22 / 45.09 |

- Tracer overhead: +0.2 to +0.6 ms on ordinary requests, ≈ 2× on process spawning (every syscall of the new
  process stops: attach mode cannot use `--seccomp-bpf`, which only applies to processes strace starts).
- Sidecar overhead without the tracer ≈ 1–2 ms plus the grace period.
- **L1 reset** (terminate sessions + DROP + CREATE … TEMPLATE, tiny seed): median **29 ms** (p95 33–58 ms) with
  `fsync=off synchronous_commit=off full_page_writes=off` on the disposable clone Postgres; **66–68 ms** median
  (p95 ≈ 80 ms) with a durable Postgres. A full L1 request including the reset wait: ≈ 84 ms (≈ 120 ms durable).
  Measured alternatives: `DROP … WITH (FORCE)` on live sessions alone: ≈ 108 ms (Postgres polls exiting backends
  in 100 ms sleeps); `pg_terminate_backend(pid, timeout)` first: ≈ 200 ms for two sessions; `STRATEGY FILE_COPY`:
  slower than the default `WAL_LOG` (30 vs 27 ms with fsync off, 175 vs 60 ms durable).
- **Grace period (30 ms default, `grace_ms` / env `SIDECAR_GRACE_MS`)**: strace stops the tracee at syscall exit and
  writes the line before resuming it, so anything the app did *before* writing its response is already in the
  pipe when the response arrives; measured latest arrival relative to the end of the response over 205 requests
  per route: **+0.13 ms** (`/download`), −1.96 ms (`/lookup`). The grace therefore exists for work the app defers
  past its response (unawaited promises, `setImmediate`, short timers, log flushes): `test_grace_period_…` shows a
  read 5 ms after the response is caught, one 300 ms after is not (and is not misattributed to the next request).
  30 ms covers event-loop deferrals with a wide margin and costs a flat 30 ms only on detonated (suspect) requests;
  raise it for apps with known delayed side effects.

## Tests

```
.venv/bin/pytest sidecar/tests -q          # unit + integration (Docker; ~25 s). test_policy_and_sql.py and
                                           # test_prodwatch.py cover the rules above; docker mode end to end: the Grafana lab
.venv/bin/python -m sidecar.tests.bench 200 30 [durable]
```

Unit: strace parser (`[pid N]` and `-o` prefixes, unfinished/resumed per pid, orphan resumed, relative paths,
`AT_FDCWD</dir>`, dirfd, escapes/commas, `(deleted)`, failed opens/execs ignored, threads vs forks, inet/inet6/unix,
sendto with/without address), observer windows/allowlist/net rules, pg protocol (simple/extended, errors,
multi-statement, batch failure until Sync, portal suspended, 200 KB messages fed byte by byte and in 4 KB pieces,
startup/SSL, a real proxy against a fake upstream checking byte-identical forwarding), constants extraction.
Integration (containers `p4-*` on a private `--internal` network, removed afterwards): every case of
`acceptance/wp2_shadow/test_shadow.py` that applies, against the Node app, plus `proc`/`net`, grace period,
fail-closed, the C app, and launch mode.

## Limits

Confirmed (observed in tests or experiments here):
- Cross-container attach works with exactly `--pid container:<app> --cap-add SYS_PTRACE` on the sidecar
  (ptrace_scope=1 is satisfied by CAP_SYS_PTRACE; Docker's default seccomp and AppArmor allow it).
- Statically linked binaries are observed fine (C demo): only syscalls matter, not libc.
- `detail.path` is the syscall argument as the app passed it, e.g. Node's `path.join` already normalised
  `../../etc/hostname` to `/etc/hostname`; `realpath` is the kernel's.
- Without app string constants, an input equal to an identifier in a statement fires (`/notes/1` → `notes` in
  `FROM notes` fired for the C app until executable strings were added). Apps whose SQL text is assembled at
  runtime or compressed in the binary, or huge executables above the cap, have no constants.
- Effects deferred beyond `grace_ms` are not attributed (by design; see the 300 ms case).
- If strace dies the sidecar answers 503/`inconclusive`; the app keeps running untraced.
- Attach mode stops the tracee on every syscall (no seccomp-bpf for attached processes): ~2× on spawn-heavy work.
- `pre_state_b64` is `null`: there is no SQLite snapshot for Postgres (see CONTRACT_GAP).

Reasoned, not tested:
- In-process databases (SQLite, H2, embedded KV) produce no SQL oracle; their file is opened at startup
  (before attach or during warm-up), so they are invisible. Only Postgres has a proxy; MySQL goes through `sql_log`.
- Docker mode traces PID 1 and the children it starts after the attach; processes already running besides PID 1
  are not traced. The tracer's lines cross a docker pipe, so use a larger `grace_ms` (the lab uses 100).
- The structure baseline is global, not per route. `sql_log` was run against a real Postgres 16 (time-based,
  error-based, base64-wrapped input, forged learn request); the MySQL parser only has unit tests after the unification.
- Memory-only effects (caches, globals, in-process privilege changes) are invisible; only `owner` (response body)
  sees data leaks that touch no syscall/SQL.
- io_uring opens/connects bypass the traced syscalls (Docker's default seccomp profile blocks `io_uring_setup`, so
  this matters only for containers run with a custom profile). `open_by_handle_at` (needs CAP_DAC_READ_SEARCH) is not
  traced; `mmap` of an already-open fd is not an open; `stat`/`readlink`/`unlink`/`rename` are not traced (no `file`
  oracle for existence probes, deletes or writes through an fd opened during warm-up).
- Background work of the app (timers, job queues) that happens during a request window is attributed to that
  request: possible false `file`/`proc`/`net` events, and statements (harmless unless they contain request inputs).
- Apps that resolve hostnames per request fire `net` (DNS); apps requiring TLS to Postgres (`sslmode=require`)
  cannot connect, because the proxy refuses SSL; apps that open their own direct connection to Postgres bypass the
  proxy (no SQL oracle) and are only cut by `WITH (FORCE)` at reset.
- Apps that refuse to run traced (anti-debug checks on `TracerPid`) or ptrace themselves cannot be observed.
- In attach mode the app listens in the shared network namespace: if it binds `0.0.0.0` the gateway could reach it
  bypassing the sidecar; bind it to loopback (the demos do).
- Launch mode with an interpreted app: modules imported lazily on a request path not covered by warm-up fire
  `file` (same as the Python wrapper's warm-up limit).
- Only one request at a time is judged; a second sidecar per app is not supported.

## CONTRACT_GAP

- product.md §6 says the clone container's entrypoint is the sidecar, starting the app as a traced child. That
  needs Python and strace *inside the app's image*; with the app's own unmodified image this is only possible as a
  second container sharing PID/network namespaces (attach mode, needs `CAP_SYS_PTRACE` on the sidecar, which
  contradicts the clone rule `--cap-drop ALL` in README §8). Both modes are implemented; fleet must pick one.
- Evidence `pre_state_b64` is defined as SQLite bytes; there is no Postgres equivalent (`null` today).
- The profile's `ensure_user(conn, uid, role)` is specified with a sqlite3 connection; here `conn.execute(sql, params)`
  uses Postgres `$n` placeholders.
- Per-clone Postgres: who starts it, how the `seed` template is produced (product.md §4 only covers SQLite), and on
  which network (clones may reach only the gateway; the clone's Postgres must be reachable from the sidecar).
- Requester identity for requests without `x-imm-uid` under `auth.kind` jwt-hs256 / introspect: the sidecar needs
  the same auth facts as the gateway (today: `profile.identify`, or an immune-token with `APP_SECRET`).
