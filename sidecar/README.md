# sidecar

## Purpose

The sidecar provides the oracles for an application that cannot be instrumented in process: any language, run
unmodified from its own image (`app.runtime: generic`). It sits in front of the app of a shadow clone,
observes it from outside (system calls through `strace`, SQL through a PostgreSQL or MySQL wire proxy or the
database's statement log, the response body) and gives the gateway the same per-request verdict as the
in-process wrapper in [`shadow/`](../shadow/README.md).

The package holds three more entry points that reuse its rules: `python -m sidecar.learn` (teaches the SQL
structure baseline), `python -m sidecar.prodwatch` (the system-call rules on production containers, alert
only) and `python -m sidecar.httpds` (a single-purpose proxy for the ScadaBR lab).

## How it runs

```
python -m sidecar --config /cfg/sidecar.json
```

One asyncio process (uvicorn). Where it runs depends on `mode`:

| `mode` | Placement | Used by |
|---|---|---|
| `attach` (default) | Container of image `immune-sidecar:1` (`deploy/Dockerfile.sidecar`) sharing the app container's network and PID namespaces, with `SYS_PTRACE` as its only added capability | fleet clones `<prefix>-clone-<n>-obs` (`fleet/generic.py`), the pipeline's validation clones (`pipeline/generic.py`) |
| `launch` | The sidecar starts the app command as a traced child, both in one container | `sidecar/tests/test_integration.py` (`test_launch_mode_without_capabilities`) |
| `docker` | The sidecar is a host process; it starts a tracer container (`tracer_image`, default `immune-strace:1`, `deploy/Dockerfile.strace`) that joins the PID namespace of `container`. Nothing is added to the app's container | `labs/grafana-cve-2021-43798` |

```mermaid
flowchart LR
  GW[gateway] -->|HTTP :8000, x-imm-* headers| SC
  subgraph ns[shared network and PID namespaces, attach mode]
    SC[sidecar] -->|HTTP on loopback| APP[app, unmodified image]
    SC -. strace -f -p .-> APP
    APP -->|database protocol on loopback| PX[SQL proxy, inside the sidecar]
  end
  PX --> DB[(clone database)]
  SC -->|signed evidence| GW
```

Ports: the wire protocol on `listen_port` (8000), the app on `app_host:app_port`, the SQL proxy on
`postgres.listen` (127.0.0.1:5432) or `mysql.listen` (127.0.0.1:3306). The wire protocol (headers, verdicts,
evidence) is specified in [`contracts/README.md`](../contracts/README.md) section 5.

Command-line flags (`main` in `server.py`): `--config` (default `$SIDECAR_CONFIG`), `--host`, `--port`,
`--app-port`, `--mode attach|launch` (`docker` can only be set in the config file), `--no-trace` (no tracer:
overhead measurement only, the `file`, `proc` and `net` oracles are off), `--log-level` (default
`$SIDECAR_LOG_LEVEL`, else `info`), and after `--` the app command for launch mode.

Other entry points:

| Command | Arguments | Role |
|---|---|---|
| `python -m sidecar.learn` | `--sidecar URL --recordings FILE`; env `CLONE_KEY` | Replays the gateway's clean recordings through a sidecar in learn mode |
| `python -m sidecar.prodwatch` | environment only (see "Production watcher") | System-call rules on production containers through eBPF; publishes `prod.alert` |
| `python -m sidecar.httpds` | `--host` (0.0.0.0), `--port` (8000); environment (see "ScadaBR proxy") | Authorization oracle in front of a shadow ScadaBR |

## Layout

| File | Role |
|---|---|
| `server.py` | `Sidecar`: start-up, warm-up, one request end to end, verdict, evidence push, L1 database reset; ASGI front end; CLI |
| `tracer.py` | Starts `strace` (attach, launch or docker mode), reads its output on a thread, finds the app's processes |
| `strace.py` | Parser of `strace` output and classification of each call into an observation |
| `observer.py` | Request window, warm-up allowlists, `file`/`proc`/`net`/`owner` oracle rules, file markers |
| `pgproxy.py` | PostgreSQL wire proxy and `StatementTracker` (which statements executed) |
| `pgclient.py` | Minimal asyncio Postgres client for the sidecar's own work (database reset, `ensure_user`) |
| `mysqlproxy.py` | MySQL / MariaDB wire proxy, its `StatementTracker`, and `written_tables` (which tables a statement writes) |
| `mysqlclient.py` | Minimal asyncio MySQL client (`mysql_native_password`) for the reset and `ensure_user` |
| `sqllog.py` | Statements from the database's own log (`LogFollower`, `LogParser`), statement `fingerprint`, `Baseline` and the `new_structure` rule |
| `learn.py` | `python -m sidecar.learn` and the learn-mode signature |
| `phptrace.py` | Reads Xdebug function traces of a PHP clone and fills the `stack` of oracle events |
| `prodwatch.py` | `python -m sidecar.prodwatch` |
| `httpds/` | `python -m sidecar.httpds` |
| `constants.py` | String literals of the app's source and executables, for the SQL taint check |
| `identity.py` | Identity translation, markers and public paths from a profile or a command |
| `http1.py` | Minimal HTTP/1.1 client to the app (raw response bytes, `Connection: close`) |
| `config.py` | Config file loading |
| `examples/` | Fixture apps for the tests: `node/` (Node `http` + `pg`), `c/` (statically linked C), `pyhttp/` (stdlib Python, launch mode) |
| `tests/` | Unit and Docker integration tests; `tests/bench.py` is a measurement script, not a test |

## Configuration

A JSON or YAML file (`sidecar/config.py`). A product config with an `app:` section is also accepted:
`app.port`, `app.health`, `app.allowed_file_roots`, `app.command`, `app.source_dirs` and `shadow.profile` map
to the keys below, and its `sidecar:` section supplies the rest.

| Key | Default | Meaning |
|---|---|---|
| `listen_host`, `listen_port` | `0.0.0.0`, 8000 | Where the sidecar serves the wire protocol |
| `app_host`, `app_port` | `127.0.0.1`, 3000 | The app |
| `health` | `/health` | Health path, used for readiness and warm-up |
| `mode` | `attach` | `attach`, `launch` or `docker` |
| `command` | `[]` | Launch mode: the app command |
| `target_pid` | none | Attach mode: anchor process (default PID 1 of the shared namespace) |
| `container` | empty | Docker mode: the app container (env `SIDECAR_CONTAINER` overrides) |
| `tracer_image`, `tracer_label` | `immune-strace:1`, empty | Docker mode: image and optional label of the tracer container |
| `allowed_file_roots` | `[]` | Paths, as the app sees them, that the app may open |
| `protected_paths` | `[]` | Globs. When non-empty, or when the markers file holds file markers, the `file` rule changes to "a protected path was opened or attempted" |
| `exec_allow` | `[]` | Globs of program paths that never fire `proc` |
| `net_allow` | `[]` | Globs of `address:port` that never fire `net` |
| `learn_background` | `false` | Remember what the app does with no request in flight and stop firing on it |
| `prod_ignore` | `[]` | Protected paths that production opens in normal operation; read by `sidecar.prodwatch` only |
| `source_dirs` | `[]` | App source directories scanned for string literals |
| `scan_executable_max_mb` | 32 | Size limit for scanning the app's executables for strings |
| `openapi` | none | Path of the app's OpenAPI; literal segments of a matched route are then not request inputs |
| `warmup_paths` | `[]` | Extra benign GETs at start-up |
| `warmup_rounds` | 2 | How many times the warm-up requests are sent |
| `grace_ms` | 30 | How long observations still count after the app's response |
| `request_timeout_s` | 30 | Timeout of the request to the app |
| `profile` | none | Python module name or `.py` path with identity hooks |
| `identity_command` | none | Shell command that prints the app credentials |
| `public_paths` | `[]` | Path prefixes with the relaxed owner rule (a profile's `public_paths()` wins) |
| `markers_path` | `$MARKERS_PATH` | JSON holding owner markers `{marker: owner uid}` and file markers `{marker: {"path": file}}` |
| `postgres.listen` | `127.0.0.1:5432` | Proxy address; the app's database URL points here |
| `postgres.upstream` | required in the section | The clone's Postgres |
| `postgres.admin_url` | empty | Superuser URL used to reset the database and run `ensure_user` |
| `postgres.database`, `postgres.template` | `clone`, `seed` | Database the app uses and the template it is recreated from |
| `mysql.listen` | `127.0.0.1:3306` | MySQL / MariaDB proxy address; used when there is no `postgres` section |
| `mysql.upstream` | required in the section | The clone's MySQL / MariaDB |
| `mysql.admin_url` | empty | `mysql://user:password@host:port/` used for the reset and `ensure_user` |
| `mysql.database`, `mysql.template` | `clone`, `seed` | Database the app uses and the database it is rebuilt from |
| `sql_log.cmd`, `sql_log.dialect` | none, `postgres` | Command whose output is the database's statement log, and `postgres` or `mysql`. Env `SQL_LOG_CMD`, `SQL_DIALECT` override |
| `sql_baseline` | none | JSON file where the learnt statement structures persist (env `SQL_BASELINE` overrides); without it the baseline lives in memory |
| `tracer.kind`, `tracer.dir`, `tracer.exclude` | `php-xdebug`, `/tmp/immune-trace`, `/vendor/` and two ADOdb paths | In-process call traces for evidence stacks (`phptrace.py`) |

Environment: `CLONE_ID`, `CLONE_KEY`, `COLLECTOR_URL`, `RELEASE` (evidence fields and where to push it),
`MARKERS_PATH`, `SIDECAR_GRACE_MS` (overrides `grace_ms`), `SIDECAR_CONTAINER`, `SQL_LOG_CMD`, `SQL_DIALECT`,
`SQL_BASELINE`, `SIDECAR_CONFIG`, `SIDECAR_LOG_LEVEL`, `SIDECAR_JUDGE=1` (validation clones of the pipeline
only: every response also carries `x-imm-trace`, a base64 JSON with the events, executed statements and their
bound parameters, failed statements, opened files and marker owners). The whole environment is passed to the
profile hooks as `env`.

## Behaviour

### Oracles at a glance

| Oracle | Source | Fires when |
|---|---|---|
| `sql` | Wire proxy (`pgproxy.py`, `mysqlproxy.py`) or statement log (`sqllog.py`) | A request input breaks out of a literal in a statement (`shadow/sqltaint.py`); or the statement's structure is outside the learnt baseline (`reason: new_structure`) |
| `file` | `strace` on `openat`, `openat2`, `open`, `creat`; the response body | Default rule: a successful open outside `allowed_file_roots` and the warm-up allowlist. Protected rule: an open of a protected path, failed attempts included. A file marker appears in the response |
| `proc` | `strace` on `execve`, `execveat`, non-thread `clone`, `clone3`, `fork`, `vfork` | Any process started during the request, except programs matching `exec_allow` |
| `net` | `strace` on `connect`, `sendto`, `sendmsg` | An attempt to a non-loopback address not seen in warm-up, any destination on port 53, a unix socket not seen in warm-up; except destinations matching `net_allow` |
| `owner` | Response body | A marker of another owner (same rule as `Engine.owner_events` in `shadow/core.py`) |

Evidence `stack` is `[]` unless a source of frames is configured (see *Where in the app's code* below); `detail` is `{statement,input,param,location,reason}`,
`{path,realpath}`, `{path,argv}` / `{syscall,child}`, `{family,address,port,syscall}`, `{marker_owner,requester}`.

### One request

`Sidecar.handle` in `server.py`. Requests are processed one at a time under a lock, so everything observed
while a request window is open belongs to that request.

1. Remove the `x-imm-*` headers and read `x-imm-rid`, `x-imm-mode` (`L1`, `L2` or `learn`), `x-imm-uid`,
   `x-imm-role`.
2. Identity. With `x-imm-uid`: run the profile's `ensure_user` on the clone database, then replace the
   client's credentials with the ones from the identity source. Without it: the requester is whatever
   `identify` returns from the client's own headers. A profile with `rewrite_request` may then replace
   session-bound values (CSRF tokens) in the query and body.
3. If the tracer is not running, or the sidecar is warming up again after a re-attach (docker mode), answer
   503 with verdict `inconclusive` without calling the app.
4. Open the observation window, forward the request to the app with the request target byte for byte, buffer
   the whole response, keep the window open `grace_ms` longer, close it. An app error or timeout becomes a 502.
5. Evaluate the oracles: SQL taint, SQL structure, system calls merged with file markers, owner, and the
   profile's optional `extra_oracles(ctx)` hook (its exceptions are logged and ignored; the OpenEMR profile
   uses it for events of kind `acl`, `mfa` and `xss`, which `contracts/schemas/evidence.schema.json` accepts). With a `tracer`
   section, `phptrace.CallTracer.attach` then fills the events' `stack`.
6. Verdict: `oracle` if any oracle fired; otherwise `inconclusive` if the status is 401, 404 or 5xx, or if the
   tracer died while the request was in flight; otherwise `clean`.
7. On `oracle`, push the evidence to `$COLLECTOR_URL/_clone/evidence`, signed with `CLONE_KEY`, before the
   response is released (2 s timeout; a failed push is logged and does not change the response).
8. Answer with the app's response plus `x-imm-verdict` and `x-imm-events`.
9. In `L1` mode, reset the clone database (Postgres or MySQL section only).

Evidence has the same shape as the in-process wrapper's, with two differences: `stack` is empty unless a
`tracer` section is configured and a trace matched, and `pre_state_b64` is always null (the pre-request
snapshot exists for SQLite only).

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

### Tracer

`tracer.py` runs:

```
strace -f -y -qq -s 4096 -e signal=none -e trace=openat,openat2,open,creat,execve,execveat,connect,sendto,sendmsg,fork,vfork,clone,clone3
```

- **Attach mode** (default). The sidecar shares the app container's PID namespace and attaches with `-p` to
  every process whose mount namespace is that of the anchor process and differs from the sidecar's own. Its own
  processes are therefore never traced. Needs `SYS_PTRACE`.
- **Launch mode.** The sidecar starts the app command as a traced child (`strace -f --seccomp-bpf -- <command>`),
  for when both run in one container. It needs no added capability (`test_launch_mode_without_capabilities`).
- **Docker mode.** `docker_cmd` in `tracer.py` runs `docker run --rm --pid=container:<container> --network none
  --cap-drop ALL --cap-add SYS_PTRACE --cap-add KILL <tracer_image> strace ... -p 1`. It traces PID 1 of the
  app container and the children PID 1 starts after the attach; processes already running besides PID 1 are
  not traced. When the app container is replaced the tracer attaches again, and the sidecar answers 503
  `inconclusive` until the warm-up has run again (`Sidecar._reattached`). The sidecar process needs access to
  the Docker CLI. Paths are taken as `strace` prints them: there is no working-directory lookup in this mode.

`-f` follows children. `strace.py` joins `<unfinished ...>` and `<... resumed>` lines per process. A line that
cannot be turned into a call is counted; the count is logged with every request as `strace_dropped=N`.

How each call becomes an observation (`observe` in `strace.py`) and when it fires (`Observer.system_events`):

| Calls | Observation | Fires |
|---|---|---|
| `open`, `openat`, `openat2`, `creat` | Successful opens; with the protected rule also failed ones (detail `result` holds the errno). The path is the kernel's path of the returned descriptor (`-y`), so symlinks and `..` are already resolved; otherwise the argument joined with the directory descriptor or the process's working directory and normalised. | `file`. Default rule: the path is outside `allowed_file_roots` and was not opened during warm-up. Protected rule: the path matches a protected glob and was not opened during warm-up |
| `execve`, `execveat` | Only successful execs | `proc`, unless the program path matches `exec_allow` |
| `fork`, `vfork`, `clone`, `clone3` | Only when a child was created and the call did not carry `CLONE_THREAD` | `proc`, when the child did not exec during the window (an exec is reported once, by `execve`) |
| `connect`, `sendto`, `sendmsg` with a destination address | Attempts count even when they fail | `net`: any destination on port 53; a non-loopback IP address not seen in warm-up; a unix socket not seen in warm-up; any other address family except netlink. Loopback destinations on other ports never fire. A destination matching `net_allow` never fires, port 53 included |

The protected rule (`Observer.path_allowed`, `observer.from_config`) is for apps that legitimately open files
all over the disk. The protected set is `protected_paths` plus the path of every file marker. Under it, files
outside `allowed_file_roots` that are not protected fire nothing.

With `learn_background: true`, an observation that arrives with no request window open and more than one
second after the last window closed is remembered (`Observer.background`), and an identical observation
inside a later window does not fire. Fork observations are never learnt this way.

Not seen by the tracer:

- anything done through a descriptor that was already open (reads, writes, `mmap`);
- `rename`, `unlink`, `stat`, `readlink` and every other call not in the list above, so deleting, renaming or
  probing a file fires nothing;
- failed execs, and failed opens under the default file rule (the app did not get the file or the process);
- io_uring operations, which bypass these system calls, and `open_by_handle_at`;
- files opened before the tracer attached, and in-process databases (SQLite and the like): only their file
  open is visible, and it happens at start-up or during warm-up;
- effects the app defers for longer than `grace_ms` after its response. They are not attributed to the request
  and not to the next one either (`test_grace_period_catches_deferred_effect_and_bounds_it`: a read 5 ms after
  the response is caught, one 300 ms after is not).

### Warm-up

After the tracer is attached and the app answers its health path, the sidecar requests the health path,
`warmup_paths` and a path that does not exist, `warmup_rounds` times, with the observer in learning mode. Every
file opened and every network destination seen is added to an allowlist (port 53 fires regardless). The defaults `/dev/null`,
`/dev/urandom`, `/dev/random`, `/dev/zero` and `/dev/tty` are always allowed.

### File markers

A markers-file entry `{marker: {"path": file}}` declares a secret planted in that file of the clone
(`observer.load_file_markers`). `observer.marker_events` adds a `file` event for each such marker found in the
(decompressed) response body, with `observed: response`, or `response+syscall` when a successful open of the
same file was seen in the window. This catches a leak of a file that was already open before the request.

### Postgres proxy and the `sql` oracle

`pgproxy.py` forwards every byte between the app and the clone's Postgres unchanged, with one exception: it
answers `SSLRequest` and `GSSENCRequest` itself with `N`. The connection between app and database is therefore
always plaintext, and an app that requires TLS to its database cannot connect. Authentication passes through.

Statement text comes from two messages:

- `Q` (simple query): the whole query string, which may hold several statements. It counts as executed when at
  least one `CommandComplete` or `EmptyQueryResponse` arrives before its `ReadyForQuery`.
- `Parse` (extended protocol): the statement text, recorded when an `Execute` of a portal bound to it is
  answered by `CommandComplete`, `EmptyQueryResponse` or `PortalSuspended`. An `ErrorResponse` fails that
  `Execute` and every later one up to the next `Sync`.

`Bind` parameter values are data: they are never part of the statement text and are never taint-checked. There
is no handling specific to `COPY`: the text of a `COPY` statement sent in a `Q` is checked like any other
statement, and the rows streamed as `CopyData` are forwarded without inspection.

Statements that failed are logged and are not taint-checked with this source; the structure rule below still
sees them.

Each successfully executed statement goes through the same taint check as the in-process wrapper
(`shadow/sqltaint.py`, with the inputs extracted by `shadow/inputs.py`): an occurrence of a request input in
the statement text fires unless it sits inside exactly one literal token or is part of a verbatim copy of a
string the app itself wrote. From outside the process, "strings the app wrote" are approximated by
`constants.py`: quoted literals in text files under `source_dirs` (extensions in `EXTS`, dependency directories
skipped, template interpolations split) plus printable runs of the app's executables up to
`scan_executable_max_mb`.

When there are no app constants (no `source_dirs`, as in docker mode), or when the source is the statement log
with dialect `mysql`, taint matches with reason `token` (the input lies inside a single non-literal token) are dropped: such a
match cannot be told from an identifier the app wrote, for example `?sort=name` in `ORDER BY name`
(`test_taint_fires_without_constants_only_on_multi_token_matches`).

### MySQL / MariaDB proxy

`mysqlproxy.py` is used when the config has a `mysql` section and no `postgres` section. It forwards every
byte unchanged except the server greeting: it clears `CLIENT_SSL` and `CLIENT_COMPRESS` and zeroes MariaDB's
extended capabilities (`patch_greeting`), so the connection stays plaintext and uncompressed. Authentication
passes through.

- `COM_QUERY`: the whole query string. Executed when at least one OK packet or result set answers it.
- `COM_STMT_PREPARE`: the statement text per statement id; `COM_STMT_EXECUTE` of that id is the execution,
  executed when an OK or a result set answers it. Bound parameters are never statement text.
- Every write statement (`INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `TRUNCATE`, `ALTER`, `CREATE`, `DROP`,
  `RENAME`, `LOAD`), executed or not, inside a window or not, marks its target tables dirty (`written_tables`).
  A write whose target cannot be read marks every table dirty.

### Statement log as the SQL source

With `sql_log.cmd` set, `sqllog.LogFollower` runs that command (restarting it one second after it ends) and
feeds each statement of the database's log to the observer. This is for an app that cannot be pointed at a
proxy. Expected log formats (`LogParser`): Postgres with `log_statement=all` and `log_line_prefix='%n [%p] '`;
MySQL general log lines.

The log does not say whether a statement ran. Every statement is reported as executed, except the ones
Postgres repeats after an error (`STATEMENT:`), reported as failed. With this source failed statements are
taint-checked too, because error-based injection fails on purpose. Statements are attributed to a request by
arrival time: `LogFollower.flush` is called when a window opens and before it closes.

### Structure rule (`new_structure`) and learn mode

`sqllog.fingerprint` reduces a statement to its structure: literals and placeholders become `?`, comments
become `/**/`, unquoted words are lower-cased, value lists and multi-row `VALUES` collapse. `Baseline` is the
set of structures the app is known to produce. `sqllog.structure_events` fires a `sql` event with `reason:
new_structure` for each statement of the request (executed or failed, either SQL source) whose fingerprint is
not in the baseline and that the taint rule did not already report. The rule covers input that does not appear
verbatim in the statement (encoded input, stored input used later).

The baseline is fed by two things:

- statements seen with no request window open, added at the start of the next request;
- learn-mode requests: `x-imm-mode: learn` plus `x-imm-learn`, an HMAC over `learn <METHOD> <target>` with
  `CLONE_KEY` (`learn.learn_message`). The sidecar adds the request's statement structures to the baseline,
  answers `clean` with `x-imm-learnt: <new structures>` and evaluates no oracle. Without a valid signature the
  request is judged as an ordinary `L1` request (`test_learn_mode_needs_a_valid_signature_and_structure_rule_fires`).

The rule is off until at least one learn-mode request has been accepted (`Baseline.ready`). The baseline is
global, not per route. A legitimate structure that was never learnt fires.

`python -m sidecar.learn --sidecar URL --recordings FILE` replays, in learn mode, the records of the gateway's
recording file with `class: clean`, no classifier reasons, `route: prod` and status below 400, once per
distinct request, and prints `{replayed, learnt, skipped, errors}`. The gateway redacts `authorization` and
`cookie` in its recordings (`gateway/core.py`), so a recorded authenticated request is replayed without its
credentials.

### Call stacks for PHP clones (`phptrace.py`)

With a `tracer` section (`kind: php-xdebug`), the sidecar adds the cookie `XDEBUG_TRACE=immune` to the judged
request, reads the Xdebug function trace the app wrote under `tracer.dir` (through `/proc/<pid>/root` in
attach mode) and, for each oracle event, looks for the matching sink call: an SQL call whose argument is the
observed statement, a file function whose argument resolves to the opened file, a process or network
function; for `owner`, the entry script. The event's `stack` becomes `[{file, line, func}]`, outermost first,
ending at the innermost frame inside `source_dirs` and outside `tracer.exclude`. The fleet builds the
`<image>-trace` image that produces these traces and runs it for clones only (`fleet/generic.py`). A missing
or unmatched trace leaves `stack` empty and never changes the verdict.

### Database reset (L1)

`Sidecar.reset_db`: the proxy stops accepting new app connections, ends every proxied session (sends
`Terminate` upstream and closes the app side), waits up to 0.5 s for the sessions to leave, then runs
`DROP DATABASE IF EXISTS <database> WITH (FORCE)` and `CREATE DATABASE <database> TEMPLATE <template>` over the admin
connection. New app connections wait in the proxy until the database exists again. The app's connection pool
must tolerate its idle connections being closed. A failed reset is logged; the request has already been
answered.

MySQL has no `CREATE DATABASE ... TEMPLATE`. `Sidecar._reset_mysql` ends the proxied sessions and rebuilds, from
the `template` database, only the tables marked dirty since the last reset (by the proxy, or by `ensure_user`
through `_note_admin_write`); tables the app created are dropped. When a write target was unknown, and at
start-up, it drops and rebuilds the whole database (`reset_statements`).

With `sql_log` and no proxy section there is no reset: the sidecar does not restore the clone's state.

### Identity, markers and the `owner` oracle

`identity.py`, first source that applies:

1. A `profile` module with any of `identity_headers(env, uid, role)` (headers to set), `mint_token(env, uid,
   role)` (becomes `Authorization: Bearer <token>`), `ensure_user(conn, uid, role)` (`conn.execute(sql,
   params)` on the clone database before the window opens; `$n` placeholders on Postgres, `?` on MySQL),
   `identify(env, headers)`, `load_markers(env)`, `public_paths()`, `rewrite_request(env, uid, role, query,
   headers, body)`, `extra_oracles(ctx)`.
2. `identity_command`: a shell command run with `IMM_UID` and `IMM_ROLE`; its output is `Header: value` lines
   or one bare line taken as a bearer token.
3. Nothing: the client's headers are forwarded untouched.

Without an `identify` hook, the requester of a request without `x-imm-uid` is read from a bearer token in the
format of `immune_contracts/authtoken.py` verified with `APP_SECRET`, if that variable is set; otherwise the
requester is anonymous.

The `owner` oracle scans the (decompressed) response body for markers `MK` plus ten characters. It fires for
every marker whose owner is not the requester, unless the requester's role is `admin`. On a public path it
fires only when the body holds markers of two or more other owners or another oracle fired in the same request.
The group-shared access exemption of the in-process wrapper (`sharing.json`) is not implemented here.

### Behaviours that fail closed

- Tracer not running before the request, or re-attaching in docker mode: 503 and `inconclusive`. Tracer dies during the request:
  `inconclusive`. The app keeps running untraced and the clone answers 503 from then on. Nothing replaces
  such a clone while its three containers keep running: the fleet's reconcile loop checks container status,
  not the tracer.
- Markers configured (a profile `load_markers`, or a markers path) but unreadable or invalid: the sidecar
  refuses to start (`Identity.markers`). With no markers configured at all, it starts with the `owner` oracle off and logs a
  warning.
- A response without `x-imm-verdict` is treated as `inconclusive` by the gateway.

### Production watcher (`python -m sidecar.prodwatch`)

Alert only: it never blocks or delays a request, and the request it reports has already run in production.
For each container named in `PROD_CONTAINERS` it starts a tracer container (`tracer_cmd`: image `BPF_IMAGE`,
`--privileged`, `--network none`) running a fixed `bpftrace` program filtered by the container's cgroup, on
the tracepoints `sys_enter_openat`, `sys_enter_execve` and `sys_enter_connect` (IPv4 and IPv6). There is no
ptrace; the app is not stopped. Each line goes through the sidecar's own `strace.observe` and
`Observer.system_events`, built from the same config file:

- `file`: only the protected rule applies (protected paths and file-marker paths, minus `prod_ignore`). With
  nothing protected the file rule never fires. The tracepoint is the entry of the call, so an attempt counts
  whether or not it succeeded.
- `proc`: every `execve` whose program does not match `exec_allow`. Forks are not observed.
- `net`: every non-loopback `connect` and every port-53 destination not matching `net_allow`. There is no
  warm-up allowlist of destinations.

What a container does in its first `PROD_GRACE_S` seconds is learnt as normal. The same (container, oracle,
detail) alerts at most once per `PROD_COOLDOWN_S`. On an alert (`Watch.alert`):

1. Read the gateway's recordings (`RECORD_PATH`) and select up to 10 requests with `route: prod` that were in
   flight at that instant, within 0.3 s (`candidates`).
2. Replay each on the clone through the sidecar at `REPRO_URL` in `L1` mode. A replay whose verdict is
   `oracle` is confirmed; the sidecar pushes its evidence as for any detonation, which opens the incident in
   the pipeline.
3. Publish `prod.alert` on the bus: `{container, oracle, detail, candidates, confirmed, note}`, where
   `detail.observed` is `prod-syscall`, `candidates` is a count and `confirmed` a list of `{method, path,
   query}`. No candidate means the traffic did not pass through the gateway or the app acted on its own.

| Variable | Default | Meaning |
|---|---|---|
| `PROD_CONTAINERS` | empty | Comma-separated container names; one not running is waited for |
| `SIDECAR_CONFIG`, `MARKERS_PATH` | none | The sidecar's config file and markers file |
| `RECORD_PATH` | empty | The gateway's recording file; without it there are no candidates |
| `REPRO_URL` | empty | Sidecar of the clone used for replays; without it nothing is confirmed |
| `BUS_URL`, `BUS_TOKEN`, `RUN_ID` | empty | Where to publish `prod.alert` |
| `BPF_IMAGE` | `immune-bpftrace:1` | Tracer image (`deploy/Dockerfile.bpftrace`) |
| `PROD_LABEL` | empty | Label put on the tracer containers |
| `PROD_GRACE_S`, `PROD_COOLDOWN_S` | 15, 30 | Start-up learning period; minimum interval between identical alerts |

Only `labs/grafana-cve-2021-43798/lab.sh` starts it; `immune up` does not.

### ScadaBR proxy (`python -m sidecar.httpds`)

A single-file HTTP proxy (`httpds/core.py`) that speaks the same clone protocol with one oracle, written for
[`labs/scadabr-cve-2026-8602`](../labs/scadabr-cve-2026-8602/README.md). It forwards the request to
`SHADOW_UPSTREAM` and buffers the response. For a request whose path ends in `/httpds`, it fires an `owner`
event when a query (or POST form) parameter listed in the manifest's `point_params` is absent from the
`Unconsumed key: <k>` lines of ScadaBR's response, which means a data point consumed the value
(`consumed_points`). Verdict rule as in "One request". It does not trace system calls, proxy a database,
translate identities or reset state; it does not itself check that the request was unauthenticated, and
relies on the gateway detonating only requests it classified as lacking a trusted identity. Environment:
`SHADOW_UPSTREAM` (default `127.0.0.1:8080`), `HTTPDS_MANIFEST` (JSON with `point_params`, `reserved_keys`,
`reserved_prefixes`), `CLONE_ID`, `CLONE_KEY`, `COLLECTOR_URL`, `RELEASE` (default `1.2`), `SIDECAR_TIMEOUT_S`
(15).

## Tests

```
.venv/bin/pytest sidecar/tests -q
```

| File (under `sidecar/tests/`) | Needs | Covers |
|---|---|---|
| `test_strace.py`, `test_pgproxy.py`, `test_constants.py`, `test_judge_trace.py`, `test_node_deps.py` | nothing | Parser, observer rules, Postgres protocol tracking (simple and extended, errors, split messages), literal extraction, trace of bound parameters, installation of the Node fixture's dependencies |
| `test_fail_closed.py` | nothing | Marker loading failures, verdict when the tracer is dead before or during a request, dropped-line counter |
| `test_policy_and_sql.py` | nothing | Protected-path rule and failed opens, file markers, `exec_allow`/`net_allow`, background learning, the docker-mode tracer command line, config keys, log parsers, `fingerprint`, `Baseline`, the structure rule, learn-mode signature, `sidecar.learn` record selection |
| `test_mysqlproxy.py` | nothing, except one test marked `docker` that needs the pinned MariaDB image and is skipped without it | MySQL packet framing, greeting patch, statement outcomes, prepared statements, `written_tables`, `reset_statements`, client helpers; live round trip through the proxy |
| `test_phptrace.py` | nothing | Xdebug trace parsing and sink matching on written trace files |
| `test_prodwatch.py` | nothing | Candidate selection, start-up learning, cooldown, the alert with a fake replay and bus, the tracer command line |
| `test_httpds_sidecar.py` | nothing | `consumed_points`, the verdict rule, signed evidence push, with a fake upstream |
| `test_integration.py` (marked `docker`) | Docker; images `immune-sidecar:1`, `node:22-alpine`, `postgres:16-alpine`, and `immune-cbuild:1` for the C app | Every oracle against the Node app, identity, L1 reset and L2 state, grace period, signed evidence, collector down, tracer death, the statically linked C app, launch mode |

Verification level of the parts that have no end-to-end test in this directory:

| Part | Level |
|---|---|
| Attach and launch mode, Postgres proxy | Implemented and tested (`test_integration.py`) |
| Docker mode | Implemented; the command line is unit-tested; end to end only by running `labs/grafana-cve-2021-43798/lab.sh` by hand |
| Statement log source, structure rule, learn mode | Implemented; unit-tested with fed log lines and a fake app; no test runs them against a real database |
| MySQL proxy | Implemented; one live test against MariaDB; no integration test of a whole clone on MySQL in this directory |
| `phptrace.py` | Implemented; unit-tested on trace files; no test runs a PHP app |
| `prodwatch.py` | Implemented; unit-tested without `bpftrace`; the eBPF tracer is only exercised by the Grafana lab, by hand |

The integration tests create containers and an `--internal` network with a test-only prefix and remove them.
The Node fixture's `node_modules` is not in the repository; `ensure_node_deps` in `tests/dockerenv.py` installs
it from `package-lock.json` (host `npm`, else a one-off container), which needs access to the npm registry
once; the tests are skipped when that is impossible.

`python -m sidecar.tests.bench [N] [grace_ms] [durable]` brings up the Node fixture with and without the tracer
and prints latency and reset times. No result of it is recorded in the repository, so this document states no
overhead figures; measured results of the project are in [`docs/resultados.md`](../docs/resultados.md).

## Limits

- Everything listed under "Not seen by the tracer".
- SQL: PostgreSQL and MySQL / MariaDB have a proxy; other databases need the statement log. An app that opens
  its own connection directly to the database, bypassing the proxy, has no `sql` oracle. Bind parameters and
  `COPY` data are not checked. The limits of the taint check itself are in
  [`shadow/README.md`](../shadow/README.md).
- Both proxies refuse TLS, so an app that requires TLS to its database cannot connect.
- Statement log: it cannot tell executed from failed statements except for Postgres `STATEMENT:` lines, and
  attribution to a request is by arrival time of log lines.
- Structure rule: off until a learn-mode request is accepted; global baseline; an unlearnt legitimate
  structure is a false positive, so the learning traffic bounds its precision.
- App constants are approximate. Without them, single-token taint matches are dropped, so an injection whose
  whole payload is one token is not reported by the taint rule. Apps whose SQL text is assembled at run time or
  stored compressed, and executables above the size limit, contribute no constants.
- Protected file rule: only the listed globs and marked files are watched; any other file read fires nothing.
- `owner` sees only markers in the response body; a leak that never reaches the body is invisible to it. No
  group-shared access.
- Memory-only effects (caches, globals) are invisible.
- Background work of the app that happens while a request window is open is attributed to that request.
  `learn_background` reduces this only for behaviour already seen outside a window.
- An app that resolves host names per request fires `net`, unless `net_allow` lists the resolver.
- In attach mode the app listens in the shared network namespace. If it binds `0.0.0.0`, the gateway could
  reach it without passing through the sidecar; the fleet sets the variable named by `app.bind_env` to
  `127.0.0.1` in clones, which only helps if the app honours it.
- Attach and docker mode stop the traced processes on every system call (`--seccomp-bpf` applies only to
  processes `strace` starts), which costs most on work that spawns processes.
- Docker mode: observations cross a container's output pipe, so a short `grace_ms` can miss late lines (the
  Grafana lab sets 100); the app's executables are not scanned for constants, and `source_dirs` would be read
  from the sidecar's own filesystem, not the app container's.
- An app that refuses to run traced cannot be observed.
- One request at a time per clone.
- A clone whose tracer died keeps answering 503 with `inconclusive` until its containers are replaced (attach
  and launch mode; docker mode re-attaches).
- Production watcher: detection after the fact; privileged tracer container; attribution by instant, so
  "confirmed" means a request in flight at that moment fires on the clone, not that it caused the production
  event; requests whose credentials were redacted in the recording replay unauthenticated; paths containing
  quotes are dropped (`Watch.observe`).
- Tested on one Node app and one statically linked C app.

The project-wide list is in [`docs/limites.md`](../docs/limites.md); where the sidecar sits in the system is in
[`docs/arquitectura.md`](../docs/arquitectura.md).
