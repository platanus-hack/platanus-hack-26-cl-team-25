# shadow

## Purpose

`shadow` runs an unmodified Python ASGI app on synthetic data, under in-process instrumentation, and reports for
each request whether the app did something it must not do. Each such check is an oracle. The result is a verdict
(`clean`, `oracle` or `inconclusive`) that the gateway routes on and that the pipeline's gates use to judge a
patch.

The instrumentation runs only in clones and in the validation runner. Production runs the app without it.

## How it runs

Two front ends share one engine (`core.Engine`), so a request gets the same verdict either way.

**Clone server.** One process per clone container, started by the fleet (`fleet/config.py`, `clone_command`):

```
python -m shadow.run --profile <module> [--host 0.0.0.0] [--port 8000] [--log-level info]
```

**In-process harness.** No network; used by the validation runner (`pipeline/runner_entry.py`, job kind
`harness`, which the gates and the property checks submit) and by the doctor (`immune/doctor.py`, through
`immune/initsteps/harness_runner.py`):

```python
from shadow.harness import Harness
h = Harness(profile="victim.shadow_profile", seed_db="seed.db", state=None)
r = h.send("GET", "/api/products", query="q=x", uid=None, role="user", mode="L1")
r.status, r.headers, r.body, r.verdict, r.events, r.evidence
h.snapshot(); h.close()
```

A process handles one request at a time (an asyncio lock in the server, a process lock in the harness). Every
event observed while a request is in flight, from any thread, belongs to that request.

## Layout

| File | Role |
|---|---|
| `run.py` | Clone server: installs the instrumentation, builds the engine, serves the wrapped app with uvicorn |
| `harness.py` | `Harness`: the same engine on a private event loop thread |
| `core.py` | `Engine`: identity, pre-state snapshot, buffered run of the app, oracle evaluation, verdict, evidence push, reset; the owner oracle |
| `instrument.py` | Process-wide hooks: `sqlite3.connect` wrapper, `sys.addaudithook`, `FileResponse` stack capture |
| `sqltaint.py` | SQL oracle: tokenizer and taint check |
| `inputs.py` | Extracts the client-controlled values of a request |
| `db.py` | SQLite state handling through the backup API |
| `tests/` | Unit tests and two small apps with positive and negative cases per oracle |

## Configuration

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `SHADOW_SEED_DB` | none | Seed database restored at start and after every L1 request |
| `SHADOW_DB_ENV` | `APP_DB` | Name of the variable through which the app receives its SQLite path. If that variable is unset, a temporary file is used |
| `APP_SECRET` | `shadow-secret` | Secret of the clone. Must differ from the production secret |
| `CLONE_ID`, `CLONE_KEY` | empty | Identity of the clone and the key that signs its evidence |
| `COLLECTOR_URL` | none | Gateway ingest base URL. Unset: evidence is built but not pushed |
| `RELEASE` | empty | Release id stamped on the evidence |
| `SHADOW_RELEASE_ROOT` | directory containing the app package | Stack frame paths are relative to it |
| `SHADOW_RELEASE_PATHS` | the app's top-level package | Colon-separated paths (relative to the release root) whose frames appear in stacks |
| `SHADOW_SHARING_PATH` | `sharing.json` next to the seed | Group-shared access relations for the owner oracle |
| `SHADOW_LOG_LEVEL` | `info` | One log line per request on stderr |
| `APP_NOW` | unset | Fixed clock for token verification, used by tests |

`MARKERS_PATH` is not read by `shadow` itself: the profile's `load_markers(env)` decides where markers come from.
The demo profile (`victim/shadow_profile.py`) and the profiles drafted by `immune init` (`immune/initsteps/drafts.py`) read that variable.

### Profile module

`--profile` names a Python module that adapts one app:

| Attribute | Meaning |
|---|---|
| `APP` | `"package.module:attribute"` of the ASGI app |
| `allowed_file_roots(env)` | Directories the app may read during a request |
| `load_markers(env)` | `{marker: owner uid}`. Markers match `MK[A-Z0-9]{10}` |
| `public_paths()` | Path prefixes where a response may carry the caller's own data while anonymous (login, register, public listings) |
| `ensure_user(conn, uid, role)` | Makes sure a user row exists in the clone database |
| `mint_token(env, uid, role)` | A credential the clone's app accepts for that user |
| `identify(env, headers)` | Optional. Returns `(uid, role)` from the client's own credentials; default is the bearer token verified with `APP_SECRET` |

## Behaviour

### One request (`Engine.handle`, `Engine.finish`)

1. Read and remove the `x-imm-*` headers: request id, mode (`L1` or `L2`), uid and role.
2. Resolve the identity. With `x-imm-uid`, the engine ensures the user exists and replaces `Authorization` with a
   token minted for it. Otherwise it uses the client's own credentials if they verify inside the clone, else the
   request is anonymous.
3. In mode `L2`, snapshot the database before the request.
4. Run the app with the response fully buffered until the app callable returns.
5. Evaluate the oracles.
6. Verdict: any oracle event gives `oracle`; otherwise a 401, 404 or 5xx status gives `inconclusive`; otherwise
   `clean`.
7. On `oracle`, build the evidence (request, events with stacks, pre-state for L2) and push it to the collector,
   signed with the clone key, before the response is released. The push has a 2 s timeout; a failure is logged
   and does not change the response.
8. Add `x-imm-verdict` and `x-imm-events` to the response.
9. In mode `L1`, restore the database to the seed.

At start the engine runs the app's lifespan and a warm-up (`GET /health`, `/`, `/openapi.json`, `/docs` and a
missing path, plus `mimetypes.init()`). Files opened during warm-up are learned as benign.

Database state always moves through the SQLite backup API (`db.py`), which rewrites pages in place so the app's
open connections see the new content. Files are never copied.

### SQL oracle (`sqltaint.py`)

`instrument.py` replaces `sqlite3.connect` so every connection and cursor records the text of each statement that
executed successfully, with the app stack. Bound parameters never appear in that text, so a parameterised query
cannot fire.

Inputs are the values the client controls (`inputs.extract`): query values and names, path segments (named after
the route parameter when known), JSON string leaves, form fields, multipart fields and file names, raw bodies under
4096 characters, header values and cookie values. Values shorter than 2 characters are ignored. Each value is also
tried URL-decoded again, stripped, lower-cased and upper-cased.

For every occurrence of an input in a statement, `sqltaint.classify` decides:

1. The occurrence overlaps or touches a comment token: fire (`reason: comment`).
2. The non-whitespace tokens it overlaps are exactly one literal (string, number or blob): safe.
3. The occurrence is part of a verbatim copy of a string constant of the app's own code: safe. This is how the
   input `notes` stays clean inside `SELECT ... FROM notes`, which the app wrote.
4. Otherwise fire: `reason: token` when it covers one non-literal token, `reason: structure` when it spans
   several.

The tokenizer follows SQLite's lexical rules, comments included. `sqltaint.check` also accepts `dialect="mysql"`
(backslash escapes inside quotes, double-quoted strings, `#` comments), which only the sidecar uses. The app's
constants are collected from the code objects of its loaded modules.

Multipart bodies are parsed with the Content-Type header as sent, because the boundary is case-sensitive.

### File, process and network oracles (`instrument.py`)

One `sys.addaudithook` handler, inert unless a request is in flight.

| Oracle | Audit events | Fires when |
|---|---|---|
| `file` | `open`, `os.listdir`, `os.scandir` | The real path is outside `allowed_file_roots()` and outside the warm-up allowlist. Opens made by the import system, `linecache` or `tokenize` are ignored |
| `proc` | `subprocess.Popen`, `os.system`, `os.exec`, `os.posix_spawn`, `os.spawn`, `os.fork`, `os.forkpty`, `pty.spawn`, `os.startfile` | Any of them during a request |
| `net` | `socket.connect`, `socket.sendto`, `socket.sendmsg`, `socket.getaddrinfo`, `socket.gethostbyname`, `socket.gethostbyname_ex`, `socket.gethostbyaddr` | Any of them during a request |

The evidence push happens after the request window closes, so it does not trip the `net` oracle.
`FileResponse.__init__` is wrapped to capture the app stack, because the file itself is opened later in a worker
thread with no app frame.

### Owner oracle (`Engine.owner_events`)

The synthetic data carries a per-owner marker in each private cell. The oracle scans the response body
(decompressed if gzip or deflate) for markers.

- It fires once per distinct marker owner different from the requester. An anonymous requester differs from
  every owner. A requester with role `admin` never fires.
- Group-shared access: when `sharing.json` declares that a path parameter addresses a group, and the requester is
  a member of the addressed group (read from the clone's own database), markers of that group's members are not
  foreign. This exemption does not apply when another oracle fired in the same request.
- On a path listed in `public_paths()` it fires only when the body holds markers of two or more foreign owners,
  or another oracle fired in the same request. A response about one person on a public path (login, register) is
  clean.
- If the profile's `load_markers` raises, the clone does not start. If it returns no markers, the oracle is off
  and a warning is logged.

### Stacks

Evidence stacks contain only frames inside the release's app paths, with file paths relative to the release
root, outermost frame first and the sink last. For SQL the last frame is usually the app's database helper; the
handler that built the statement is earlier in the list.

Wire-level detail (headers, evidence schema) is in [`contracts/`](../contracts/README.md).

## Tests

```
.venv/bin/pytest shadow/tests -q
.venv/bin/pytest acceptance/shadow -q
```

Neither needs Docker or the LLM.

## Limits

- SQL: an input the app transforms beyond URL-decoding, stripping or case change (trimmed inside, base64) is
  missed. Failed statements are logged, not judged. Only statements executed through `sqlite3` are seen;
  C-level or extension access to SQLite is not.
- SQL: an input equal to a single identifier or keyword that is not among the app's constants fires, for example
  a raw `ORDER BY <column>` with a legitimate column name. That code is injectable, but legitimate traffic trips
  it too.
- SQL: a statement assembled only from fragments that each exist as app constants could hide an injection that
  copies a constant verbatim.
- File: only `open`, `os.listdir` and `os.scandir` are watched, not `stat` and not SQLite `ATTACH`. A file inside
  an allowed root is never an event. An app file first read on a path the warm-up did not exercise (a template)
  fires.
- Network: an app that makes legitimate outbound calls trips the `net` oracle. There is no fake internet sink for
  clone egress.
- Owner: a public path leaking exactly one foreign owner's private data, with no other oracle firing, is missed.
- An app that holds an uncommitted write transaction open across requests blocks the L1 reset.
- The pre-state snapshot exists for SQLite only.
- Only Python ASGI apps are supported. Other runtimes use [`sidecar/`](../sidecar/README.md).

The full list across components is in [`docs/limites.md`](../docs/limites.md).
