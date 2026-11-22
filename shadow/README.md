# shadow/ — clone wrapper (WP2)

Runs the unmodified app with synthetic data under instrumentation ("oracles") and
reports per request whether it did something it must not do. Contract: `contracts/README.md` §5.

```
python -m shadow.run --profile victim.shadow_profile [--host 0.0.0.0] --port 8000
```
Env: `APP_DB`, `APP_SECRET`, `SHADOW_SEED_DB`, `CLONE_ID`, `CLONE_KEY`, `COLLECTOR_URL`, `RELEASE`, `MARKERS_PATH`
(`SHADOW_LOG_LEVEL`, default `info`, one line per request on stderr).

```python
from shadow.harness import Harness            # in-process judge, no network
h = Harness(profile="victim.shadow_profile", seed_db="seed.db", state=None)
r = h.send("GET", "/api/products", query="q=x", uid=None, role="user", mode="L1")
r.status, r.headers, r.body, r.verdict, r.events, r.evidence
h.snapshot(); h.close()
```

## How it works
- `instrument.py` is installed **before** the app is imported: `sqlite3.connect` returns
  instrumented Connection/Cursor subclasses (statement text + success/failure), a
  `sys.addaudithook` sees `open`/`os.listdir`/`os.scandir`, process spawns and socket
  connects/DNS, and `FileResponse.__init__` records the app stack (the file itself is
  opened later in an anyio worker thread). Everything is inert unless a request is in flight.
- `core.Engine` is shared by server and harness: strip `x-imm-*`, resolve identity
  (`x-imm-uid` → `ensure_user` + `mint_token`; else the client's token if it verifies with
  `APP_SECRET`; else anonymous), L2 pre-state snapshot, run the ASGI app with the response
  **fully buffered** until the app callable returns, evaluate oracles, verdict, signed evidence push
  (2 s timeout, failures only logged) before the response is released, then L1 reset.
- One request at a time (asyncio lock in server mode, process lock in the harness), so all
  events observed meanwhile, from any thread, belong to that request.
- DB state is always moved with the sqlite backup API (`db.py`), never file copies. Harness L1
  resets to its base state (the seed, or the `state` bytes it was created with).
- Warm-up at start (app lifespan, `mimetypes.init()`, GET `/health`, `/`, `/openapi.json`, `/docs`, a 404)
  learns the benign file opens (e.g. `/etc/mime.types`).

## Oracles
- `sql` (`sqltaint.py`): every input value (query values and names, path segments named after the
  route param, JSON string leaves, form fields, headers/cookies; len ≥ 2; also URL-decoded again,
  lower/upper-cased) is searched in each **successfully executed** statement text. An occurrence fires
  if it touches a comment, or if it is not exactly one literal token (string/number/blob) **and** is
  not part of a verbatim copy of a string constant of the app's own code (that is how `notes` in
  `... FROM notes` or `price` in an allow-listed `ORDER BY` stay clean). Failed statements are only logged.
- `file`: realpath outside `allowed_file_roots()` and the warm-up allowlist. Opens made by the import
  system or `linecache` are ignored.
- `proc`: any spawn audit event during a request. `net`: `socket.connect/sendto/sendmsg/getaddrinfo/gethostby*`
  during a request (the evidence push happens outside the request window).
- `owner`: markers in the (decompressed) body whose owner ≠ requester, requester not admin. Group-shared access:
  with `sharing.json` (next to the seed, or `SHADOW_SHARING_PATH`; written by `immune.shadowdata` from `shared_via`),
  on a request whose path parameter addresses group G, markers of G's members are not foreign to a requester who is
  a member of G (membership read from the clone's own database). Markers of anyone outside G still fire, and nothing
  is exempt when another oracle fired or no relation is declared. On
  `public_paths()` it still fires when the body holds markers of ≥ 2 foreign owners (bulk dump) or another
  oracle fired in the same request (e.g. SQLi through public search); a single-owner echo (login/register) is clean.

Stacks: only frames inside the app's top-level package, path relative to the release root
(`victim/app/products.py`), **outermost first, innermost last**. For SQL the innermost frame is usually the
app's DB helper (`victim/app/db.py`); the route handler that built the statement is earlier in the list.

## Known limits
- SQL: an input equal to a single identifier/keyword that is not in the app's constants fires (e.g. a raw
  `ORDER BY <col>` with a legit column name) — real vuln, but legit traffic hits it too. Inputs transformed by the
  app beyond decode/case (e.g. trimmed inside, base64) are missed. Statements built only from fragments that
  each exist as app constants could hide an injection that copies a constant verbatim (theoretical).
  Cursor factories are instrumented by subclassing; C-level/extension access to sqlite is not seen.
- file: only `open`/listdir/scandir are watched (not `stat`, not sqlite `ATTACH`); app files read lazily on a
  path not exercised by warm-up (e.g. templates) would fire.
- owner: a public endpoint leaking exactly one foreign owner's private data without another oracle firing is missed.
  An app holding an uncommitted write transaction open across requests would block the L1 reset.

Tests: `.venv/bin/pytest shadow/tests -q` (unit + a demo app with positive/negative cases per oracle).
