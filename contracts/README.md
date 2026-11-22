# System contract (v1)

Owned by the orchestrator. Work packages read it; they never edit `contracts/` or `immune_contracts/`.
If something you need is missing or contradictory, **stop and report `CONTRACT_GAP: <what>`** in your final message instead of inventing it.

Design background: `docs/arquitectura.md`, `docs/plan-construccion.md` (Spanish). This file wins on any conflict.

## 1. Processes, ports, networks

| Component | Package | Runs as | Listens | Notes |
|---|---|---|---|---|
| victim (prod) | `victim/` | containers `prod-blue` / `prod-green` | 8000 | unmodified app |
| shadow clone | `shadow/` wrapping `victim` | containers `clone-<id>` | 8000 | same code + oracles |
| gateway | `gateway/` | container `gateway` | 8080 data, 8081 admin, 9000 clone ingest | only entry point |
| bus + dashboard | `dashboard/` | container `dashboard` | 8090 | event bus (POST/SSE) + UI |
| fleet | `fleet/` | **host process** | 127.0.0.1:8070 | only component with the Docker socket |
| pipeline | `pipeline/` | **host process** | — | drives incident → patch → deploy |
| patcher | `patcher/` | library called by pipeline | — | runs `claude -p` |
| sim | `sim/` | host process | — | attacker bot + legit traffic |

Docker networks (all created by `deploy/compose.yaml`):

- `prodnet` (internal): gateway, prod-blue, prod-green.
- `clonenet` (internal): gateway, clones. **Clones can reach nothing but the gateway.**
- `ctrlnet` (internal): gateway, dashboard.
- `edge` (bridge): gateway, dashboard. Published only on `127.0.0.1`: 8080, 8081, 8090.

Containers cannot reach the host (host firewall rejects it). So: **nothing in a container calls fleet/pipeline**; host processes call containers through the published ports.

All containers use image `immune-base:1` with the repo bind-mounted read-only at `/srv` (`PYTHONPATH=/srv`). No `docker build`, no `pip install` anywhere. Host processes use `/home/ubuntu/platanus-hack-26-cl-team-25/.venv`.

Entry points (must exist exactly like this):

```
uvicorn victim.app.main:app --host 0.0.0.0 --port 8000
python -m shadow.run --profile victim.shadow_profile --port 8000
python -m gateway
python -m dashboard
python -m fleet
python -m pipeline
python -m sim.attacker   /   python -m sim.legit
```

## 2. Runtime directory (`runtime/`, git-ignored)

```
runtime/run_id                         current run id (string)
runtime/releases/<release>/victim/...  immutable code of one release (t0 = "t0")
runtime/data/prod/app.db               prod database (directory is bind-mounted, never the file)
runtime/data/shadow/seed.db            shadow seed database (read-only for clones)
runtime/data/manifest.json             see §4
runtime/data/markers.json              shadow only, see §4
runtime/recordings/requests.jsonl      gateway request log (§7)
runtime/bus/events.jsonl               bus persistence
runtime/repo/                          local git repo used by RepoTarget "local"
```

A release is mounted so that `/srv/victim` inside prod/clone containers is `runtime/releases/<release>/victim`.

## 3. Shared secrets / env

| Variable | Used by | Meaning |
|---|---|---|
| `APP_SECRET` | victim | token secret (prod value in prod, shadow value in clones) |
| `APP_DB` | victim | sqlite path |
| `APP_STATIC` | victim | read-only static dir |
| `APP_NOW` | victim | optional frozen unix time (tests / differential replay) |
| `PROD_APP_SECRET`, `SHADOW_APP_SECRET` | gateway | to verify prod tokens and to recognise shadow tokens |
| `ADMIN_TOKEN` | gateway admin, fleet, pipeline | header `x-admin-token` |
| `BUS_URL`, `BUS_TOKEN` | all publishers | see `immune_contracts/events.py` |
| `RUN_ID` | all | stamped on events |
| `CLONE_ID`, `CLONE_KEY`, `COLLECTOR_URL`, `SHADOW_SEED_DB`, `RELEASE`, `MARKERS_PATH` | shadow | per-clone identity, HMAC key, `http://gateway:9000`, seed path, release id, markers file |
| `GW_HOST`, `GW_DATA_PORT`, `GW_ADMIN_PORT`, `GW_INGEST_PORT` | gateway | bind address and the three ports (defaults `0.0.0.0`, 8080, 8081, 9000) |
| `PROD_ADDR`, `PROD_RELEASE`, `OPENAPI_PATH`, `MANIFEST_PATH`, `RECORD_PATH` | gateway | initial upstream `host:port`, its release id, and file paths |
| `DASH_HOST`, `DASH_PORT`, `BUS_STORE` | dashboard | bind (default `0.0.0.0:8090`) and the events JSONL path |
| `FLEET_PORT`, `GATEWAY_ADMIN_URL`, `RUNTIME_DIR`, `REPO_DIR` | fleet, pipeline | 8070, `http://127.0.0.1:8081`, absolute `runtime/`, absolute repo root |

Demo values live in `deploy/demo.env`. `python -m shadow.run` also accepts `--host` (default `0.0.0.0`).

## 4. Victim contract

API: `contracts/openapi.yaml`. Extensions used by the gateway and pipeline:

- `x-owner-scoped: true` on an operation: the resource belongs to one user.
- `x-sensitive: true` on a parameter/property: never grammar-checked, redacted in recordings.

Rules for the victim code:

- FastAPI, raw **synchronous** `sqlite3` (stdlib), no ORM, no threads/executors of its own, no background tasks.
- All mutable state in SQLite (`APP_DB`). Filesystem is read-only; files are served only from `APP_STATIC`.
- Auth: `immune_contracts.authtoken` with `APP_SECRET`.
- Time comes from `APP_NOW` when set. Ids are autoincrement integers.
- Each planted vulnerability has a comment-free, realistic implementation (no `# VULN` markers) and is listed in `victim/VULNS.md` (class, route, param, file:line, example exploit).
- `victim/tests/` is a pytest suite that passes on t0 and exercises every route with legitimate inputs (including a name with an apostrophe and file names with dots).

Seeding: `python -m victim.seed --out-prod <db> --out-shadow <db> --manifest <json> --markers <json> [--seed 1]`

- Prod and shadow have the **same key skeleton**: same ids, same owner relations, same public data (products, static files). Private fields (names, emails, addresses, phone, order notes, invoice text) are different in shadow.
- Every private field value in shadow embeds that owner's **marker**: a token `MK` + 10 chars `[A-Z0-9]`, unique per owner, placed so the value still looks plausible (e.g. `Apt MK4F7Q2ZP0XA`). Prod data contains no string matching `MK[A-Z0-9]{10}`.
- `manifest.json`:
  ```json
  {"seed_max_uid": 60, "seed_max_order_id": 240,
   "legit_users": [{"id": 3, "email": "...", "password": "...", "role": "user"}],
   "admin": {"id": 1, "email": "...", "password": "..."},
   "canaries": {"user_id": [7, 19], "order_id": [12, 31]},
   "ownership": {"orders": {"1": 3, "2": 5}}}
  ```
  `canaries` is keyed by **OpenAPI path-parameter name**. Canary users/orders exist in both databases; nobody ever logs in as a canary user and no legit user owns a canary order. Any non-admin request whose path parameter hits a canary value is evidence.
- Required tables/columns (others are free): `users(id, email, role, ...)`, `orders(id, user_id, ...)`, `products(id, ...)`.
- `victim/static/manuals/` and `victim/static/images/` hold the public files; at least one manual has two dots in its name.
- `markers.json`: `{"MK4F7Q2ZP0XA": 3, ...}` (marker → owner uid).

Shadow profile `victim/shadow_profile.py` (the only victim-specific knowledge the wrapper gets):

```python
APP = "victim.app.main:app"
def allowed_file_roots(env: dict) -> list[str]: ...      # static dir etc.
def ensure_user(conn, uid: int, role: str) -> None: ...  # insert a synthetic user row if uid is missing
def mint_token(env: dict, uid: int, role: str) -> str: ...
def load_markers(env: dict) -> dict[str, int]: ...      # reads env["MARKERS_PATH"]
def public_paths() -> list[str]: ...                      # path prefixes whose responses are never owner-checked
```

## 5. Shadow wrapper contract

One request at a time per clone (the wrapper holds a lock). For each request:

1. Read and remove the `x-imm-*` request headers (`immune_contracts/wire.py`).
2. If `x-imm-uid` is present: `ensure_user`, then replace `Authorization` with `mint_token(uid, role)`.
3. If mode is `L2`: take the pre-request state with the sqlite **backup API** (never copy the file).
4. Run the app; **buffer the whole response** until the ASGI app callable has returned.
5. Evaluate oracles → `events`.
6. Verdict: `oracle` if any event; else `inconclusive` if status is 401, 404 or ≥ 500; else `clean`.
7. If verdict is `oracle`: POST the evidence (schema `contracts/schemas/evidence.schema.json`) to `{COLLECTOR_URL}/_clone/evidence`, signed (`wire.sign`), **before** releasing the response. Collector failure must not break the response.
8. Release the response with `x-imm-verdict` and `x-imm-events`.
9. If mode is `L1`: restore the database from `SHADOW_SEED_DB` with the backup API.

Oracles (kinds in `wire.ORACLES`):

| Kind | Fires when | Must not fire when |
|---|---|---|
| `sql` | a request input value (query/path/json/form/header, length ≥ 2) appears in an **executed** statement and is not contained in a single literal token, or touches a comment | the statement fails to parse/execute; a parameterised query receives `O'Brien` |
| `file` | a file is opened whose realpath is outside the allowed roots and outside the warm-up allowlist | interpreter/library files learned during warm-up (e.g. `/etc/mime.types`) |
| `proc` | a child process is spawned during a request | — |
| `net` | an outbound connection is made during a request | the wrapper's own evidence push |
| `owner` | the response body contains a marker of an owner ≠ requester, requester is not admin, path not in `public_paths()` | login/register, public data |

Each event: `{"oracle": kind, "detail": {...}, "stack": [{"file": "<path relative to the release>", "line": n, "func": "..."}]}` with only frames inside the victim package. `detail` for `sql`: `{statement, input, param}`; `file`: `{path, realpath}`; `owner`: `{marker_owner, requester}`.

In-process harness (used by the pipeline runner as the judge):

```python
from shadow.harness import Harness
h = Harness(profile="victim.shadow_profile", seed_db="/path/seed.db", state=None)   # state: sqlite bytes or None (= seed)
r = h.send("GET", "/api/products", query="q=x", headers={}, body=b"", uid=None, role="user", mode="L1")
r.status, r.headers, r.body, r.verdict, r.events
h.snapshot() -> bytes ; h.close()
```

`victim` is imported from `sys.path`, so the caller chooses the release.

## 6. Gateway contract

Decision per request (enforce mode):

1. Strip `x-imm-*` request headers. Mint `rid`. Resolve identity: prod token → uid/role; shadow-secret token → **evidence** (honeytoken).
2. Session key: `uid:<n>` if identified, else cookie `gwsid` (the gateway sets it on every response that lacks it). Never the IP.
3. If the session is captive → its L2 clone (`x-imm-mode: L2`, client headers untouched). Serialise per clone.
4. Known scanner path (fixed list) → L0 procedural response. Any other unknown path → forwarded normally.
5. Classify. **suspect** if any: a parameter (query, path, JSON string leaf, form) violates the OpenAPI schema or `grammar.is_safe_default` (skip `x-sensitive`), duplicated query parameter, operation is `x-owner-scoped` and uid is untrusted (`uid > seed_max_uid`) or anonymous, an active rule matches, enumeration heuristic. **evidence** if: canary order/user id requested by a non-owner, honeytoken.
6. `clean` → prod.
7. `suspect` → acquire a free L1 clone (wait ≤ 300 ms), send with `x-imm-rid`, `x-imm-mode: L1`, and `x-imm-uid`/`x-imm-role` if identified. Read the full response, then the verdict:
   - `clean` → forward the **same bytes** to prod, return prod's response.
   - `oracle` → attack confirmed (see 8).
   - `inconclusive` → if an active rule matched **strictly**: generic deny; else forward to prod. A `scope: all` rule and a `scope: param` rule always match strictly; a `scope: param_present` rule matches strictly only when the value is outside its `grammar` (a clone holds synthetic credentials, so a real user's login is a 401 there: denying every inconclusive would take the endpoint down).
   - no clone available → evict the oldest clone-bound captive (its clone becomes `retired`, so fleet replaces it), then: if an active rule matched **or the request is high-signal** (a reason of kind schema/grammar violation or duplicated parameter) → generic deny; else forward to prod.
8. Confirmed attack (`oracle` verdict, or `evidence`):
   - trusted identity (`uid ≤ seed_max_uid`): never serve synthetic data → generic deny, publish `oracle.fired`.
   - otherwise: return the clone's response and mark the session **captive**. Captivity is bound to a clone **lazily**: after an L1 detonation the clone goes back to `free` (the wrapper already reset it to the seed) and the session holds no clone. On the captive session's **next** request the gateway acquires a clone (evicting the oldest clone-bound captive if none is free), binds it and uses `L2` from then on. A captive session that never comes back costs nothing.
   - `evidence` without a detonation (canary, honeytoken): mark captive, acquire and bind a clone now, replay the request there in `L2`.
   - a captive request that cannot get a clone → generic deny, never prod.
9. Generic deny = `404 {"detail":"Not Found"}`.

Rules (`contracts/schemas/rule.schema.json`): a rule marks a confirmed-vulnerable point. Effects, **for every identity, trusted included**: `scope: "param_present"` (what the pipeline emits for sqli and traversal) makes every request that carries the parameter suspect, whatever its value — the oracle in the clone is the detector, not a character whitelist (`1 UNION SELECT user,pass FROM users` has no unsafe character); `scope: "param"` makes only values not matching `grammar` suspect; `scope: "all"` makes every request on that route suspect; fail-closed as in step 7. A rule has no expiry unless it carries `ttl_s`: it lives until `DELETE` (the pipeline deletes it once the patch is deployed and verified). Active rules are written to `RULES_PATH` (default: `rules.json` next to `RECORD_PATH`) on every change and reloaded at start, so a restart does not uncover a confirmed-vulnerable point. `GET /_admin/rules` returns, per rule, `expires_in` (null without ttl) and `stats: {hits, oracle, denied}`; `denied` counts requests refused with no oracle fired (no clone, or inconclusive) and is the signal that a rule is hurting legitimate traffic.

Captivity: TTL 15 min idle; when no clone is free and a new capture is needed, evict the oldest captive (its clone becomes `retired`).

Passthrough mode: everything goes to prod (negative control).

Admin API on 8081, header `x-admin-token`:

```
GET  /_admin/health
PUT  /_admin/pool        {"clones":[{"id","addr","key","release"}]}   full set of registered clones
GET  /_admin/pool        {"clones":[{"id","state":"free|busy|captive|retired","session","release"}]}
GET|POST /_admin/rules ; DELETE /_admin/rules/{id}
GET|POST /_admin/upstream   {"addr":"prod-green:8000","release":"..."}   POST drains in-flight requests, then switches
GET  /_admin/sessions       {"captive":[{"session","clone","since"}]}   clone is null until bound
POST /_admin/mode           {"mode":"enforce|passthrough"}
GET  /_admin/prodlog?rid=   {"forwarded": bool, "status": n}
GET  /_admin/stats          {"prod_requests", "prod_5xx", ...} since last upstream switch
POST /_admin/reset          clear sessions, rules, stats, logs
```

Clone ingest on 9000: `POST /_clone/evidence` (headers `x-imm-clone`, `x-imm-signature`). The gateway verifies the signature with that clone's key, attaches `session`/`uid`, and publishes `oracle.fired`.

Responses to clients never contain `x-imm-*` headers.

## 7. Recording format

`runtime/recordings/requests.jsonl`, one line per client request:

```json
{"rid":"...","ts":1.0,"session":"uid:3","uid":3,"trusted":true,"method":"GET","path":"/api/products","query":"q=usb",
 "headers":{"content-type":"..."},"body_b64":"","class":"clean","reasons":[],"route":"prod","verdict":null,"status":200}
```

`x-sensitive` values and `Authorization` are replaced by `"<redacted>"`.

## 8. Fleet contract (127.0.0.1:8070, header `x-admin-token`)

```
POST /reset   {"release":"t0","pool_size":4}   stop everything fleet owns, start prod-blue on the release, create the pool, register it (PUT /_admin/pool), set upstream
POST /deploy  {"release":"<id>"}               start the idle colour on the release, health check + smoke, switch upstream via the gateway, watch /_admin/stats for 20 s, roll back on 5xx; then replace free L1 clones with the new release
GET  /state   {"prod":{"active":"blue","release":"t0"},"clones":[...]}
```

Fleet reconciles continuously: every `retired` clone is destroyed and replaced. Clone containers: network `clonenet` only, read-only root, `tmpfs /data`, `--cap-drop ALL`, `--pids-limit`, memory limit, env from §3. Names and labels are prefixed `immune-` and labelled `immune.run=<RUN_ID>`; fleet never touches containers without that label.

## 9. Pipeline contract

Trigger: `oracle.fired` events on the bus. Per incident (dedupe key: oracle kind + route + param + sink file:line):

1. Build the PoC (`contracts/schemas/poc.schema.json`), confirm it reproduces 3/3 in the runner (harness, container `--network none`).
2. Rule: derive it from the evidence, `POST /_admin/rules`.
3. Patch: `patcher.propose(release_dir, evidence, feedback) -> unified diff`. Up to 3 attempts, feeding back gate output.
4. Gates, in order, each published as `gate.result`: `policy`, `properties`, `poc`, `tests`, `legit` (`docs/plan-construccion.md` §4).
5. `RepoTarget` (`local` | `scratch` | `official`): branch `run/<run>/fix-<incident>`, PR to `run/<run>/base`, one check per gate, merge. Materialise the merged tree as `runtime/releases/<sha>/`.
6. `POST fleet /deploy`. Then verify the exploit directly against prod and through the gateway. Delete the rule.

Legit scenarios for the `legit` gate: `sim.scenarios.SCENARIOS` — a list of deterministic callables `(client) -> list[tuple[str, int, object]]` (step name, status, normalised JSON) runnable against a `starlette.testclient.TestClient` on a fresh seed.

## 10. Rules for work packages

- Write only inside your own directory. Never run `git` commands that change state (`commit`, `stash`, `checkout`, `reset`, `clean`). Never edit `contracts/`, `immune_contracts/`, `acceptance/`, `deploy/`, `e2e/`, another package, or root files.
- Never `pip install`, `apt`, `sudo`, `docker build`, `docker system prune`, or remove containers you did not create. Name your test containers `wp<N>-...`.
- Use `.venv/bin/python` and `.venv/bin/pytest`. Bind test servers to `127.0.0.1` on an ephemeral port.
- Missing dependency or contract problem → report `CONTRACT_GAP`, do not work around it.
- If you believe an acceptance test is wrong, report `ACCEPTANCE_BUG: <test> <why>` with evidence; do not change the test.
- Docker names fleet uses: networks `immune_prodnet`, `immune_clonenet`; the gateway is reachable from both as `gateway`; image `immune-base:1`.
- Your own tests go in `<package>/tests/`. The acceptance tests in `acceptance/` are the bar; do not copy or weaken them.
