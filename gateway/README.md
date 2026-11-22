# gateway

## Purpose

The gateway is the L7 reverse proxy in front of the protected app. For every request it classifies the request
from its shape and the caller's identity, detonates the suspect ones in a clone, and routes on the clone's verdict:
to production, to the clone's answer, to a decoy, or to a 404. It also applies the rules posted by the pipeline,
splits production traffic between two releases during a deploy canary, records the traffic, and publishes
events to the bus.

It decides by execution, not by score: a request is treated as an attack when an oracle fires in a clone
(see [`shadow/`](../shadow/README.md) and [`sidecar/`](../sidecar/README.md)).

## How it runs

One asyncio process with three uvicorn listeners, started as `python -m gateway` (`gateway/__main__.py`).
`immune up` runs it as the container `immune-<project>-gateway` from `deploy/compose.yaml`.

| Listener | Port in the container | Published by `deploy/compose.yaml` | Used by |
|---|---|---|---|
| data | 8080 (`GW_DATA_PORT`) | `127.0.0.1:<ports.gateway>` | clients |
| admin | 8081 (`GW_ADMIN_PORT`) | `127.0.0.1:<ports.admin>` | fleet, pipeline, CLI |
| clone ingest | 9000 (`GW_INGEST_PORT`) | not published | clones, over the internal clone network |

The container is read-only, runs with all capabilities dropped and `no-new-privileges`, as the host user. It is
attached to the production, clone and control networks (all `internal: true`) and to the `edge` network.
It has no Docker access; clones are created by [`fleet/`](../fleet/README.md), which registers them through
`PUT /_admin/pool`.

## Layout

| File | Role |
|---|---|
| `__main__.py` | Starts the three listeners and handles SIGINT/SIGTERM once for all of them |
| `core.py` | `Config`, `Gateway`: request reading, routing decision, forwarding to prod and clones, canary split, upstream switch with drain, persisted state, recording, admin app, ingest app |
| `classifier.py` | `classify()`: reasons and class of a request; `Rule`; `Manifest`; `EnumTracker`; the built-in traversal rule; redaction helpers for the recording |
| `spec.py` | OpenAPI loading (local `$ref`), path-template matching on both readings of the path, per-value schema checks |
| `pool.py` | Clone states and captive sessions: acquire, bind, evict, idle expiry |
| `l0.py` | Fixed list of scanner paths and their deterministic decoy answers |
| `waf.py` | `WafClient`: HTTP client of the optional OWASP CRS detection service ([`waf/`](../waf/README.md)) |
| `bus.py` | Non-blocking event publisher with a retry buffer |
| `tests/` | Unit tests and a gateway run as a real process against fake prod, clone and bus (`tests/world.py`) |

## Configuration

Environment variables read by `Config.from_env` and `Recorder` in `core.py`. `immune up` sets them through
`deploy/compose.yaml` and the project's secrets file.

| Variable | Default | Meaning |
|---|---|---|
| `GW_HOST` | `0.0.0.0` | Bind address of the three listeners (inside the container) |
| `GW_DATA_PORT` | `8080` | Data listener |
| `GW_ADMIN_PORT` | `8081` | Admin listener |
| `GW_INGEST_PORT` | `9000` | Clone evidence listener |
| `GW_MODE` | `enforce` | Initial mode: `enforce`, `observe` or `passthrough`. An unknown value means `enforce` |
| `GW_AFTERCHECK` | off | `1`, `true`, `yes` or `on` enables the after-check (config key `aftercheck`) |
| `GW_STATE_PATH` | empty | File where upstream, mode and rules are persisted. Empty disables persistence |
| `GW_CAPTIVE_TTL_S` | `900` | Idle time after which a captive session is released |
| `PROD_ADDR` | `127.0.0.1:8000` | Initial upstream `host:port` |
| `PROD_RELEASE` | empty | Release id of the initial upstream |
| `PROD_APP_SECRET` | empty | Secret that verifies production tokens (`auth.kind: immune-token`) |
| `SHADOW_APP_SECRET` | empty | Secret used inside clones. A token signed with it and seen here is a honeytoken |
| `IMMUNE_AUTH` | `{"kind":"immune-token"}` | JSON of the `auth` block of `.immune/config.yaml` (see `immune/auth.py`) |
| `ADMIN_TOKEN` | empty | Required value of `x-admin-token` on the admin listener. Empty refuses every admin call |
| `BUS_URL` | empty | Base URL of the event bus. Empty disables publishing |
| `BUS_TOKEN` | empty | Sent as `x-bus-token` |
| `RUN_ID` | empty | Stamped on every event; also keys the persisted state |
| `OPENAPI_PATH` | empty | OpenAPI document of the app. Missing file or empty value means an empty spec |
| `MANIFEST_PATH` | empty | `manifest.json` of the shadow data (seed uid limit, ownership, canaries, groups) |
| `RECORD_PATH` | empty | Request recording (JSONL). Empty disables recording |
| `RECORD_MAX_MB` | `256` | Size at which the recording rotates to `<RECORD_PATH>.1` (one generation kept) |
| `WAF_URL` | empty | Base URL of the detection service of [`waf/`](../waf/README.md). Empty disables the check. `immune up` sets it to `http://waf:8080` only with `IMMUNE_WAF=1` in its environment |

With `auth.kind: jwt-hs256` the production secret is read from the variable named by `auth.secret_env`
(`immune/auth.py`, `prod_secret_for`).

Fixed constants in `core.py`: request body limit 10 MiB (`MAX_BODY`), body read timeout 30 s, wait for a free clone
0.3 s (`CLONE_WAIT_S`), production timeout 30 s (connect 3 s), clone timeout 20 s (connect 1 s), detection
service timeout 1.5 s (`WafClient`).

## Behaviour

### Request path

```mermaid
flowchart TD
    A[request] --> B{captive session<br/>and identity not trusted}
    B -- yes --> L2[bound clone, L2]
    B -- no --> C{scanner path<br/>not in the OpenAPI}
    C -- yes --> L0[decoy answer]
    C -- no --> D[classify]
    D -- clean --> W{WAF_URL set and<br/>the service reports an anomaly}
    W -- no --> P[production]
    W -- yes --> F
    D -- evidence --> E{trusted}
    E -- yes --> X[deny 404]
    E -- no --> L2
    D -- suspect --> F[detonate in a free clone, L1]
    F --> G[decision table]
```

This is `Gateway.handle` in enforce mode. The steps in detail, numbered as in `contracts/README.md` section 6.3:

1. **Read** (`_read`). The body is read in full before anything is forwarded. A request with a non-origin-form
   target gets 400, a body over 10 MiB gets 413, a body not completed in 30 s gets 408. A client that disconnects
   mid-body is dropped: not forwarded, not answered, not recorded. Client headers starting with `x-imm-` are
   removed. The identity is resolved in the same step (`resolve`, `identify`). `auth.kind` decides how: `immune-token` and `jwt-hs256` verify the bearer
   token locally; `introspect` asks production (`GET <auth.path>` with the client's `Authorization` and `Cookie`,
   cached per credential for `auth.cache_s`, default 30 s, 5 s for a negative answer); `none` treats everyone as
   anonymous. Trust is binary: an identity is trusted when `uid <= seed_max_uid` of the manifest. Newer and
   anonymous identities are untrusted.
2. **Session key**. `uid:<n>` for an identified client, else `gwsid:<cookie>`. A missing or malformed `gwsid`
   cookie is minted and set on the response (`HttpOnly; SameSite=Lax`). The `gwsid` cookie is removed from the
   `Cookie` header forwarded to production and clones.
3. **Captive session**. An untrusted identity whose session is captive is served from its clone and never from
   production. For an identified client the cookie session is checked too, so a captive anonymous client stays
   captive after it logs in.
4. **L0**. A path in `l0.SCANNER_PATHS` (or under `/wp-admin/`, `/phpmyadmin/`) that the OpenAPI does not define
   gets a fake answer whose content is derived from a hash of path and session. No production call is made.
5. **Classification** (`classifier.classify`). A request classified `clean` is then sent to the detection
   service when `WAF_URL` is set (`_waf_upgrade`); an anomaly makes it `suspect`. Then the decision below.

### Classification reasons

A request with no reason is `clean`. A request with `honeytoken` or `canary:*` is `evidence`. Any other reason
makes it `suspect`.

| Reason | Fires when | Needs the route in the OpenAPI |
|---|---|---|
| `path:encoded_slash` | The two readings of the path (decode then split, split then decode) route to different operations, or only one of them routes | at least one reading must match an operation |
| `honeytoken` | The bearer token verifies with the shadow secret | no |
| `dup_query:<name>` | A query parameter appears more than once | no |
| `traversal:path` | A `..` path segment under any of the handled encodings (up to 4 decode rounds, overlong UTF-8 forms, backslash) | no |
| `traversal:query.<name>` | A query value contains `../`, ends in `/..` or is `..` | no |
| `schema:<where>.<name>:<kind>` | A value violates its declared schema. `kind` is `type`, `enum`, `bounds`, `length` or `pattern`; `where` is `query`, `path`, `header`, `form` or `json` | yes |
| `schema:json:invalid`, `schema:form:invalid` | The body cannot be parsed as its declared type | yes |
| `grammar:<where>.<name>` | A textual value is outside the safe-default grammar (`immune_contracts/grammar.py`); catch-all path parameters also allow `/` | yes |
| `grammar:query.key`, `grammar:json.key` | A parameter name or JSON key is not `[A-Za-z0-9_-]{1,64}` | yes |
| `owner_scoped:anonymous`, `owner_scoped:untrusted` | The operation is `x-owner-scoped` and the identity is not trusted | yes |
| `owner_scoped:mismatch:<param>` | The operation is `x-owner-scoped`, the identity is trusted and not admin, and the manifest attributes the addressed object to someone else | yes |
| `canary:<param>` | A path parameter equals a canary id of the manifest and the caller is neither its owner nor admin | yes |
| `enumeration` | One session addressed more than 8 distinct parameter tuples on one `x-owner-scoped` template within 30 s. The tuple is the path parameters; query parameters whose OpenAPI declaration carries `x-owner-id: true` are counted the same way | yes |
| `rule:<id>` | An active rule matches (see Rules) | no |
| `waf:<rule id>` | Added by `core.py` (`_waf_upgrade`) to a request `classify` called clean, when the detection service answers `anomalous: true`. `<rule id>` is the CRS rule that interrupted the evaluation, or `crs` when the answer names none | no |
| `scanner` | Assigned by `core.py` to L0 requests | no |
| `captive` | Prefixed by `core.py` for requests of a captive session | no |

Details that change what is caught:

- Routes and rules match on the path decoded once and then split on `/` (what uvicorn and starlette do), and also
  on the path split first and then decoded. A match on either reading counts. `%252F` and `%5C` are never
  separators.
- `x-sensitive` parameters and JSON properties are not inspected at all. In the recording, the `x-sensitive`
  values of path and header parameters, of the query string, of a JSON body and of form fields (URL-encoded or
  multipart) are replaced by `<redacted>`.
- Header parameters are inspected only when the OpenAPI declares them. Cookies are not inspected. File parts of a
  multipart body are ignored.
- Ownership (`classifier._owns`) comes from the manifest: a `group_routes` entry means membership in the group;
  `user_id` is compared with the caller's uid; `<name>_id` is looked up in `ownership["<name>s"]`. An object
  absent from the manifest is not flagged.

### Decision for a suspect request

`Gateway._detonation` runs the request in a free clone in mode L1 (the clone resets itself afterwards) and
decides. "Fail closed" means: a rule matched, or the reason `traversal:path` is present, or any reason starts
with `schema:`, `grammar:`, `dup_query:` or `traversal:`. A rule matches "strictly" (`Result.rule_strict`) when
its scope is `all` or `param`, or its scope is `param_present` and the value is outside its grammar (see Rules).
The function returns `prod`, `deny`, `rule_deny` or `shadow_l1`; `rule_deny` is a deny decided without an
oracle, recorded with route `deny` and counted in the `denied` statistic of each rule that matched.

| Clone verdict | Identity | Condition | Route | Client receives |
|---|---|---|---|---|
| no clone answered | any | fail closed | `deny` | 404 `{"detail":"Not Found"}` |
| no clone answered | any | otherwise | `prod` | production's response |
| `oracle` | trusted | | `deny` | 404 |
| `oracle` | untrusted | | `shadow_l1` | the clone's response; the session becomes captive |
| `clean` or `inconclusive` | any | reason `traversal:path` present | `deny` | 404 |
| `clean` | any | otherwise | `prod` | production's response |
| `inconclusive` | any | a rule matched strictly | `deny` | 404 |
| `inconclusive` | any | otherwise | `prod` | production's response |

"No clone answered" covers no free clone within 0.3 s and a clone that failed (it is retired; the fleet replaces
it). When no clone was free the gateway also retires the clone of the oldest clone-bound captive session, so the
fleet replaces it and a later detonation finds one. A missing or
unknown verdict header counts as `inconclusive`. A handler exception results in `deny`.

Evidence (`honeytoken`, `canary:*`) is not detonated: a trusted identity is denied; an untrusted one becomes
captive at once and the request is replayed in its L2 clone (deny when no clone can be bound).

### Captive sessions and the clone pool (`pool.py`)

- Clone states: `free`, `busy` (one L1 request), `captive` (bound to one session), `retired`. A retired clone is
  never reused.
- Captivity is lazy. An L1 oracle marks the session captive and releases the clone. The session's next request
  binds a clone, evicting the oldest bound captive when none is free. An evicted session stays captive and binds
  again on its next request.
- A clone serves one request at a time (per-clone lock), so a bound session is serialised on its clone.
- Limits: a global cap of 50000 captive sessions (`Pool.max_sessions`, oldest unbound dropped first) and the idle
  TTL `GW_CAPTIVE_TTL_S`. There is no per-origin cap.
- Requests to a clone carry `x-imm-rid`, `x-imm-mode` and, for an identified client, `x-imm-uid` and `x-imm-role`
  (production tokens do not verify inside a clone). Response headers starting with `x-imm-` are never sent to
  the client.

### Rules

A rule marks a point confirmed vulnerable (`classifier.Rule`, `contracts/schemas/rule.schema.json`). Rules are
never scoped to an IP address, a fingerprint or a user agent.

| Field | Meaning |
|---|---|
| `id`, `incident` | Identifier (posting an existing id replaces the rule) and the incident it belongs to |
| `method`, `route` | HTTP method (`*` and `ANY` match all; a `GET` rule also covers `HEAD`) and path template, matched on both readings of the path; the route does not have to be in the OpenAPI |
| `scope` | `param`, `param_present` or `all` (table below) |
| `param` | `{in, name}` with `in` one of `path`, `query`, `header`, `json`, `form`; required unless the scope is `all` |
| `grammar` | Full-match regular expression; when absent and the scope is not `all`, `grammar.SAFE_DEFAULT` |
| `identity` | Optional. `untrusted`: the rule is skipped for a trusted identity. Absent: it applies to every identity, trusted included |
| `ttl_s` | Lifetime in seconds, at least 1. `null` or absent: the rule has no expiry and lives until it is deleted |

| Scope | The rule matches when | Strict match |
|---|---|---|
| `all` | any request on the route | always |
| `param` | a value of the parameter is outside the grammar | always |
| `param_present` | the request carries the parameter, whatever its value | only when a value is outside the grammar |

A rule hit does not block by itself. It adds the reason `rule:<id>`, which makes the request suspect and fail
closed: the request is detonated, and it reaches production only when the clone says `clean`, or when the clone
is `inconclusive` and the match is not strict. A rule is therefore as strong as the oracle behind it. The
non-strict case exists because a clone holds synthetic credentials: a real user's login is a 401 there, and
denying every inconclusive request that carries the parameter would close the endpoint. When no clone answers,
any rule hit denies, strict or not.

A rule ends by its TTL when it has one (`rule.expired`, reason `ttl`), by `DELETE /_admin/rules/{id}` (reason
`deleted`; the pipeline does this once the fix is deployed and verified) or by `POST /_admin/reset` (reason
`reset`).

Each rule keeps three counters, returned as `stats` by `GET /_admin/rules`: `hits` (detonations the rule
caused), `oracle` (of those, an oracle fired) and `denied` (denied without an oracle: no clone, or a strict
match with an inconclusive verdict). A growing `denied` means the rule is refusing requests that no oracle
confirmed. The counters are in memory only and are not updated in observe mode.

### Modes

| Mode | Behaviour |
|---|---|
| `enforce` | As described above |
| `observe` | Classifies and detonates like enforce, answers every request from production, never evicts or captures. The decision enforce would have taken is recorded as `would_route`, and events carry `observe: true`. The detection service is not consulted |
| `passthrough` | Classifies for the record and forwards everything to production. No detonation, no detection service, and no `request.classified` event |

`immune mode` switches between `observe` and `enforce`. `passthrough` is reachable only through `GW_MODE` or
`POST /_admin/mode`.

### After-check

Off by default (`GW_AFTERCHECK`). When on, in enforce mode, each distinct clean request that production already
answered is replayed once per release in an L1 clone by a single background worker (queue of 256, 2 s wait for a
clone). If an oracle fires, the evidence opens an incident as for any detonation, the request is marked in the
recording so it stays out of the legitimate corpus, and an untrusted session becomes captive from its next
request.

### Detection service (WAF)

With `WAF_URL` set, `_waf_upgrade` posts each request that `classify` called clean, in enforce mode, to
`<WAF_URL>/eval` (`waf.py`, `WafClient.check`: method, path, query, headers, base64 body). When the answer is
200 with `anomalous: true`, the request becomes `suspect` with the reason `waf:<rule id>` and is detonated like
any other suspect request. The service never blocks: a `waf:` reason does not make a request fail closed, so
without a clone or with an `inconclusive` verdict the request goes to production. Any error, timeout (1.5 s) or
non-200 answer leaves the request clean. The call is made inline, so it adds its latency to every clean request.
Captive sessions, scanner paths and the `observe` and `passthrough` modes do not consult it.

### Forwarding to production

- The request target is sent byte for byte as the client sent it; dot segments are not resolved.
- Hop-by-hop headers are removed in both directions. Responses are fully buffered; `content-encoding`, `date`
  and `server` are dropped.
- A connection error before anything was sent is retried once for any method. A broken pooled connection is
  retried once for `GET`, `HEAD` and `OPTIONS` only. A timeout answers 504, any other failure 502.
- A request that cannot be put on the wire as sent answers 400 and is not counted as a production error.
- `POST /_admin/upstream` closes the gate for new production requests, waits up to 30 s for in-flight ones,
  ends a running canary, switches, resets the statistics and reopens.

### Canary

`POST /_admin/canary {addr, release, weight}` (`start_canary`) makes `to_prod` send each production-bound
request to `addr` with probability `weight` (0 < weight <= 1) and to the stable upstream otherwise. The side is
drawn per request, not per session, so both releases receive the same mix of clients. The fleet uses it before
the upstream switch of a deploy ([`fleet/README.md`](../fleet/README.md)).

- Counters are kept per side as `{requests, 5xx, 4xx, conn_errors}` and returned in `canary` of
  `GET /_admin/stats` and by `GET /_admin/canary`. Requests answered by the canary are not counted in
  `prod_requests`, `prod_5xx` or `prod_conn_errors`, which describe the stable release.
- A connection refused by the canary is counted against it (one request, one 5xx, one connection error) and
  the request is sent to the stable upstream instead; the client does not see the failure.
- A request answered by the canary is recorded with the canary's release id in `release`.
- The canary ends by `DELETE /_admin/canary` (`canary.done`, reason `aborted`), by an upstream switch (reason
  `promoted` when the new upstream is the canary address, else `superseded`) or by `POST /_admin/reset` (no
  event). It is not persisted: a restarted gateway serves the stable upstream only.

### Persisted state

With `GW_STATE_PATH` set, the upstream, the mode and the active rules (with their expiry times) are written to
that file on every change and restored at start when the file's `run_id` equals `RUN_ID`. `immune up` points it
at `<runtime>/stack/gateway-state.json`. A rule without a TTL is stored with an infinite expiry (the JSON token
`Infinity`, which Python's `json` writes and reads). Captive sessions, the clone set, a running canary, the
production log, enumeration counters, per-rule counters and statistics are in memory only; the fleet registers
the clone set again.

### Admin API (port 8081)

Every route requires `x-admin-token` (constant-time comparison); otherwise 403.

| Route | Purpose |
|---|---|
| `GET /_admin/health` | Mode, upstream, pool counts |
| `GET /_admin/pool`, `PUT /_admin/pool` | Read or replace the full clone set `{clones:[{id, addr, key, release}]}` |
| `GET /_admin/rules`, `POST /_admin/rules`, `DELETE /_admin/rules/{id}` | Active rules, each with `expires_in` (`null` without a TTL) and `stats: {hits, oracle, denied}`; add one or a list (201, or 422 when invalid); remove |
| `GET /_admin/upstream`, `POST /_admin/upstream` | Read or switch the upstream `{addr, release}` |
| `GET /_admin/canary`, `POST /_admin/canary`, `DELETE /_admin/canary` | Read, start (`{addr, release, weight}`, 422 unless `0 < weight <= 1`) or stop the canary; each answers `{canary: <view or null>}` |
| `GET /_admin/sessions` | Captive sessions |
| `POST /_admin/mode` | `{mode: enforce|observe|passthrough}` |
| `GET /_admin/prodlog?rid=` | `{forwarded, status}` for one request id (last 50000 requests) |
| `GET /_admin/stats` | Counters since the last upstream switch: production requests, 5xx, connection errors, by class, by route, after-check, events dropped; `canary` holds the canary view or `null` |
| `POST /_admin/reset` | Releases every captive session, removes every rule, drops a running canary, clears counters. Does not truncate the recording |

### Clone ingest (port 9000)

`POST /_clone/evidence`: a clone pushes its evidence, signed with HMAC-SHA256 of the body under the clone's key
(`immune_contracts/wire.py`). An unknown clone or a bad signature gets 403. The gateway adds the session and uid
of the request and publishes `oracle.fired`.

### Recording and events

- One JSON line per answered request in `RECORD_PATH`: identity, method, path, query, headers, base64 body,
  class, reasons, route, verdict, status, latency, release, mode. `Authorization`, `Cookie` and
  `Proxy-Authorization` values and every `x-sensitive` value (path, header, query, JSON, form fields) are redacted.
- Events published: `request.classified`, `request.routed`, `oracle.fired`, `session.captured`,
  `session.released`, `rule.active`, `rule.expired`, `upstream.switched`, `canary.started`, `canary.done`.
  Publishing never blocks a request.
  `request.*` events are dropped when the bus fails; the others are retried for 120 s (at most 2000 kept). The HTTP
  timeout is 1.0 s, connect 0.3 s.

Wire-level detail (headers, schemas, event payloads) is in [`contracts/`](../contracts/README.md).

## Tests

```
.venv/bin/pytest gateway/tests -q
.venv/bin/pytest acceptance/gateway -q
```

Neither needs Docker or the LLM. `gateway/tests` runs the gateway as a subprocess against in-process fakes;
the acceptance suite does the same with the fixture app in `acceptance/fixture/`. `tests/test_rule_present.py`
covers the `param_present` scope (strict and non-strict matches, per-rule counters, deny without a clone) and the
persistence of rules across a gateway restart; `tests/test_waf.py`
covers `WafClient` against a mocked transport (anomaly, connection error, non-200) and `_waf_upgrade` (an
anomaly turns a clean request into a suspect one; no service or a benign answer leaves it clean).
No test of this directory runs the Go service of `waf/`. The canary is tested in `fleet/tests/test_canary.py`.

## Limits

- An `inconclusive` verdict (the clone answered 401, 404 or 5xx) fails open to production unless a rule matched
  strictly. This includes a `param_present` rule whose value is inside its grammar: an attack value made only
  of grammar characters that leaves the clone inconclusive reaches production.
- A rule with `identity: untrusted` does not apply to trusted identities: a seeded account can still reach the
  vulnerable point.
- A rule without a TTL stays until something deletes it. The pipeline deletes it after a verified fix; a rule of
  an incident that never gets a fix is removed only by `DELETE /_admin/rules/{id}` or a reset.
- The detection service is optional, fails open, and only widens what is detonated; it is not wired into
  `deploy/compose.yaml`.
- `gwsid` is supplied by the client and unsigned. Captivity of an anonymous client holds only while the client
  keeps sending the cookie.
- The built-in traversal rule recognises `..` segments only. Absolute paths and other file-access tricks depend
  on the schema, the grammar and the oracles.
- A route missing from the OpenAPI classifies clean unless a rule, the built-in traversal rule, a duplicated query
  parameter or a honeytoken applies. A scanner path gets the L0 decoy.
- `x-sensitive` fields, undeclared headers and cookies are not inspected.
- Clones run the seed snapshot. An object created in production after the seed is a 404 in the clone, hence
  `inconclusive`.
- Identity trust is a seed-uid threshold. There is no grading by account age, MFA or payment history.
- L0 is a fixed list of paths with static decoys. There is no generated pagination and no slow drip.
- Captive sessions have a global cap and an idle TTL only.
- The honeytoken is the only decoy credential: a token signed with the shadow secret. No other credentials are
  planted.
- The ownership lookup assumes the manifest key is the parameter name without `_id` plus `s`.

The full list across components is in [`docs/limites.md`](../docs/limites.md).
