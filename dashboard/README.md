# dashboard

## Purpose

`dashboard` is two things in one process: the event bus every other component publishes to, and the live web
panel that renders those events. The bus accepts events over HTTP, numbers them, keeps them in memory and appends
them to a JSONL file. The panel replays that history and follows new events over server-sent events.

## How it runs

```
BUS_TOKEN=... [BUS_STORE=runtime/bus/events.jsonl] python -m dashboard
```

One Starlette app served by uvicorn (`dashboard/__main__.py`, `dashboard/server.py`). `immune up` runs it as the
container `immune-<project>-dashboard` from `deploy/compose.yaml`: read-only, capabilities dropped, on the
networks `ctrlnet` and `edge`, with the store at `<runtime>/bus/events.jsonl` and port 8090 published on
`127.0.0.1:<ports.dashboard>`.

On SIGTERM the open event streams are ended so the process exits at once.

`immune fuxa dashboard` starts the same app a second way (`immune/fuxa_dashboard.py` `serve`): on the host, bound
to `127.0.0.1` (default port 8091), with no store and no bus token, fed in-process from the FUXA demo's records
through the `lifespan` argument of `create_app`, and with two extra public routes, `GET /fuxa/requests` and
`GET /fuxa/restrictions`. With no token configured, `POST /events` on that instance always answers 401.

## Layout

| File | Role |
|---|---|
| `__main__.py` | Entry point; reads `DASH_HOST` and `DASH_PORT` |
| `server.py` | `Bus` (sequence numbers, memory window, JSONL store, rotation), `redact()`, the routes, security headers |
| `static/index.html`, `static/style.css` | The page. No build step, no external resources |
| `static/state.js` | Pure reducer: events to page state. Runs in the browser and under node |
| `static/app.js` | DOM layer and stream connection |
| `static/inter.woff2`, `static/mono.woff2` | Fonts, licensed as stated in `FONTS-LICENSE.txt` |
| `demo_events.py` | Posts a scripted, invented event sequence to develop the page without a stack |
| `tests/` | Bus, public surface, static checks, and the reducer test run with node |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `BUS_TOKEN` | empty | Required value of `x-bus-token` for writes. Empty refuses every write |
| `BUS_STORE` | none | JSONL file of the bus. Unset: memory only |
| `DASH_HOST` | `0.0.0.0` | Bind address (inside the container) |
| `DASH_PORT` | `8090` | Port |
| `DASH_REDACT` | `1` | `0` serves unredacted events to every reader |
| `DASH_EVENTS_LIMIT` | `1000` | Page size of `GET /events` when the client sends no `limit` |
| `DASH_EVENTS_LIMIT_MAX` | `5000` | Largest page a client may ask for |
| `DASH_MAX_BODY_MB` | `32` | Largest `POST /events` body |
| `DASH_MAX_EVENTS` | `50000` | Events kept in memory |
| `DASH_STORE_MAX_MB` | `256` | Size at which the store rotates to `<store>.1`; `0` disables rotation |
| `DASH_MAX_STREAMS` | `200` | Concurrent event streams; the next one gets 503 |
| `DASHBOARD_SUBTITLE` | empty | Text shown next to the page title. Sent to the page in the stream's `hello` message. `deploy/compose.yaml` passes it through; `immune up` takes it from its own environment and, when unset, sets it only for the project named `openemr` (`compose_env` in `immune/__main__.py`) |

## Behaviour

### Routes

| Route | Access | Behaviour |
|---|---|---|
| `GET /` | public | The page |
| `GET /static/<file>` | public | `app.js`, `state.js`, `style.css` and the two fonts; nothing else is served |
| `GET /health` | public | `{ok, events, seq}` |
| `GET /events?since=&type=&limit=` | public | One page of events with `seq > since`, optionally filtered by type prefix. The response carries `next`; a reader follows it until a page comes back empty |
| `GET /events/stream?since=` | public | Server-sent events: history after `since` (or `Last-Event-ID`), then live |
| `POST /events` | `x-bus-token` | One event or a list. An unknown `type` rejects the whole batch with 400; a body over the limit gets 413 |
| `POST /admin/clear` | `x-bus-token` | Empties memory and the store, removes the rotated file |

A write without the token, or with any token when `BUS_TOKEN` is empty, gets 401. The token is compared in
constant time. These two POST routes are the only ones that change state; `tests/test_public_surface.py` lists
the routes and fails if another appears.

Accepted event types are the ones in `immune_contracts/events.py` (`TYPES`). Each stored event has `seq`, `ts`, `run`, `src`, `rid`,
`incident`, `type` and `data`.

### Stream protocol

- The stream opens with `event: hello` carrying `{gen, seq}`, plus `subtitle` when `DASHBOARD_SUBTITLE` is set. `gen` identifies the stored history: it survives a
  restart on the same store and changes when the store is cleared or replaced. A page that reconnects to a
  different history starts over.
- Each event is sent with `id: <seq>`.
- After `POST /admin/clear`, live streams receive `event: reset`. Sequence numbers keep growing.
- A heartbeat (`: hb` plus `event: hb`) is sent after 15 s without events. The page reconnects by itself after
  40 s of silence.

### What an unauthenticated reader sees

Readers that do not send `x-bus-token` get a redacted copy of each event (`server.redact`), unless
`DASH_REDACT=0`.

| Redacted | How |
|---|---|
| Values of sensitive headers inside a `headers` object (names matching authorization, cookie, token, secret, api key, password, session, credential, signature) | `[redacted]`; the scheme is kept, as in `Bearer [redacted]` |
| `body_b64`, `pre_state_b64`, oracle `statement` | `[redacted: N chars]` |
| Values of sensitive-named parameters in a `query` string or in the query part of `path`, `url`, `target` | `[redacted]` |
| `file:///` URLs (local pull requests) | host path removed |
| `gwsid:<cookie>` session keys | `gwsid:~<12 hex>`, a keyed hash that is stable within one dashboard process |

Not redacted: method, path, non-sensitive query parameters, `uid:<n>` session keys, stack frames, diffs, gate
details, rule grammars and timings. With the token, readers get the stored event. The JSONL store is never
redacted.

### Bounds

- Memory holds at most `DASH_MAX_EVENTS` events. Past that, events of earlier runs are evicted first, then the
  `request.*` events of the current run, then the oldest. The JSONL store keeps everything it has not rotated out.
- The store rotates to `<store>.1` at `DASH_STORE_MAX_MB`; one old generation is kept and both are loaded at
  start.

### Page

- Event data enters the DOM through `textContent` only. Every response carries a Content-Security-Policy with
  `script-src 'self'`, plus `nosniff`, `no-referrer` and `X-Frame-Options: DENY`. `tests/test_static.py` fails on
  HTML sinks, inline scripts and external URLs in the static files.
- The header shows "Corrida <run id>".
- An `oracle.fired` event belongs to the incident whose `evidence_rid` equals its `rid`. An oracle with no
  incident yet is shown as a confirmed attack waiting for the pipeline. `deploy.*` and `upstream.switched` carry
  no incident id; they are attached to the merged incident whose commit `sha` prefixes the release.
- Timings follow `immune/metrics.py`: everything is measured from `incident.opened`; the rule time is the first
  `rule.active`; the in-production time is the first `upstream.switched` after `pr.merged`. The wait between the
  oracle (or the audit finding) and `incident.opened` is shown separately as queue time.
  `tests/test_public_surface.py` compares the page's numbers with `immune.metrics` on a recorded run
  (`tests/fixtures/real_run.jsonl`).
- Canary: between `canary.started` and `canary.done` the production panel shows the share of traffic and the
  release under canary; the `canary` object of `deploy.done` is summarised in the incident's deploy section.
- FUXA mode: once a `fuxa.status` event is in the current run the page switches layout (subtitle
  "Estación Delta · FUXA v1.2.9", panels "Estado de FUXA" and "Peticiones en vivo", the latter polled from
  `GET /fuxa/requests`, which only the `immune fuxa dashboard` instance serves). `session.restricted` events fill
  the panel "Restricciones de sesión" until `session.released`; `fuxa.review` marks an incident's candidate as
  waiting for approval.
- Accepted but not displayed: `prod.alert` events are kept in the reducer's state (last 50) and no panel renders
  them; `outcome_detail` of `incident.closed` is not read, so an escalated incident appears as `rule_only`; a
  `gate.result` whose gate is not one of `policy`, `properties`, `poc`, `tests`, `legit` (the `build` gate of
  `pipeline/extfix.py`) is not shown. Event types without a reducer case are counted as ignored.
- The panel "Bot atacante" appears only when the current run has `attack.attempt` events. They come from the demo
  attacker `sim/attacker.py` (real attempts against the running shop) or from `demo_events.py` (invented, labelled
  "DEMO").

### Scripted events for UI development

```
BUS_TOKEN=... python dashboard/demo_events.py [--url http://127.0.0.1:8090] [--speed 1.0] [--clear]
```

`demo_events.py` posts about 110 invented events with `run="demo"`: routes, diffs, SHAs and timings are made up
and nothing in them was measured. It refuses a `--url` that is not a loopback address unless
`--i-know-this-is-scripted` is passed. While any such event is on the page, the header shows
"DEMO · datos guionados" and the connection is labelled "Conectado", never "En vivo".

## Tests

```
.venv/bin/pytest dashboard/tests -q
```

No Docker and no LLM. The reducer test (`tests/reducer.test.js`) and one page test need `node` and are skipped
without it.

## Limits

- The read side is public by design. Anyone who can reach the port sees paths, non-sensitive query parameters,
  stack frames and diffs. Redaction is by key name and value shape, not by content inspection: a secret placed
  in a non-sensitive-named query parameter or in a path segment is shown.
- The public session name is stable only within one dashboard process.
- The page rebuilds its state from the events in memory. After eviction, request counts of the current run and
  incidents of earlier runs are incomplete on the page; the store still has them.
- There is one bus token for all writers and no per-writer identity.
- The "Bot atacante" panel shows only what `sim/attacker.py` reports: the seven documented exploits of the shop,
  not an attacker that finds new defects.

The full list across components is in [`docs/limites.md`](../docs/limites.md). Operation (ports, files under the
runtime directory) is in [`docs/operacion.md`](../docs/operacion.md).
