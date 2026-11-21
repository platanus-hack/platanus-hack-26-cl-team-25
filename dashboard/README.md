# dashboard (WP7): event bus + live dashboard

    BUS_TOKEN=... [BUS_STORE=runtime/bus/events.jsonl] [DASH_HOST=0.0.0.0 DASH_PORT=8090] python -m dashboard

- Bus (see `immune_contracts/events.py`): `POST /events` (header `x-bus-token`; one event or a list; unknown `type` -> 400, whole batch rejected), `GET /events?since=&type=&limit=`, `GET /events/stream?since=` (SSE, `id:` = seq, replays history then live, `Last-Event-ID`, `: hb` heartbeat every 15 s), `POST /admin/clear` (same token; empties the store; seq keeps growing and live subscribers get an SSE `reset` event), `GET /health`. If `BUS_TOKEN` is unset every write is refused.
- UI at `/`: static files in `static/`, no build step, no external resources, CSP `default-src 'self'`. `state.js` is the pure reducer (events -> state), shared by the browser and the node test; `app.js` builds the DOM with `textContent` only.
- Demo without the rest of the system: `BUS_TOKEN=... python dashboard/demo_events.py [--url ...] [--speed 2] [--clear]`.
- Tests: `.venv/bin/pytest dashboard/tests -q` (also runs `node dashboard/tests/reducer.test.js`).

Read side, as served to anyone (the page is meant to be published read-only):

- Readers that do not send `x-bus-token` get a redacted copy of each event: the value of every credential-like header inside a `headers` object (`authorization`, `cookie`, `*token*`, `*key*`, ...) becomes `[redacted]` (the scheme is kept: `Bearer [redacted]`) and `file:///...` urls lose their host path. Everything else, including `rid`, `session`, `uid`, bodies and `pre_state_b64`, is unchanged. With the token, `GET /events` and `/events/stream` return the stored event. `DASH_REDACT=0` turns redaction off. The pipeline reads without the token today, so it sees `Bearer [redacted]`; if it ever needs the original header it has to send the token.
- The stream opens with `event: hello` (`{"gen", "seq"}`). `gen` identifies the stored history: it survives a restart on the same store and changes when the store is cleared or replaced, so a page that reconnects to a different history starts over instead of mixing two runs. The heartbeat is `: hb` plus a named `event: hb` (the page reconnects by itself after 40 s of silence). At most `DASH_MAX_STREAMS` (200) streams are open at once; the next one gets 503.
- On SIGTERM open streams are ended so the process exits at once (before, uvicorn waited for them and the old process kept the pages attached to it).
- Every response carries the CSP, `nosniff`, `no-referrer` and `X-Frame-Options: DENY`. The only routes that change state are `POST /events` and `POST /admin/clear`, both behind the token (`tests/test_public_surface.py` lists them and fails if a new one appears).

Correlation rules the UI relies on: `oracle.fired` belongs to the incident whose `evidence_rid` equals its `rid` (several incidents share the sink `db.py:25`, so the sink only decides for later hits, together with the route); an oracle that has no incident yet is shown as a confirmed attack waiting for the pipeline. `deploy.*` and `upstream.switched` carry no incident and go to the merged incident whose `sha` prefixes the release (else the oldest merged one still waiting).

Timings on the page are the ones of `python -m immune.metrics` (`tests/test_public_surface.py` compares them on a recorded run, `tests/fixtures/real_run.jsonl`): everything is measured from `incident.opened`; "regla" is the first `rule.active`, "parche en producción" is the first `upstream.switched` after `pr.merged`; the wait between the oracle (or the audit finding) and `incident.opened` is shown apart as "en cola". `seconds_to_rule` / `seconds_to_patch` of `incident.closed` are not used (they include the queue and the verification).
