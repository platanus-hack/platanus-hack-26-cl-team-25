# dashboard (WP7): event bus + live dashboard

    BUS_TOKEN=... [BUS_STORE=runtime/bus/events.jsonl] [DASH_HOST=0.0.0.0 DASH_PORT=8090] python -m dashboard

- Bus (see `immune_contracts/events.py`): `POST /events` (header `x-bus-token`; one event or a list; unknown `type` -> 400, whole batch rejected), `GET /events?since=&type=&limit=`, `GET /events/stream?since=` (SSE, `id:` = seq, replays history then live, `Last-Event-ID`, `: hb` heartbeat every 15 s), `POST /admin/clear` (same token; empties the store; seq keeps growing and live subscribers get an SSE `reset` event), `GET /health`. If `BUS_TOKEN` is unset every write is refused.
- UI at `/`: static files in `static/`, no build step, no external resources, CSP `default-src 'self'`. `state.js` is the pure reducer (events -> state), shared by the browser and the node test; `app.js` builds the DOM with `textContent` only.
- Demo without the rest of the system: `BUS_TOKEN=... python dashboard/demo_events.py [--url ...] [--speed 2] [--clear]`.
- Tests: `.venv/bin/pytest dashboard/tests -q` (also runs `node dashboard/tests/reducer.test.js`).

Correlation rules the UI relies on (the contract has no explicit ids for these): `oracle.fired` is attached to the incident whose `sink` file:line appears in the evidence stack; `deploy.*` is attached to the merged incident whose `sha` prefixes the release (else the oldest merged one without a deploy).
