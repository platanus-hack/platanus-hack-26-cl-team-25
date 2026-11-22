# fleet (WP4)

Host process, the only component with the Docker socket. `python -m fleet` serves `127.0.0.1:$FLEET_PORT` (8070),
header `x-admin-token` (`ADMIN_TOKEN`, falls back to `deploy/demo.env`).

- `POST /reset {release, pool_size}`: removes every container labelled `immune.run=<RUN_ID>`, starts `immune-prod-blue`, creates the clone pool,
  registers it (`PUT /_admin/pool`, addr `immune-clone-<n>:8000`), sets upstream `prod-blue:8000`, `POST /_admin/reset`.
  Gateway failures do not fail the call (listed in `gateway_errors`); the reconcile loop re-registers later.
- `POST /deploy {release}`: idle colour on the new release (same `runtime/data/prod` dir) -> health -> smoke (`SMOKE_PATH`, default `/openapi.json`)
  -> **canary** (below) -> gateway upstream switch -> watch `/_admin/stats` `prod_5xx` for `DEPLOY_WATCH_S` (20) -> rollback (`rolled_back: true`) or stop the old colour,
  then replace every `free` clone with one on the new release (captive/busy untouched). Events `deploy.started` / `deploy.done`.
- Canary: before the switch the gateway sends `CANARY_WEIGHT` (0.2; 0 turns it off) of the real prod traffic to the new colour for
  `CANARY_S` (8) seconds (`POST /_admin/canary`), drawn per request so both releases see the same clients. The fleet compares the two
  sides over that window (`/_admin/stats` `canary`): clearly more 5xx, or clearly more 4xx (a fix that refuses legitimate requests),
  than the release in production ends the deploy at once: `ok: false`, `rolled_back: false`, the new colour is removed and only that
  share of requests ever saw it. Fewer than `CANARY_MIN_REQUESTS` (20) canary requests prove nothing: the deploy goes on with the
  plain switch and full watch (with no traffic at all it stops waiting after 2 s). A canary that passed counts as watch time.
  The containment rule stays active the whole time (the pipeline removes it after the deploy). The result is `canary` in the
  response and in `deploy.done`: `{verdict: ok|worse|skipped, detail, weight, seconds, canary: {requests, 5xx, 4xx, conn_errors}, stable: {...}}`.
- `GET /state`: `{prod:{active,release}, clones:[{id,name,addr,release,state}], pool_size, gateway_ok, run_id}`.
- Reconcile loop (`RECONCILE_S`, 1 s): replaces `retired` (and dead) clones, keeps `pool_size`, re-registers when the gateway pool differs,
  re-applies the upstream, publishes `pool.state`. Gateway down is tolerated. State is in memory: after a fleet restart call `/reset`.

Safety: fleet only removes containers carrying `immune.run=<RUN_ID>`; a same-named unlabelled container aborts the operation.
Containers run as the host uid/gid (so cap-drop ALL can still write the bind-mounted data dir), read-only root, tmpfs `/tmp`,
no-new-privileges, pids and memory limits. Repo root is mounted ro at `/srv`, the release package over `/srv/$RELEASE_PKG`.

Env: `RUNTIME_DIR REPO_DIR RUN_ID ADMIN_TOKEN FLEET_PORT GATEWAY_ADMIN_URL FLEET_BUS_URL` (host bus, default `http://127.0.0.1:8090`; `BUS_URL`
in demo.env is the in-container address and is deliberately not used), `BUS_TOKEN PROD_APP_SECRET SHADOW_APP_SECRET`,
`RELEASE_PKG VICTIM_APP SHADOW_PROFILE`, `CLONE_CMD` (override clone command), `EXTRA_PYTHONPATH` (appended to PYTHONPATH),
`NAME_PREFIX` (default `immune`), `PRODNET CLONENET IMMUNE_IMAGE DEPLOY_WATCH_S HEALTH_TIMEOUT_S`.

Tests: `.venv/bin/pytest fleet/tests` (real Docker, temp runtime, fake gateway, `wp4-*` containers/networks, cleaned up).
