# waf

## Purpose

A detection-only verdict service: it evaluates one HTTP request against the OWASP Core Rule Set (CRS v4) with
the Coraza engine and reports whether the rule set would have blocked it. It does not proxy and does not
block. The gateway can ask it about requests its own classifier called clean; when the answer is "anomalous"
the gateway reclassifies the request as suspect, so it is detonated in a clone instead of going straight to
production.

## How it runs

One Go process, built and run from `waf/Dockerfile`:

```bash
docker build -t immune-waf:1 waf
docker run -d --name immune-waf -p 127.0.0.1:8085:8080 immune-waf:1
```

The gateway uses it only when its environment has `WAF_URL` (for the example above,
`WAF_URL=http://127.0.0.1:8085`). The only place in the repository that starts the service and sets `WAF_URL`
is `labs/scadabr-cve-2026-8602/lab.sh`. `immune up` and `deploy/compose.yaml` do not start it, so in a stack
started by the CLI the WAF is off.

| Route | Request | Response |
|---|---|---|
| `POST /eval` | JSON `{method, path, query, headers: {name: value}, body_b64}` | 200, JSON `{anomalous, rule_id, status, msg}`; 400 on a body that is not JSON |
| `GET /health` | none | 200 |

The service has no authentication. `path` is the raw request path; `query` is appended after `?`. An empty
`method` is treated as `GET`.

## Layout

| File | Role |
|---|---|
| `main.go` | The whole service: Coraza set-up (`main`), one evaluation (`evaluate`) |
| `go.mod` | Module name and Go version; it lists no dependencies |
| `Dockerfile` | Two-stage build: `golang:1.25-alpine` fetches the dependencies with `go get` and builds; the binary runs on `alpine:3.20` |

The client lives in the gateway: `gateway/waf.py` (`WafClient`) and `Gateway._waf_upgrade` in `gateway/core.py`.

## Configuration

| Variable | Read by | Default | Meaning |
|---|---|---|---|
| `WAF_ADDR` | the service (`main.go`) | `0.0.0.0:8080` | Listen address |
| `WAF_URL` | the gateway (`Config.from_env` in `gateway/core.py`) | empty | Base URL of the service; empty disables the check |

The rule set configuration is fixed in `main.go`: `@coraza.conf-recommended`, `@crs-setup.conf.example`, every
`@owasp_crs/*.conf`, then `SecRuleEngine On`. The CRS defaults (paranoia level, anomaly threshold) are those
of `crs-setup.conf.example`; there is no option to change them or to exclude rules.

## Behaviour

Service side (`evaluate` in `main.go`). One Coraza transaction per call, with a fixed client address
`127.0.0.1`. It processes the URI and the request headers, then the request body (decoded from `body_b64`;
phase 2 always runs, so query arguments are evaluated for a request without a body). The engine is `On`, so a
request the rule set would block produces an interruption; the service reports it as `anomalous: true` with
the interrupting `rule_id` and `status`, and `msg` naming the phase (`request headers` or `request`).
Otherwise it answers `anomalous: false`. Responses are never evaluated.

Gateway side:

1. In `enforce` mode the gateway consults the WAF only after `classify` returned `clean`, and only when
   `WAF_URL` is set (`_waf_upgrade` is called from the request path in `gateway/core.py`). It is not consulted
   in `observe` or `passthrough` mode, for captive sessions, for L0 answers, or for requests already classified
   as suspect or evidence.
2. `WafClient.check` posts the method, raw path, query, the request headers and the body to `/eval` with a
   1.5 s timeout. Any error, timeout, non-200 status or invalid JSON returns `None`: the request stays clean.
3. On `anomalous: true`, `_waf_upgrade` sets the class to `suspect` and appends the reason `waf:<rule_id>`
   (`waf:crs` when the id is missing). The `request.classified` event carries that reason.
4. The request then follows the normal suspect path (`Gateway._detonation`). A `waf:` reason is not a
   high-signal reason (`_high_signal`), so without an active rule the request is forwarded to production when
   no clone is available or when the clone's verdict is `clean` or `inconclusive`. Only an oracle firing in
   the clone keeps it away from production. The WAF never causes a deny by itself.

## Tests

```
.venv/bin/pytest gateway/tests/test_waf.py -q
```

Four tests, no Docker and no Go toolchain: `WafClient` against a mocked transport (anomaly reported; `None`
on a connection error and on a 502) and `_waf_upgrade` (clean becomes suspect with `waf:<rule_id>`; stays clean
with no WAF or a benign answer).

| Part | Level |
|---|---|
| Gateway client and reclassification | Implemented and tested (`gateway/tests/test_waf.py`) |
| The Go service (`main.go`) | Implemented; no automated test in the repository. It is built and started by `labs/scadabr-cve-2026-8602/lab.sh` |
| The service in a stack started by `immune up` | Not built |

## Limits

- The dependencies are not pinned: there is no `go.sum` and the Dockerfile runs `go get` without versions, so
  two builds can ship different Coraza and CRS versions. The build needs network access.
- The check adds one HTTP round trip to every request the classifier calls clean, and up to 1.5 s when the
  service is slow.
- Fail-open by design: with the service down, nothing changes and nothing is reported on the bus.
- A WAF match alone decides nothing: the outcome depends on the clone's oracles, with the fail-open cases
  listed under "Behaviour" step 4.
- CRS false positives cost a detonation (one clone, one L1 round trip), not a block.
- The request headers and the body are sent to the service as received, including credentials. The lab
  publishes the service on `127.0.0.1` without authentication.
- CRS is evaluated with its default settings and no application-specific exclusions.

The project-wide list is in [`docs/limites.md`](../docs/limites.md).
