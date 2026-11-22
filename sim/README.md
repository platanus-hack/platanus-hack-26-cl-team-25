# sim

## Purpose

`sim/` holds the legitimate traffic of the demo shop Tienda (`victim/`), in two forms. `sim/scenarios.py` is a
set of five deterministic scripted journeys that the pipeline's `legit` gate runs before and after a patch.
`sim/legit.py` is a continuous traffic generator for a running stack that checks every response for signs that a
legitimate customer was harmed. Both speak only HTTP and know only this shop's routes.

## How it runs

| Entry point | Used by | Where |
|---|---|---|
| `sim.scenarios.SCENARIOS` (library) | The `legit` gate, because the demo project's `.immune/config.yaml` sets `scenarios: sim.scenarios` | Inside the pipeline's runner container, against a `TestClient` |
| `python -m sim.legit` | A person, by hand | On the host, against the gateway's data port |
| `python -m sim.attacker` | A person, during the demo | On the host, against the gateway's data port (loopback only) |

Neither opens a port.

```
python -m sim.legit --base http://127.0.0.1:8080 --duration 60
```

## Layout

| File | Role |
|---|---|
| `scenarios.py` | The five scenarios, the response normaliser and the step recorder |
| `legit.py` | The traffic generator: `Actor` (journeys and checks), `Stats`, `main` |
| `attacker.py` | The demo attacker: replays the seven documented exploits in a loop, scores each attempt, publishes `attack.attempt` |
| `tests/` | Tests of both |

## Configuration

`python -m sim.legit` flags (`main` in `sim/legit.py`):

| Flag | Default | Meaning |
|---|---|---|
| `--base` | `http://127.0.0.1:8080` | Base URL of the target |
| `--users` | `6` | Number of the manifest's `legit_users` to simulate |
| `--anon` | `3` | Number of anonymous visitors |
| `--rate` | `5.0` | Total requests per second across all actors |
| `--duration` | `0` | Seconds to run; 0 runs until interrupted |
| `--manifest` | `runtime/data/manifest.json` | Manifest with the seeded users and their passwords (path relative to the current directory) |
| `--json` | none | Write the final summary to this file |
| `--seed` | random | Seed of the random journeys; the one used is in the summary |

`sim.scenarios` has no configuration. It reads `legit_users`, `admin` and `seed_max_order_id` from the manifest it
is given.

## Behaviour

### Scenarios

`SCENARIOS` is a list of callables `(client, manifest) -> list[step]`, where
`step = {"step", "method", "path", "status", "body"}`. The contract is in
[`contracts/interfaces.md`](../contracts/interfaces.md).

| Scenario | What it does |
|---|---|
| `anonymous_catalog` | Health, catalogue listing with every category, sort and page, searches with spaces and hyphens, product pages, the four images, the five manuals, missing files, mistyped URLs (404), protected routes without a token or with a garbage token (401) |
| `new_customer_obrien` | Registers "Conan O'Brien", logs in, reads the own profile, creates orders (one with a note containing an apostrophe and accented characters), invalid orders (422), own order and invoice, the admin listing as a user (403), unknown ids (404) |
| `existing_customer` | First seeded user: login, profile, up to three own orders with their invoices, a new order, browsing while logged in |
| `second_customer` | Second seeded user: login, profile, last own order and invoice, an order whose note contains an apostrophe |
| `admin` | Admin login, the admin order listing restricted to seeded orders, a user's profile read by the admin |

Properties the gate relies on:

- In the gate each scenario gets its own client on its own copy of a freshly seeded production-like database, with
  `APP_NOW` frozen (`job_scenarios` in `pipeline/runner_entry.py`), so no scenario sees what another one wrote. The
  tests in `sim/tests/` run all five in list order on one client instead. The same release and the same seed give
  identical output.
- They import nothing from the app, so they run against any release.
- Volatile values are normalised: tokens become `<token>`; non-JSON, non-text bodies become
  `{"binary_sha256", "bytes"}`; the admin listing is cut to orders with `id <= seed_max_order_id`.
- Together they touch every operation of `contracts/openapi.yaml`; a test checks this.
- No catalogue search contains an apostrophe. On the unpatched release a search with an apostrophe fails, so the
  scenario output would change with a correct fix. The apostrophe case is covered by the `properties` gate instead
  (see [`docs/validaciones.md`](../docs/validaciones.md)).

### Traffic generator

`sim.legit` creates one actor per simulated seeded user and per anonymous visitor, each with its own HTTP client
(and cookie jar) and token. Seeded users log in first. An anonymous visitor registers with probability 0.08 per
iteration and from then on acts as a new customer, whose uid is above the manifest's `seed_max_uid`. Each actor
picks weighted random journeys: browse, search, download a manual, mistyped URLs, and, once it has a token, own
profile, own orders, new order, the admin listing (expected 403). Each actor sleeps between requests so that the
total rate is `--rate`.

Every response is checked (`Actor.req`, `Actor.check_own`):

| Check | Counted as |
|---|---|
| Status 5xx | `5xx` |
| Status outside the expected set for that request | violation `unexpected_status` |
| A response header starting with `x-imm-` | violation `x-imm-header` |
| A marker `MK[A-Z0-9]{10}` in the body | violation `synthetic_marker` |
| `/api/me`, own profile, own orders or own invoice not carrying the actor's own id or email | violation `wrong_owner` |
| Connection or transport error | `conn_err` |

A marker or an `x-imm-` header in a response means a legitimate client was answered by a clone. The generator
prints a status line every 2 s (`t= reqs= rps= status={..} violations= 5xx= conn_err=`), a `FINAL` line, and up to
20 problem records on stderr. It exits 1 on any violation, 5xx or connection error, else 0. `--json` writes the
summary with up to 200 problem records.

## Tests

```
.venv/bin/pytest sim/tests -q
```

No Docker and no LLM. The tests cover: identical scenario output on two fresh seeds, step shape and absence of
volatile values, expected statuses for awkward inputs, coverage of every OpenAPI route, the generator against an
in-process server with no violations, detection of an injected `x-imm-` header and marker, and a connection
failure counted as a failure.

## Limits

- The legitimate corpus is synthetic. The five scenarios are hand-written for this shop; they are not recorded
  production traffic, and "identical before and after" in the `legit` gate means identical on these scripts.
- Both modules are specific to Tienda's routes. Other projects use scenarios generated by `immune init`
  (`immune/initsteps/scenarios.py`) or recorded requests.
- A live `sim.legit` run writes to the target database: visitor registrations and orders.
- `sim.legit` detects harm to legitimate traffic only through the checks in the table above; a wrong but
  well-formed answer about a public resource is not detected.
- This directory generates legitimate traffic only.

Limits of the system as a whole: [`docs/limites.md`](../docs/limites.md).
