# sim (WP8): legitimate traffic

Only legitimate customers live here (the attacker bot is a separate module).

## `sim.scenarios`

`SCENARIOS: list[(client, manifest) -> list[step]]`, per `contracts/interfaces.md`.
`step = {"step", "method", "path", "status", "body"}`.

- Run the list in order on ONE client (TestClient on a freshly seeded prod-like DB, `APP_NOW` frozen).
  Scenarios create users/orders, so later ones see earlier state; same release + same seed gives identical output.
- Only the HTTP interface is used (no app imports), so it works against any release.
- Volatile values are normalised: tokens become `<token>`, binary files become `{"binary_sha256","bytes"}`;
  the admin listing is restricted to seeded orders (`id <= seed_max_order_id`).
- Covers every operation of `contracts/openapi.yaml` (checked by `sim/tests`), including O'Brien, an order note
  with apostrophe and accents, searches with spaces/hyphens, dotted manual names, a mistyped URL (404),
  missing/garbage token (401), admin as user (403). No search contains an apostrophe.

## `python -m sim.legit`

```
python -m sim.legit --base http://127.0.0.1:8080 [--users 6] [--anon 3] [--rate 5] [--duration 0]
                    [--manifest runtime/data/manifest.json] [--json out.json] [--seed N]
```

Simulates manifest legit users and anonymous visitors (some register and then act as new, untrusted-uid
customers), each with its own cookie jar and token, running random journeys at `--rate` total req/s
(`--duration 0` = until Ctrl-C). Per response it checks: no `x-imm-*` header, no `MK[A-Z0-9]{10}` in the body,
expected status (a legit request that gets 404/403 unexpectedly is a violation), and that `/api/me`, own profile,
own orders and own invoices carry the actor's own id/email. Prints a rolling line
(`t= reqs= rps= status={..} violations= 5xx= conn_err=`) and exits 1 on any violation, 5xx or connection error.
`--json` writes the final summary including up to 200 problem records.

Note: live runs create a few real users/orders in the target database (visitor registrations, orders).

## Tests

`.venv/bin/pytest sim/tests -q` (determinism on two fresh seeds, route coverage, generator against an
in-process uvicorn on an ephemeral port, detection of an injected `x-imm-` header, connection failure).
