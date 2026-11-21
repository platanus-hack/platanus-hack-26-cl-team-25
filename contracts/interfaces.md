# Interfaces between pipeline, patcher and sim (v1)

Owned by the orchestrator. Binding for `pipeline/`, `patcher/` and `sim/`.

## patcher (library, called by pipeline)

```python
patcher.propose(release_dir: str, incident: dict, feedback: list[str], attempt: int) -> dict
#   release_dir contains `victim/` (the code currently in prod).
#   -> {"diff": "<unified diff, paths relative to release_dir, e.g. victim/app/products.py>",
#       "source": "llm" | "fallback", "notes": str}
#   feedback = human-readable output of the validation gates that rejected earlier attempts.
patcher.variants(poc: dict, evidence: dict) -> list[dict]
#   extra regression requests derived from the captured request; same shape as poc["requests"] items.
patcher.derive_rule(incident: dict, openapi: dict) -> dict
#   rule per contracts/schemas/rule.schema.json
```

`incident`:

```json
{"incident": "<id>", "vuln_class": "sqli|traversal|idor|other", "method": "GET",
 "route": "<OpenAPI template>", "param": {"in": "query", "name": "q"},
 "sink": {"file": "victim/app/x.py", "line": 1}, "evidence_rid": "...",
 "request": {"method": "", "path": "", "query": "", "body_b64": ""},
 "evidence": { "...": "contracts/schemas/evidence.schema.json" },
 "poc": { "...": "contracts/schemas/poc.schema.json" }}
```

Pipeline selects the implementation with env `PATCHER_MODULE` (default `patcher`) and ships `pipeline/stub_patcher.py` with the same signatures for its tests.

## sim.scenarios (library, used by the pipeline's `legit` gate)

```python
sim.scenarios.SCENARIOS: list[Callable[[client, manifest], list[dict]]]
#   client:   starlette TestClient on a freshly seeded PROD-like database, APP_NOW frozen
#   manifest: the dict from manifest.json
#   returns:  [{"step": str, "method": str, "path": str, "status": int, "body": <normalised JSON or text>}]
```

Scenarios are deterministic: same release + same seed ⇒ identical output. Volatile values (tokens) are replaced by placeholders in `body`. Together the scenarios touch every route of `contracts/openapi.yaml` with legitimate inputs.

## Runner

Any execution of app code by the pipeline happens in `docker run --rm --network none` on `immune-base:1`, repo mounted read-only at `/srv`, the release under test mounted read-only over `/srv/victim`. Containers are named `immune-runner-<n>`.
