# Interfaces between pipeline, patch generator and scenarios

Reference for the Python interfaces the pipeline calls and for the runner in which it executes application
code. The incident flow that uses them is in `contracts/README.md` section 9.

## 1. Patch generator

A module that provides three functions. The pipeline imports the module named by the environment variable
`PATCHER_MODULE` (default `patcher`). `pipeline/stub_patcher.py` has the same signatures and is used by the
pipeline's tests. For `app.runtime: generic` the pipeline uses `pipeline/generic_patch.py` instead
(`pipeline/external.py`): it renders its prompt through `patcher.core.render` and has no pre-written diffs.

```python
propose(release_dir: str, incident: dict, feedback: list[str] | None = None, attempt: int = 1) -> dict
variants(poc: dict, evidence: dict) -> list[dict]
derive_rule(incident: dict, openapi: dict) -> dict
```

### `propose`

| Argument | Meaning |
|---|---|
| `release_dir` | directory of the release in production; it contains the paths of `app.release_paths` |
| `incident` | the incident object below |
| `feedback` | detail text of the gate that rejected each earlier attempt, one string per attempt |
| `attempt` | 1-based attempt number |

Result:

| Key | Type | Meaning |
|---|---|---|
| `diff` | string | unified diff with paths relative to `release_dir`. Empty when nothing is proposed |
| `source` | `"llm"` \| `"fallback"` | who wrote the diff. The pipeline reports any other value, or a missing key, as `unknown` |
| `notes` | string | free text for the log (model, duration, why a fallback was used) |

Behaviour of `patcher.propose` (`patcher/core.py`):

| Case | Result |
|---|---|
| the model edited files and the workspace diff is not empty | `source: "llm"` |
| the `claude` CLI failed or timed out, or the diff is empty | the pre-written diff `patcher/fallbacks/<class>__<method-and-route slug>.diff` if one exists, `source: "fallback"`; otherwise an empty diff with `source: "fallback"` |
| `PATCHER_FORCE_FALLBACK=1` | the pre-written diff, without calling the model |

The pre-written diffs exist only for the seven planted defects of the built-in demo. They go through the same
five gates as a model diff. The pipeline calls `propose` with a time limit (`PIPELINE_PATCHER_TIMEOUT_S`, 600 s)
and treats an exception or a non-dict result as "no proposal".

The model runs through the `claude` CLI on a temporary copy of the release (`patcher/workspace.py`,
`patcher/claude_cli.py`): it may read that copy and edit only an allow-list of files under `app.source_dirs`.
The request, the oracle detail and the gate feedback are placed in the prompt as untrusted data. The CLI
process gets an environment built from an allowlist (`claude_cli.child_env`), not the pipeline's own: the
stack secrets are not passed. The variables are listed in `patcher/README.md`, "Configuration".

### `variants`

Extra regression requests derived from the captured request. Each item has the shape of an item of
`poc["requests"]`. `patcher.variants` returns between 0 and 40 distinct requests, none equal to the PoC request
(`patcher/variants.py`, `MAX_VARIANTS`). The pipeline calls it with a time limit of one minute and continues without
variants if it fails. A variant counts for the `poc` gate only if it fires the incident's oracle on the
unpatched release.

### `derive_rule`

Returns a rule that validates against `contracts/schemas/rule.schema.json`. `patcher.derive_rule`
(`patcher/rule.py`):

| Incident | Rule |
|---|---|
| class `sqli` or `traversal` with a parameter the gateway can address (`query`, `path`, `json`, `form`, `header`) | scope `param_present`, with a grammar that only decides the case of an inconclusive clone (`contracts/README.md` section 6.4). The grammar is the safe default; for `sqli` it also allows one apostrophe between two letters and never `--`. Length capped by the parameter's `maxLength` (at most 128) |
| the same, when the parameter is `x-sensitive` or in a location the gateway cannot address | scope `all` |
| class `idor`, `other`, or no parameter | scope `all` |

`derive_rule` sets `ttl_s: null` (`TTL_S` is `None`) and never sets `identity`. It does not check the captured
value against the grammar: with scope `param_present` every request that carries the parameter is detonated.

The pipeline calls it with a 30 s limit and then (`pipeline/rules.py`, `finalize`): forces `incident`; fills in
`id` and `ttl_s` when the rule lacks them (`ttl_s` from `PIPELINE_RULE_TTL_S`, which is unset by default, so
`null`); checks that the rule targets the incident's method and route; adds `identity: untrusted` to a rule of
scope `all` when the incident has the `anon` flag; validates the rule against the schema and compiles its
grammar. If any of that fails it uses its own rule (`default_rule`): scope `all` for `idor`, without a
parameter or for a location the gateway cannot address (with `identity: untrusted` for an `anon` incident);
else scope `param_present` with `[0-9]{1,9}` for an integer parameter, `grammar.PATH_SAFE` for a catch-all path
parameter and `grammar.SAFE_DEFAULT` for the rest. The escalation path and the reproduction-only mode of
`pipeline/external.py` use `default_rule` directly.

### Incident object

What `propose` and `derive_rule` receive (`pipeline/incident.py`, `public`):

```json
{"incident": "<id>",
 "vuln_class": "sqli|traversal|idor|other",
 "anon": false,
 "method": "GET",
 "route": "<OpenAPI path template, or the escaped request path when no template matches>",
 "param": {"in": "query|path|json|form", "name": "q"},
 "sink": {"file": "victim/app/products.py", "line": 1},
 "evidence_rid": "<rid>",
 "request": {"method": "", "path": "", "query": "", "body_b64": ""},
 "evidence": {},
 "poc": {}}
```

| Key | Notes |
|---|---|
| `anon` | `true` when the primary event is an `owner` oracle on a request without an identity (missing authentication); the rule of such an incident is limited to untrusted identities |
| `param` | `null` when no parameter could be attributed |
| `sink` | innermost stack frame of the primary oracle event; `{"file": "", "line": 0}` when the evidence has no stack (generic runtime without `shadow.tracer`) |
| `evidence` | `contracts/schemas/evidence.schema.json` |
| `poc` | `contracts/schemas/poc.schema.json` |
| `route`, `param.name` | derived from attacker input when no template matches: the route is percent-encoded and capped at 200 characters, the name stripped of non-printable characters and capped at 100 (`safe_route`, `safe_name`) |

## 2. Scenario modules

The `legit` gate compares legitimate behaviour before and after a patch. The module is named by `scenarios` in
`config.yaml`; for the built-in demo it is `sim/scenarios.py`.

```python
SCENARIOS: list[Callable[[client, manifest], list[dict]]]
PARTIAL_COVERAGE: bool   # optional, default False
```

| Element | Contract |
|---|---|
| `client` | a `starlette.testclient.TestClient` on the app, over a copy of a freshly seeded production-like database, with the clock frozen (`RUNNER_APP_NOW`) |
| `manifest` | the dict of `manifest.json` (`contracts/README.md` section 4.3) |
| return value | a list of steps: `{"step": str, "method": str, "path": str, "status": int, "body": <normalised JSON or text>}` |
| determinism | same release and same seed give identical output. Volatile values (tokens) are replaced by placeholders in `body` |
| isolation | each scenario runs on its own copy of the seed |
| `PARTIAL_COVERAGE = True` | declares that the module does not cover every route: a patched route without a covering step caps autopatch at `pr` instead of rejecting the patch |

The gate (`pipeline/gates.py`, `gate_legit`) fails when a scenario raises on the unpatched release, when any
step differs between the unpatched and the patched release, or when no step covers the patched route (subject
to `PARTIAL_COVERAGE`). A module that cannot be imported is an error of the runner job and fails the gate.

`sim/scenarios.py` holds five scripted scenarios for the demo: `anonymous_catalog`, `new_customer_obrien`,
`existing_customer`, `second_customer`, `admin`. They are written by hand, not recorded from users.
`immune init` generates a module for other projects (`.immune/scenarios.py`, run by `immune/legit.py`): `GET`
journeys of seeded users over their own resources, with `PARTIAL_COVERAGE = True`.

## 3. Runner

Every execution of application code by the pipeline happens in a container (`pipeline/runner.py`,
`Runner.docker_cmd`). There is no mode that runs it in a host process.

```
docker run --rm -i --name immune-<name>-runner-<pid>-<n> --network none --read-only \
  --tmpfs /tmp:rw,size=512m --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 1g --cpus 2 --user <uid>:<gid> \
  -w /app -v <immune home>:/opt/immune:ro -v <release>:/app:ro \
  immune-base:1 python -m pipeline.runner_entry
```

| Aspect | Value |
|---|---|
| Release under test | mounted read-only at `/app`, the working directory |
| `.immune/` of the project | mounted read-only at `/app/.immune` when it exists |
| Hidden from the code under test | the runtime directory and `.git` (empty tmpfs over them); `.env` of the Immune home (masked with `/dev/null`) |
| Seed | built inside the container by `data.seed_command`; without one, the stack's shadow seed is mounted read-only at `/seed` and the manifest at `/seed-manifest/manifest.json`. Production data is never mounted |
| Job | one JSON object on stdin: `{"kind", "app": <app facts>, "seed", "app_now", "result_nonce", ...}` |
| Time limit | `RUNNER_TIMEOUT_S` (240 s) by default; the container is killed past it |

Job kinds (`pipeline/runner_entry.py`, `JOBS`):

| Kind | Does | Result |
|---|---|---|
| `harness` | sequences of requests through `shadow.harness.Harness`; the last request of a sequence runs in `L1`, earlier ones in `L2` | `{"sequences": [{"name", "runs": [[{"status", "verdict", "events", ...}]]}], "manifest"}` |
| `plain` | requests against the app without oracles, each on a fresh production-like seed, recording executed SQL with bound parameters and file opens | `{"results": [...], "roots", "warm_opens", "manifest"}` |
| `pytest` | `tests.command` in the release directory | `{"ok", "code", "summary", "failed"}`; `{"ok": true, "skipped": true}` without a command |
| `scenarios` | the scenarios module (section 2) | `{"module", "scenarios": [{"name", "steps"}\|{"name", "error"}], "partial"}` |
| `replay` | recorded clean `GET` requests, each on a fresh production-like seed | `{"results": [{"name", "method", "path", "status", "body"}]}` |

Result line. The result is written to stdout, which the code under test shares:

```
@@RESULT@@ <nonce> <json>
```

`<nonce>` is 16 random bytes in hex, generated per run by the host and passed in the job as `result_nonce`.
The entry module removes it from the job before any application code is imported. The host accepts only the
last line that starts with `@@RESULT@@ <nonce> ` for this run's nonce (`parse_result`), so application code
that prints a result line cannot forge the verdict. Limit: code that inspects the interpreter of its own
process (frames, the garbage collector) could find the nonce; the `policy` gate rejects the constructs that
would need.

A job with no accepted result line, with `ok_run: false`, or past its time limit raises `RunnerError`; a gate
that cannot run counts as failed.

### Generic runtime

For `app.runtime: generic` the same job kinds (`harness`, `plain`, `replay`, `pytest`) run against a
throw-away clone triple instead: the database of `database.kind` (Postgres or MariaDB) loaded from the shadow
dump, the app image of release `t0` (or of `JUDGE_BASE_RELEASE`) with the release under test mounted read-only
over `app.workdir`, one mount per entry of `app.release_paths`, and the observer in judge mode
(`SIDECAR_JUDGE=1`), on its own internal Docker network (`pipeline/generic.py`, `JudgeValidator`). The `replay`
job applies the expressions of `legit.normalize` (`contracts/product.md` section 2) to each response body
before comparing. In judge mode every response carries
`x-imm-trace`: base64 of a JSON object with the oracle events, the executed statements with their bound
parameters, the successful file opens and the marker owners. Job results have the same shape as above.
Mounting the release over the image works for interpreted languages only.
