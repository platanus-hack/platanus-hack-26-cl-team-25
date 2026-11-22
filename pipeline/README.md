# pipeline/ (WP5): incident → rule → patch → gates → PR → deploy → verify

Host process. Contract: `contracts/README.md` §9, `contracts/interfaces.md`, `docs/plan-construccion.md` §4, §9b, §9c.

```
python -m pipeline                    # follow the bus (SSE), one incident at a time, forever
python -m pipeline --replay ev.json   # enqueue a saved oracle.fired event, process, exit
python -m pipeline --status           # persisted state summary
python -m pipeline.selftest           # gate self-test against t0 (real harness, real runner containers)
python -m pipeline.dryrun [ev.json…]  # whole flow with fake bus/gateway/fleet, REPO_TARGET=local, stub patcher
```

## Flow per incident

1. **Intake** (`bus.Follower`): `GET /events/stream?since=<last seq>`. The seq is persisted, so a restart resumes where it stopped, and a bus `reset` replays from 0. Each `oracle.fired` becomes an incident (`incident.py`). The oracle preference is sql > file > owner, giving the class (sqli, traversal, idor). The method and route template come from `contracts/openapi.yaml`. The parameter comes from the evidence: the sql `detail.param`, the input contained in the opened file path, or the path parameter (the canary-keyed one first). The sink is the innermost stack frame. The dedupe key is `kind|METHOD|route|in:name`. Duplicates only increase `hits`. Patched and `rule_only` incidents are never reopened. `escalated` incidents (see PoC) can reopen after `PIPELINE_REOPEN_COOLDOWN_S`. Incidents are queued and processed one at a time.
2. **PoC** (`poc.py`) per `poc.schema.json`. The identity is kept as `uid`/`role` and the attacker's token is dropped. Variants are built-in mutators plus `patcher.variants`. The PoC must fire its oracle in 3/3 runs on the current release, otherwise (0/3 included: it did fire once on the live request, the attack may be stateful or non-deterministic) the containment rule is still posted, no fix is attempted, and the incident closes `rule_only` with `outcome_detail: escalated` for a person. Only variants that fire on the unpatched code are counted.
3. **Rule**: `patcher.derive_rule`, schema-validated and forced to the incident's route and method. If it fails or is invalid, the pipeline uses a built-in rule (grammar per parameter; `scope: all` for idor). It is posted to `POST /_admin/rules` and deleted after a successful deploy. It is re-posted if verification fails.
4. **Fix loop**: up to `PIPELINE_MAX_ATTEMPTS` (3) calls of `patcher.propose(release_dir, incident, feedback, attempt)`, run in a thread with a timeout. Each diff is applied to a temporary copy of the current release; a diff that does not apply is rejected at `policy`. The gates' `detail` is fed back to the next attempt.
5. **Gates** (`gates.py`), in order, each published as `gate.result`. The first failure stops the attempt.
   - `policy` (`policy.py`, AST before vs after, no regexes): only existing `victim/app/*.py` files may change (no new, deleted, renamed, binary or mode changes). It rejects: new imports or dynamic/env/process access; new request reads (new handler parameters, `Header`/`Request`/…, `.headers`/`.cookies`/…); new route handlers; comparisons against literals the app never compared against (a role check using the existing `"admin"` literal is fine); fewer 401/403 checks in any function (raises, or calls to the app's own guard functions); high-entropy string constants; more than 120 changed lines or 4 files.
   - `properties` (`properties.py`), per class, derived from the incident, the shadow profile and the manifest:
     - sqli: the executed statement structure (sqlparse, literals normalised) is identical for 14 metacharacter inputs and benign values, with the same status, and `O'Brien` reaches the database intact.
     - traversal: 14 traversal inputs open nothing outside the allowed roots. Every legitimate value (every file under the roots, by every relative suffix) that served correct bytes before still does.
     - idor: an identity × resource matrix in the harness. Owners (found from the markers) get 2xx with only their own data; another seed user and a new user get 403/404; the anonymous status is unchanged.
       For a members-scoped route (manifest `group_routes`/`groups`, from `shared_via` + `access: members` in `columns.yaml`) the matrix is per group: a member gets exactly the unpatched response (2xx, same bytes, no oracle), a seed user outside the group and a new user get 403/404 with no oracle, admin and anonymous are unchanged.
     - every sqli check first requires the benign value to reach an executed statement (otherwise the request never exercised the query, e.g. a 401).
   - `poc`: the PoC and the counted variants fire no oracle on the patched code.
   - `tests`: `victim/tests` (pytest) of the patched release.
   - `legit`: `sim.scenarios.SCENARIOS` (falling back to `standin_scenarios` if missing) on fresh prod-like seeds with a frozen clock. The output must be identical before and after, and some step must cover the incident's endpoint and every route handler the diff changed. A scenarios module that sets `PARTIAL_COVERAGE = True` (the GET-only journeys `immune init` generates in `.immune/scenarios.py`) caps autopatch at pr when the endpoint is not covered, instead of rejecting the patch.
6. **RepoTarget** (`repo.py`, `REPO_TARGET`): base branch `run/<run>/base` created from tag `victim-t0`, branch `run/<run>/fix-<incident>`, label `run-<run>`. The PR is opened after the policy gate. There is one status per gate (`immune/<gate>`) and a merge when green. Then `<runtime>/releases/<sha[:12]>/victim/` is materialised (safe extraction, no links), and a final comment gives the timings. On a failed deploy the merge is reverted on the base branch.
   - `local`: a git repo at `<runtime>/repo`. PR records are kept in `.git/immune/prs/*.json`.
   - `scratch`/`official`: the `gh` CLI against `GITHUB_REPO`. Objects are created through `gh api` (blobs, trees, commits, refs; no clone), PRs and comments through `gh pr`. If GitHub fails, the pipeline continues on `local` (plan §9c).
7. **Deploy**: `POST fleet /deploy {release}`. If it rolls back or fails, the rule is kept and the incident closes as `rule_only`.
8. **Verify** (`verify.py`), published as `verify.result`. (a) Runner: the PoC and its variants fire nothing on the deployed release. (b) Gateway: the same request from a fresh session (a new cookie, or a freshly minted token of the same trust class; with `auth.kind: introspect` a brand-new account registered and logged in through the app's own register/login routes found in the OpenAPI, sent through the gateway) must be `route: prod` on the bus or in the recordings, with `prodlog.forwarded` true. Then `incident.closed` is published with `seconds_to_rule` and `seconds_to_patch`, both measured from the `oracle.fired` timestamp, so queue time is included.

Robustness: every HTTP call, runner job and patcher call has a timeout. Any exception closes the incident as `rule_only` with the reason, and the loop continues. State is stored in `<runtime>/pipeline/state.json` (atomic writes). An incident left `open` by a crash is redone from the start. While `<runtime>/pipeline/PAUSE` exists, no new incident starts. Every published event is also appended to `<runtime>/pipeline/events.jsonl`.

## Class self-audit and corpus (`audit.py`, `corpus.py`; plan §9d)

After an incident of class C closes `patched` or `rule_only`, its id goes to `audit_pending` (state); the next `step()` (not while PAUSE exists) audits the rest of the OpenAPI for C on the **current** release, in the judge only (runner containers, or judge triples for `app.runtime: generic`), one judge job per candidate (operation x parameter), each on a fresh shadow seed. Candidates: string-shaped query/path/form parameters and JSON string leaves for sqli and traversal (enum, integer, number, boolean schemas skipped); path and `*id` query parameters for idor. Inputs: the `properties` gate battery of the class (`SQL_META`, `TRAVERSAL`, the idor candidate ids) plus up to 40 corpus values. Identity: a legitimate seed user on routes that need one; for idor a new user who owns nothing. A probe that fires C's oracle becomes an incident with `origin: "audit"`, `parent: <id>` (dedupe key as usual; known keys are never probed). Budget: `audit: {enabled, max_jobs, max_seconds}` in `.immune/config.yaml` (default on for python-asgi, off for generic). Loop prevention: one audit per class per release (`state.audits[C].releases`); the closure of an audit incident only judges candidates no earlier audit of C has judged. Events: `audit.started`, `audit.finding`, `audit.done`; `incident.opened` carries `origin` and `parent`.

Corpus: `<runtime>/corpus/<class>.jsonl` gets the affected parameter's value of the PoC and of every counted variant once the PoC reproduces (deduplicated, at most 500 per class, oldest dropped). The reproduction step adds corpus values as extra variants (counted only if they fire on the unpatched release), so the `poc` gate and post-deploy verification judge them too. `bin/immune reset` does not clear the corpus.

## Runner

`runner.py` runs `runner_entry.py` (JSON job on stdin, `@@RESULT@@ <json>` on stdout) in `docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit --memory --cpus --tmpfs /tmp`, on `immune-base:1`. The repo is mounted read-only at `/srv`, the release under test read-only over `/srv/victim`, and `/srv/runtime` and `/srv/.git` are hidden. There is a hard timeout (`docker kill`). Containers are named `immune-runner-<pid>-<n>` (`RUNNER_PREFIX`). Job kinds: `harness` (shadow `Harness` sequences, the judge), `plain` (prod-like app recording SQL text + params and file opens), `pytest`, `scenarios`. `RUNNER_MODE=local` (host subprocess with rlimits) exists for debugging only.

## Environment

`RUNTIME_DIR REPO_DIR RUN_ID BUS_TOKEN ADMIN_TOKEN PROD_APP_SECRET` (secrets fall back to `deploy/demo.env`),
`PIPELINE_BUS_URL` (host bus, default `http://127.0.0.1:8090`; `BUS_URL` is the in-container address and is ignored),
`GATEWAY_ADMIN_URL` (8081), `GATEWAY_URL` (8080), `FLEET_URL` (8070), `REPO_TARGET` (`local`), `GITHUB_REPO`, `REPO_TARGET_DIR`,
`PATCHER_MODULE` (`patcher`), `SCENARIOS_MODULE` (`sim.scenarios`), `PIPELINE_STATE_DIR`, `OPENAPI_PATH_HOST`, `MANIFEST_PATH_HOST`,
`RECORD_PATH_HOST`, `RUNNER_MODE RUNNER_IMAGE RUNNER_PREFIX RUNNER_TIMEOUT_S RUNNER_MEMORY RUNNER_CPUS RUNNER_PIDS RUNNER_APP_NOW`,
`PIPELINE_MAX_ATTEMPTS PIPELINE_HTTP_TIMEOUT_S PIPELINE_DEPLOY_TIMEOUT_S PIPELINE_PATCHER_TIMEOUT_S PIPELINE_VERIFY_WAIT_S
PIPELINE_RULE_TTL_S PIPELINE_REOPEN_COOLDOWN_S POLICY_MAX_LINES POLICY_MAX_FILES`.

## Self-test

`selftest.py` detonates every documented exploit of `victim/VULNS.md` in the harness and derives incidents from the real evidence. The three live fixtures must derive to the same keys. It then checks that the 7 known-good fixes in `patcher/fallbacks/` pass all five gates, and that the 15 inadequate fixes in `fixes.py` are rejected by the stated gate:
- blacklisting `'`;
- stripping quotes;
- a debug-header backdoor;
- a deleted endpoint;
- a broken page size;
- a changed invoice format;
- a dropped admin check;
- a naive `../` strip;
- `..`-only blocking;
- mangled dotted names;
- a new import;
- a special case for the PoC id;
- deny-everyone;
- a hard-coded support key;
- edited tests.

It takes about 45 s.

## Tests

`.venv/bin/pytest pipeline/tests -q`: units (incident derivation, policy, diffs, rules, bus, state), the orchestrator (a scripted validator plus HTTP fakes: dedupe, queue, pause, restart, rollback, feedback loop, failure isolation), the local repo, the GitHub target with a mocked `gh`, and integration with real `wp5-runner-*` containers (the gates and the full dry run). `stub_patcher.py` has the patcher's signatures (`STUB_PATCHER_PLAN` scripts the fix per attempt); `fakes.py` provides the bus, gateway and fleet fakes.
