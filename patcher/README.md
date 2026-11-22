# patcher

## Purpose

The patcher is a library the pipeline calls to obtain three things for an incident: a proposed fix as a unified
diff, a set of request variants for the regression case, and a containment rule for the gateway. The fix is written
by an LLM (the `claude` CLI) confined to reading a temporary copy of the release and editing an allow-list of files.
The patcher decides nothing: every diff it returns, whatever its source, is judged by the five gates of
[`../pipeline/README.md`](../pipeline/README.md).

Related documents: interface in [`../contracts/interfaces.md`](../contracts/interfaces.md), gates in
[`../docs/validaciones.md`](../docs/validaciones.md), trust boundaries in
[`../docs/arquitectura.md`](../docs/arquitectura.md), limits in [`../docs/limites.md`](../docs/limites.md).

## How it runs

It has no process and no port. The pipeline imports the module named by `PATCHER_MODULE` (default `patcher`) and
calls, in the pipeline's host process:

```python
patcher.propose(release_dir, incident, feedback, attempt) -> {"diff": str, "source": "llm" | "fallback", "notes": str}
patcher.variants(poc, evidence) -> [request, ...]     # deterministic, no LLM
patcher.derive_rule(incident, openapi) -> rule        # contracts/schemas/rule.schema.json
```

`propose` starts one `claude` subprocess per call. `variants` and `derive_rule` are pure functions.

For `app.runtime: generic` the pipeline uses `pipeline/generic_patch.py` instead of `patcher.propose`. It reuses
`claude_cli.py`, `workspace.py` and the prompt templates of this directory, and has no fallback.

## Layout

| File | Role |
|---|---|
| `__init__.py` | Exports `propose`, `variants`, `derive_rule` |
| `core.py` | `propose`, the choice of editable files, prompt rendering |
| `claude_cli.py` | The confined `claude` invocation: flags, per-call settings, timeout, redaction |
| `workspace.py` | Temporary copy of a release with a git baseline kept outside the work tree |
| `prompts/fix.md` | The prompt template, one for every runtime |
| `prompts/classes.md` | What a correct fix looks like, per class (`sqli`, `traversal`, `idor`, `other`) |
| `prompts/feedback.md` | Section added on retries with the gates' output |
| `rule.py` | `derive_rule` |
| `variants.py` | `variants` |
| `fallback.py` | Selection and application of a fallback diff |
| `fallbacks/` | Seven hand-written diffs for the demo shop |
| `checks.py`, `_harness_probe.py` | Local checks used by this directory's tests and by `bench.py`; not the pipeline's gates |
| `bench.py` | Script that times `propose` on three recorded incidents with the real CLI |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PATCHER_MODEL` | `sonnet` | Value of `--model` |
| `PATCHER_TIMEOUT_S` | `180` | Limit of one CLI call; on expiry its process group gets SIGKILL |
| `CLAUDE_BIN` | `$CLAUDE_CODE_EXECPATH` if executable, else `claude` on `PATH` | CLI binary |
| `PATCHER_FORCE_FALLBACK` | unset | `1` skips the LLM and uses the fallback |
| `PATCHER_FALLBACK_DIR` | `fallbacks/` of this directory | Where fallback diffs are read from |

The CLI inherits the environment of the pipeline process unchanged (including `ANTHROPIC_BASE_URL` and any API
credentials) and uses the login already configured for the invoking user.

Project facts come from `.immune/config.yaml`: `app.release_paths` (what is copied), `app.source_dirs` (where
editable files may be), `database.kind` (prompt hint).

## Behaviour

### What the model can read and edit

`propose` (`core.py`):

1. `Workspace` copies the `app.release_paths` of `release_dir` into `<tmp>/work`. Only regular files and directories
   are copied; symlinks, `__pycache__`, `.pytest_cache`, `.git` and `*.pyc` are skipped. A baseline git repository is
   created at `<tmp>/git`, next to the work tree and not inside it, so the model's file tools never see it.
2. `editable_files` builds the edit allow-list from the evidence: the files in the oracle events' stacks that are
   `.py` files under `app.source_dirs` and exist in the copy, plus the incident's sink file. A file that appears only
   as the innermost frame below other app frames is excluded (the database helper the statement reached, not where
   it was built).
3. `claude_cli.run` starts the CLI with `cwd=<tmp>/work` and the prompt on stdin.
4. The result is `git diff` of the copy against the baseline, with paths relative to the release. The model's reply
   text is only copied into `notes` (first 2000 characters). Nothing the model writes outside the copy, and nothing
   in its reply, is applied.

The model therefore reads only the release paths of the project. Files outside them are not in the copy; this
includes the lists of planted defects of the demo apps, which live in `docs/demo/respuestas/`.

### CLI confinement

The command is built by `claude_cli.command` on every call; nothing is written to the user's CLI configuration.

```
claude -p --model <PATCHER_MODEL> --tools Read,Edit --strict-mcp-config --disable-slash-commands \
  --restricted --permission-mode dontAsk --permission-prompts none --no-session-persistence \
  --output-format json --settings '<json>'
```

| Flag | Effect |
|---|---|
| `--tools Read,Edit` | Only the two file tools exist: no shell, web, agents or notebook tools |
| `--strict-mcp-config` | No MCP servers (none are passed) |
| `--disable-slash-commands` | No skills or commands |
| `--restricted` | File tools confined to the working directory; user, project and local settings are ignored |
| `--permission-mode dontAsk`, `--permission-prompts none` | Anything not allowed in advance is denied; nothing can be approved at run time |
| `--settings` | The per-call permission rules below, and `disableAllHooks` |

Per-call settings (`claude_cli.settings_for`):

- allow: `Read(<work>/**)` and one `Edit(<file>)` per editable file. With an empty list no edit is allowed.
- deny: `Edit` under every directory named `tests` at the top two levels of the copy, and `Write` anywhere in it.

The CLI reports refused tool calls as `permission_denials`; `propose` copies them into `notes`. If the installed CLI
does not accept one of these flags it exits with an error and `propose` falls back; it does not run unconfined.

### Prompt and untrusted data

`core.render` fills `prompts/fix.md`. One template serves every runtime; the facts are taken from the project
configuration and the incident: the language of the editable files, `app.source_dirs`, `database.kind`, the class,
endpoint, parameter, the sink and the stack (`file:line`), the editable files, and the class section of
`prompts/classes.md`. The templates name no application.

Everything derived from the request is data, not instruction:

- The evidence record (request, response status, requester, oracle details) is JSON between
  `<<<EVIDENCE-<nonce>` and `EVIDENCE-<nonce>>>>`. On retries the gates' output is between `<<<GATES-<nonce>` and
  `GATES-<nonce>>>>`. The nonce is 16 random hex characters, regenerated until it does not occur in either text, so
  the content cannot close its own block. The prompt declares both blocks untrusted.
- Redaction: the values of the `authorization`, `cookie` and `x-imm-signature` request headers are replaced by
  `<redacted>`. Strings longer than 1500 characters are truncated and lists are cut to 20 items.
- The route and the parameter name appear outside the fence; the pipeline sanitises them when it builds the incident
  (`safe_route`, `safe_name` in `pipeline/incident.py`).
- The values of `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are removed from the CLI's
  output and error text before they reach `notes`.

The fence does not make the model obey. The defence against a patch steered by attacker text is the tool confinement
plus the gates.

### Timeouts and failures

`claude_cli.run` never raises for a CLI problem. It returns a failure when the binary cannot be started, when
`PATCHER_TIMEOUT_S` expires, when the exit code is not 0 or the output is not JSON, or when the CLI reports
`is_error`. The pipeline additionally bounds the whole `propose` call with `PIPELINE_PATCHER_TIMEOUT_S` (600).

### Fallback diffs

`fallbacks/<class>__<slug>.diff`, where the slug is the method and route in lower case with every run of characters
outside `[a-z0-9_]` replaced by `-`. There are seven, one per planted defect of the demo shop; no other project has
any.

A fallback is used only when the LLM call fails, times out or yields an empty diff, or when
`PATCHER_FORCE_FALLBACK=1`. `apply_fallback` applies the diff to a fresh copy of the release and returns the diff
regenerated against that release, with `source: "fallback"` and the reason in `notes`. If no file matches the
incident, if the diff is already applied or if it does not apply, the result is an empty diff with the reason in
`notes`, and the pipeline counts the attempt as having no proposal.

A fallback goes through the same five gates as an LLM diff. Its source is published on the bus (`patch.attempt`),
shown in the dashboard and stated in the pull request body and the commit message.

### derive_rule

`rule.py`. The result always has `id: rule-<incident>`, the incident's method and route, and `ttl_s: 3600`.

- `sqli` or `traversal` with a parameter: `scope: "param"`. The grammar is the character set of
  `grammar.SAFE_DEFAULT` with the length capped by the parameter's OpenAPI `maxLength` (at most 128). For `sqli` it
  also accepts one apostrophe between two letters (`O'Brien`) and never accepts `--`.
- The captured value must not match the grammar. If it does, `SAFE_DEFAULT` is tried; if the value matches that too,
  or cannot be found, the rule is `scope: "all"`.
- `idor`, `other`, no parameter, or a parameter marked `x-sensitive`: `scope: "all"`, `grammar: null`.

The pipeline validates the rule against the schema and replaces it with its built-in rule if it is invalid
(`pipeline/rules.py`). The rule is not replayed against legitimate traffic before activation. How the gateway
applies a rule is described in [`../gateway/README.md`](../gateway/README.md).

### variants

`variants.py` mutates the PoC's parameter, located from the evidence: the parameter named by the `sql` oracle, the
query or JSON value that ends the path opened in a `file` event, or the last numeric path segment for `owner`.

- `sqli`: case, whitespace and comment spacing; tautologies; comment terminators; parenthesis breaks; `UNION`; `||`;
  wire encodings; a duplicated query parameter.
- `traversal`: other depths and targets, absolute paths, `//` and `/./`, detours through sibling directories,
  `%2e` and `%2f` encodings.
- `idor`: other object ids, other spellings of the id (`05`, `+5`), other requesters.

It returns between 0 and 40 distinct requests (`MAX_VARIANTS`), none equal to the captured request and no padding:
a request with no parameter to mutate yields none. For the three recorded demo incidents it returns 31 (`sqli`),
26 (`traversal`) and 26 (`idor`); `tests/test_variants.py` asserts these counts. The pipeline counts only the
variants that fire the oracle on the unpatched release.

## Tests

```
.venv/bin/pytest patcher/tests -q -m "not live"
.venv/bin/pytest patcher/tests -q -m live -s
```

Run from the repository root. The first command needs neither Docker nor the LLM: it covers rules, variants (in the
in-process shadow harness), fallbacks (each applies to the `t0` code, the demo shop's tests pass, the documented
exploit fires before and not after), CLI failure handling with a stubbed CLI, the prompt fencing, and that the
workspace of the demo release holds no answer key. The second command calls the real `claude` CLI
(`tests/test_live.py`): a fix per class, and two confinement checks that plant a canary file outside the workspace.

`python -m patcher.bench [--release DIR] [--tests]` is a script, not a test; it calls the real CLI on the three
recorded incidents and prints seconds per fix.

## Limits

- The policy gate that judges the result is a heuristic. A model that follows injected text can still write a bad
  change inside the allowed files; the gates must reject it, and a semantic backdoor that needs no new literal,
  import or request read is not caught by `policy`.
- One model proposes. There is no second reviewer model.
- Edits are limited to files in the stack. A defect whose root cause is in a file outside the stack cannot be fixed
  by the LLM.
- The edit allow-list of `propose` contains only `.py` files. Other languages go through
  `pipeline/generic_patch.py`.
- The CLI process itself is not sandboxed by the operating system: it runs as the invoking user with the pipeline's
  environment, and the confinement is the CLI's own tool and permission enforcement.
- Fallbacks exist only for the demo shop and are tied to its `t0` code; after unrelated changes to the same lines
  they may not apply.
- `derive_rule` handles `sqli` and `traversal` parameters; every other case yields a rule scoped to the whole route.

The full list is in [`../docs/limites.md`](../docs/limites.md).
