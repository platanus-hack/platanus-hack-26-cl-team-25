# patcher/ (WP6)

Library called by `pipeline/` (interface: `contracts/interfaces.md`):

```python
patcher.propose(release_dir, incident, feedback, attempt) -> {"diff", "source": "llm"|"fallback", "notes"}
patcher.variants(poc, evidence) -> [request, ...]          # 15–40, deterministic, no LLM
patcher.derive_rule(incident, openapi) -> rule             # contracts/schemas/rule.schema.json
```

## propose: the LLM writes a diff, nothing else

1. `release_dir/victim` is copied (regular files only; symlinks, `__pycache__`, `*.pyc` are skipped)
   to `/tmp/patcher-XXXX/work/victim`. A baseline git repo is created in `/tmp/patcher-XXXX/git`,
   **outside** the work tree, so the model never sees or edits `.git`.
2. Claude Code runs headless with `cwd=/tmp/patcher-XXXX/work`, the prompt on stdin:

   ```
   $CLAUDE_BIN -p --model $PATCHER_MODEL --tools Read,Edit --strict-mcp-config --disable-slash-commands \
     --restricted --permission-mode dontAsk --permission-prompts none --no-session-persistence \
     --output-format json \
     --settings '{"permissions":{"allow":["Read(//tmp/patcher-XXXX/work/**)","Edit(//tmp/patcher-XXXX/work/victim/app/products.py)"],
                  "deny":["Edit(//tmp/patcher-XXXX/work/victim/tests/**)","Write(//tmp/patcher-XXXX/work/**)"],
                  "defaultMode":"dontAsk"},"disableAllHooks":true}'
   ```
   The binary is `$CLAUDE_BIN`, else `$CLAUDE_CODE_EXECPATH`, else `claude` on PATH. It uses the
   existing OAuth login (no `--bare`, no API key). The environment is inherited unchanged, so
   `ANTHROPIC_BASE_URL` passes through. Its value is never logged and is redacted from `notes`.
3. The result is `git diff` of the copy against the baseline (new files included), with paths
   relative to `release_dir` (`a/victim/app/products.py`). The model's final text only goes into `notes`.
4. Timeout, CLI failure, `is_error`, empty diff, or `PATCHER_FORCE_FALLBACK=1` → the fallback is
   applied to a fresh copy of the release and its diff is regenerated against that release, with
   `source: "fallback"` and the reason in `notes`. If there is no fallback, if it is already applied,
   or if it does not apply, the result is an empty diff with the reason in `notes`.

### Confinement (enforced per invocation; `~/.claude` is never modified)

| Layer | Mechanism | Effect |
|---|---|---|
| tool set | `--tools Read,Edit`, `--strict-mcp-config`, `--disable-slash-commands` | no Bash, web, agents, notebook, MCP, or skills; the CLI's init reports `tools: [Edit, Read]`, `mcp_servers: []` |
| directory | `--restricted` | file tools are confined to the working directory; user/project/local settings are ignored, so no user allow rules, hooks or plugins leak in |
| permissions | `--permission-mode dontAsk` + `--permission-prompts none` + `--settings` allow rules | everything not pre-allowed is denied. Read is allowed only under the copy. Edit is allowed only on the stack's app files (the generic DB helper, when it appears only as the innermost frame, is excluded). Tests are denied explicitly. Hooks are off |

Observed on this host (CLI 2.1.326):
- With `--restricted`, a Read outside the copy fails with "… is outside <work>; --restricted confines
  the file tools …", whether the path is absolute or written as `../../…`.
- In a separate probe without `--restricted`, the dontAsk allow-list alone also denied the outside Read.
- Edits to `victim/tests/conftest.py` and `victim/app/db.py` inside the copy were denied. The edit to
  `products.py` was allowed. This also shows the `--settings` JSON is loaded (an invalid settings file
  would be silently ignored in `-p` mode, and then no Edit at all would be allowed).
- All of this is recorded in the CLI's `permission_denials`, and `notes` includes it.

Tests: `tests/test_live.py::test_canary_direct_instruction_is_denied_by_cli` (operator-level
instruction to read the canary: denied by the CLI) and `::test_canary_via_evidence_injection`
(attacker text in the evidence: the canary is absent from the diff).

### Prompt

`prompts/fix.md` (main template), `prompts/classes.md` (what a correct fix looks like, per class), and
`prompts/feedback.md` (gate output on retries). The prompt gives the class, endpoint, parameter, sink,
the stack with file:line, the editable files and the rules (root-cause fix, no new imports, inputs or
special-cased literals, legitimate behaviour unchanged, tests untouched). Evidence and gate output
are JSON or text inside `<<<EVIDENCE-<nonce>` … `EVIDENCE-<nonce>>>>` markers and are declared
untrusted data. Authorization and cookie headers are redacted, and long strings are clipped.

## Fallbacks (plan B)

`fallbacks/<class>__<slug>.diff`, where slug is method + route in lower case with each run of
non-`[a-z0-9_]` characters turned into `-`. There is one fallback per `victim/VULNS.md` entry:

```
sqli__get-api-products.diff                     sqli__post-api-login.diff
traversal__get-api-files-download.diff          traversal__get-api-products-product_id-image.diff
idor__get-api-orders-order_id.diff              idor__get-api-orders-order_id-invoice.diff
idor__get-api-users-user_id-profile.diff
```
Each one is checked by `tests/test_fallbacks.py`: it applies to t0, `victim/tests` passes, and the
VULNS.md exploit fires the oracle before the fix and not after. All seven together also pass, and
the invoice fix still applies after the get_order fix has shipped.

## variants

The variants mutate the PoC's parameter, found from the evidence: the `sql` detail param and
location, the query/JSON value that ends the `file` path, or the last numeric path segment for `owner`.
- sqli: case, whitespace and comment spacing; tautologies with the captured prefix and generic ones;
  comment terminators; parenthesis breaks; UNION; `||`; several wire encodings; a duplicated parameter.
- traversal: other depths and targets, absolute paths, `//` and `/./`, detours through sibling
  directories, and `%2e`/`%2f` encodings.
- idor: other object ids, other spellings of the id (`05`, `+5`), and other requesters (`uid`).

On t0, 23/31 (sqli), 25/29 (traversal) and 26/26 (idor) fire the oracle. A naive fix that only
blocks the captured value still fires ≥5. The root-cause fallback fires 0 (`tests/test_variants.py`).

## derive_rule

- sqli or traversal with a parameter → `scope: "param"`. Traversal uses `[A-Za-z0-9 _.,@:+\-]{0,N}`
  (the `SAFE_DEFAULT` set). sqli uses the same set plus one apostrophe between two letters
  (`O'Brien`, `o'neil@…`) and never `--`. N is the OpenAPI `maxLength` (≤128). The captured value
  is checked not to match.
- idor/other, no parameter, an `x-sensitive` parameter, or a captured value that would match
  `SAFE_DEFAULT` → `scope: "all"`, `grammar: null`.
- `id: rule-<incident>`, `ttl_s: 3600`.

## Env

| Var | Default | Meaning |
|---|---|---|
| `PATCHER_MODEL` | `sonnet` | `--model` |
| `PATCHER_TIMEOUT_S` | `180` | hard timeout; the CLI's process group gets SIGKILL |
| `CLAUDE_BIN` | `$CLAUDE_CODE_EXECPATH` or `claude` | CLI binary |
| `PATCHER_FORCE_FALLBACK` | unset | `1` = skip the LLM and use the plan B |
| `ANTHROPIC_BASE_URL` | inherited | passed through unchanged, never logged |

## Commands

```
.venv/bin/pytest patcher/tests -m "not live" -q        # unit tests (~1 min, no LLM)
.venv/bin/pytest patcher/tests -m live -s -q           # 5 real CLI calls
PATCHER_MODEL=opus .venv/bin/python -m patcher.bench --tests
```

## Limits

- The prompt-injection defence is the confinement plus the pipeline's gates, not the delimiters.
  A model that follows injected text can still write a bad fix *inside* the allowed files. The policy,
  properties and PoC gates must reject it.
- Edit is limited to the stack's app files. A bug whose root cause is outside the stack cannot be
  fixed by the LLM and falls back.
- Fallbacks are tied to the t0 code. After unrelated changes to the same lines they may not apply
  (reported in `notes`, empty diff).
- `--restricted`, `dontAsk` and `--permission-prompts` are CLI features of 2.1.x. If a future CLI
  drops one of them, startup fails and propose falls back. It does not run unconfined.
- `checks.py` and `_harness_probe.py` are local self-checks for these tests and the bench, not the
  pipeline's gates.
