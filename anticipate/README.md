# anticipate

## Purpose

`anticipate` is a source-code review mode, separate from the request path. Given the public source of a released
version that was later fixed upstream, it asks the model to find and fix a defect of a stated class in a stated
area, then checks the suggested patch mechanically and compares it with the official fix. It never runs the
target server and sends no traffic.

It is demonstrated on one target: Apache HTTP Server 2.4.49 (`targets/apache-httpd-2.4.49/`).

## How it runs

On the host, as a CLI. `immune anticipate ...` is an alias of `python -m anticipate ...` (`immune/__main__.py`).

```
.venv/bin/python -m anticipate list
.venv/bin/python -m anticipate check apache-httpd-2.4.49
.venv/bin/python -m anticipate run apache-httpd-2.4.49 [--model MODEL] [--out DIR]
.venv/bin/python -m anticipate recheck RESULT_DIR
```

| Command | Model call | Does |
|---|---|---|
| `list` | no | Lists the targets under `targets/` |
| `check T` | no | Runs the mechanical check on the released and the official version and prints each vector |
| `run T` | yes | Full run: fetch, baseline check, confined review, checks of both patches, comparison, report. Exit 0 only when the suggested patch compiles and passes every vector |
| `recheck RESULT_DIR` | no | Re-runs the checks and the comparison on a stored `result.json` and rewrites the report |

Prerequisites: `git` and network access to the target's repository (the two tags are fetched shallowly into
`<runtime>/anticipate/cache/`); Docker with the image `immune-cbuild:1`, which `install.sh` builds only when
`IMMUNE_WITH_ANTICIPATE=1`; for `run`, the `claude` CLI.

Reports are written to `<runtime>/anticipate/reports/<target>/<timestamp>/` as `result.json`, `report.md` and a
self-contained `report.html`, or to `--out`.

## Layout

| File | Role |
|---|---|
| `__main__.py` | Argument parsing and exit codes |
| `core.py` | Fetch, workspace, prompt rendering, review, C function extraction, check, equivalence, localisation, `run`, `recheck` |
| `report.py` | Markdown and HTML report, including the notes on what the model was given and what the score means |
| `prompts/audit.md` | The single prompt template |
| `targets/<id>/target.yaml` | Repository, refs, defect class, area text, scope, read-only context, check definition |
| `targets/<id>/vectors.yaml` | Test vectors, written by the team |
| `targets/<id>/shim.h` | Minimal declarations so the extracted functions compile alone |
| `tests/` | Unit tests; one Docker-backed test of the check |

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `RUNTIME_DIR` | `runtime/` in the repository | Root of the cache and the reports |
| `ANTICIPATE_MODEL` | `opus` | Model, when `--model` is not given |
| `ANTICIPATE_TIMEOUT_S` | `900` | Timeout of the review |

## Behaviour

`core.run` does five steps:

1. **Fetch** both tags (`vulnerable_ref`, `fixed_ref`) into a cached repository and compute the official diff
   over the scope.
2. **Baseline check** of the released code.
3. **Review**. The files in `scope` and `context` are copied from the released version into a temporary work
   tree with a private git baseline kept outside it. The model runs through `patcher/claude_cli.py`, the same
   confinement as the patch generator: it can read that work tree and edit only the files in `scope`. The diff
   is taken against the baseline.
4. **Check** the suggested patch and the official version with the same vectors, and compare them.
5. **Report**.

### What the model is given

Rendered from `prompts/audit.md` by `core.render_prompt`: the product name and version, the `area` text, the
defect class with its mechanism (`CLASS_TEXT` in `core.py`), the list of files in scope and in context, and the
instruction to keep legitimate behaviour unchanged. It is not given the advisory identifier, the fixed version,
the official diff or the vectors. `tests/test_anticipate.py` checks the prompt for the first two.

### The mechanical check (`core.run_check`)

The check kind is `c-function`. The functions named in `target.yaml` are extracted from the file by brace
matching, concatenated after `shim.h` with a generated `main`, compiled with `gcc` and run in a container with
`--network none`, a read-only root, all capabilities dropped, `no-new-privileges`, and pid, memory and CPU
limits. For the Apache target the 21 vectors are of two kinds:

| Kind | Count | Passes when |
|---|---|---|
| `legit` (`exact`) | 12 | Return value and output buffer equal the expected ones |
| `dot-segment` (`no_parent_segment`) | 9 | The output has no `..` segment (with `%2e` read as `.`), and inputs marked `above_root` are rejected |

### Comparison

- `equivalence`: the number of vectors for which the suggested and the official version return the same pair
  (return value, output buffer).
- `compare`: whether the two diffs change the same enclosing C function, whether their changed line ranges
  overlap, and how many lines each changes.

The measured result on Apache 2.4.49, with its date, conditions and the generated report, is in
[`docs/resultados.md`](../docs/resultados.md) and
[`docs/demo/anticipacion-apache-2.4.49.md`](../docs/demo/anticipacion-apache-2.4.49.md).

## Tests

```
.venv/bin/pytest anticipate/tests -q
.venv/bin/pytest anticipate/tests -q -m "not docker"
```

The first form includes one test marked `docker`, which needs Docker, the image `immune-cbuild:1` and the two
Apache tags (fetched over the network unless already in the cache). No test calls the LLM.

## Limits

- It is not a blind review. The model is told the product, the version, the area, the defect class and a
  one-file scope chosen by the operator. The advisory for this target is public and almost certainly in the
  model's training data. The run demonstrates the mechanism (find, patch, check, compare), not discovery.
- The score is the behaviour of the extracted function compiled against a shim on the team's vectors. It is not
  behavioural equivalence of the server: httpd is neither built nor run, and nothing is claimed outside those
  inputs.
- The reference is the official 2.4.50 change. Upstream later found that fix incomplete (CVE-2021-42013, fixed
  in 2.4.51), so agreement with 2.4.50 is agreement with an incomplete fix.
- The check harness (`c-function` calling `ap_normalize_path`) is specific to this target. Another target needs
  its own harness.
- For third-party software the operational answer is a gateway rule and an upgrade to the fixed version. The
  suggested patch is evidence that the cause was located, not something to deploy.

The full list across components is in [`docs/limites.md`](../docs/limites.md).
