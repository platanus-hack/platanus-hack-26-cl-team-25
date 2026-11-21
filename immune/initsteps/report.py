"""`.immune/context/schema.md` (LLM context: schema and value *shapes*, never values) and `.immune/report.md`."""
from __future__ import annotations

import json
import os
import re
import sqlite3

import yaml


EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEXRE = re.compile(r"^[0-9a-fA-F]{16,}$")


def _shape(conn, table, col) -> str:
    q = '"%s"' % col.replace('"', '""')
    t = '"%s"' % table.replace('"', '""')
    rows = [r[0] for r in conn.execute("SELECT %s FROM %s LIMIT 500" % (q, t))]
    if not rows:
        return "empty"
    n = len(rows)
    nulls = sum(v is None for v in rows)
    vals = [v for v in rows if v is not None]
    if not vals:
        return "all NULL"
    kinds = []
    s = [v for v in vals if isinstance(v, str)]
    if s:
        avg = sum(len(v) for v in s) / len(s)
        em = sum(bool(EMAIL.match(v)) for v in s)
        hx = sum(bool(HEXRE.match(v)) for v in s)
        sp = sum(" " in v for v in s)
        kinds.append("text avg %d chars" % avg)
        if em:
            kinds.append("%d%% e-mail-like" % (100 * em // len(s)))
        if hx:
            kinds.append("%d%% long hex" % (100 * hx // len(s)))
        if sp:
            kinds.append("%d%% contain spaces" % (100 * sp // len(s)))
    nums = [v for v in vals if isinstance(v, (int, float))]
    if nums:
        kinds.append("numeric %s..%s" % (min(nums), max(nums)) if len(set(nums)) > 1 else "numeric constant")
    distinct = len(set(map(str, vals)))
    kinds.append("%d distinct of %d" % (distinct, len(vals)))
    if nulls:
        kinds.append("%d%% NULL" % (100 * nulls // n))
    return ", ".join(kinds)


def schema_md(schema: dict, prod_db: str) -> str:
    conn = sqlite3.connect("file:%s?mode=ro" % prod_db, uri=True)
    try:
        out = ["# Database schema (from the production SQLite file; values are never shown, only their shape)", ""]
        for name, info in schema["tables"].items():
            out.append("## %s (%d rows)%s" % (name, info["rows"], " WITHOUT ROWID" if info["without_rowid"] else ""))
            out.append("")
            out.append("| column | type | key | shape |")
            out.append("|---|---|---|---|")
            fks = {f["from"]: "%s.%s" % (f["table"], f["to"] or "?") for f in info["fks"]}
            for c in info["columns"]:
                key = []
                if c["pk"]:
                    key.append("PK")
                if c["name"] in fks:
                    key.append("FK->" + fks[c["name"]])
                if c["notnull"]:
                    key.append("NOT NULL")
                out.append("| %s | %s | %s | %s |" % (c["name"], c["type"] or "?", " ".join(key),
                                                       _shape(conn, name, c["name"])))
            out.append("")
            if info.get("sql"):
                out += ["```sql", info["sql"], "```", ""]
        return "\n".join(out)
    finally:
        conn.close()


def _load(path):
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def write(init) -> str:
    p = init.path
    cols = _load(p(".immune/shadow/columns.yaml"))
    auth = _load(p(".immune/shadow/auth.yaml"))
    marks = _load(p(".immune/shadow/marks.yaml"))
    d = init.det
    st = init.step_state
    L = ["# immune init report: %s" % d.get("name"), ""]
    L += ["## Detected", ""]
    for k, label in (("runtime", "runtime"), ("framework", "framework"), ("asgi", "ASGI entry"), ("port", "port"),
                     ("port_source", "port from"), ("health", "health route"), ("db_env", "database env var"),
                     ("prod_db_abs", "production database"), ("secret_envs", "secret env vars"),
                     ("time_env", "frozen-time env var"), ("release_paths", "release paths"),
                     ("source_dirs", "source dirs (fix edit area)"), ("tests_command", "tests command")):
        L.append("- %s: `%s`" % (label, d.get(k)))
    L.append("- deploy style: `%s` (%s)" % ((d.get("deploy") or {}).get("style"),
                                            ", ".join((d.get("deploy") or {}).get("files") or []) or "no files"))
    L += ["", "## Assumed", ""]
    L += ["- %s" % a for a in init.assumptions] or ["- nothing beyond the detected facts"]
    if not d.get("tests_command"):
        L.append("- no tests command: autopatch is capped at `pr`")
    L.append("- autopatch set to `pr` (opening a PR, no automatic merge); enable merge with `immune autopatch merge`")
    L += ["", "## LLM calls", ""]
    if not init.use_llm:
        L.append("- none (`--no-llm`): the files below are heuristic drafts; every TODO(immune) needs a human")
    for c in init.llm_calls:
        L.append("- %s: %.0fs, ok=%s, changed=%s%s" % (c["step"], c["seconds"], c["ok"], c["changed"] or "nothing",
                                                       (", " + c["reason"][:160]) if c["reason"] else ""))
    for step, s in st.items():
        L.append("- result of %s: %s%s" % (step, s.get("source"), (" (errors: %s)" % "; ".join(s["errors"][:3]))
                                           if s.get("errors") else ""))
    L += ["", "## Needs human review", "",
          "Every classification below was proposed by %s and verified only mechanically (doctor checks); "
          "a wrong `public` or missing `private` column can copy real data into the shadow." % (
              "the LLM" if (st.get("columns") or {}).get("source") == "llm" else "heuristics"), ""]
    why = cols.get("why") or {}
    L += ["### Tables and columns (`.immune/shadow/columns.yaml`)", "",
          "| table.column | classification | justification |", "|---|---|---|"]
    for t, spec in (cols.get("tables") or {}).items():
        spec = spec or {}
        if spec.get("public"):
            L.append("| %s | public (copied) | %s |" % (t, why.get(t, "")))
            continue
        L.append("| %s | owner: `%s` | %s |" % (t, spec.get("owner"), why.get(t, "")))
        for kind in ("private", "secret"):
            for c in spec.get(kind) or []:
                L.append("| %s.%s | %s | %s |" % (t, c, kind, why.get("%s.%s" % (t, c), "")))
    L += ["", "Path parameters -> rows: %s" % json.dumps(cols.get("routes") or {}), ""]
    L += ["### Authentication (`.immune/shadow/auth.yaml`, `.immune/profile.py`)", "",
          "- auth: `%s`" % json.dumps(auth.get("auth")), "- why: %s" % (auth.get("why") or ""), ""]
    L += ["### OpenAPI marks (`.immune/shadow/marks.yaml` -> `.immune/openapi.yaml`)", ""]
    for e in marks.get("owner_scoped") or []:
        L.append("- x-owner-scoped `%s`: %s" % (e.get("op") if isinstance(e, dict) else e,
                                                (e.get("why") if isinstance(e, dict) else "")))
    for e in marks.get("sensitive") or []:
        L.append("- x-sensitive `%s` %s `%s`: %s" % (e.get("op"), e.get("in"), e.get("name"), e.get("why", "")))
    todos = []
    for rel in (".immune/profile.py", ".immune/shadow/columns.yaml", ".immune/shadow/auth.yaml",
                ".immune/shadow/marks.yaml"):
        try:
            with open(p(rel), encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    if "TODO(immune)" in line:
                        todos.append("`%s:%d` %s" % (rel, i, line.strip()[:120]))
        except OSError:
            pass
    if todos:
        L += ["", "### TODO(immune) markers left", ""] + ["- %s" % t for t in todos]
    warns = (init.shadow_report or {}).get("warnings") or []
    if warns:
        L += ["", "### Shadow data warnings", ""] + ["- %s" % w for w in warns]
    L += ["", "## Verification (`immune doctor`)", ""]
    for c in init.doctor_results:
        L.append("- [%s] %d %s: %s" % (c["status"], c["id"], c["name"], c["reason"]))
    if init.attention:
        L += ["", "## Needs attention", ""] + ["- %s" % a for a in init.attention]
    L.append("")
    text = "\n".join(L)
    with open(p(".immune/report.md"), "w") as f:
        f.write(text)
    return text
