"""Patch generator for app.runtime generic (any language): `propose(release_dir, incident, feedback, attempt)`.

Same contract as `patcher.propose` (contracts/interfaces.md) and the same confined Claude Code call
(`patcher.claude_cli`: Read + Edit only, Edit allowed only on the listed files, on a throw-away copy of
the release). What differs: there are no stack frames from outside the process, so the editable files
are located from the incident itself, by scoring every source file under `app.source_dirs` (tests and
vendored code excluded) on
  - the route: its static path segments (e.g. `/api/tasks/search`, `export`),
  - the parameter name (`q`, `name`, `task_id`),
  - the observed sink: constant fragments of the executed SQL statement around the attacker input
    (sql), the opened path (file), the table behind the route's path parameter in columns.yaml (owner),
  - class-specific sink APIs (query calls, file reads, SELECT ... WHERE id).
The best route file and the best sink files (up to 3 in total) become editable; the model may read
everything in the release. There is no plan-B (fallback) patch for this runtime.

The prompt is the shared template of `patcher.core.render` (patcher/prompts/*.md); this module only
supplies what is specific to a bug observed from outside the process.
"""
from __future__ import annotations

import json
import os
import re
import time

from patcher import claude_cli
from patcher import core as pcore
from patcher.workspace import Workspace

from .generic import TEST_RE, DEP_DIRS, SOURCE_EXT

MAX_EDITABLE = 3

# what the observer saw, without any request text: the statement / path themselves are attacker-influenced
# and are only shown inside the fenced evidence block (`observed[].detail`)
OBSERVED = {
    "sqli": "an SQL statement was executed with the request value outside a string literal (the statement is "
            "`observed[].detail.statement` in the evidence block below)",
    "traversal": "a file outside the allowed directories was opened (its path is `observed[].detail.path` in the "
                 "evidence block below)",
    "idor": "the response contained data that belongs to a user other than the requester (`observed[].detail` in "
            "the evidence block below)",
}
SINK_APIS = {
    "sqli": [r"\.query\s*\(", r"\bSELECT\b", r"\bexecute\s*\(", r"\bILIKE\b|\bLIKE\b"],
    "traversal": [r"readFile|createReadStream|sendFile|fs\.\w*open|os\.Open|File\.open|open\s*\(", r"path\.join|filepath\.Join|os\.path\.join"],
    "idor": [r"\bSELECT\b", r"WHERE\s+\w*\.?id\s*=", r"\.query\s*\("],
}


def _sources(root: str, dirs: list) -> list:
    out = []
    for d in dirs:
        base = os.path.join(root, d)
        if os.path.isfile(base):
            out.append(d)
            continue
        for cur, subdirs, files in os.walk(base):
            subdirs[:] = [s for s in subdirs if s not in DEP_DIRS and not s.startswith(".")]
            for fn in files:
                rel = os.path.relpath(os.path.join(cur, fn), root).replace(os.sep, "/")
                if os.path.splitext(fn)[1].lower() in SOURCE_EXT and not TEST_RE.search(rel) \
                        and not os.path.islink(os.path.join(cur, fn)):
                    out.append(rel)
    return sorted(set(out))


def _segments(route: str) -> list:
    segs = [s for s in (route or "").strip("/").split("/") if s and not s.startswith("{")]
    out = []
    if segs:
        out.append("/" + "/".join(segs))
        out.append(segs[-1])
    return [s for s in out if len(s) >= 3]


def _statement_fragments(inc: dict) -> list:
    """Constant pieces of the observed SQL around the attacker input (3+ words), as they appear in code."""
    frags = []
    for e in (inc.get("evidence") or {}).get("events") or []:
        d = e.get("detail") or {}
        st, inp = str(d.get("statement") or ""), str(d.get("input") or "")
        if not st:
            continue
        pieces = st.split(inp) if inp and inp in st else [st]
        for p in pieces:
            for chunk in re.split(r"'[^']*'?|\d+", p):
                chunk = chunk.strip(" ()%'")
                if len(chunk.split()) >= 3:
                    frags.append(chunk)
    return frags[:8]


def _owner_tables(inc: dict, cfg) -> list:
    try:
        import yaml
        from immune import _cfg
        with open(_cfg.columns_path(cfg)) as fh:
            cols = yaml.safe_load(fh) or {}
        name = (inc.get("param") or {}).get("name")
        m = (cols.get("routes") or {}).get(name) or {}
        return [m["table"]] if m.get("table") else []
    except Exception:  # noqa: BLE001
        return []


def locate(workdir: str, incident: dict, cfg) -> tuple[list, dict]:
    """-> (editable files, {file: score detail}) ranked from the incident (no stack frames)."""
    cls = incident.get("vuln_class") or "other"
    files = _sources(workdir, cfg.app.source_dirs)
    route_toks = _segments(incident.get("route") or "")
    param = (incident.get("param") or {}).get("name") or ""
    frags = _statement_fragments(incident) if cls == "sqli" else []
    tables = _owner_tables(incident, cfg) if cls == "idor" else []
    paths = []
    if cls == "traversal":
        for e in (incident.get("evidence") or {}).get("events") or []:
            paths.append(str((e.get("detail") or {}).get("path") or ""))
    route_score, sink_score, why = {}, {}, {}
    for f in files:
        try:
            with open(os.path.join(workdir, f), encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except OSError:
            continue
        r = s = 0
        notes = []
        for t in route_toks:
            if t in src or t.replace("/", "\\/") in src:
                r += 3 if t.startswith("/") else 2
                notes.append("route %s" % t)
        if param and re.search(r"""['"]%s['"]""" % re.escape(param), src):
            r += 1
            s += 1
            notes.append("param %s" % param)
        for fr in frags:
            if fr in src:
                s += 6
                notes.append("statement %r" % fr[:40])
        for t in tables:
            if re.search(r"\bFROM\s+%s\b" % re.escape(t), src, re.I):
                s += 3
                notes.append("FROM %s" % t)
        for api in SINK_APIS.get(cls, []):
            if re.search(api, src):
                s += 1
        if cls == "traversal" and re.search(r"readFile|createReadStream|sendFile|open\s*\(", src) and \
                re.search(r"path\.join|Join\(|os\.path\.join", src):
            s += 4
            notes.append("joins and opens a path")
        if cls == "idor" and route_toks and route_toks[-1] in src and re.search(r"\bSELECT\b", src):
            s += 2
        route_score[f], sink_score[f], why[f] = r, s, notes
    chosen = []
    by_route = sorted((f for f in files if route_score.get(f)), key=lambda f: (-route_score[f], f))
    by_sink = sorted((f for f in files if sink_score.get(f)), key=lambda f: (-sink_score[f], -route_score.get(f, 0), f))
    for f in by_sink[:2] + by_route[:1] + by_sink[2:]:
        if f not in chosen and len(chosen) < MAX_EDITABLE:
            chosen.append(f)
    return chosen, {f: {"route": route_score.get(f, 0), "sink": sink_score.get(f, 0), "why": why.get(f, [])}
                    for f in chosen}


def render(incident: dict, editable: list, feedback, attempt: int, cfg=None) -> str:
    dirs, db_kind = pcore._project(cfg)
    cls = incident.get("vuln_class") or "other"
    return pcore.render(
        incident, feedback, attempt, editable, source_dirs=dirs, db_kind=db_kind,
        observed_how="observed from outside the process: no stack trace is available",
        bug_lines=["- Observed at the sink: " + OBSERVED.get(cls, "(unknown)")],
        editable_note="They were located from the route, the parameter and the observed sink; read other files if "
                      "you need to (e.g. how the route is dispatched), but the fix belongs in the listed files.",
        start="Start by reading the listed files, then make the edit.")


def propose(release_dir: str, incident: dict, feedback: list | None = None, attempt: int = 1) -> dict:
    from immune import config as icfg
    cfg = icfg.current()
    t0 = time.time()
    with Workspace(release_dir, paths=cfg.app.release_paths) as ws:
        editable, scores = locate(ws.work, incident, cfg)
        if not editable:
            return {"diff": "", "source": "none", "notes": "no source file under %s matches the route, parameter or "
                                                          "sink" % cfg.app.source_dirs}
        prompt = render(incident, editable, feedback, attempt, cfg)
        res = claude_cli.run(prompt, ws.work, editable)
        diff = ws.diff()
    meta = "llm model=%s %.1fs turns=%s editable=%s located=%s" % (
        claude_cli.model(), time.time() - t0, res.turns, editable, json.dumps(scores)[:600])
    if res.ok and diff.strip():
        return {"diff": diff, "source": "llm", "notes": "%s\n%s" % (meta, res.text[:1500])}
    why = res.reason if not res.ok else "LLM produced an empty diff: %s" % res.text[:300]
    return {"diff": "", "source": "none", "notes": "%s; %s (no fallback patch for runtime generic)" % (meta, why)}
