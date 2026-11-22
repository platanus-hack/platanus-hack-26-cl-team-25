"""patcher.propose: an untrusted LLM proposes a diff, nothing else."""
from __future__ import annotations

import json
import os
import re
import secrets
from string import Template

from . import claude_cli
from .fallback import apply_fallback
from .workspace import Workspace

PROMPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts")
_MAX_STR = 1500
_SECRET_HEADERS = {"authorization", "cookie", "x-imm-signature"}


def _read(name: str) -> str:
    with open(os.path.join(PROMPT_DIR, name), encoding="utf-8") as f:
        return f.read()


def _class_rules(vuln_class: str) -> str:
    sections, cur = {}, None
    for line in _read("classes.md").splitlines(keepends=True):
        m = re.fullmatch(r"## (\w+)\s*", line)
        if m and m.group(1) in ("sqli", "traversal", "idor", "other"):
            cur = m.group(1)
            sections[cur] = ""
        elif cur:
            sections[cur] += line
    return (sections.get(vuln_class) or sections["other"]).strip()


def _clip(v):
    if isinstance(v, str):
        return v if len(v) <= _MAX_STR else v[:_MAX_STR] + "...<truncated>"
    if isinstance(v, dict):
        return {k: _clip(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_clip(x) for x in v[:20]]
    return v


def _evidence_record(incident: dict) -> dict:
    ev = incident.get("evidence") or {}
    req = dict(ev.get("request") or incident.get("request") or {})
    if isinstance(req.get("headers"), dict):
        req["headers"] = {k: ("<redacted>" if k.lower() in _SECRET_HEADERS else v) for k, v in req["headers"].items()}
    return _clip({
        "request": req,
        "response_status": ev.get("status"),
        "requester": {"uid": ev.get("uid"), "role": ev.get("role")},
        "observed": [{"oracle": e.get("oracle"), "detail": e.get("detail")} for e in ev.get("events") or []],
    })


def stack_frames(incident: dict) -> list[dict]:
    seen, out = set(), []
    for e in (incident.get("evidence") or {}).get("events") or []:
        for fr in e.get("stack") or []:
            key = (fr.get("file"), fr.get("line"))
            if key not in seen:
                seen.add(key)
                out.append(fr)
    sink = incident.get("sink") or {}
    if sink.get("file") and (sink.get("file"), sink.get("line")) not in seen:
        out.append({"file": sink["file"], "line": sink.get("line"), "func": "(sink)"})
    return out


def _source_dirs(dirs=None) -> list[str]:
    if dirs is None:
        from immune import config as icfg
        dirs = icfg.current().app.source_dirs
    return [d.strip("/") for d in dirs if d and d.strip("/")]


def editable_files(incident: dict, workdir: str, source_dirs: list[str] | None = None) -> list[str]:
    """Files the model may edit (relative to workdir): the app files of the stack under
    `app.source_dirs`, except a file that only appears as the innermost frame below app code
    (the generic DB helper the statement reached, not where it was built), plus the reported sink file."""
    dirs = _source_dirs(source_dirs)
    cands = []
    for e in (incident.get("evidence") or {}).get("events") or []:
        st = list(e.get("stack") or [])
        inner = st[-1].get("file") if st else None
        outer = [fr for fr in st if fr.get("file") != inner]
        cands += outer or st
    if (incident.get("sink") or {}).get("file"):
        cands.append(incident["sink"])
    files = []
    for fr in cands:
        # Stack paths are POSIX-relative; normpath only validates the shape, and
        # the comparison against source_dirs must stay slash-based on Windows too.
        f = os.path.normpath(str(fr.get("file") or "")).replace(os.sep, "/")
        if any(f.startswith(d + "/") for d in dirs) and f.endswith(".py") and f not in files \
                and os.path.isfile(os.path.join(workdir, f)):
            files.append(f)
    return files


def render_prompt(incident: dict, feedback: list[str] | None, attempt: int, editable: list[str]) -> str:
    nonce = secrets.token_hex(8)
    evidence_json = json.dumps(_evidence_record(incident), indent=1, ensure_ascii=True, sort_keys=True)
    fb_text = "\n\n".join(_clip(str(f)) for f in (feedback or []) if str(f).strip())
    while nonce in evidence_json or nonce in fb_text:
        nonce = secrets.token_hex(8)
    param = incident.get("param") or {}
    sink = incident.get("sink") or {}
    frames = stack_frames(incident)
    stack = "\n".join(f"  - {fr.get('file')}:{fr.get('line')} in {fr.get('func')}" for fr in frames) or "  (none)"
    feedback_section = ""
    if fb_text:
        feedback_section = Template(_read("feedback.md")).safe_substitute(
            attempt=max(1, attempt - 1), nonce=nonce, feedback=fb_text)
    return Template(_read("fix.md")).safe_substitute(
        vuln_class=incident.get("vuln_class", "other"),
        method=incident.get("method", "?"),
        route=incident.get("route", "?"),
        param=(f"{param.get('name')} (in {param.get('in')})" if param.get("name") else "(none)"),
        sink=(f"{sink.get('file')}:{sink.get('line')}" if sink.get("file") else "(unknown)"),
        stack=stack,
        editable_files=", ".join(f"`{e}`" for e in editable) or ", ".join(f"`{d}/*.py`" for d in _source_dirs()),
        class_rules=_class_rules(incident.get("vuln_class", "other")),
        nonce=nonce,
        evidence_json=evidence_json,
        feedback_section=feedback_section,
    )


def propose(release_dir: str, incident: dict, feedback: list[str] | None = None, attempt: int = 1) -> dict:
    if os.environ.get("PATCHER_FORCE_FALLBACK") == "1":
        return apply_fallback(release_dir, incident, "PATCHER_FORCE_FALLBACK=1")
    with Workspace(release_dir) as ws:
        editable = editable_files(incident, ws.work)
        prompt = render_prompt(incident, feedback, attempt, editable)
        res = claude_cli.run(prompt, ws.work, editable)
        diff = ws.diff()
    if res.ok and diff.strip():
        meta = f"llm model={claude_cli.model()} {res.seconds:.1f}s turns={res.turns}"
        if res.denials:
            meta += f" denied={json.dumps(res.denials)[:600]}"
        if ws.skipped:
            meta += f" skipped_symlinks={ws.skipped[:5]}"
        return {"diff": diff, "source": "llm", "notes": f"{meta}\n{res.text[:2000]}".strip()}
    reason = res.reason if not res.ok else f"LLM produced an empty diff ({res.seconds:.1f}s): {res.text[:300]}"
    return apply_fallback(release_dir, incident, reason)
