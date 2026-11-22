"""Plan B: hand-written root-cause fixes, one per entry of the demo answer key
(docs/demo/respuestas/tienda.md, outside every release path).

Used only when the LLM is unavailable (timeout, CLI failure, empty diff, or
PATCHER_FORCE_FALLBACK=1). Always reported with source "fallback".
File name: fallbacks/<vuln_class>__<slug>.diff, slug = method + route, lower case,
every run of characters outside [a-z0-9_] replaced by "-".
"""
from __future__ import annotations

import os
import re

from .workspace import Workspace

FALLBACK_DIR = os.environ.get("PATCHER_FALLBACK_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "fallbacks")


def route_slug(method: str, route: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "-", f"{method} {route}".lower()).strip("-")


def fallback_path(incident: dict) -> str:
    name = f"{incident.get('vuln_class', 'other')}__{route_slug(incident.get('method', ''), incident.get('route', ''))}.diff"
    return os.path.join(FALLBACK_DIR, name)


def apply_fallback(release_dir: str, incident: dict, reason: str) -> dict:
    """Apply the pre-written fix to a fresh copy of the release and return its diff
    regenerated against that release (so context always matches what is in prod)."""
    path = fallback_path(incident)
    head = f"fallback ({reason})"
    if not os.path.isfile(path):
        return {"diff": "", "source": "fallback", "notes": f"{head}; no fallback {os.path.basename(path)}"}
    patch = open(path, encoding="utf-8").read()
    with Workspace(release_dir, prefix="patcher-fb-") as ws:
        if ws.is_applied(patch):
            return {"diff": "", "source": "fallback",
                    "notes": f"{head}; {os.path.basename(path)} is already applied in this release"}
        ok, msg = ws.apply(patch)
        if not ok:
            return {"diff": "", "source": "fallback",
                    "notes": f"{head}; {os.path.basename(path)} does not apply: {msg[:500]}"}
        diff = ws.diff()
    note = f"{head}; pre-written fix {os.path.basename(path)}" + (f" ({msg})" if msg else "")
    return {"diff": diff, "source": "fallback", "notes": note}
