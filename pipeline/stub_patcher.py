"""Stand-in for `patcher` with the same signatures (contracts/interfaces.md), for tests and dry runs.

propose() returns the pre-recorded adequate fix of the incident's class from pipeline.fixes
(source "fallback"). STUB_PATCHER_PLAN=name1,name2,... picks the fix per attempt instead
(e.g. "sqli-quote-blacklist,adequate" to exercise the feedback loop). `calls` records invocations.
"""
from __future__ import annotations

import os

from . import fixes, rules

calls = []


def propose(release_dir: str, incident: dict, feedback: list, attempt: int) -> dict:
    calls.append({"release_dir": release_dir, "incident": incident.get("incident"), "feedback": list(feedback or []),
                  "attempt": attempt})
    plan = [p for p in os.environ.get("STUB_PATCHER_PLAN", "").split(",") if p]
    name = plan[attempt - 1] if attempt - 1 < len(plan) else "adequate"
    fix = fixes.adequate(incident.get("vuln_class")) if name == "adequate" else fixes.BY_NAME.get(name)
    if fix is None:
        return {"diff": "", "source": "fallback", "notes": "stub: no fix for %r" % name}
    try:
        diff = fixes.diff_for(fix, release_dir, incident)
    except fixes.FixNotApplicable as e:
        return {"diff": "", "source": "fallback", "notes": "stub: %s" % e}
    return {"diff": diff, "source": "fallback", "notes": "stub fix %s" % fix.name}


def variants(poc: dict, evidence: dict) -> list:
    return []


def derive_rule(incident: dict, openapi: dict) -> dict:
    return rules.default_rule(incident, openapi)
