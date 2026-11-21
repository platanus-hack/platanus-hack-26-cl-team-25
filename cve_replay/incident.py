"""Turn an oracle hit on a replay target into an incident of the shape patcher.propose eats
(see contracts/interfaces.md). The patcher only ever sees generic evidence + source; the
target name and CVE never reach the model.
"""
from __future__ import annotations

import base64

from .targets import Target


def build_incident(target: Target, request: dict, oracle_events: list[dict]) -> dict:
    """request: {method, path, status}. oracle_events: from FileEscapeOracle.check()."""
    inc_id = f"cve-{target.key}"
    body_b64 = base64.b64encode(b"").decode()
    req_record = {
        "method": request.get("method", target.method),
        "path": request.get("path", target.poc_path),
        "query": request.get("query", ""),
        "body_b64": body_b64,
    }
    # attach the statically-localised stack to the oracle event(s)
    events = [dict(e, stack=target.stack) for e in oracle_events]
    evidence = {
        "rid": inc_id,
        "release": target.source_subdir,
        "request": req_record,
        "status": request.get("status"),
        "uid": None,
        "role": None,
        "events": events,
    }
    return {
        "incident": inc_id,
        "vuln_class": target.vuln_class,
        "lang": "c",
        "method": req_record["method"],
        "route": target.route,
        "param": target.param,
        "sink": target.sink,
        "app_subdirs": target.app_subdirs,
        "editable_files": target.editable_files,
        "request": req_record,
        "evidence": evidence,
    }
