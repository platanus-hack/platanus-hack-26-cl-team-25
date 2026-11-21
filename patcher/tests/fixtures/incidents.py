"""Incidents (contracts/interfaces.md shape) built from the three real oracle.fired events
captured from the running stack (oracle_events.json, GET /events?type=oracle)."""
from __future__ import annotations

import copy
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# what the pipeline would derive from each event (class, OpenAPI route, param, sink)
_META = {
    "sql": dict(vuln_class="sqli", route="/api/products", param={"in": "query", "name": "q"},
                sink={"file": "victim/app/products.py", "line": 28}),
    "file": dict(vuln_class="traversal", route="/api/files/download", param={"in": "query", "name": "name"},
                 sink={"file": "victim/app/files.py", "line": 20}),
    "owner": dict(vuln_class="idor", route="/api/orders/{order_id}", param={"in": "path", "name": "order_id"},
                  sink={"file": "victim/app/orders.py", "line": 82}),
}


def events() -> list[dict]:
    with open(os.path.join(HERE, "oracle_events.json")) as f:
        return json.load(f)["events"]


def incident_for(oracle: str) -> dict:
    for ev in events():
        data = ev["data"]
        if data["events"][0]["oracle"] != oracle:
            continue
        meta = copy.deepcopy(_META[oracle])
        req = data["request"]
        inc_id = f"fx-{meta['vuln_class']}"
        poc = {"incident": inc_id, "release": data["release"], "state_b64": None,
               "requests": [dict(req, uid=data.get("uid"), role=data.get("role"))],
               "expect": {"oracle": oracle, "sink": meta["sink"]}}
        return {"incident": inc_id, "method": req["method"], "evidence_rid": data["rid"],
                "request": {k: req[k] for k in ("method", "path", "query", "body_b64")},
                "evidence": data, "poc": poc, **meta}
    raise KeyError(oracle)


def all_incidents() -> dict[str, dict]:
    return {o: incident_for(o) for o in _META}
