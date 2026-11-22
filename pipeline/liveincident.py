"""The incident the patcher works on, built from the bus events of a live incident.

``incident.opened`` carries the class, route, request and the sink (``stack[-1]`` of the oracle's evidence, see
``incident.py``); ``oracle.fired`` (same evidence rid) carries the evidence the patcher is shown: the request, who sent
it, and the oracle events with their stack. Putting them together means a patch is proposed from what the oracles
actually observed, with the sink they located, instead of from a hand-written incident.

Returns None when the evidence did not locate a sink (``stack: []``): the caller keeps its own fallback.
"""
from __future__ import annotations


def from_events(events: list[dict], iid: str, lang: str = "") -> dict | None:
    opened = next((e for e in events if e.get("type") == "incident.opened" and e.get("incident") == iid), None)
    if opened is None:
        return None
    d = opened.get("data") or {}
    sink = d.get("sink") or {}
    if not sink.get("file"):
        return None
    rid = d.get("evidence_rid")
    fired = next((e for e in events if e.get("type") == "oracle.fired" and rid and e.get("rid") == rid), None)
    evidence = dict((fired or {}).get("data") or {})
    inc = {"incident": iid, "vuln_class": d.get("vuln_class") or "other",
           # no established identity behind the request: a missing-authentication bug, not an IDOR
           "anon": evidence.get("uid") is None,
           "method": d.get("method") or "GET", "route": d.get("route") or "/", "param": d.get("param"),
           "sink": {"file": sink["file"], "line": int(sink.get("line") or 1),
                    "func": ((evidence.get("events") or [{}])[0].get("stack") or [{}])[-1].get("func", "")},
           "request": d.get("request") or evidence.get("request"), "evidence": evidence,
           # the file the oracle located is the one the fix belongs in, whatever the language
           "editable_files": [sink["file"]], "app_subdirs": [sink["file"].split("/")[0]]}
    if lang:
        inc["lang"] = lang
    return inc
