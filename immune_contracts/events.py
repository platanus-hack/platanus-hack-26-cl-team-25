"""Event bus envelope and event type names.

Every event is one JSON object:
  {"type": <one of TYPES>, "ts": <unix float>, "run": <run id str>, "src": <component>, "rid": <request id or null>,
   "incident": <incident id or null>, "data": {...}}

Publish:   POST {BUS_URL}/events          header x-bus-token: $BUS_TOKEN    body: one event or a JSON list of events
Subscribe: GET  {BUS_URL}/events/stream?since=<seq>   (text/event-stream; each message: id=<seq>, data=<event json>)
History:   GET  {BUS_URL}/events?since=<seq>&type=<prefix>&limit=<n>  -> {"events":[{"seq":n, ...event}], "next": n}
           always one page (dashboard/server.py: 1000 events by default, 5000 at most); a reader repeats the call
           with since=<next> until a page comes back empty.
Readers that do not send the bus token get a redacted copy of each event (dashboard/server.py, redact).

Publishing must never block a request path. The gateway queues events and posts them from a background worker
(gateway/bus.py: 1.0 s timeout, 0.3 s connect): `request.*` events are dropped on failure, the others are
retried for 120 s (at most 2000 kept). The pipeline keeps undelivered events pending and sends them again
(pipeline/bus.py); the fleet does not retry (fleet/manager.py).

Full reference, including which fields are optional: contracts/README.md section 10.
"""
from __future__ import annotations
import time

# gateway
REQ_CLASSIFIED = "request.classified"   # data: {class: clean|suspect|captive|evidence, reasons:[..], method, path, session, uid}; observe: true in observe mode
REQ_ROUTED = "request.routed"           # data: {route: prod|shadow_l1|shadow_l2|l0|deny, status, verdict, ms}; observe mode adds observe: true and would_route
ORACLE_FIRED = "oracle.fired"           # data: evidence object (contracts/schemas/evidence.schema.json) + {session, uid}
SESSION_CAPTURED = "session.captured"   # data: {session, clone: id or null until bound, reason: oracle|aftercheck|bound|<first classification reason>}
SESSION_RELEASED = "session.released"   # data: {session, clone, reason: ttl|evicted|clone_gone|reset}
RULE_ACTIVE = "rule.active"             # data: rule object (contracts/schemas/rule.schema.json) + expires_in
RULE_EXPIRED = "rule.expired"           # data: {id, reason: ttl|deleted|reset}
UPSTREAM_SWITCHED = "upstream.switched" # data: {release, addr}
# fleet (container manager)
POOL_STATE = "pool.state"               # data: {l1_free, l2_busy, size}
DEPLOY_STARTED = "deploy.started"       # data: {release}
DEPLOY_DONE = "deploy.done"             # data: {release, ok: bool, rolled_back: bool, detail}
# pipeline
INCIDENT_OPENED = "incident.opened"     # data: {incident, vuln_class: sqli|traversal|idor|other, method, route, param, sink:{file,line}, evidence_rid, request:{method,path,query,body_b64}}
POC_READY = "poc.ready"                 # data: {incident, reproducible: bool, runs, poc}
PATCH_ATTEMPT = "patch.attempt"         # data: {incident, attempt, source: llm|fallback|unknown}  (unknown: the generator did not say)
PATCH_DIFF = "patch.diff"               # data: {incident, attempt, diff}
GATE_RESULT = "gate.result"             # data: {incident, attempt, gate: policy|properties|poc|tests|legit, ok, detail}; skipped: true when the gate was skipped
PR_OPENED = "pr.opened"                 # data: {incident, url, branch}
PR_MERGED = "pr.merged"                 # data: {incident, url, sha}
INCIDENT_CLOSED = "incident.closed"     # data: {incident, outcome: patched|rule_only|not_reproducible|error, seconds_to_rule, seconds_to_patch}; optional outcome_detail: transient|pr_open|autopatch_off
VERIFY_RESULT = "verify.result"         # data: {incident, exploit_blocked_on_prod: bool}
# pipeline: class audit after an incident closes (contracts/product.md section 8)
AUDIT_STARTED = "audit.started"         # data: {incident, vuln_class, candidates}
AUDIT_FINDING = "audit.finding"         # data: {incident, parent, route, param}
AUDIT_DONE = "audit.done"               # data: {incident, checked, findings, seconds}
# incident.opened also carries optional origin: live|audit and parent: <incident id>
# no component of a live stack publishes this type; the only emitter is the scripted dashboard/demo_events.py
ATTACK_ATTEMPT = "attack.attempt"       # data: {vuln, ok: bool, saw_real_data: bool}

TYPES = tuple(v for k, v in list(globals().items()) if k.isupper() and isinstance(v, str) and "." in v)


def make(type_: str, src: str, data: dict, *, run: str = "", rid: str | None = None, incident: str | None = None) -> dict:
    assert type_ in TYPES, type_
    return {"type": type_, "ts": time.time(), "run": run, "src": src, "rid": rid, "incident": incident, "data": data}
