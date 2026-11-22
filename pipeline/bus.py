"""Event bus: publisher (exact data fields per immune_contracts/events.py) and SSE follower."""
from __future__ import annotations

import collections
import json
import logging
import os
import threading
import time

import httpx

from immune_contracts import events as E

log = logging.getLogger("pipeline.bus")

# class self-audit (pipeline/audit.py). Not yet in immune_contracts/events.py: the pipeline builds their
# envelope itself, and the dashboard bus accepts them (dashboard/server.py EXTRA_TYPES).
AUDIT_STARTED = "audit.started"     # data: {incident, vuln_class, candidates}   incident = the closed one audited from
AUDIT_FINDING = "audit.finding"     # data: {incident, parent, route, param}     incident = the new one (origin audit)
AUDIT_DONE = "audit.done"           # data: {incident, checked, findings, seconds}
EXTRA_TYPES = (AUDIT_STARTED, AUDIT_FINDING, AUDIT_DONE)
TYPES = tuple(E.TYPES) + tuple(t for t in EXTRA_TYPES if t not in E.TYPES)

# data fields of every event the pipeline publishes (immune_contracts/events.py, verbatim)
FIELDS = {
    AUDIT_STARTED: {"incident", "vuln_class", "candidates"},
    AUDIT_FINDING: {"incident", "parent", "route", "param"},
    AUDIT_DONE: {"incident", "checked", "findings", "seconds"},
    E.INCIDENT_OPENED: {"incident", "vuln_class", "method", "route", "param", "sink", "evidence_rid", "request"},
    E.POC_READY: {"incident", "reproducible", "runs", "poc"},
    E.PATCH_ATTEMPT: {"incident", "attempt", "source"},
    E.PATCH_DIFF: {"incident", "attempt", "diff"},
    E.GATE_RESULT: {"incident", "attempt", "gate", "ok", "detail"},
    E.PR_OPENED: {"incident", "url", "branch"},
    E.PR_MERGED: {"incident", "url", "sha"},
    E.INCIDENT_CLOSED: {"incident", "outcome", "seconds_to_rule", "seconds_to_patch"},
    E.VERIFY_RESULT: {"incident", "exploit_blocked_on_prod"},
}
# optional fields added by contracts/product.md §3 (pr_open / autopatch_off, a skipped tests gate)
OPTIONAL = {
    E.INCIDENT_OPENED: {"origin", "parent"},      # origin: live | audit; parent: the incident whose audit found it
    E.INCIDENT_CLOSED: {"outcome_detail"},
    E.GATE_RESULT: {"skipped"},
}


def make(type_: str, data: dict, *, run: str = "", rid: str | None = None, incident: str | None = None) -> dict:
    """Event envelope (immune_contracts/events.py), also for the pipeline's audit.* types."""
    if type_ in E.TYPES:
        return E.make(type_, "pipeline", data, run=run, rid=rid, incident=incident)
    if type_ not in EXTRA_TYPES:
        raise ValueError("unknown event type %r" % type_)
    return {"type": type_, "ts": time.time(), "run": run, "src": "pipeline", "rid": rid, "incident": incident,
            "data": data}


class Publisher:
    """Publishes to the bus (2 s timeout, drop on failure) and appends every event to a local log."""

    def __init__(self, url: str, token: str, run: str, log_path: str | None = None, timeout: float = 2.0,
                 client: httpx.Client | None = None):
        self.url, self.token, self.run, self.timeout = url.rstrip("/"), token, run, timeout
        self.log_path = log_path
        self.client = client
        self.sent = collections.deque(maxlen=5000)     # recent events (tests, debugging); the full log is log_path
        self.dropped = 0
        self._pending = collections.deque(maxlen=2000)  # not delivered yet: sent first on the next publish
        self._lock = threading.Lock()

    def publish(self, type_: str, data: dict, incident: str | None = None, rid: str | None = None) -> dict:
        want = FIELDS.get(type_)
        if want is not None and not (want <= set(data) <= want | OPTIONAL.get(type_, set())):
            raise ValueError("%s data fields %s != contract %s" % (type_, sorted(data), sorted(want)))
        ev = make(type_, data, run=self.run, rid=rid, incident=incident)
        with self._lock:
            self.sent.append(ev)
            if self.log_path:
                try:
                    os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
                    with open(self.log_path, "a") as f:
                        f.write(json.dumps(ev, default=str) + "\n")
                except OSError:
                    pass
        self._pending.append(ev)
        self.flush()
        return ev

    def flush(self) -> int:
        """Deliver what is pending, oldest first. An event the bus could not take (down, restarting) stays
        pending and goes out with the next publish: the dashboard must not show an incident open forever
        because its closing event met a bus restart. -> events still pending."""
        c = self.client or httpx
        with self._lock:
            while self._pending:
                ev = self._pending[0]
                try:
                    r = c.post(self.url + "/events", json=ev, headers={"x-bus-token": self.token}, timeout=self.timeout)
                except Exception as e:  # noqa: BLE001
                    log.warning("bus publish %s failed (kept for retry): %s", ev.get("type"), e)
                    break
                if r.status_code >= 500:
                    log.warning("bus answered %s for %s (kept for retry)", r.status_code, ev.get("type"))
                    break
                self._pending.popleft()
                if r.status_code >= 300:           # refused as invalid: retrying cannot help
                    self.dropped += 1
                    log.warning("bus rejected %s: %s %s", ev.get("type"), r.status_code, r.text[:200])
            return len(self._pending)


def parse_sse(lines):
    """Yield (kind, id, data) from an iterator of SSE text lines. kind: 'message' | 'reset' | other event name."""
    eid, data, kind = None, [], "message"
    for line in lines:
        if line == "" or line is None:
            if data or kind != "message":
                yield kind, eid, "\n".join(data)
            eid, data, kind = None, [], "message"
            continue
        if line.startswith(":"):
            continue
        field, _, val = line.partition(":")
        val = val[1:] if val.startswith(" ") else val
        if field == "id":
            eid = val
        elif field == "data":
            data.append(val)
        elif field == "event":
            kind = val


def _auth() -> dict:
    tok = os.environ.get("BUS_TOKEN") or ""
    return {"x-bus-token": tok} if tok else {}


class Follower(threading.Thread):
    """Follows GET /events/stream?since=<seq>; calls on_event(seq, event) and on_reset() in this thread."""

    def __init__(self, url: str, get_since, on_event, on_reset=None, read_timeout: float = 45.0):
        super().__init__(name="bus-follower", daemon=True)
        self.url = url.rstrip("/")
        self.get_since, self.on_event, self.on_reset = get_since, on_event, on_reset
        self.read_timeout = read_timeout
        # with the token the bus sends events as stored; without it, the redacted copy meant for the public page
        self.headers = _auth()
        self.stop_evt = threading.Event()
        self.connected = threading.Event()

    def stop(self):
        self.stop_evt.set()

    def run(self):
        backoff = 0.5
        while not self.stop_evt.is_set():
            try:
                since = int(self.get_since() or 0)
                timeout = httpx.Timeout(connect=3.0, read=self.read_timeout, write=3.0, pool=3.0)
                with httpx.stream("GET", self.url + "/events/stream", params={"since": since}, timeout=timeout,
                                  headers=self.headers) as r:
                    if r.status_code != 200:
                        raise RuntimeError("stream status %d" % r.status_code)
                    self.connected.set()
                    backoff = 0.5
                    for kind, eid, data in parse_sse(r.iter_lines()):
                        if self.stop_evt.is_set():
                            return
                        if kind == "reset":
                            if self.on_reset:
                                self.on_reset()
                            continue
                        if kind != "message" or not data:
                            continue
                        try:
                            ev = json.loads(data)
                        except ValueError:
                            continue
                        seq = int(ev.get("seq") or eid or 0)
                        self.on_event(seq, ev)
            except Exception as e:  # noqa: BLE001
                self.connected.clear()
                if self.stop_evt.is_set():
                    return
                log.info("bus stream: %s; reconnecting in %.1fs", e, backoff)
                self.stop_evt.wait(backoff)
                backoff = min(backoff * 2, 10.0)


def history(url: str, since: int = 0, type_prefix: str | None = None, timeout: float = 5.0) -> dict:
    params = {"since": since}
    if type_prefix:
        params["type"] = type_prefix
    r = httpx.get(url.rstrip("/") + "/events", params=params, timeout=timeout, headers=_auth())
    r.raise_for_status()
    return r.json()
