"""Event bus: publisher (exact data fields per immune_contracts/events.py) and SSE follower."""
from __future__ import annotations

import json
import logging
import os
import threading
import time

import httpx

from immune_contracts import events as E

log = logging.getLogger("pipeline.bus")

# data fields of every event the pipeline publishes (immune_contracts/events.py, verbatim)
FIELDS = {
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


class Publisher:
    """Publishes to the bus (2 s timeout, drop on failure) and appends every event to a local log."""

    def __init__(self, url: str, token: str, run: str, log_path: str | None = None, timeout: float = 2.0,
                 client: httpx.Client | None = None):
        self.url, self.token, self.run, self.timeout = url.rstrip("/"), token, run, timeout
        self.log_path = log_path
        self.client = client
        self.sent = []
        self.dropped = 0
        self._lock = threading.Lock()

    def publish(self, type_: str, data: dict, incident: str | None = None, rid: str | None = None) -> dict:
        want = FIELDS.get(type_)
        if want is not None and set(data) != want:
            raise ValueError("%s data fields %s != contract %s" % (type_, sorted(data), sorted(want)))
        ev = E.make(type_, "pipeline", data, run=self.run, rid=rid, incident=incident)
        with self._lock:
            self.sent.append(ev)
            if self.log_path:
                try:
                    os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
                    with open(self.log_path, "a") as f:
                        f.write(json.dumps(ev, default=str) + "\n")
                except OSError:
                    pass
        try:
            c = self.client or httpx
            r = c.post(self.url + "/events", json=ev, headers={"x-bus-token": self.token}, timeout=self.timeout)
            if r.status_code >= 300:
                self.dropped += 1
                log.warning("bus rejected %s: %s %s", type_, r.status_code, r.text[:200])
        except Exception as e:  # noqa: BLE001
            self.dropped += 1
            log.warning("bus publish %s failed: %s", type_, e)
        return ev


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


class Follower(threading.Thread):
    """Follows GET /events/stream?since=<seq>; calls on_event(seq, event) and on_reset() in this thread."""

    def __init__(self, url: str, get_since, on_event, on_reset=None, read_timeout: float = 45.0):
        super().__init__(name="bus-follower", daemon=True)
        self.url = url.rstrip("/")
        self.get_since, self.on_event, self.on_reset = get_since, on_event, on_reset
        self.read_timeout = read_timeout
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
                with httpx.stream("GET", self.url + "/events/stream", params={"since": since}, timeout=timeout) as r:
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
    r = httpx.get(url.rstrip("/") + "/events", params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()
