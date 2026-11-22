"""Best-effort publishing to the existing immune event bus so the live dashboard shows the
CVE-replay run. No-op unless BUS_URL (or CVE_BUS_URL) and BUS_TOKEN are set."""
from __future__ import annotations

import json
import os
import time
import urllib.request

from immune_contracts import events as E

_URL = os.environ.get("CVE_BUS_URL") or os.environ.get("PIPELINE_BUS_URL") or os.environ.get("BUS_URL")
_TOKEN = os.environ.get("BUS_TOKEN")
RUN = os.environ.get("RUN_ID") or time.strftime("cve-%m%d-%H%M%S")


def publish(type_: str, data: dict, *, rid: str | None = None, incident: str | None = None) -> None:
    if not (_URL and _TOKEN):
        return
    ev = E.make(type_, src="cve_replay", data=data, run=RUN, rid=rid, incident=incident)
    try:
        req = urllib.request.Request(_URL.rstrip("/") + "/events", method="POST",
                                     data=json.dumps(ev).encode(),
                                     headers={"content-type": "application/json", "x-bus-token": _TOKEN})
        urllib.request.urlopen(req, timeout=3).read()
    except Exception as e:  # the demo must not die because the dashboard is down
        print(f"  [bus] skipped {type_}: {e.__class__.__name__}")
