"""python -m sidecar.marker.learn --sidecar http://127.0.0.1:3902 --recordings runtime/.../requests.jsonl

Teaches the sql oracle the statement structures of legitimate traffic: replays, through the sidecar in learn
mode, the requests the gateway recorded as clean (class clean, no classifier reasons, served by prod, status
below 400). Each request is signed with the clone key (CLONE_KEY), so only the operator can extend the baseline.

Requests that need a session only teach something if the recorded credentials are valid on the shadow.
"""
from __future__ import annotations

import argparse
import base64
import json
import os

import httpx

from immune_contracts import wire
from .core import H_LEARN, learn_message

DROP = {"host", "content-length", "connection", "transfer-encoding", "accept-encoding"}


def legit(rec: dict) -> bool:
    return (rec.get("class") == "clean" and not rec.get("reasons") and rec.get("route") == "prod"
            and int(rec.get("status") or 599) < 400)


def replay(sidecar: str, key: str, records, client: httpx.Client | None = None) -> dict:
    client = client or httpx.Client(timeout=30)
    out = {"replayed": 0, "learnt": 0, "skipped": 0, "errors": 0}
    seen = set()
    for rec in records:
        target = rec["path"] + ("?" + rec["query"] if rec.get("query") else "")
        body = base64.b64decode(rec.get("body_b64") or "")
        k = (rec["method"], target, body)
        if not legit(rec) or k in seen:
            out["skipped"] += 1
            continue
        seen.add(k)
        raw = target.encode("latin-1")
        headers = {h: v for h, v in (rec.get("headers") or {}).items() if h.lower() not in DROP}
        headers.update({wire.H_MODE: "learn", H_LEARN: wire.sign(key, learn_message(rec["method"], raw))})
        try:
            r = client.send(client.build_request(rec["method"], httpx.URL(sidecar + "/").copy_with(raw_path=raw),
                                                 headers=headers, content=body or None, extensions={"target": raw}))
            out["replayed"] += 1
            out["learnt"] += int(r.headers.get("x-imm-learnt") or 0)
        except httpx.HTTPError:
            out["errors"] += 1
    return out


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m sidecar.marker.learn")
    ap.add_argument("--sidecar", required=True)
    ap.add_argument("--recordings", required=True, help="the gateway's RECORD_PATH (jsonl)")
    a = ap.parse_args()
    with open(a.recordings) as f:
        records = [json.loads(line) for line in f if line.strip()]
    print(json.dumps(replay(a.sidecar.rstrip("/"), os.environ.get("CLONE_KEY", ""), records)))


if __name__ == "__main__":
    main()
