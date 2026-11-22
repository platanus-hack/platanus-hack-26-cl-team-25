"""Child-process driver of shadow.harness.Harness (run through immune.initsteps.hostrun).

Job (stdin JSON):
    {"profile": "profile", "seed_db": "/abs/seed.db",
     "selftest": null | {"owner": {"table", "column", "owner_col"}},     # wraps the app in immune.doctor_selftest
     "requests": [{"name", "method", "path", "query", "headers", "body" | "json",
                   "uid", "role", "mode", "auth_from": "<earlier name>", "token_field": "token"}],
     "reset_check": null | {"uid": n, "path": "/health"}}
Result (last stdout line): {"ok", "results": [{name, status, verdict, oracles, events, body, marker_owners}],
                            "reset": {...}, "error"}
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import traceback

MARKER_RE = re.compile(r"MK[A-Z0-9]{10}")


def _canon(db_bytes: bytes) -> str:
    from shadow.instrument import ORIG_CONNECT
    c = ORIG_CONNECT(":memory:")
    try:
        c.deserialize(db_bytes)
        h = hashlib.sha256()
        for (t,) in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
            h.update(t.encode())
            try:
                rows = c.execute('SELECT * FROM "%s" ORDER BY rowid' % t.replace('"', '""')).fetchall()
            except Exception:
                rows = sorted(c.execute('SELECT * FROM "%s"' % t.replace('"', '""')).fetchall(), key=repr)
            for r in rows:
                h.update(repr(r).encode())
        return h.hexdigest()
    finally:
        c.close()


def _file_bytes(path):
    from shadow.instrument import ORIG_CONNECT
    src = ORIG_CONNECT("file:%s?mode=ro" % path, uri=True)
    mem = ORIG_CONNECT(":memory:")
    try:
        src.backup(mem)
        return mem.serialize()
    finally:
        src.close()
        mem.close()


def _short_events(events):
    out = []
    for e in events or []:
        d = dict(e.get("detail") or {})
        for k, v in list(d.items()):
            if isinstance(v, str) and len(v) > 300:
                d[k] = v[:300] + "..."
        out.append({"oracle": e.get("oracle"), "detail": d, "stack": (e.get("stack") or [])[-3:]})
    return out


def main():
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    out = {"ok": False}
    h = None
    try:
        job = json.loads(sys.stdin.read() or "{}")
        from shadow import instrument
        instrument.install()  # before the profile/app are imported
        if job.get("selftest") is not None:
            os.environ["SHADOW_SELFTEST"] = "1"
            from immune import doctor_selftest
            doctor_selftest.install(job["profile"], job["selftest"])
        from shadow.harness import Harness
        h = Harness(profile=job["profile"], seed_db=job.get("seed_db"))
        markers = {}
        try:
            with open(os.environ.get("MARKERS_PATH", "")) as f:
                markers = json.load(f)
        except Exception:
            pass
        results, by_name = [], {}
        for rq in job.get("requests") or []:
            headers = dict(rq.get("headers") or {})
            body = rq.get("body") or b""
            if rq.get("json") is not None:
                body = json.dumps(rq["json"])
                headers.setdefault("content-type", "application/json")
            if rq.get("auth_from"):
                prev = by_name.get(rq["auth_from"]) or {}
                tok = (prev.get("json") or {}).get(rq.get("token_field") or "token") if isinstance(prev.get("json"), dict) else None
                if tok:
                    headers["authorization"] = "Bearer %s" % tok
            uid = rq.get("uid")
            r = h.send(rq.get("method", "GET"), rq["path"], query=rq.get("query") or "", headers=headers,
                       body=body.encode() if isinstance(body, str) else body, uid=uid, role=rq.get("role") or "user",
                       mode=rq.get("mode") or "L1")
            text = r.body.decode("utf-8", "replace")
            try:
                js = json.loads(text)
            except ValueError:
                js = None
            owners = sorted({markers.get(m) for m in MARKER_RE.findall(text) if m in markers}, key=str)
            res = {"name": rq.get("name") or rq["path"], "method": rq.get("method", "GET"), "path": rq["path"],
                   "query": rq.get("query") or "", "uid": uid, "status": r.status, "verdict": r.verdict,
                   "oracles": sorted({e["oracle"] for e in r.events}), "events": _short_events(r.events)[:6],
                   "body": text[:600], "marker_owners": owners,
                   "json": js if (js is not None and len(text) < 20000) else None}
            by_name[res["name"]] = res
            results.append(dict(res, json=None))
        reset = None
        rc = job.get("reset_check")
        if rc:
            seed_hash = _canon(_file_bytes(job["seed_db"]))
            start = _canon(h.snapshot())
            path = rc.get("path") or "/health"
            h.send("GET", path, uid=int(rc["uid"]), role="user", mode="L2")
            mutated = _canon(h.snapshot()) != start
            h.send("GET", path, mode="L1")
            end = _canon(h.snapshot())
            reset = {"start_equals_seed": start == seed_hash, "mutated_by_L2": mutated, "restored": end == seed_hash}
        out = {"ok": True, "results": results, "reset": reset}
    except BaseException as e:  # noqa: BLE001
        out = {"ok": False, "error": "%s: %s" % (e.__class__.__name__, e), "trace": traceback.format_exc()[-3000:]}
    finally:
        if h is not None:
            try:
                h.close()
            except Exception:
                pass
    real_stdout.write("\n" + json.dumps(out, default=str) + "\n")
    real_stdout.flush()


if __name__ == "__main__":
    main()
