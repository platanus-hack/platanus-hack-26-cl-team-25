"""Result shaping shared by the two runner back ends: `runner_entry.py` (inside the sandbox container,
which mounts this repository read-only) and `generic.py` (clone triples, on the host). Standard library
only at import time."""
from __future__ import annotations

import hashlib
import json
import os
import re


def short(v, n=400):
    s = v if isinstance(v, str) else json.dumps(v, default=str)
    return s if len(s) <= n else s[:n] + "..."


def body_info(body: bytes) -> dict:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("latin-1")
    return {"sha": hashlib.sha256(body or b"").hexdigest(), "len": len(body or b""), "head": text[:300]}


def norm_body(body: bytes, normalize=None):
    """A replayed body as compared by the legit gate. `normalize` (legit.normalize of the project config):
    regexes of per-session values (CSRF tokens, timestamps) replaced before comparing."""
    if normalize:
        text = (body or b"").decode("utf-8", "replace")
        for rx in normalize:
            try:
                text = re.sub(rx, "<normalized>", text)
            except re.error:
                continue
        body = text.encode("utf-8")
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return {"sha256": hashlib.sha256(body or b"").hexdigest(), "len": len(body or b"")}


def file_candidates(dirs: list, spec: dict) -> list:
    """Candidate legit values for a file parameter: every file under `dirs` (readable where this runs), by
    every relative suffix. spec: {"base": request, "param": ..., "template": ...}.
    -> requests named `cand:<value>` with `expect_sha`."""
    from . import reqs as R
    out, seen = [], set()
    for root in dirs:
        for d, _dirs, files in os.walk(root):
            for fn in sorted(files):
                full = os.path.join(d, fn)
                rel = os.path.relpath(full, root).split(os.sep)
                with open(full, "rb") as fh:
                    sha = hashlib.sha256(fh.read()).hexdigest()
                for i in range(len(rel)):
                    val = "/".join(rel[i:])
                    if val in seen:
                        continue
                    seen.add(val)
                    rq = R.set_value(spec["base"], spec["param"], val, spec.get("template"))
                    rq.update(name="cand:" + val, expect_sha=sha)
                    out.append(rq)
    return out
