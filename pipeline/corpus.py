"""Technique corpus (docs/plan-construccion.md §9d "Corpus de técnicas"): `<runtime>/corpus/<class>.jsonl`.

Every value the instrumentation confirmed — the incident's regression case and each variant that fired its
oracle on the unpatched release — is appended for its class. Only the value of the affected parameter is
kept (never the rest of the request: no tokens, no other fields), with the incident, route and parameter
name it came from. Deduplicated by value, bounded to MAX lines per class (the oldest are dropped).

Readers: the class self-audit (pipeline/audit.py) and the reproduction step, whose fired corpus
variants are judged again by the `poc` gate and by post-deploy verification.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time

MAX = 500
MAX_VALUE_LEN = 1000
CLASS_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


class Corpus:
    def __init__(self, directory: str, limit: int = MAX):
        self.dir = directory
        self.limit = int(limit)
        self._lock = threading.Lock()

    def path(self, vuln_class: str) -> str:
        if not CLASS_RE.match(str(vuln_class or "")):
            raise ValueError("bad class name %r" % vuln_class)
        return os.path.join(self.dir, "%s.jsonl" % vuln_class)

    def load(self, vuln_class: str) -> list:
        """[{value, incident, route, param, ts}], oldest first."""
        try:
            with open(self.path(vuln_class), encoding="utf-8") as f:
                lines = f.read().splitlines()
        except (OSError, ValueError):
            return []
        out = []
        for line in lines:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict) and isinstance(r.get("value"), str):
                out.append(r)
        return out

    def values(self, vuln_class: str, limit: int | None = None) -> list:
        """Distinct values, most recent first."""
        out = [r["value"] for r in reversed(self.load(vuln_class))]
        return out[:limit] if limit else out

    def add(self, vuln_class: str, values, incident: str = "", route: str = "", param: str = "") -> int:
        """Append the new distinct values; -> how many were new. Rewrites the file atomically when it is trimmed."""
        clean = []
        for v in values or []:
            if v is None or isinstance(v, (dict, list)):
                continue
            s = v if isinstance(v, str) else str(v)
            if not s or len(s) > MAX_VALUE_LEN or s in clean:
                continue
            clean.append(s)
        if not clean:
            return 0
        with self._lock:
            rows = self.load(vuln_class)
            have = {r["value"] for r in rows}
            new = [{"value": s, "incident": incident, "route": route, "param": param, "ts": round(time.time(), 3)}
                   for s in clean if s not in have]
            if not new:
                return 0
            rows += new
            if len(rows) > self.limit:
                rows = rows[-self.limit:]
            os.makedirs(self.dir, exist_ok=True)
            p = self.path(vuln_class)
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                for r in rows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            os.replace(tmp, p)
            return len(new)
