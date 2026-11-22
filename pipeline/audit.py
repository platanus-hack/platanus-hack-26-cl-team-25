"""Class self-audit ("memoria inmunológica", docs/arquitectura.md).

After an incident of class C closes (patched or rule_only), every other operation x parameter of the
project's OpenAPI document that class C could affect is probed with the regression battery of C — the
same inputs the `properties` gate validates a fix with (pipeline/properties.py), plus the class corpus
(pipeline/corpus.py) — against the CURRENT release, inside the isolated judge only (runner containers for
python-asgi, judge triples for generic; never production, never the live clones), each job on a fresh
shadow seed. A probe whose instrumentation reports C's oracle (sql / file / owner) becomes an incident
with origin "audit" and goes through the normal flow.

  candidates(spec, C, manifest)  -> [Candidate]   which (operation, parameter) pairs C could affect
  battery(C, cand, manifest, corpus_values)        -> [value]
  probe_request(cand, value)                       -> runner request dict
  run(validator, release_dir, cands, ...)          -> AuditResult (budget: max_jobs, deadline, stop())

Candidate rules
  sqli, traversal (string-shaped): query/path/form parameters and JSON string leaves whose schema is a
      string; enum, integer, number and boolean schemas are skipped. A route that needs an identity is
      probed as a legitimate seed user (manifest legit_users[0]).
  idor: path parameters (any non-enum schema) and integer / *id query parameters, probed as a brand-new
      user (above seed_max_uid) who owns nothing, so any owner marker in the answer is foreign.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field

from . import incident as incmod, openapi, properties, reqs

log = logging.getLogger("pipeline.audit")

ORACLE_OF = {"sqli": "sql", "traversal": "file", "idor": "owner"}
STRING_CLASSES = ("sqli", "traversal")
MAX_CORPUS_PER_PROBE = 40
MAX_JSON_DEPTH = 3


@dataclass
class Candidate:
    method: str
    route: str
    param: dict                   # {"in": query|path|json|form, "name": ...}
    base: dict                    # request dict (poc.schema.json `requests` item) with benign values
    secured: bool = False
    schema: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return "%s %s %s:%s" % (self.method, self.route, self.param.get("in"), self.param.get("name"))

    def key(self, vuln_class: str) -> str:
        return incmod.dedupe_key(ORACLE_OF.get(vuln_class, vuln_class), self.method, self.route, self.param)


# ------------------------------------------------------------------ schema helpers
def shape(schema: dict | None) -> str:
    """'enum' | 'number' | 'string' | 'object' | 'array' | 'other'"""
    s = schema or {}
    if s.get("enum") is not None or "const" in s:
        return "enum"
    t = s.get("type")
    if t is None:
        alts = [a for a in (s.get("anyOf") or s.get("oneOf") or []) if isinstance(a, dict) and a.get("type") != "null"]
        if len(alts) == 1:
            return shape(alts[0])
        if s.get("properties"):
            return "object"
        return "string" if not alts else "other"
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    if t in ("integer", "number", "boolean"):
        return "number"
    if t in ("string", "object", "array"):
        return t
    return "other"


def benign(schema: dict | None, name: str = ""):
    """A plausible benign value for a schema (used for the parameters that are not under test)."""
    s = schema or {}
    for k in ("example", "default"):
        if k in s and not isinstance(s[k], (dict, list)):
            return s[k]
    if s.get("enum"):
        return s["enum"][0]
    sh = shape(s)
    if sh == "number":
        if s.get("type") == "boolean":
            return False
        lo = s.get("minimum")
        return int(lo) if isinstance(lo, (int, float)) and lo > 1 else 1
    if sh == "object":
        return fill_object(s)
    if sh == "array":
        return [benign(s.get("items") or {}, name)]
    n = name.lower()
    if "mail" in n:
        return "audit@example.com"
    return "abc"


def fill_object(schema: dict, depth: int = 0) -> dict:
    out = {}
    req = schema.get("required") or []
    for name, p in (schema.get("properties") or {}).items():
        if name in req and depth < MAX_JSON_DEPTH + 1:
            out[name] = benign(p, name) if shape(p) != "object" else fill_object(p, depth + 1)
    return out


def json_string_leaves(schema: dict, prefix: str = "", depth: int = 0):
    """[(json path, schema)] of string leaves (array items addressed as [0])."""
    out = []
    if depth > MAX_JSON_DEPTH:
        return out
    sh = shape(schema)
    if sh == "object":
        for name, p in (schema.get("properties") or {}).items():
            out += json_string_leaves(p or {}, "%s.%s" % (prefix, name) if prefix else str(name), depth + 1)
    elif sh == "array":
        out += json_string_leaves(schema.get("items") or {}, "%s[0]" % prefix, depth + 1)
    elif prefix:
        out.append((prefix, schema, sh))
    return out


def _secured(spec: dict, op: dict) -> bool:
    if "security" in op:
        return bool(op.get("security"))
    if "security" in spec:
        return bool(spec.get("security"))
    # no security information anywhere in the document (e.g. a generated spec): assume an identity helps
    return not any("security" in o for _m, _t, o in openapi.operations(spec))


def _base_request(spec: dict, method: str, tpl: str, op: dict) -> dict:
    pp = {}
    query = []
    for p in op.get("parameters") or []:
        if not isinstance(p, dict):
            continue
        sch = p.get("schema") or {}
        if p.get("in") == "path":
            pp[p.get("name")] = benign(sch, p.get("name") or "")
        elif p.get("in") == "query" and p.get("required"):
            query.append((p.get("name"), str(benign(sch, p.get("name") or ""))))
    for name in openapi.path_params(tpl):
        pp.setdefault(name, 1)
    rq = {"method": method, "path": openapi.fill(tpl, pp), "query": reqs.encode_query(query), "headers": {},
          "body_b64": "", "uid": None, "role": None}
    content = (op.get("requestBody") or {}).get("content") or {}
    if "application/json" in content:
        sch = openapi.resolve(spec, (content["application/json"] or {}).get("schema") or {})
        rq = reqs.with_body(rq, json.dumps(benign(sch)).encode())
        rq["headers"] = {"content-type": "application/json"}
    elif "application/x-www-form-urlencoded" in content:
        sch = openapi.resolve(spec, (content["application/x-www-form-urlencoded"] or {}).get("schema") or {})
        body = fill_object(sch) if shape(sch) == "object" else {}
        rq = reqs.with_body(rq, reqs.encode_query([(k, str(v)) for k, v in body.items()]).encode())
        rq["headers"] = {"content-type": "application/x-www-form-urlencoded"}
    return rq


def candidates(spec: dict, vuln_class: str, manifest: dict | None = None) -> list:
    """Every (operation, parameter) of the OpenAPI document that `vuln_class` could affect, in document order."""
    if vuln_class not in ORACLE_OF:
        return []
    out, seen = [], set()
    for method, tpl, op in openapi.operations(spec):
        base = _base_request(spec, method, tpl, op)
        sec = _secured(spec, op)
        params = []
        for p in op.get("parameters") or []:
            if not isinstance(p, dict) or p.get("in") not in ("query", "path"):
                continue
            params.append(({"in": p["in"], "name": p.get("name")}, p.get("schema") or {}, shape(p.get("schema") or {})))
        content = (op.get("requestBody") or {}).get("content") or {}
        if "application/json" in content:
            sch = openapi.resolve(spec, (content["application/json"] or {}).get("schema") or {})
            for path, s, sh in json_string_leaves(sch):
                params.append(({"in": "json", "name": path}, s, sh))
        elif "application/x-www-form-urlencoded" in content:
            sch = openapi.resolve(spec, (content["application/x-www-form-urlencoded"] or {}).get("schema") or {})
            for name, s in (sch.get("properties") or {}).items():
                params.append(({"in": "form", "name": name}, s or {}, shape(s or {})))
        for param, sch, sh in params:
            if not param.get("name"):
                continue
            if vuln_class in STRING_CLASSES:
                if sh != "string":
                    continue      # enum / integer / number / boolean schemas cannot carry a string payload
            else:   # idor: identifiers
                n = str(param["name"]).lower()
                if param["in"] == "path":
                    if sh == "enum":
                        continue
                elif not (param["in"] == "query" and sh in ("number", "string") and (n == "id" or n.endswith("_id")
                                                                          or n.endswith("id"))):
                    continue
            k = (method, tpl, param["in"], param["name"])
            if k in seen:
                continue
            seen.add(k)
            out.append(Candidate(method, tpl, param, base, sec, sch))
    return out


# ------------------------------------------------------------------ battery and probes
def battery(vuln_class: str, cand: Candidate, manifest: dict | None, corpus_values=None) -> list:
    """The properties-gate inputs of the class, then the corpus values (deduplicated)."""
    if vuln_class == "sqli":
        vals = list(properties.SQL_META)
    elif vuln_class == "traversal":
        vals = list(properties.TRAVERSAL)
    elif vuln_class == "idor":
        vals = [str(i) for i in properties._candidate_ids({"param": cand.param}, manifest or {}, None)]
    else:
        vals = []
    extra = []
    for v in corpus_values or []:
        if vuln_class == "idor" and not str(v).isdigit():
            continue
        extra.append(str(v))
        if len(extra) >= MAX_CORPUS_PER_PROBE:
            break
    out = []
    for v in vals + extra:
        if v not in out:
            out.append(v)
    return out


def identity(vuln_class: str, cand: Candidate, manifest: dict | None):
    """(uid, role) for the probe: a new user for idor, a legitimate seed user where the route needs one."""
    m = manifest or {}
    if vuln_class == "idor":
        return int(m.get("seed_max_uid") or 0) + 1000, "user"
    if cand.secured:
        legit = [u for u in m.get("legit_users") or [] if isinstance(u, dict) and u.get("id") is not None]
        if legit:
            return int(legit[0]["id"]), legit[0].get("role") or "user"
        return int(m.get("seed_max_uid") or 0) + 1000, "user"
    return None, None


def probe_request(cand: Candidate, value, uid=None, role=None) -> dict:
    v = value
    if cand.param.get("in") == "json" and shape(cand.schema) == "number" and str(value).isdigit():
        v = int(value)
    rq = reqs.set_value(cand.base, cand.param, v, cand.route)
    rq["uid"], rq["role"] = uid, (role if uid is not None else None)
    return rq


def synth_evidence(rq: dict, item: dict, release: str) -> dict:
    """Evidence object (contracts/schemas/evidence.schema.json shape) from a judge result without one
    (the generic judge reports events, not evidence)."""
    return {"clone": "audit", "rid": "", "mode": "L1", "release": release, "verdict": "oracle",
            "uid": rq.get("uid"), "role": rq.get("role") if rq.get("uid") is not None else None,
            "request": {"method": rq.get("method", "GET"), "path": rq.get("path", "/"), "query": rq.get("query") or "",
                        "headers": reqs.clean_headers(rq.get("headers") or {}, drop_auth=True),
                        "body_b64": rq.get("body_b64") or ""},
            "status": item.get("status"), "events": item.get("events") or [], "pre_state_b64": None}


# ------------------------------------------------------------------ execution
@dataclass
class Finding:
    candidate: Candidate
    value: str
    evidence: dict


@dataclass
class AuditResult:
    checked: list = field(default_factory=list)      # Candidate, judged
    skipped: list = field(default_factory=list)      # (Candidate, why) not judged (budget, pause, judge errors)
    findings: list = field(default_factory=list)     # Finding
    jobs: int = 0
    seconds: float = 0.0


def judge_one(validator, release_dir: str, vuln_class: str, cand: Candidate, manifest: dict | None,
              corpus_values, release: str, timeout: float | None = None):
    """One judge job: the whole battery for one candidate, each value as its own L1 request. -> Finding | None"""
    uid, role = identity(vuln_class, cand, manifest)
    kind = ORACLE_OF[vuln_class]
    seqs, rqs = [], []
    for i, val in enumerate(battery(vuln_class, cand, manifest, corpus_values)):
        try:
            rq = probe_request(cand, val, uid, role)
        except Exception:  # noqa: BLE001 - a value the parameter location cannot carry
            continue
        rqs.append((val, rq))
        seqs.append({"name": "a%d" % i, "requests": [rq], "with_evidence": True})
    if not seqs:
        return None
    res = validator.run(release_dir, {"kind": "harness", "sequences": seqs}, timeout)
    for (val, rq), s in zip(rqs, res.get("sequences") or []):
        item = s["runs"][0][-1]
        if not any(e.get("oracle") == kind for e in item.get("events") or []):
            continue
        ev = dict(item.get("evidence") or synth_evidence(rq, item, release))
        ev["events"] = [e for e in ev.get("events") or [] if e.get("oracle") == kind] or ev.get("events") or []
        return Finding(cand, val, ev)
    return None


def run(validator, release_dir: str, vuln_class: str, cands: list, manifest: dict | None, corpus_values=None, *,
        max_jobs: int = 40, max_seconds: float = 120.0, parallel: int = 3, stop=None, release: str = "",
        on_finding=None) -> AuditResult:
    """Judge `cands` within the budget: at most `max_jobs` judge jobs, no job started after `max_seconds`,
    and none started once `stop()` is true (PAUSE). Running jobs are bounded by the remaining time."""
    t0 = time.time()
    deadline = t0 + max(0.0, float(max_seconds))
    out = AuditResult()
    todo = list(cands)
    if max_jobs is not None and len(todo) > max_jobs:
        out.skipped += [(c, "budget: max_jobs %d" % max_jobs) for c in todo[max_jobs:]]
        todo = todo[:max_jobs]
    lock = threading.Lock()
    runner_timeout = float(getattr(getattr(validator, "cfg", None), "runner_timeout_s", 240) or 240)

    def job(c):
        remaining = max(5.0, deadline - time.time())
        return judge_one(validator, release_dir, vuln_class, c, manifest, corpus_values, release,
                         timeout=min(runner_timeout, remaining + 5.0))

    with ThreadPoolExecutor(max_workers=max(1, int(parallel))) as ex:
        running = {}
        while todo or running:
            while todo and len(running) < max(1, int(parallel)):
                if time.time() >= deadline:
                    out.skipped += [(c, "budget: max_seconds %.0f" % max_seconds) for c in todo]
                    todo = []
                    break
                if stop is not None and stop():
                    out.skipped += [(c, "paused") for c in todo]
                    todo = []
                    break
                c = todo.pop(0)
                running[ex.submit(job, c)] = c
                out.jobs += 1
            if not running:
                break
            done, _ = wait(list(running), return_when=FIRST_COMPLETED)
            for f in done:
                c = running.pop(f)
                try:
                    fnd = f.result()
                except Exception as e:  # noqa: BLE001
                    log.warning("audit probe %s failed: %s", c.label, e)
                    with lock:
                        out.skipped.append((c, "judge error: %s" % str(e)[:200]))
                    continue
                with lock:
                    out.checked.append(c)
                    if fnd is not None:
                        out.findings.append(fnd)
                if fnd is not None and on_finding is not None:
                    on_finding(fnd)
    out.seconds = round(time.time() - t0, 2)
    return out
