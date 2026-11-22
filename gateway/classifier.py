"""Stage-1 classification (contracts/README.md §6 step 5). Pure functions + small state objects."""
from __future__ import annotations

import json
import math
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, unquote_plus

from immune_contracts import grammar

from .spec import (Spec, check_json_value, check_string_value, is_catchall, match_template,
                   split_template)

CLEAN, SUSPECT, EVIDENCE, CAPTIVE = "clean", "suspect", "evidence", "captive"
SCOPES = ("param", "param_present", "all")
SAFE_KEY = re.compile(r"[A-Za-z0-9_\-]{1,64}")
REDACTED = "<redacted>"


# ---------------------------------------------------------------- manifest

@dataclass
class Manifest:
    seed_max_uid: int = 0
    canaries: dict = field(default_factory=dict)     # path-param name -> set of str values
    ownership: dict = field(default_factory=dict)    # "orders" -> {"12": 7}
    groups: dict = field(default_factory=dict)       # group-shared access: "teams" -> {"1": [3, 5]}
    group_routes: dict = field(default_factory=dict)  # path param -> group table ("team_id" -> "teams")

    @classmethod
    def from_dict(cls, d: dict | None) -> "Manifest":
        d = d or {}
        canaries = {}
        for name, values in (d.get("canaries") or {}).items():
            if isinstance(values, (list, tuple)):
                canaries[str(name)] = {str(v) for v in values}
        try:
            smu = int(d.get("seed_max_uid") or 0)
        except (TypeError, ValueError):
            smu = 0
        groups = {str(t): {str(g): {str(u) for u in (ms or [])} for g, ms in (gm or {}).items()}
                  for t, gm in (d.get("groups") or {}).items() if isinstance(gm, dict)}
        group_routes = {str(p): str(t) for p, t in (d.get("group_routes") or {}).items() if str(t) in groups}
        return cls(seed_max_uid=smu, canaries=canaries, ownership=d.get("ownership") or {}, groups=groups,
                   group_routes=group_routes)

    @classmethod
    def load(cls, path: str | None) -> "Manifest":
        try:
            with open(path) as f:
                return cls.from_dict(json.load(f))
        except Exception:
            return cls()


# ---------------------------------------------------------------- identity

@dataclass
class Who:
    uid: int | None = None           # from a PROD token only
    role: str | None = None
    trusted: bool = False
    honeytoken: bool = False


# ---------------------------------------------------------------- rules

class Rule:
    """A confirmed-vulnerable point (contracts/schemas/rule.schema.json).

    scope "param": values of `param` outside `grammar` are suspect.
    scope "param_present": every request that carries `param` is suspect, whatever its value; `grammar` only
        decides what happens when the clone is inconclusive (outside it -> deny, inside -> prod).
    scope "all": every request on the route is suspect.
    ttl_s None: no expiry; the rule lives until it is deleted.
    """

    def __init__(self, d: dict, now: float | None = None, expires: float | None = None):
        now = time.time() if now is None else now
        self.raw = dict(d)
        self.id = str(d["id"])
        self.method = str(d["method"]).upper()
        self.route = str(d["route"])
        self.segments = split_template(self.route)
        self.param = d.get("param") or None
        self.scope = d.get("scope")
        if self.scope not in SCOPES:
            raise ValueError("scope must be %s" % "|".join(SCOPES))
        self.identity = d.get("identity") or None   # "untrusted": only anonymous/untrusted callers (missing-auth, CWE-306)
        if self.identity not in (None, "untrusted"):
            raise ValueError("identity must be 'untrusted' or absent")
        if self.scope != "all" and not (isinstance(self.param, dict) and self.param.get("in") and self.param.get("name")):
            raise ValueError("scope=%s needs param.in and param.name" % self.scope)
        self.grammar = d.get("grammar") or (grammar.SAFE_DEFAULT if self.scope != "all" else None)
        if self.grammar:
            re.compile(self.grammar)
        ttl = d.get("ttl_s")
        self.ttl_s = None if ttl is None else int(ttl)
        if self.ttl_s is not None and self.ttl_s < 1:
            raise ValueError("ttl_s must be >= 1 or null")
        self.raw["ttl_s"] = self.ttl_s
        self.raw.setdefault("created", now)
        self.raw.setdefault("incident", None)
        self.raw.setdefault("param", None)
        self.raw.setdefault("grammar", None)
        # `expires` restores a persisted rule without restarting its clock
        self.expires = expires if expires is not None else (math.inf if self.ttl_s is None else now + self.ttl_s)
        # hits: requests the rule matched; oracle: of those, confirmed attacks; denied: refused with no oracle
        # fired (no clone, or inconclusive). A growing `denied` means the rule is hurting legitimate traffic.
        self.stats = {"hits": 0, "oracle": 0, "denied": 0}

    def to_dict(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        left = None if self.expires == math.inf else max(0.0, round(self.expires - now, 1))
        return {**self.raw, "expires_in": left, "stats": dict(self.stats)}

    def to_store(self) -> dict:
        return {"rule": self.raw, "expires": None if self.expires == math.inf else self.expires}

    def applies(self, method: str, raw_path: str) -> dict | None:
        m = method.upper()
        if self.method not in ("*", "ANY", m) and not (m == "HEAD" and self.method == "GET"):
            return None
        return match_template(self.segments, raw_path) if raw_path else None


# ---------------------------------------------------------------- request view

@dataclass
class View:
    method: str
    raw_path: str                  # percent-encoded path (no query)
    query: str                     # raw query string
    headers: dict                  # lower-case name -> value (last wins)
    body: bytes = b""

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or "").split(";")[0].strip().lower()


@dataclass
class Result:
    cls: str = CLEAN
    reasons: list = field(default_factory=list)
    rule_hit: list = field(default_factory=list)       # ids of rules that matched
    rule_strict: list = field(default_factory=list)    # of those, the ones that deny on an inconclusive clone
    # {"query": {names}, "json": {dotted}, "form": {names}, "header": {lower names}, "path": {decoded values}}
    sensitive: dict = field(default_factory=dict)

    def add(self, reason: str):
        if reason not in self.reasons:
            self.reasons.append(reason)


# ---------------------------------------------------------------- enumeration heuristic

class EnumTracker:
    """Many distinct ids on owner-scoped routes from one session within a short window."""

    def __init__(self, window_s: float = 30.0, threshold: int = 8, max_sessions: int = 20000):
        self.window_s, self.threshold, self.max_sessions = window_s, threshold, max_sessions
        self.seen: dict[str, deque] = defaultdict(deque)

    def hit(self, session: str, template: str, values: tuple, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        if len(self.seen) > self.max_sessions:
            self.seen.clear()
        dq = self.seen[session]
        dq.append((now, template, values))
        while dq and dq[0][0] < now - self.window_s:
            dq.popleft()
        distinct = {(t, v) for _, t, v in dq if t == template}
        return len(distinct) > self.threshold

    def clear(self):
        self.seen.clear()


# ---------------------------------------------------------------- built-in rule: classic path traversal

# Works on any route, in or out of the OpenAPI spec (an unknown app has no spec to violate).
_OVERLONG = {"%c0%ae": ".", "%e0%80%ae": ".", "%c0%af": "/", "%e0%80%af": "/", "%c1%9c": "\\", "%c0%5c": "\\"}
_OVERLONG_RE = re.compile("|".join(re.escape(k) for k in _OVERLONG), re.IGNORECASE)
_DECODE_ROUNDS = 4   # %252e%252e, %%32%65 ... : decode until stable, bounded


def _forms(raw: str):
    """The value as successive decoders would see it, with backslashes folded to '/'."""
    cur = raw
    for _ in range(_DECODE_ROUNDS):
        cur = _OVERLONG_RE.sub(lambda m: _OVERLONG[m.group(0).lower()], cur)
        yield cur.replace("\\", "/")
        nxt = unquote(cur)
        if nxt == cur:
            return
        cur = nxt


def traversal_in_path(raw_path: str) -> bool:
    """A '..' path segment under any classic encoding. Clients resolve dot segments before sending,
    so a request that still carries one was built by hand."""
    return any(seg.split(";", 1)[0] == ".." for form in _forms(raw_path) for seg in form.split("/"))


def traversal_in_value(value: str) -> bool:
    """A parameter value that climbs directories: '../', '/..' or a bare '..' (also '....//')."""
    return any(f == ".." or "../" in f or f.endswith("/..") for f in _forms(value))


def is_builtin_rule(reasons) -> bool:
    """Reasons that fail closed like an active rule (deny unless a clone says clean)."""
    return any(r == "traversal:path" for r in reasons)


# ---------------------------------------------------------------- helpers

def _check_text(res: Result, where: str, name: str, value: str, schema: dict | None, sensitive: bool,
                gram: str = grammar.SAFE_DEFAULT):
    if sensitive:
        return
    if schema is not None:
        bad = check_string_value(value, schema)
        if bad:
            res.add(f"schema:{where}.{name}:{bad}")
    if not grammar.matches(gram, value):
        res.add(f"grammar:{where}.{name}")


def _walk_json(res: Result, value, schema: dict | None, path: str, values: dict):
    schema = schema if isinstance(schema, dict) else None
    if schema is not None and schema.get("x-sensitive"):
        res.sensitive.setdefault("json", set()).add(path)
        return
    if isinstance(value, dict):
        if schema is not None and schema.get("type") not in (None, "object"):
            res.add(f"schema:json.{path or '$'}:type")
        props = (schema or {}).get("properties") or {}
        addl = (schema or {}).get("additionalProperties")
        for k, v in value.items():
            if not SAFE_KEY.fullmatch(str(k)):
                res.add("grammar:json.key")
            sub = props.get(k)
            if sub is None and isinstance(addl, dict):
                sub = addl
            _walk_json(res, v, sub, f"{path}.{k}" if path else str(k), values)
        return
    if isinstance(value, list):
        if schema is not None and schema.get("type") not in (None, "array"):
            res.add(f"schema:json.{path or '$'}:type")
        if schema is not None and "maxItems" in schema and len(value) > schema["maxItems"]:
            res.add(f"schema:json.{path or '$'}:length")
        items = (schema or {}).get("items")
        for v in value:
            _walk_json(res, v, items, path, values)
        return
    name = path or "$"
    values.setdefault(("json", name), []).append(value if isinstance(value, str) else json.dumps(value))
    if schema is not None:
        bad = check_json_value(value, schema)
        if bad:
            res.add(f"schema:json.{name}:{bad}")
    if isinstance(value, str) and not grammar.is_safe_default(value):
        res.add(f"grammar:json.{name}")


def parse_form(body: bytes) -> list[tuple[str, str]] | None:
    try:
        return parse_qsl(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
    except Exception:
        return None


def parse_multipart_fields(body: bytes, content_type_header: str) -> list[tuple[str, str]] | None:
    """Text fields of a multipart body (files are ignored). None if unparsable."""
    try:
        from email.parser import BytesParser
        from email.policy import HTTP
        msg = BytesParser(policy=HTTP).parsebytes(b"Content-Type: " + content_type_header.encode() + b"\r\n\r\n" + body)
        if not msg.is_multipart():
            return None
        out = []
        for part in msg.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name or part.get_filename():
                continue
            payload = part.get_payload(decode=True) or b""
            out.append((str(name), payload.decode("utf-8", "replace")))
        return out
    except Exception:
        return None


# ---------------------------------------------------------------- main entry

def classify(view: View, spec: Spec, who: Who, manifest: Manifest, rules: list[Rule],
             session: str, enum: EnumTracker | None = None) -> Result:
    res = Result()
    readings = spec.match_readings(view.method, view.raw_path)
    op, path_params = next((m for m in readings if m is not None), (None, {}))
    values: dict[tuple, list] = {}

    # ---- an encoded slash that changes the route depending on who decodes it (spec.path_readings)
    if any(m != readings[0] for m in readings):
        res.add("path:encoded_slash")

    # ---- evidence: honeytoken
    if who.honeytoken:
        res.add("honeytoken")

    # ---- query string (always parsed: duplicated params matter even off-spec)
    pairs = parse_qsl(view.query, keep_blank_values=True) if view.query else []
    counts: dict[str, int] = {}
    for k, v in pairs:
        counts[k] = counts.get(k, 0) + 1
        values.setdefault(("query", k), []).append(v)
    for k, n in counts.items():
        if n > 1:
            res.add(f"dup_query:{k}")

    # ---- built-in rule: classic path traversal (path and query, on- or off-spec)
    if traversal_in_path(view.raw_path):
        res.add("traversal:path")
    for k, v in pairs:
        if traversal_in_value(v):
            res.add(f"traversal:query.{k if SAFE_KEY.fullmatch(k) else '?'}")

    if op is not None:
        sens_q = res.sensitive.setdefault("query", set())
        for k, v in pairs:
            p = op.params.get(("query", k))
            sensitive = bool(p and (p.get("x-sensitive") or (p.get("schema") or {}).get("x-sensitive")))
            if sensitive:
                sens_q.add(k)
            if not SAFE_KEY.fullmatch(k):
                res.add("grammar:query.key")
            _check_text(res, "query", k, v, (p or {}).get("schema") if p else None, sensitive)

        catchall = {s[0] for s in op.segments if is_catchall(s)}
        for name, v in path_params.items():
            p = op.params.get(("path", name)) or {}
            values.setdefault(("path", name), []).append(v)
            sensitive = bool(p.get("x-sensitive") or (p.get("schema") or {}).get("x-sensitive"))
            if sensitive:
                res.sensitive.setdefault("path", set()).add(v)
            _check_text(res, "path", name, v, p.get("schema") or {}, sensitive,
                        grammar.PATH_SAFE if name in catchall else grammar.SAFE_DEFAULT)

        for (where, name), p in op.params.items():
            if where == "header" and name.lower() in view.headers:
                v = view.headers[name.lower()]
                values.setdefault(("header", name.lower()), []).append(v)
                sensitive = bool(p.get("x-sensitive") or (p.get("schema") or {}).get("x-sensitive"))
                if sensitive:
                    res.sensitive.setdefault("header", set()).add(name.lower())
                _check_text(res, "header", name, v, p.get("schema") or {}, sensitive)

        # ---- body
        ctype = view.content_type
        if view.body:
            if "json" in ctype or (op.json_schema is not None and not ctype):
                try:
                    doc = json.loads(view.body)
                except Exception:
                    doc = None
                    res.add("schema:json:invalid")
                if doc is not None or view.body.strip() == b"null":
                    _walk_json(res, doc, op.json_schema, "", values)
            elif ctype == "application/x-www-form-urlencoded" or ctype.startswith("multipart/form-data"):
                fields = parse_form(view.body) if ctype.startswith("application/") else \
                    parse_multipart_fields(view.body, view.headers.get("content-type", ""))
                if fields is None:
                    res.add("schema:form:invalid")
                else:
                    props = (op.form_schema or {}).get("properties") or {}
                    sens_f = res.sensitive.setdefault("form", set())
                    for k, v in fields:
                        values.setdefault(("form", k), []).append(v)
                        sub = props.get(k)
                        sensitive = bool(sub and sub.get("x-sensitive"))
                        if sensitive:
                            sens_f.add(k)
                        _check_text(res, "form", k, v, sub if op.form_schema is not None else None, sensitive)

        # ---- owner-scoped with an untrusted / anonymous identity
        if op.owner_scoped and not who.trusted:
            res.add("owner_scoped:anonymous" if who.uid is None else "owner_scoped:untrusted")
        # ---- owner-scoped, seeded identity, but the manifest says the addressed object is someone else's
        elif op.owner_scoped and who.role != "admin":
            for name, v in path_params.items():
                if _owns(manifest, name, v, who.uid) is False:
                    res.add(f"owner_scoped:mismatch:{name}")

        # ---- canaries (path parameters; admins exempt; the owner itself is exempt)
        if who.role != "admin":
            for name, v in path_params.items():
                if v in manifest.canaries.get(name, ()):
                    if not _is_owner(manifest, name, v, who.uid):
                        res.add(f"canary:{name}")

        # ---- enumeration
        if enum is not None and op.owner_scoped and path_params:
            if enum.hit(session, op.template, tuple(sorted(path_params.items()))):
                res.add("enumeration")
        # file-based apps carry the entity in the query string (sl_eob_invoice.php?id=): query params
        # declared x-owner-id on an owner-scoped route count for the same session-window heuristic
        if enum is not None and op.owner_scoped:
            qhits = tuple(sorted((k, str(v)) for k, v in pairs
                                 if (op.params.get(("query", k)) or {}).get("x-owner-id")))
            if qhits and enum.hit(session, op.template, qhits):
                res.add("enumeration")

    # ---- active rules (route may be off-spec). `identity: untrusted` rules skip a trusted caller,
    #      so a missing-auth containment rule does not detonate legitimate authenticated traffic.
    for rule in rules:
        rp = rule.applies(view.method, view.raw_path)
        if rp is None:
            continue
        if rule.identity == "untrusted" and who.trusted:
            continue
        if rule.scope == "all":
            _rule_hit(res, rule, strict=True)
            continue
        where, name = rule.param["in"], str(rule.param["name"])
        if where == "path":
            vals = [rp[name]] if name in rp else []
        elif where == "header":
            vals = [view.headers[name.lower()]] if name.lower() in view.headers else []
        elif where == "json":
            vals = values.get(("json", _strip_indices(name)), [])
            if not vals and op is None and view.body:
                tmp: dict = {}
                try:
                    _walk_json(Result(), json.loads(view.body), None, "", tmp)
                except Exception:
                    pass
                vals = tmp.get(("json", _strip_indices(name)), [])
        elif where == "query":
            vals = values.get(("query", name), [])
        else:
            vals = values.get((where, name), [])
            if not vals and where == "form" and view.body:
                vals = [v for k, v in (parse_form(view.body) or []) if k == name]
        outside = any(not grammar.matches(rule.grammar, str(v)) for v in vals)
        if rule.scope == "param_present":
            if vals:   # the parameter is in the request: detonate whatever the value looks like
                _rule_hit(res, rule, strict=outside)
        elif outside:
            _rule_hit(res, rule, strict=True)

    if any(r == "honeytoken" or r.startswith("canary:") for r in res.reasons):
        res.cls = EVIDENCE
    elif res.reasons:
        res.cls = SUSPECT
    return res


def _rule_hit(res: Result, rule: Rule, strict: bool):
    res.rule_hit.append(rule.id)
    if strict:
        res.rule_strict.append(rule.id)
    res.add(f"rule:{rule.id}")


def _strip_indices(dotted: str) -> str:
    return ".".join(p for p in dotted.split(".") if not p.isdigit())


def _owns(manifest: Manifest, param: str, value: str, uid: int | None) -> bool | None:
    """Whether `uid` owns the object a path parameter addresses. None: the manifest cannot tell (a
    parameter with no ownership table, or an object created after the seed)."""
    if uid is None:
        return False
    if param in manifest.group_routes:      # a members-scoped route: every member of the group "owns" it
        members = manifest.groups.get(manifest.group_routes[param], {}).get(value)
        return None if members is None else str(uid) in members
    if param == "user_id":
        return str(uid) == value
    if param.endswith("_id"):
        owner = (manifest.ownership.get(param[:-3] + "s") or {}).get(value)
        return None if owner is None else str(owner) == str(uid)
    return None


def _is_owner(manifest: Manifest, param: str, value: str, uid: int | None) -> bool:
    return _owns(manifest, param, value, uid) is True


# ---------------------------------------------------------------- redaction for recordings

def redact_query(query: str, names: set) -> str:
    if not query or not names:
        return query
    from urllib.parse import quote_plus
    out = []
    for part in query.split("&"):
        k = unquote_plus(part.split("=", 1)[0])
        out.append(f"{part.split('=', 1)[0]}={quote_plus(REDACTED)}" if k in names else part)
    return "&".join(out)


def redact_json(body: bytes, paths: set) -> bytes:
    if not paths:
        return body
    try:
        doc = json.loads(body)
    except Exception:
        return body

    def walk(node, path):
        if isinstance(node, dict):
            return {k: (REDACTED if (f"{path}.{k}" if path else k) in paths else walk(v, f"{path}.{k}" if path else k))
                    for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, path) for v in node]
        return node
    return json.dumps(walk(doc, ""), separators=(",", ":")).encode()


def redact_form(body: bytes, names: set) -> bytes:
    if not names:
        return body
    return redact_query(body.decode("utf-8", "replace"), names).encode()


def redact_path(raw_path: str, values: set) -> str:
    """Replace every segment of the raw path whose decoded value is a sensitive path-parameter value."""
    if not values:
        return raw_path
    return "/".join(REDACTED if seg and unquote(seg) in values else seg for seg in raw_path.split("/"))


_PART_NAME = re.compile(rb'content-disposition:[^\r\n]*?[;\s]name="?([^";\r\n]*)"?', re.I)


def redact_multipart(body: bytes, content_type_header: str, names: set) -> bytes:
    """Replace the content of the multipart parts whose field name is in `names`. A body whose boundary
    cannot be read is replaced whole: a recording must not keep a value marked x-sensitive."""
    if not names:
        return body
    m = re.search(r'boundary="?([^";]+)"?', content_type_header or "", re.I)
    if not m:
        return REDACTED.encode()
    delim = b"--" + m.group(1).strip().encode()
    chunks = body.split(delim)
    for i in range(1, len(chunks)):
        head, sep, _ = chunks[i].partition(b"\r\n\r\n")
        nm = _PART_NAME.search(head)
        if sep and nm and nm.group(1).decode("utf-8", "replace") in names:
            chunks[i] = head + sep + REDACTED.encode() + b"\r\n"
    return delim.join(chunks)
