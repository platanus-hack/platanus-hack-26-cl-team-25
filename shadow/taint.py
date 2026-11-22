"""Multi-step (stored) taint across a captive session: second-order SQL injection and stored XSS.

The single-request oracles compare a request's own inputs against what that request did. A stored attack splits
over two requests of one captive (L2) session: request N stores a value (a note body, a profile field), request
N+M reads it back into an unparameterised query (**second-order SQL**) or reflects it unescaped into an HTML page
(**stored XSS**). The dangerous value is not in request N+M's own inputs, so the per-request oracles never see it.

``TaintTracker`` lives on the engine for the length of a captive session (it is reset on L1, like the clone's
database). It remembers every input value each request introduced, with a reference to that request, and on a later
request:

- **second-order SQL**: runs the same taint check (`shadow/sqltaint`) of the *earlier* requests' inputs against the
  statements this request executed; a hit is a `sql` event with ``reason: second_order`` and the request that
  introduced the value in ``origin``;
- **stored XSS**: an earlier (or the current) request's input that contains real markup appears verbatim, not
  HTML-escaped, in this request's HTML response — an `xss` event, again with the introducing request in ``origin``.

Both are mechanical: a value either appears where it must not or it does not. ``origin`` lets the incident and the
PoC replay the two steps and point the patch at the request that planted the value; ``stack`` stays the sink of the
request where it fired. Nothing here can change a verdict on its own beyond adding these events.
"""
from __future__ import annotations

import html
import re

from immune_contracts import wire

from . import sqltaint

MIN_VALUE = 4            # a shorter stored value matches too much
MAX_TRACKED = 2000       # inputs remembered per session
# a value that carries real markup: an opening tag <x / </x, or an event handler / javascript: url after a quote
_MARKUP = re.compile(r"<\s*/?[a-zA-Z][\w:-]*|on[a-z]+\s*=|javascript:", re.I)
_HTMLISH = re.compile(rb"<\s*/?[a-zA-Z!]")


class TaintTracker:
    def __init__(self, max_tracked: int = MAX_TRACKED):
        self.max_tracked = max_tracked
        self.seen: list[dict] = []          # [{value, location, param, origin}]
        self._values: set[str] = set()

    def reset(self) -> None:
        self.seen.clear()
        self._values.clear()

    def observe(self, rid: str, request: dict, inputs) -> None:
        """Remember this request's inputs so a later request can be attributed to it. ``request`` is the evidence
        request dict (method, path, query, headers, body_b64)."""
        origin = {"rid": rid, "request": request}
        for location, param, value in inputs:
            if not isinstance(value, str) or len(value) < MIN_VALUE:
                continue
            key = (location, param, value)
            if key in self._values:
                continue
            if len(self.seen) >= self.max_tracked:
                return
            self._values.add(key)
            self.seen.append({"value": value, "location": location, "param": param, "origin": origin})

    # ------------------------------------------------------------------ oracles
    def second_order_sql(self, statements, constants, dialect: str, current_values: set) -> list[dict]:
        """`sql` events for an *earlier* request's input breaking out of a literal in a statement this request ran.
        Values that are also in the current request are left to the normal first-order check."""
        prior = [(t["location"], t["param"], t["value"]) for t in self.seen if t["value"] not in current_values]
        if not prior:
            return []
        by_value = {t["value"]: t["origin"] for t in self.seen}
        out = []
        for e in sqltaint.check(statements, prior, constants, dialect):
            origin = by_value.get(e["detail"]["input"])
            e["detail"]["second_order"] = True            # the taint came from an earlier request, not this one
            e["detail"]["origin_rid"] = (origin or {}).get("rid")
            if origin:
                e["origin"] = origin
            out.append(e)
        return out

    def stored_xss(self, body: bytes, content_type: str, current_inputs, stack=()) -> list[dict]:
        """`xss` events: an input with real markup appears verbatim and unescaped in an HTML response. Inputs of the
        current request count as reflected XSS (``origin`` is this request); earlier ones as stored."""
        if not body or not _is_html(content_type, body):
            return []
        cur = {(loc, p, v) for loc, p, v in current_inputs if isinstance(v, str)}
        cur_origin = {"rid": None, "request": None}
        candidates = [{"value": v, "location": loc, "param": p, "origin": cur_origin, "stored": False}
                      for loc, p, v in cur] \
            + [{**t, "stored": True} for t in self.seen]
        out, seen = [], set()
        for c in candidates:
            v = c["value"]
            if len(v) < MIN_VALUE or not _MARKUP.search(v):
                continue
            if v.encode("utf-8", "replace") not in body:
                continue                                   # the raw value is not in the page...
            if html.escape(v, quote=True).encode("utf-8", "replace") in body and v.encode() not in _strip_escaped(body, v):
                continue                                   # ...it is only there escaped: safe
            key = (c["param"], v)
            if key in seen:
                continue
            seen.add(key)
            out.append({"oracle": wire.ORACLE_XSS,
                        "detail": {"input": v[:300], "param": c["param"], "location": c["location"],
                                   "stored": c["stored"],
                                   **({"origin_rid": c["origin"]["rid"]} if c["origin"]["rid"] else {})},
                        "stack": list(stack),
                        **({"origin": c["origin"]} if c["origin"]["rid"] else {})})
        return out


def _is_html(content_type: str, body: bytes) -> bool:
    ct = (content_type or "").lower()
    if "html" in ct:
        return True
    if ct and "html" not in ct and ("json" in ct or "javascript" in ct or "octet-stream" in ct or "image" in ct):
        return False
    return bool(_HTMLISH.search(body[:1000]))


def _strip_escaped(body: bytes, value: str) -> bytes:
    """The body with the escaped spelling of ``value`` removed, to tell a page that has the value both escaped and
    raw (vulnerable) from one that only has it escaped (safe)."""
    esc = html.escape(value, quote=True).encode("utf-8", "replace")
    return body.replace(esc, b"") if esc else body
