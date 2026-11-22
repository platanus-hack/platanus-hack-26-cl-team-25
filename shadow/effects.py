"""Input -> effect correlation oracles: ssrf, cmdi, ssti, deser, xxe, redirect.

The channel oracles (proc, net, file) say *that* the app did something it should not. These say *what the request had
to do with it*: they upgrade a generic observation to a class of its own only when the request's own input is
provably what reached the effect, by a mechanical test with a stated rule and no scoring:

  ssrf      a net event whose destination (address, port, or looked-up name) is a host the request named
  cmdi      a proc event whose command line contains an input of the request
  ssti      the response contains the product of a template expression of the request (and not the expression), or a
            proc/file event contains a string literal written inside a template expression of the request
  deser     a proc event while the request carried a serialized object (pickle, Java, PHP, .NET, Ruby, YAML ...); a
            net/file event only if the decoded object also names that host/path
  xxe       a file/net event for the URI of an external entity declared in the request's XML body
  redirect  a 3xx whose Location host is not the request's host and appears in an input

Nothing here guesses: a request that merely looks hostile but whose input does not reach the effect keeps the
generic oracle (or none). The same function runs inside the in-process engine (shadow/core.py) and the out-of-process
sidecar (sidecar/server.py), so a class means the same thing in both. Never raises: on any error the events come back
unchanged.
"""
from __future__ import annotations

import base64
import ipaddress
import logging
import posixpath
import re
import socket
from urllib.parse import unquote, urlsplit

log = logging.getLogger("shadow.effects")

MIN_INPUT = 3          # a shorter input matches anything
MIN_PRODUCT = 1000     # ssti canary: a product this large does not show up in a page by accident

_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'<>]+")
_BARE_HOST = re.compile(r"^(?:[\w.\-]+|\[[0-9a-fA-F:.]+\])(?::\d{1,5})?$")


# ------------------------------------------------------------------ hosts
def canon(host: str) -> str:
    """One spelling per host: lower case, IPv6 brackets and IPv4-mapped prefix removed, legacy IPv4 forms (decimal,
    hex, octal, short) turned into dotted quads."""
    h = (host or "").strip().strip("[]").lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(h)
        return str(ip.ipv4_mapped) if ip.version == 6 and ip.ipv4_mapped else str(ip)
    except ValueError:
        pass
    try:
        return socket.inet_ntoa(socket.inet_aton(h))
    except (OSError, ValueError):
        return h


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def hosts_of(value: str, urls_only: bool = False) -> list[tuple[str, int | None]]:
    """[(canonical host, port or None)] an input value names: URLs (also embedded in a longer text), and, unless
    ``urls_only``, a bare ``host[:port]`` / IP."""
    v = value.strip()
    cands = [m.group(0) for m in _URL.finditer(v)]
    if v.startswith("//"):
        cands.append("http:" + v)
    elif not urls_only and not cands and _BARE_HOST.match(v):
        cands.append("http://" + v)
    out = []
    for c in cands:
        try:
            u = urlsplit(c)
            host, port = u.hostname, u.port
        except ValueError:
            continue
        if host and (canon(host), port) not in out:
            out.append((canon(host), port))
    return out


def input_hosts(ins) -> set:
    """Canonical hosts the request's inputs name: what lets the observer treat a loopback or otherwise ordinary
    destination as input-controlled."""
    out = set()
    for _loc, _param, value in ins or ():
        if isinstance(value, str):
            out.update(h for h, _p in hosts_of(value))
    return out


def _dest(detail: dict):
    """(names, port, dns_only) of a net event: the canonical address and looked-up host/name."""
    names = set()
    for k in ("address", "host", "qname"):
        val = detail.get(k)
        if isinstance(val, str) and val and not val.startswith("("):
            names.add(canon(val))
    port = detail.get("port")
    port = int(port) if isinstance(port, (int, str)) and str(port).isdigit() else None
    return names, port, (port == 53 and not detail.get("qname"))


def _hay(detail: dict) -> str:
    """The text of a proc/file/net event an input can appear in."""
    parts = []
    argv = detail.get("argv")
    if isinstance(argv, (list, tuple)):
        parts += [str(a) for a in argv]
    for k in ("path", "realpath", "command", "args", "address", "host"):
        if isinstance(detail.get(k), str):
            parts.append(detail[k])
    return "\0".join(parts)


def _contains(hay: str, text: str) -> bool:
    """``text`` is in ``hay``: as a substring when it is long enough to be specific, otherwise only as whole words
    (the 2-character ``id`` must not match inside ``uid`` or ``/bin/sh``)."""
    if len(text) >= 6:
        return text in hay
    return re.search(r"(?<![\w])" + re.escape(text) + r"(?![\w])", hay) is not None


def _tag(detail: dict, value: str, param: str, loc: str, **extra) -> dict:
    return {**detail, "input": value[:300], "param": param, "location": loc, **extra}


# ------------------------------------------------------------------ ssrf
def _ssrf(detail, ins):
    names, port, dns_only = _dest(detail)
    for loc, param, value in ins:
        for host, p in hosts_of(value, urls_only=dns_only):
            if dns_only:
                if not is_ip(host):          # a name had to be resolved, and the request named a URL
                    return _tag(detail, value, param, loc, matched="dns")
            elif host in names and (p is None or port is None or p == port):
                return _tag(detail, value, param, loc, matched="address")
    return None


# ------------------------------------------------------------------ cmdi
def _cmdi(detail, ins):
    hay = _hay(detail)
    for loc, param, value in ins:
        if len(value) >= MIN_INPUT and _contains(hay, value):
            return _tag(detail, value, param, loc, metachar=bool(re.search(r"[;|&`$()<>\n]", value)))
    return None


# ------------------------------------------------------------------ ssti
_TPL = re.compile(r"(\{\{|\{%|\$\{|#\{|<%=?|\[\[|\{#)(.{1,400}?)(\}\}|%\}|\}|#\}|%>|\]\])", re.S)
_LIT = re.compile(r"'((?:[^'\\]|\\.){2,})'|\"((?:[^\"\\]|\\.){2,})\"")
_ARITH = re.compile(r"^\s*(\d{2,9})\s*\*\s*(\d{2,9})\s*$")


def _ssti_effect(detail, ins):
    hay = _hay(detail)
    for loc, param, value in ins:
        for m in _TPL.finditer(value):
            for lit in _LIT.finditer(m.group(2)):
                text = re.sub(r"\\(.)", r"\1", lit.group(1) or lit.group(2))
                if len(text) >= 2 and _contains(hay, text):
                    return _tag(detail, value, param, loc, expression=m.group(0)[:200], literal=text)
    return None


def _ssti_response(ins, response):
    body = response.get("body") or b""
    if not body:
        return None
    raw = [v for _l, _p, v in ins]
    for loc, param, value in ins:
        for m in _TPL.finditer(value):
            a = _ARITH.match(m.group(2))
            if not a:
                continue
            product = int(a.group(1)) * int(a.group(2))
            needle = str(product)
            if product < MIN_PRODUCT or needle.encode() not in body or m.group(0).encode() in body:
                continue                      # an app that echoes the expression unevaluated is safe
            if any(needle in v for v in raw):
                continue                      # the input itself carried the number
            return {"expression": m.group(0)[:200], "evaluated": needle, "input": value[:300], "param": param,
                    "location": loc, "observed": "response"}
    return None


# ------------------------------------------------------------------ deser
_ENVELOPES = (
    ("pickle", re.compile(r"^(?:gA[JNQSW][A-Za-z0-9+/_\-]{6,}|Y29z[A-Za-z0-9+/_\-]{6,})={0,2}$")),
    ("java", re.compile(r"^rO0AB[A-Za-z0-9+/_\-]{8,}={0,2}$")),
    ("dotnet", re.compile(r"^AAEAAAD(?:/|_){3,}[A-Za-z0-9+/_\-]*={0,2}$")),
    ("ruby", re.compile(r"^BAh[A-Za-z0-9+/_\-]{6,}={0,2}$")),
    ("php", re.compile(r'^(?:[OC]:\d+:"|a:\d+:\{|s:\d+:")')),
    ("yaml", re.compile(r"!!python/|!ruby/object|!!java\.|!!javax\.")),
    ("nodejs", re.compile(r"_\$\$ND_FUNC\$\$_")),
)


def _b64(v: str) -> bytes:
    try:
        return base64.b64decode(v.replace("-", "+").replace("_", "/") + "=" * (-len(v) % 4), validate=False)
    except Exception:   # noqa: BLE001
        return b""


def _envelope(value: str):
    """(format, decoded text) when the input is a serialized object, else None. Binary formats are recognised by
    their base64 prefix; text formats (php, yaml, node-serialize) also inside a base64 wrapper."""
    v = value.strip()
    if v.startswith("\xac\xed\x00\x05"):
        return "java", v
    for name, rx in _ENVELOPES:
        if rx.search(v):
            raw = _b64(v)
            return name, (raw.decode("latin-1") if raw else v)
    if re.fullmatch(r"[A-Za-z0-9+/_\-]{16,}={0,2}", v):          # a base64 wrapper around a text format
        text = _b64(v).decode("latin-1")
        for name, rx in _ENVELOPES:
            if name in ("php", "yaml", "nodejs") and rx.search(text):
                return name, text
    return None


def _deser(kind, detail, ins):
    hay = _hay(detail)
    tokens = [t for t in re.split(r"[^\w./\-]+", hay) if len(t) >= 3]
    for loc, param, value in ins:
        env = _envelope(value)
        if not env:
            continue
        fmt, text = env
        correlated = any(t in text or t in value for t in tokens)
        if kind == "proc" or correlated:      # a spawned process is the effect; elsewhere the object must name it
            return _tag(detail, value, param, loc, format=fmt, correlated=correlated)
    return None


# ------------------------------------------------------------------ xxe
_ENT = re.compile(r"<!ENTITY\s+(?:%\s+)?[^\s>]+\s+(?:SYSTEM|PUBLIC\s+(?:\"[^\"]*\"|'[^']*'))\s*(?:\"([^\"]+)\"|'([^']+)')", re.I)
_DTD = re.compile(r"<!DOCTYPE\s+[^\s>\[]+\s+(?:SYSTEM|PUBLIC\s+(?:\"[^\"]*\"|'[^']*'))\s*(?:\"([^\"]+)\"|'([^']+)')", re.I)


def _entities(request) -> list[str]:
    body = request.get("body") or b""
    ctype = (request.get("headers") or {}).get("content-type", "").lower()
    if not body or not ("xml" in ctype or body.lstrip()[:1] == b"<"):
        return []
    text = body.decode("utf-8", "replace")
    return [a or b for a, b in _ENT.findall(text) + _DTD.findall(text)]


def _entity_path(uri: str) -> str | None:
    m = re.search(r"resource=(/[^&\s]+)", uri)          # php://filter/.../resource=/etc/passwd
    if m:
        return posixpath.normpath(unquote(m.group(1)))
    if uri.startswith("/"):
        return posixpath.normpath(uri)
    u = urlsplit(uri)
    if u.scheme == "file":
        return posixpath.normpath(unquote(u.path)) if u.path else None
    return None


def _xxe(kind, detail, request):
    uris = _entities(request)
    if kind == "file":
        got = {detail.get(k) for k in ("realpath", "path") if isinstance(detail.get(k), str)}
        for uri in uris:
            p = _entity_path(uri)
            if p and any(g == p or posixpath.normpath(g) == p for g in got):
                return _tag(detail, uri, "body", "body", entity=uri)
    elif kind == "net":
        names, port, _dns = _dest(detail)
        for uri in uris:
            for host, hp in hosts_of(uri, urls_only=True):
                if host in names and (hp is None or port is None or hp == port):
                    return _tag(detail, uri, "body", "body", entity=uri)
    return None


# ------------------------------------------------------------------ redirect
def _redirect(ins, request, response):
    st = response.get("status") or 0
    loc = (response.get("headers") or {}).get("location")
    if not (300 <= int(st) < 400) or not loc:
        return None
    target = loc.strip().replace("\\", "/")
    if target.startswith("//"):
        target = "http:" + target
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", target):
        return None                                      # relative: stays on the site
    try:
        host = (urlsplit(target).hostname or "").lower()
    except ValueError:
        return None
    mine = ((request.get("headers") or {}).get("host") or "").rsplit(":", 1)[0].strip("[]").lower()
    if not host or host == mine:
        return None
    for loc_in, param, value in ins:
        if len(value) >= MIN_INPUT and host in value.lower():
            return {"target": loc[:300], "host": host, "status": int(st), "input": value[:300], "param": param,
                    "location": loc_in, "observed": "response"}
    return None


# ------------------------------------------------------------------ entry point
def _upgrade(e: dict, ins, request) -> dict | None:
    o, d = e.get("oracle"), e.get("detail") or {}
    found = None
    if o == "proc":
        for kind, fn in (("deser", lambda: _deser("proc", d, ins)), ("ssti", lambda: _ssti_effect(d, ins)),
                         ("cmdi", lambda: _cmdi(d, ins))):
            found = fn()
            if found:
                return {"oracle": kind, "detail": found, "stack": e.get("stack") or []}
    elif o == "file":
        for kind, fn in (("xxe", lambda: _xxe("file", d, request)), ("ssti", lambda: _ssti_effect(d, ins)),
                         ("deser", lambda: _deser("file", d, ins))):
            found = fn()
            if found:
                return {"oracle": kind, "detail": found, "stack": e.get("stack") or []}
    elif o == "net":
        for kind, fn in (("xxe", lambda: _xxe("net", d, request)), ("deser", lambda: _deser("net", d, ins)),
                         ("ssrf", lambda: _ssrf(d, ins))):
            found = fn()
            if found:
                return {"oracle": kind, "detail": found, "stack": e.get("stack") or []}
    return None


def refine(events: list, ins: list, request: dict, response: dict) -> list:
    """The events with every proc/net/file event whose cause is the request's input upgraded to its class, plus the
    events only the response shows (ssti canary, redirect). ``ins`` is shadow.inputs.extract's [(location, param,
    value)]; ``request`` {headers (lower-case), body}; ``response`` {status, headers (lower-case), body}."""
    try:
        ins = [i for i in ins if isinstance(i[2], str)]
        out = [_upgrade(e, ins, request) or e for e in events]
        for kind, found in (("ssti", _ssti_response(ins, response)), ("redirect", _redirect(ins, request, response))):
            if found:
                out.append({"oracle": kind, "detail": found, "stack": []})
        return out
    except Exception:   # noqa: BLE001 - the oracles' events are the evidence; never lose them to a refinement
        log.exception("effects.refine failed; returning the events unrefined")
        return list(events)
