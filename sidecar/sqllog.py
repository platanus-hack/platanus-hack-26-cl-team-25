"""SQL oracle from outside the app: read the shadow database's own statement log (docs/plan-producto.md §6b).

The shadow database is ours, so it can log every statement (Postgres: log_statement=all with
log_line_prefix='%n [%p] '; MySQL: general_log=ON to a file). The sidecar follows that log and, for each
request, looks at the statements executed while it was being served.

Two rules produce a `sql` event; neither looks at the response, so time-based, boolean-blind, login bypass
and write injections all fire:

input_as_syntax  a value sent in the request appears in a statement as SQL syntax: the text of the value
                 covers more than one token (not just one literal, number or identifier). No learning, no
                 per-app knowledge. Bound parameters never fire. Blind to input that is transformed before
                 it reaches the query (base64, stored now and used later).
new_structure    the statement's structure (`fingerprint`: literals -> ?, lists collapsed, case folded) is
                 not in the baseline of structures the app is known to produce. Does not need the value to
                 appear, so it covers transformed and second-order input. The baseline is learnt from
                 (a) what the database executes with no request in flight and (b) legitimate requests
                 replayed in learn mode (`python -m sidecar.learn`, from the gateway's recordings). The rule
                 is off until at least one request has been learnt. A legitimate structure that was never
                 learnt fires: coverage of the learning traffic is what bounds the false positives.
"""
from __future__ import annotations

import asyncio
import calendar
import json
import logging
import os
import re
import shlex
import time
from urllib.parse import parse_qsl, unquote

log = logging.getLogger("sidecar.sqllog")

PG = re.compile(r'^(\d{9,}\.\d+) \[\d+\] (?:LOG|STATEMENT):\s+(?:(?:statement|execute [^:]*): )?(.*)$')
PG_OTHER = re.compile(r'^\d{9,}\.\d+ \[\d+\] ')
MY = re.compile(r'^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?Z\s+\d+ (Query|Execute)\t(.*)$')
MY_OTHER = re.compile(r'^\d{4}-\d\d-\d\dT[\d:.]+Z\s+\d+ \w')

TOKEN = re.compile(r"""
    (?P<comment>--[^\n]*|/\*.*?\*/|\#[^\n]*)
  | (?P<string>[eE]?'(?:[^'\\]|''|\\.)*'|\$(?P<tag>\w*)\$.*?\$(?P=tag)\$)
  | (?P<dq>"(?:[^"\\]|""|\\.)*"|`[^`]*`)
  | (?P<number>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<word>[A-Za-z_][\w$]*|\$\d+|\?)
  | (?P<space>\s+)
  | (?P<op>.)
""", re.S | re.X)


def tokens(sql: str, dialect: str = "postgres") -> list:
    """[(kind, start, end)] without whitespace. In MySQL "..." is a string and # starts a comment."""
    out = []
    for m in TOKEN.finditer(sql):
        kind = m.lastgroup if m.lastgroup != "tag" else "string"
        if kind == "space":
            continue
        if kind == "comment" and m.group().startswith("#") and dialect != "mysql":
            kind = "op"
            out.append((kind, m.start(), m.start() + 1))    # '#' is an operator in Postgres
            out += [(k, s + m.start() + 1, e + m.start() + 1) for k, s, e in tokens(m.group()[1:], dialect)]
            continue
        if kind == "dq":
            kind = "string" if dialect == "mysql" and m.group().startswith('"') else "word"
        out.append((kind, m.start(), m.end()))
    return out


def injected(sql: str, value: str, dialect: str = "postgres") -> bool:
    """True if some occurrence of `value` in `sql` is more than one token of the statement."""
    value = value.strip()
    if len(value) < 2 or value not in sql:
        return False
    toks = tokens(sql, dialect)
    at = sql.find(value)
    while at != -1:
        end = at + len(value)
        over = [(k, s, e) for k, s, e in toks if s < end and e > at]
        whole = len(over) == 1 and over[0][1] <= at and over[0][2] >= end       # inside one token
        id_list = all(k == "number" or sql[s:e] == "," for k, s, e in over)     # "1,2,3" in an IN list
        if over and not whole and not id_list:
            return True
        at = sql.find(value, at + 1)
    return False


def fingerprint(sql: str, dialect: str = "postgres") -> str:
    """The statement's structure: literals and placeholders -> ?, comments -> /**/, value lists collapsed."""
    out = []
    for kind, s, e in tokens(sql, dialect):
        text = sql[s:e]
        if kind in ("string", "number") or (kind == "word" and (text == "?" or text[0] == "$")):
            if out and out[-1] in ("-", "+") and (len(out) == 1 or out[-2] in OPENERS):
                out.pop()                   # sign of a literal: "= -5" has the structure of "= 5"
            out.append("?")
        elif kind == "comment":
            out.append("/**/")
        elif kind == "word":
            out.append(text if text[0] in '"`' else text.lower())
        else:
            out.append(text)
    fp = " ".join(out)
    fp = LIST.sub("( ?+ )", fp)             # IN (1, 2, 3) and IN (1) are the same structure
    while True:
        new = ROWS.sub("( ?+ )", fp)        # multi-row VALUES
        if new == fp:
            return fp
        fp = new


OPENERS = {"(", ",", "=", "<", ">", "!", "+", "-", "*", "/", "%", "|", "select", "where", "and", "or", "not", "in",
           "values", "set", "when", "then", "else", "by", "limit", "offset", "like", "between", "return", "on"}
LIST = re.compile(r"\( \?(?: , \?)* \)")
ROWS = re.compile(r"\( \?\+ \)(?: , \( \?\+ \))+")
SKIP_HEADERS = {"host", "accept", "accept-encoding", "accept-language", "content-type", "content-length",
                "connection", "cookie", "cache-control", "pragma", "upgrade-insecure-requests"}


class Baseline:
    """Statement structures the app is known to produce. Persisted as JSON when a path is given."""

    def __init__(self, path: str = ""):
        self.path, self.known, self.requests = path, set(), 0
        if path and os.path.isfile(path):
            with open(path) as f:
                raw = json.load(f)
            self.known, self.requests = set(raw.get("structures") or []), int(raw.get("requests") or 0)

    @property
    def ready(self) -> bool:
        return self.requests > 0

    def add(self, fingerprints, from_request: bool = False) -> int:
        new = set(fingerprints) - self.known
        self.known |= new
        self.requests += bool(from_request)
        if self.path and (new or from_request):
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"requests": self.requests, "structures": sorted(self.known)}, f, indent=1)
            os.replace(tmp, self.path)
        return len(new)


def inputs_of(raw_path: str, query: str, body: bytes, content_type: str = "", headers=()) -> list:
    """[(location, name, value)] sent by the client: path segments, query string, form or JSON body,
    cookies and the other request headers."""
    out = [("path", "", unquote(seg)) for seg in raw_path.split("/") if seg]
    out += [("query", k, v) for k, v in parse_qsl(query, keep_blank_values=False)]
    text = body.decode("utf-8", "replace") if body else ""
    if text and "json" in content_type:
        try:
            def walk(node, name):
                if isinstance(node, dict):
                    for k, v in node.items():
                        walk(v, "%s.%s" % (name, k) if name else str(k))
                elif isinstance(node, list):
                    for v in node:
                        walk(v, name)
                elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
                    out.append(("body", name, str(node)))
            walk(json.loads(text), "")
        except ValueError:
            pass
    elif text and ("urlencoded" in content_type or not content_type):
        out += [("body", k, v) for k, v in parse_qsl(text, keep_blank_values=False)]
    for k, v in headers:
        if k.lower() == "cookie":
            for part in v.split(";"):
                name, _, val = part.strip().partition("=")
                out += [("cookie", name, val), ("cookie", name, unquote(val))]
        elif k.lower() not in SKIP_HEADERS:
            out.append(("header", k.lower(), v))
    seen, uniq = set(), []
    for loc, name, v in out:
        if len(v.strip()) >= 2 and v not in seen:
            seen.add(v)
            uniq.append((loc, name, v))
    return uniq


def find_injections(statements: list, inputs: list, dialect: str = "postgres") -> list:
    """One hit per input: [{"statement", "input", "param", "location"}] (param is "" for a path segment)."""
    hits, done = [], set()
    for sql in statements:
        for loc, name, value in inputs:
            if value not in done and injected(sql, value, dialect):
                done.add(value)
                hits.append({"statement": sql[:800], "input": value[:300], "param": name, "location": loc})
    return hits


class LogParser:
    """Statement log lines -> (ts, statement). Statements may span lines."""

    def __init__(self, dialect: str = "postgres"):
        self.dialect = dialect
        self.cur = None             # [ts, text] being assembled

    def feed(self, line: str) -> list:
        """Returns the statements completed by this line (0 or 1)."""
        line = line.rstrip("\n")
        done = []
        if self.dialect == "mysql":
            m, other = MY.match(line), MY_OTHER.match(line)
            if m or other:
                done, self.cur = self._flush(), None
                if m:
                    y, mo, d, h, mi, s, frac, _cmd, text = m.groups()
                    self.cur = [calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(s))) +
                                float(frac or 0), text]
            elif self.cur:
                self.cur[1] += "\n" + line
            return done
        m = PG.match(line)
        if m or PG_OTHER.match(line):
            done, self.cur = self._flush(), None
            if m and (" STATEMENT:" in line or "statement: " in line or "execute " in line):
                self.cur = [float(m.group(1)), m.group(2)]      # STATEMENT: one that failed (syntax errors too)
        elif self.cur and line.startswith("\t"):
            self.cur[1] += "\n" + line[1:]
        return done

    def _flush(self) -> list:
        return [tuple(self.cur)] if self.cur else []

    def flush(self) -> list:
        done, self.cur = self._flush(), None
        return done


class SqlLog:
    """Follows the log command and hands out the statements of a request window."""

    def __init__(self, cmd, dialect: str = "postgres", settle_s: float = 0.2, baseline: Baseline | None = None):
        self.cmd = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        self.dialect, self.settle_s = dialect, settle_s
        self.baseline = baseline or Baseline()
        self.parser = LogParser(dialect)
        self.statements = []        # (ts, text)
        self.last_ts = 0.0
        self.attached = False
        self._task = self._proc = None

    def feed(self, line: str):
        for ts, text in self.parser.feed(line):
            self._add(ts, text)

    def _add(self, ts, text):
        self.last_ts = max(self.last_ts, ts)
        self.statements.append((ts, text))
        del self.statements[:-2000]

    def take(self, t0: float, t1: float) -> list:
        for ts, text in self.parser.flush():       # the last statement has no following line yet
            self._add(ts, text)
        got = [text for ts, text in self.statements if t0 <= ts <= t1]
        # executed with no request in flight (start-up, scheduled jobs): the app's own structures
        n = self.baseline.add(fingerprint(text, self.dialect) for ts, text in self.statements if ts < t0)
        if n:
            log.info("baseline: %d background structure(s) learnt (%d known)", n, len(self.baseline.known))
        self.statements = [(ts, text) for ts, text in self.statements if ts > t1]
        return got

    def learn(self, statements: list) -> int:
        """A legitimate request (learn mode): its structures join the baseline."""
        return self.baseline.add((fingerprint(t, self.dialect) for t in statements), from_request=True)

    def novel(self, statements: list) -> list:
        """[(statement, structure)] whose structure is not in the baseline. Empty until a request was learnt."""
        if not self.baseline.ready:
            return []
        out, seen = [], set()
        for text in statements:
            fp = fingerprint(text, self.dialect)
            if fp not in self.baseline.known and fp not in seen:
                seen.add(fp)
                out.append((text, fp))
        return out

    def events(self, statements: list, inputs: list) -> list:
        """`sql` event details for one request: both rules, one event per statement or input."""
        hits = [dict(h, reason="input_as_syntax") for h in find_injections(statements, inputs, self.dialect)]
        flagged = {h["statement"] for h in hits}
        for text, fp in self.novel(statements):
            if text[:800] in flagged:
                for h in hits:
                    if h["statement"] == text[:800]:
                        h["reason"] = "input_as_syntax+new_structure"
                continue
            hits.append({"statement": text[:800], "input": "", "param": "", "location": "",
                         "reason": "new_structure", "structure": fp[:400]})
        return hits

    async def window(self, t0: float, t1: float) -> list:
        if not self.attached:
            return []
        deadline = time.time() + self.settle_s
        while self.last_ts <= t1 and time.time() < deadline:
            await asyncio.sleep(0.01)
        return self.take(t0 - 0.01, t1 + 0.01)

    async def start(self):
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        if self._task:
            self._task.cancel()
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()

    async def _run(self):
        while True:     # the database container may be replaced: follow again
            try:
                self._proc = await asyncio.create_subprocess_exec(
                    *self.cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, limit=1 << 22)
                self.attached = True
                async for raw in self._proc.stdout:
                    self.feed(raw.decode("utf-8", "replace"))
                await self._proc.wait()
            except asyncio.CancelledError:
                raise
            except Exception as e:      # noqa: BLE001
                log.warning("statement log follower failed: %s", e)
            self.attached = False
            await asyncio.sleep(1.0)
