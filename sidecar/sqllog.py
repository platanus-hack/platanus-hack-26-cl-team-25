"""SQL oracle from outside the app: read the shadow database's own statement log (docs/plan-producto.md §6b).

The shadow database is ours, so it can log every statement (Postgres: log_statement=all with
log_line_prefix='%n [%p] '; MySQL: general_log=ON to a file). The sidecar follows that log and, for each
request, looks at the statements executed while it was being served.

`sql` event: a value sent in the request appears in a statement as SQL syntax, i.e. the text of the value
covers more than one token (it is not just one literal, one number or one identifier). That is what an
injection is, whatever the response looks like: time-based, boolean-blind, login bypass and writes all fire.
Bound parameters never fire (the value is not part of the statement, or is one escaped literal).

No learning period and no per-app knowledge. Not seen: input that is transformed before reaching the query
(decoded from base64, stored and used later), and values sent in headers or cookies.
"""
from __future__ import annotations

import asyncio
import calendar
import json
import logging
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


def inputs_of(raw_path: str, query: str, body: bytes, content_type: str = "") -> list:
    """[(location, name, value)] sent by the client: path segments, query string, form or JSON body."""
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
            if m and ("statement: " in line or "execute " in line):
                self.cur = [float(m.group(1)), m.group(2)]
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

    def __init__(self, cmd, dialect: str = "postgres", settle_s: float = 0.2):
        self.cmd = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        self.dialect, self.settle_s = dialect, settle_s
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
        self.statements = [(ts, text) for ts, text in self.statements if ts > t1]
        return got

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
