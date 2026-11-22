"""SQL statements from the shadow database's own log, and the structure rule (docs/plan-producto.md §6b).

Source. The Postgres proxy (pgproxy.py) is one way to see the statements; this is the other, for when the app
cannot be pointed at a proxy or the database is MySQL: the shadow database is ours, so it logs every statement
(Postgres: ``log_statement=all`` with ``log_line_prefix='%n [%p] '``; MySQL: ``general_log=ON`` to a file) and
``LogFollower`` feeds them to the observer like the proxy does. The log cannot tell whether a statement ran, so
all are reported as executed, except the ones Postgres repeats after an error (``STATEMENT:``), reported as failed.

Rule ``new_structure`` (either source). The taint rule (shadow.sqltaint) needs the request value to appear in
the statement. This one does not: the statement's structure (``fingerprint``: literals -> ?, lists collapsed,
case folded) is not in the baseline of structures the app is known to produce. It covers input transformed
before it reaches the query (base64, stored now and used later). The baseline is learnt from (a) what the
database executes with no request in flight and (b) legitimate requests replayed in learn mode
(``python -m sidecar.learn``, from the gateway's recordings). The rule is off until one request has been learnt.
A legitimate structure that was never learnt fires: the learning traffic bounds the false positives.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import threading
import time

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


class LogParser:
    """Statement log lines -> (failed, statement). Statements may span lines."""

    def __init__(self, dialect: str = "postgres"):
        self.dialect = dialect
        self.cur = None             # [failed, text] being assembled

    def feed(self, line: str) -> list:
        """Returns the statements completed by this line (0 or 1)."""
        line = line.rstrip("\n")
        done = []
        if self.dialect == "mysql":
            m, other = MY.match(line), MY_OTHER.match(line)
            if m or other:
                done, self.cur = self._flush(), None
                if m:
                    self.cur = [False, m.group(9)]
            elif self.cur:
                self.cur[1] += "\n" + line
            return done
        m = PG.match(line)
        if m or PG_OTHER.match(line):
            done, self.cur = self._flush(), None
            if m and (" STATEMENT:" in line or "statement: " in line or "execute " in line):
                self.cur = [" STATEMENT:" in line, m.group(2)]   # STATEMENT: one that failed (syntax errors too)
        elif self.cur and line.startswith("\t"):
            self.cur[1] += "\n" + line[1:]
        return done

    def _flush(self) -> list:
        return [tuple(self.cur)] if self.cur else []

    def flush(self) -> list:
        done, self.cur = self._flush(), None
        return done


def structure_events(baseline: Baseline, statements, dialect: str = "postgres", skip=()) -> list:
    """`sql` events for statements whose structure is not in the baseline (none until a request was learnt)."""
    if not baseline.ready:
        return []
    out, seen = [], set()
    for text in statements:
        fp = fingerprint(text, dialect)
        if text in skip or fp in baseline.known or fp in seen:
            continue
        seen.add(fp)
        out.append({"oracle": "sql", "stack": [],
                    "detail": {"statement": text[:800], "input": "", "param": "", "location": "",
                               "reason": "new_structure", "structure": fp[:400]}})
    return out


class LogFollower:
    """Runs the log command and reports each statement to ``on_statement(sql, ok, error, via)`` from a thread.
    Follows again when the command ends (the database container may be replaced)."""

    def __init__(self, cmd, dialect: str, on_statement):
        self.cmd = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        self.dialect, self.on_statement = dialect, on_statement
        self.parser = LogParser(dialect)
        self.lock = threading.Lock()
        self.proc = None
        self.stopped = False

    def feed(self, line: str):
        with self.lock:
            done = self.parser.feed(line)
        self._emit(done)

    def flush(self):
        """The last statement has no following line yet: report it now (called at the edges of a window)."""
        with self.lock:
            done = self.parser.flush()
        self._emit(done)

    def _emit(self, done):
        for failed, text in done:
            self.on_statement(text, not failed, "reported by the database log" if failed else None, "log")

    def start(self):
        threading.Thread(target=self._run, daemon=True, name="sql-log").start()

    def stop(self):
        self.stopped = True
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def _run(self):
        while not self.stopped:
            try:
                self.proc = subprocess.Popen(self.cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                             stderr=subprocess.STDOUT, text=True, errors="replace")
                for line in self.proc.stdout:
                    self.feed(line)
                self.proc.wait()
            except OSError as e:
                log.warning("statement log follower failed: %s", e)
            time.sleep(1.0)
