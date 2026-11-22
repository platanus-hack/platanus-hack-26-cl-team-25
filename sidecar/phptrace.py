"""Where in the app's code: PHP call stacks for oracle events, from Xdebug function traces.

The sidecar observes from outside the process, so its evidence carries ``stack: []``. For PHP apps the
fleet can run the clone from a shadow-only ``<release>-trace`` image (the release image plus Xdebug in
``trace`` mode, computer-readable format 1, ``start_with_request=yes``); prod never runs it. Each request
writes one trace file under ``dir`` in the app's filesystem; the sidecar reads it through
``/proc/<pid>/root`` (shared PID namespace) and, for every oracle event, finds the sink call that matches:

  sql    a query/prepare/execute call (mysqli, PDO, ADOdb, the app's own wrappers) whose SQL argument
         is the observed statement (``?`` placeholders of a bound call match any literal)
  file   fopen/file_get_contents/readfile/file/include*/require*... whose path argument resolves to the
         opened file
  proc   exec/shell_exec/system/passthru/proc_open/popen/pcntl_exec
  net    fsockopen/stream_socket_client/curl_exec/file_get_contents('http...')
  owner  no sink: the entry script that produced the response

The event's ``stack`` becomes ``[{file, line, func}, ...]``, outermost first and ending at the innermost
frame inside the app's own source (frames in excluded paths such as ``vendor/`` are dropped), so the
incident's sink (``stack[-1]``) is the line of the app's code that reached the sink.
"""
from __future__ import annotations

import logging
import os
import posixpath
import re

log = logging.getLogger("sidecar.phptrace")

SQL_SINKS = re.compile(r"(?:^|->|::)(?:mysqli_query|mysqli_real_query|mysqli_prepare|mysqli_multi_query|query|"
                       r"real_query|multi_query|prepare|exec|execute|executenolog|execute_query|getall|getrow|"
                       r"getone|getcol|selectlimit|sqlstatement\w*|sqlquery\w*|sqlinsert\w*|sqlstatementnolog|"
                       r"fetchrecords|fetchsinglevalue|_query)$", re.I)
FILE_SINKS = re.compile(r"^(?:fopen|file_get_contents|readfile|file|fpassthru|file_put_contents|opendir|scandir|"
                        r"unlink|copy|rename|include|include_once|require|require_once|move_uploaded_file|"
                        r"simplexml_load_file|parse_ini_file|splfileobject->__construct|finfo_file|"
                        r"mime_content_type|filesize|is_file|file_exists|stat|realpath)$", re.I)
PROC_SINKS = re.compile(r"^(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec|mail)$", re.I)
NET_SINKS = re.compile(r"^(?:fsockopen|pfsockopen|stream_socket_client|curl_exec|curl_multi_exec|socket_connect|"
                       r"file_get_contents|fopen|get_headers|gethostbyname|dns_get_record)$", re.I)
MAX_FILE = 256 << 20
TRIGGER = b"XDEBUG_TRACE=immune"


def with_trigger(headers: list) -> list:
    """The request's headers with the Xdebug trace trigger cookie added (the -trace image traces only
    requests that carry it: the judged request, not logins or warm-up)."""
    out, done = [], False
    for k, v in headers:
        if k == b"cookie" and not done:
            v = (v + b"; " if v.strip() else b"") + TRIGGER
            done = True
        out.append((k, v))
    if not done:
        out.append((b"cookie", TRIGGER))
    return out


class Call:
    __slots__ = ("level", "func", "user", "include", "file", "line", "args", "parent")

    def __init__(self, level, func, user, include, file, line, args, parent):
        self.level, self.func, self.user, self.include = level, func, user, include
        self.file, self.line, self.args, self.parent = file, line, args, parent


def parse(lines) -> list[Call]:
    """Xdebug trace format 1 -> function-entry records (each linked to its caller)."""
    calls: list[Call] = []
    open_by_level: dict[int, Call] = {}
    for raw in lines:
        parts = raw.rstrip("\n").split("\t")
        if len(parts) < 10 or parts[2] != "0":
            continue
        try:
            level = int(parts[0])
            line = int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0
        except ValueError:
            continue
        nargs = int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else 0
        args = parts[11:11 + nargs]
        c = Call(level, parts[5], parts[6] == "1", parts[7], parts[8], line, args, open_by_level.get(level - 1))
        open_by_level[level] = c
        for deeper in [k for k in open_by_level if k > level]:
            del open_by_level[deeper]
        calls.append(c)
    return calls


def php_string(arg: str) -> str | None:
    """A string argument as Xdebug prints it ('...' with \\' and \\\\ escaped) -> its value."""
    a = arg.strip()
    if len(a) >= 2 and a[0] == "'" and a[-1] == "'":
        body = a[1:-1]
        out, i = [], 0
        while i < len(body):
            ch = body[i]
            if ch == "\\" and i + 1 < len(body) and body[i + 1] in "'\\":
                out.append(body[i + 1]); i += 2; continue
            out.append(ch); i += 1
        return "".join(out)
    return None


_WS = re.compile(r"\s+")


def _norm_sql(s: str) -> str:
    return _WS.sub(" ", s.replace("\\", "")).strip().lower()


def sql_matches(arg_sql: str, statement: str) -> bool:
    a, s = _norm_sql(arg_sql), _norm_sql(statement)
    if not a or len(a) < 6:
        return False
    if a == s or (len(a) >= 40 and (a in s or s in a)):
        return True
    if "?" in a:   # a bound call: placeholders match any literal the driver interpolated
        parts = [re.escape(p) for p in a.split("?")]
        try:
            return re.fullmatch(r"(?:'[^']*'|[^ ,)]*?|.*?)".join(parts), s, re.S) is not None
        except re.error:
            return False
    return False


class CallTracer:
    def __init__(self, directory: str, source_dirs, exclude=None, root: str = "/"):
        self.dir = directory.rstrip("/") or "/tmp/immune-trace"
        self.source_dirs = [d.rstrip("/") for d in source_dirs or [] if d]
        self.exclude = [e for e in (exclude or ["/vendor/", "/library/ADODB/", "/library/adodb/"]) if e]
        self.root = root

    @classmethod
    def from_config(cls, cfg: dict, source_dirs):
        cfg = cfg or {}
        if cfg.get("kind", "php-xdebug") != "php-xdebug":
            log.warning("unknown tracer kind %r: call stacks disabled", cfg.get("kind"))
            return None
        return cls(str(cfg.get("dir") or "/tmp/immune-trace"), source_dirs, cfg.get("exclude"))

    # ------------------------------------------------------------ files
    def _host_dir(self) -> str:
        root = self.root.rstrip("/")
        return (root + self.dir) if root else self.dir

    def clear(self):
        d = self._host_dir()
        try:
            names = os.listdir(d)
        except OSError:
            return
        for n in names:
            try:
                os.unlink(os.path.join(d, n))
            except OSError:
                pass

    def latest(self) -> str | None:
        d = self._host_dir()
        try:
            files = [os.path.join(d, n) for n in os.listdir(d) if n.endswith(".xt")]
        except OSError:
            return None
        files = [f for f in files if os.path.isfile(f)]
        return max(files, key=lambda f: os.stat(f).st_mtime) if files else None

    def read(self) -> list[Call]:
        path = self.latest()
        if not path or os.path.getsize(path) > MAX_FILE:
            return []
        with open(path, encoding="utf-8", errors="replace") as fh:
            return parse(fh)

    # ------------------------------------------------------------ matching
    def in_app(self, file: str) -> bool:
        if not file or any(x in file for x in self.exclude):
            return False
        return not self.source_dirs or any(file == d or file.startswith(d + "/") for d in self.source_dirs)

    def stack_of(self, call: Call) -> list[dict]:
        frames, c = [], call
        while c is not None:
            frames.append({"file": c.file, "line": c.line, "func": c.func})
            c = c.parent
        for i, f in enumerate(frames):   # the innermost frame inside the app's own code is the sink
            if self.in_app(f["file"]):
                frames = frames[i:i + 12]
                break
        else:
            frames = frames[:12]
        return frames[::-1]   # outermost first, the sink last (the convention of every evidence stack)

    def find(self, calls: list[Call], event: dict) -> Call | None:
        oracle, d = event.get("oracle"), event.get("detail") or {}
        if oracle == "sql":
            stmt = d.get("statement") or ""
            hits = [c for c in calls if SQL_SINKS.search(c.func) and any(
                (v := php_string(a)) is not None and sql_matches(v, stmt) for a in c.args)]
            app = [c for c in hits if self.in_app(c.file)]
            # the innermost wrapper call made from the app's code (e.g. sqlStatement in library/) is the
            # most useful location; fall back to the driver call
            return (app or hits or [None])[-1] if hits else None
        if oracle == "file":
            real, raw = d.get("realpath") or "", d.get("path") or ""
            for c in calls:
                if not FILE_SINKS.match(c.func):
                    continue
                vals = [c.include] if c.include else []
                vals += [v for a in c.args[:1] if (v := php_string(a)) is not None]
                for v in vals:
                    if not v:
                        continue
                    base = posixpath.dirname(c.file) if not v.startswith("/") else ""
                    full = posixpath.normpath(posixpath.join(base, v)) if base else posixpath.normpath(v)
                    if full == real or v == raw or (".." in v and posixpath.basename(v) == posixpath.basename(real)):
                        return c
            return None
        if oracle == "proc":
            target = posixpath.basename((d.get("argv") or [d.get("path") or ""])[0] or "")
            for c in calls:
                if PROC_SINKS.match(c.func):
                    if not target or any(target in (php_string(a) or a) for a in c.args):
                        return c
            return next((c for c in calls if PROC_SINKS.match(c.func)), None)
        if oracle == "net":
            addr = str(d.get("address") or "")
            for c in calls:
                if NET_SINKS.match(c.func) and (not addr or any(addr in (php_string(a) or a) for a in c.args)):
                    if c.func.lower() in ("file_get_contents", "fopen") and not any(
                            "://" in (php_string(a) or "") for a in c.args):
                        continue
                    return c
            return None
        return None

    def entry(self, calls: list[Call]) -> list[dict]:
        mains = [c for c in calls if c.func == "{main}"]
        main = next((c for c in mains if self.in_app(c.file)), mains[-1] if mains else None)
        if main is None:
            return []
        return [{"file": main.file, "line": main.line, "func": "{main}"}]

    def attach(self, events: list[dict]) -> int:
        """Fill ``stack`` of each event in place. -> number of events located."""
        calls = self.read()
        if not calls:
            return 0
        n = 0
        for ev in events:
            if ev.get("stack"):
                continue
            hit = self.find(calls, ev)
            stack = self.stack_of(hit) if hit is not None else self.entry(calls)
            if stack:
                ev["stack"] = stack
                n += hit is not None
        return n
