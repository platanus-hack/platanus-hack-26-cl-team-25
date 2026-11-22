"""SQL oracle: taint check of request inputs against executed statements.

Rule, for every input value v (len >= 2) and every occurrence of v in an
executed statement (the raw text given to ``execute``, so bound parameters
never appear in it):

1. the occurrence overlaps or is adjacent to a comment token  -> fire;
2. the non-whitespace tokens it overlaps are exactly ONE literal token
   (string, number or blob)                                   -> safe;
3. the occurrence is part of a verbatim copy of a string constant of the app's
   own code (e.g. the input ``notes`` inside ``"SELECT ... FROM notes"``, which
   the app wrote, not the user)                                -> safe;
4. otherwise                                                   -> fire.

Statements that failed to prepare/execute never reach this module.
We tokenise ourselves (SQLite lexical rules) because we need comments.
"""
from __future__ import annotations

import re

from immune_contracts import wire

_TOKEN = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<comment>--[^\n]*|/\*.*?(?:\*/|\Z))
  | (?P<blob>[xX]'[^']*(?:'|\Z))
  | (?P<string>'(?:[^']|'')*(?:'|\Z))
  | (?P<qident>"(?:[^"]|"")*(?:"|\Z)|`(?:[^`]|``)*(?:`|\Z)|\[[^\]]*(?:\]|\Z))
  | (?P<number>0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)
  | (?P<ident>[A-Za-z_\x80-\U0010ffff][A-Za-z0-9_$\x80-\U0010ffff]*)
  | (?P<var>\?\d*|[:@$][A-Za-z0-9_]+)
  | (?P<op>\|\||<<|>>|<=|>=|==|!=|<>|->>|->|.)
    """,
    re.VERBOSE | re.DOTALL,
)

LITERALS = {"string", "number", "blob"}


def tokenize(sql: str) -> list[tuple[str, int, int]]:
    """[(kind, start, end)] covering the whole text."""
    out = []
    pos = 0
    n = len(sql)
    while pos < n:
        m = _TOKEN.match(sql, pos)
        if not m or m.end() == pos:
            out.append(("op", pos, pos + 1))
            pos += 1
            continue
        out.append((m.lastgroup, m.start(), m.end()))
        pos = m.end()
    return out


def _occurrences(hay: str, needle: str):
    i = hay.find(needle)
    while i != -1:
        yield i
        i = hay.find(needle, i + 1)


def classify(sql: str, tokens, start: int, end: int, constants) -> str | None:
    """Return a reason string if the occurrence [start,end) is an injection, else None."""
    touched = [t for t in tokens if t[1] < end and t[2] > start and t[0] != "ws"]
    adjacent = [t for t in tokens if (t[2] == start or t[1] == end) and t[0] == "comment"]
    if any(t[0] == "comment" for t in touched) or adjacent:
        return "comment"
    if len(touched) == 1 and touched[0][0] in LITERALS:
        return None
    if constants is not None and explained_by_constant(sql, start, end, constants):
        return None
    if len(touched) == 1:
        return "token"
    return "structure"


def explained_by_constant(sql: str, start: int, end: int, constants) -> bool:
    needle = sql[start:end]
    for c in constants.containing(needle):
        for k in _occurrences(c, needle):
            s = start - k
            if s >= 0 and sql.startswith(c, s):
                return True
    return False


class Constants:
    """String constants found in the app's code objects (lazily filtered per needle)."""

    def __init__(self, strings):
        self.strings = [s for s in set(strings) if len(s) >= 2]
        self._cache = {}

    def containing(self, needle):
        hit = self._cache.get(needle)
        if hit is None:
            hit = [s for s in self.strings if needle in s]
            if len(self._cache) < 4096:
                self._cache[needle] = hit
        return hit


def check(statements, inputs, constants) -> list[dict]:
    """statements: [(sql, stack)], inputs: [(location, param, value)] -> sql events."""
    events = []
    seen = set()
    for sql, stack in statements:
        tokens = None
        for location, param, value in inputs:
            for cand in variants(value):
                hit = None
                for i in _occurrences(sql, cand):
                    if tokens is None:
                        tokens = tokenize(sql)
                    reason = classify(sql, tokens, i, i + len(cand), constants)
                    if reason:
                        hit = reason
                        break
                if hit:
                    key = (sql, param, value)
                    if key not in seen:
                        seen.add(key)
                        events.append({"oracle": wire.ORACLE_SQL,
                                       "detail": {"statement": sql, "input": value, "param": param,
                                                  "location": location, "reason": hit},
                                       "stack": stack})
                    break
    return events


def variants(value: str):
    """The value as the app may have embedded it: raw, URL-decoded again, case-folded, stripped."""
    from urllib.parse import unquote, unquote_plus
    out = []
    for v in (value, unquote(value), unquote_plus(value), value.strip()):
        for w in (v, v.lower(), v.upper()):
            if len(w.strip()) >= 2 and w not in out:
                out.append(w)
    return out
