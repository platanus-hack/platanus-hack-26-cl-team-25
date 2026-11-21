"""String literals of the app's own source code, for rule 3 of shadow.sqltaint (an input that is a
verbatim part of a constant the app wrote, e.g. ``notes`` in ``"... FROM notes"``, is not an injection).

Language-agnostic and approximate: '...', "..." and `...` literals (static parts of JS template
literals / Python f-strings split at ``${``/``{``), from text files under the configured source dirs.
"""
from __future__ import annotations

import os
import re

from shadow import sqltaint

EXTS = {".js", ".mjs", ".cjs", ".ts", ".go", ".rs", ".java", ".kt", ".cs", ".py", ".rb", ".php", ".c", ".h",
        ".cpp", ".cc", ".scala", ".ex", ".exs", ".sql"}
SKIP_DIRS = {"node_modules", ".git", "vendor", "target", "dist", "build", "__pycache__", "bin", "obj"}
MAX_FILE = 1 << 20
MAX_FILES = 5000

_LIT = re.compile(r'"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'|`((?:[^`\\]|\\.)*)`', re.S)
_INTERP = re.compile(r"\$\{[^}]*\}|#\{[^}]*\}")


def _unescape(s: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r"}.get(m.group(1), m.group(1)), s)


def literals(text: str) -> list[str]:
    out = []
    for m in _LIT.finditer(text):
        s = m.group(1) if m.group(1) is not None else m.group(2) if m.group(2) is not None else m.group(3)
        for part in _INTERP.split(s):
            part = _unescape(part)
            if len(part) >= 2:
                out.append(part)
    return out


_PRINTABLE = re.compile(rb"[\x20-\x7e\t\n]{4,}")
_PRINTF = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t|L)?[sdiufFeEgGxXoc]")


def binary_literals(path: str, max_bytes: int) -> list[str]:
    """Printable runs of an executable (compiled apps keep their SQL text in .rodata). printf-style
    specifiers split a string like template interpolation does; ``%%`` becomes ``%``."""
    try:
        if os.path.getsize(path) > max_bytes:
            return []
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    out = []
    for m in _PRINTABLE.finditer(data):
        s = m.group().decode("ascii")
        for part in _PRINTF.split(s):
            part = part.replace("%%", "%")
            if len(part) >= 2:
                out.append(part)
    return out


def scan(root: str, dirs: list[str], executables: list[str] = (), max_exe_bytes: int = 32 << 20) -> sqltaint.Constants:
    strings, count = [], 0
    seen_exe = set()
    for exe in executables:
        try:
            key = (os.stat(exe).st_dev, os.stat(exe).st_ino)
        except OSError:
            continue
        if key not in seen_exe:
            seen_exe.add(key)
            strings += binary_literals(exe, max_exe_bytes)
    for d in dirs:
        base = os.path.join(root, d.lstrip("/")) if root not in ("", "/") else d
        for dp, dns, fns in os.walk(base):
            dns[:] = [x for x in dns if x not in SKIP_DIRS and not x.startswith(".")]
            for fn in fns:
                if os.path.splitext(fn)[1] not in EXTS:
                    continue
                p = os.path.join(dp, fn)
                try:
                    if os.path.getsize(p) > MAX_FILE:
                        continue
                    with open(p, encoding="utf-8", errors="replace") as f:
                        strings += literals(f.read())
                except OSError:
                    continue
                count += 1
                if count >= MAX_FILES:
                    return sqltaint.Constants(strings)
    return sqltaint.Constants(strings)
