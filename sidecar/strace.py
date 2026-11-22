"""Parser for `strace -f -y -qq -e signal=none` output, and classification into oracle observations.

Line shapes handled (pid prefix is optional: strace omits it while it traces one task; with
``-o FILE`` the prefix is ``"12    "`` instead of ``"[pid  12] "``):

    [pid  12] openat(AT_FDCWD</usr>, "lib/x", O_RDONLY) = 17</usr/lib/x>
    [pid  12] openat(AT_FDCWD</usr>, "nope", O_RDONLY) = -1 ENOENT (No such file or directory)
    [pid  12] openat(AT_FDCWD</usr>, "x", O_RDONLY <unfinished ...>
    [pid  12] <... openat resumed>) = 3</usr/x>
    [pid  31] execve("/bin/sh", ["/bin/sh", "-c", "true"], 0xe856 /* 7 vars */) = 0
    [pid   1] connect(19<socket:[2246]>, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("10.9.9.9")}, 16) = -1 EINPROGRESS (...)

``Syscall`` is the raw parsed call; ``observe()`` turns it into an ``Observation``
(``file`` / ``exec`` / ``fork`` / ``net``) or None. Failed opens/execs are not observations.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

# "[pid  12] " on stderr; "12    " when writing to a file with -o
_PREFIX = re.compile(r"^(?:\[pid\s+(\d+)\]\s?|(\d+)\s+)")
_RESUMED = re.compile(r"^<\.\.\. ([A-Za-z0-9_]+) resumed>\s?")
_CALL = re.compile(r"^([A-Za-z0-9_]+)\(")
_UNFINISHED = " <unfinished ...>"
_RET = re.compile(r"^\s*=\s*(-?\d+|\?|0x[0-9a-f]+)(?:<(.*)>)?(?:\s+([A-Z][A-Z0-9_]+))?")
# `strace -k` frame, printed under the syscall: " > /app/bin(handler+0x22) [0x1168]"
_FRAME = re.compile(r"^(?P<path>.*?)(?:\((?P<sym>[^()]*)\))? ?\[0x(?P<addr>[0-9a-fA-F]+)\]\s*$")
_SYM = re.compile(r"^(?P<func>.*?)\+0x(?P<off>[0-9a-fA-F]+)$")


@dataclass
class Syscall:
    pid: int
    name: str
    args: list[str]
    ret: str            # raw text after '='
    retval: int | None  # None for '?'
    errno: str | None
    retpath: str | None  # fd decoration of the return value (-y), e.g. the opened file's path
    # Native call stack (``strace -k``), innermost first: (binary path, function, offset in function, address).
    # The frame lines arrive AFTER the syscall line, so this list is filled in place by Parser.feed and the
    # Observation built from the syscall shares it: read it when the event is built, not when it is observed.
    frames: list = field(default_factory=list)


@dataclass
class Observation:
    kind: str           # file | exec | fork | net
    pid: int
    detail: dict = field(default_factory=dict)
    frames: list = field(default_factory=list)   # shared with the Syscall (see above)


def unquote(s: str) -> str:
    """Decode a strace C string literal ("..." possibly followed by ... when truncated)."""
    s = s.strip()
    if s.endswith("..."):
        s = s[:-3]
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    out = bytearray()
    i, n = 0, len(s)
    simple = {"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, "a": 7, "b": 8, "\\": 92, '"': 34, "'": 39}
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            d = s[i + 1]
            if d == "x" and i + 3 < n + 1:
                h = s[i + 2:i + 4]
                try:
                    out.append(int(h, 16)); i += 4; continue
                except ValueError:
                    pass
            if d in "01234567":
                j = i + 1
                while j < n and j < i + 4 and s[j] in "01234567":
                    j += 1
                out.append(int(s[i + 1:j], 8) & 0xFF); i = j; continue
            if d in simple:
                out.append(simple[d]); i += 2; continue
            out += d.encode("utf-8", "surrogateescape"); i += 2; continue
        out += c.encode("utf-8", "surrogateescape")
        i += 1
    return out.decode("utf-8", "surrogateescape")


def split_call(text: str):
    """'name(a, b, c) = ret' -> (name, [args], ret_text) or None if the call is not closed."""
    m = _CALL.match(text)
    if not m:
        return None
    name = m.group(1)
    i = m.end()
    n = len(text)
    depth = 0
    args, cur = [], []
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1]); i += 2; continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c in "([{":
            depth += 1
        elif c == "<" and i > 0 and (text[i - 1].isalnum() or text[i - 1] in "_]"):
            depth += 1
        elif c in ")]}>":
            if depth == 0 and c == ")":
                args.append("".join(cur).strip())
                rest = text[i + 1:]
                if args == [""]:
                    args = []
                return name, args, rest
            if depth > 0:
                depth -= 1
        elif c == "," and depth == 0:
            args.append("".join(cur).strip()); cur = []; i += 1; continue
        cur.append(c)
        i += 1
    return None


def parse_frame(line: str):
    """' > /app/bin(handler+0x22) [0x1168]' -> ('/app/bin', 'handler', 0x22, 0x1168), or None for the lines
    strace -k prints that are not frames (' > No DWARF information found', unwinder errors)."""
    text = line.rstrip("\n")
    if not text.startswith(" > "):
        return None
    m = _FRAME.match(text[3:])
    if not m:
        return None
    func, off = m.group("sym") or "", 0
    sm = _SYM.match(func)
    if sm:
        func, off = sm.group("func"), int(sm.group("off"), 16)
    return (m.group("path"), func, off, int(m.group("addr"), 16))


def _fdpath(arg: str) -> str | None:
    """'AT_FDCWD</usr>' or '17</etc/x>' -> '/usr' / '/etc/x'."""
    k = arg.find("<")
    if k == -1 or not arg.endswith(">"):
        return None
    return arg[k + 1:-1]


class Parser:
    """Stateful: joins `<unfinished ...>` / `<... resumed>` pairs per pid."""

    def __init__(self, default_pid: int = 0):
        self.default_pid = default_pid
        self.pending: dict[int, str] = {}
        self.last: Syscall | None = None    # the call whose stack (strace -k) is being printed
        self.dropped = 0  # syscall lines that could not be turned into a Syscall (their observation is lost)

    def feed(self, line: str) -> Syscall | None:
        line = line.rstrip("\n")
        if not line:
            return None
        if line.startswith(" > "):
            # a frame of the stack of the syscall printed just before: attach it, it is not a syscall itself
            fr = parse_frame(line)
            if fr is not None and self.last is not None:
                self.last.frames.append(fr)
            return None
        pid = self.default_pid
        m = _PREFIX.match(line)
        if m:
            pid = int(m.group(1) or m.group(2))
            line = line[m.end():]
        if line.startswith(("---", "+++", "strace:")):
            return None
        r = _RESUMED.match(line)
        if r:
            head = self.pending.pop(pid, None)
            if head is None:
                self.dropped += 1  # resumed without the start (attached mid-call): unusable
                return None
            line = head + line[r.end():]
        if line.endswith(_UNFINISHED):
            self.pending[pid] = line[: -len(_UNFINISHED)]
            return None
        parts = split_call(line)
        if parts is None:
            self.dropped += 1
            return None
        name, args, rest = parts
        rm = _RET.match(rest)
        if not rm:
            self.dropped += 1
            return None
        raw = rm.group(1)
        retval = None if raw == "?" else int(raw, 16) if raw.startswith("0x") else int(raw)
        sc = Syscall(pid=pid, name=name, args=args, ret=rest.strip().lstrip("=").strip(),
                     retval=retval, errno=rm.group(3), retpath=rm.group(2))
        self.last = sc
        return sc


_SA_FAMILY = re.compile(r"sa_family=(AF_[A-Z0-9]+)")
_PORT = re.compile(r"sin6?_port=htons\((\d+)\)")
_ADDR4 = re.compile(r'inet_addr\("([^"]+)"\)')
_ADDR6 = re.compile(r'inet_pton\(AF_INET6, "([^"]+)"')
_SUN = re.compile(r'sun_path=(@?"(?:[^"\\]|\\.)*")')


def parse_sockaddr(text: str) -> dict | None:
    fm = _SA_FAMILY.search(text)
    if not fm:
        return None
    fam = fm.group(1)
    if fam in ("AF_INET", "AF_INET6"):
        pm = _PORT.search(text)
        am = (_ADDR4 if fam == "AF_INET" else _ADDR6).search(text)
        return {"family": fam, "address": am.group(1) if am else "", "port": int(pm.group(1)) if pm else 0}
    if fam == "AF_UNIX":
        sm = _SUN.search(text)
        p = sm.group(1) if sm else ""
        abstract = p.startswith("@")
        return {"family": fam, "address": ("@" if abstract else "") + unquote(p.lstrip("@")), "port": 0}
    return {"family": fam, "address": "", "port": 0}


_SOCK_PEER = re.compile(r"->\[?([0-9a-fA-F:.]+)\]?:(\d+)\]>?$")


def dns_qname(data: bytes) -> str | None:
    """The question name of a DNS query datagram (header 12 bytes, then length-prefixed labels), else None."""
    if len(data) < 13:
        return None
    labels, i = [], 12
    while i < len(data):
        n = data[i]
        if n == 0:
            break
        if n & 0xC0 or i + 1 + n > len(data):       # compression pointer / truncated: not a plain question
            return None
        labels.append(data[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(labels).lower() if labels else None


def _dns_send(sc: "Syscall") -> dict | None:
    """A sendto on a socket connected to a resolver (fd decoration ``<UDP:[a:p->10.0.0.2:53]>``): the destination
    comes from the decoration (the call carries no address) and the question name from the datagram."""
    if sc.name != "sendto" or len(sc.args) < 2:
        return None
    m = _SOCK_PEER.search(sc.args[0])
    if not m or m.group(2) != "53":
        return None
    q = dns_qname(unquote(sc.args[1]).encode("utf-8", "surrogateescape"))
    fam = "AF_INET6" if ":" in m.group(1) else "AF_INET"
    return {"family": fam, "address": m.group(1), "port": 53, **({"qname": q} if q else {})}


def is_loopback(addr: str) -> bool:
    a = addr.lower()
    return a.startswith("127.") or a in ("::1", "localhost") or a.startswith("::ffff:127.")


OPEN_CALLS = {"open": 0, "openat": 1, "openat2": 1, "creat": 0}
EXEC_CALLS = {"execve", "execveat"}
FORK_CALLS = {"fork", "vfork", "clone", "clone3"}
NET_CALLS = {"connect", "sendto", "sendmsg"}


def resolve(path: str, base: str | None) -> str:
    if not path.startswith("/") and base:
        path = posixpath.join(base, path)
    return posixpath.normpath(path) if path else path


def observe(sc: Syscall, cwd_of=None, attempts: bool = False) -> Observation | None:
    """Classify one syscall. ``cwd_of(pid)`` gives a fallback cwd for relative paths without -y.
    ``attempts``: failed opens are observations too (detail ``result`` = errno), for the protected-path rule,
    where trying to open the file is already the signal."""
    name = sc.name
    if name in OPEN_CALLS:
        failed = sc.retval is None or sc.retval < 0
        if failed and not (attempts and sc.errno):
            return None  # failed open: the app did not get the file
        idx = OPEN_CALLS[name]
        if len(sc.args) <= idx:
            return None
        raw = unquote(sc.args[idx])
        base = _fdpath(sc.args[0]) if idx == 1 else None
        if base is None and not raw.startswith("/") and cwd_of is not None:
            base = cwd_of(sc.pid)
        real = sc.retpath if sc.retpath and sc.retpath.startswith("/") else resolve(raw, base)
        if real.endswith(" (deleted)"):
            real = real[: -len(" (deleted)")]
        if failed:
            return Observation("file", sc.pid, {"path": raw, "realpath": real, "result": sc.errno}, sc.frames)
        return Observation("file", sc.pid, {"path": raw, "realpath": real}, sc.frames)
    if name in EXEC_CALLS:
        if sc.retval != 0:
            return None
        if name == "execve":
            path = unquote(sc.args[0]) if sc.args else ""
            argv_txt = sc.args[1] if len(sc.args) > 1 else ""
        else:
            path = unquote(sc.args[1]) if len(sc.args) > 1 else ""
            argv_txt = sc.args[2] if len(sc.args) > 2 else ""
        return Observation("exec", sc.pid, {"path": path, "argv": parse_argv(argv_txt)}, sc.frames)
    if name in FORK_CALLS:
        if sc.retval is None or sc.retval <= 0:
            return None
        if "CLONE_THREAD" in " ".join(sc.args):
            return None
        return Observation("fork", sc.pid, {"child": sc.retval, "syscall": name}, sc.frames)
    if name in NET_CALLS:
        if name == "connect":
            sa = parse_sockaddr(sc.args[1]) if len(sc.args) > 1 else None
        else:
            sa = parse_sockaddr(", ".join(sc.args[1:]))  # sendto dest / sendmsg msg_name; NULL -> None
        if sa is not None and sa.get("port") == 53 and name == "sendto" and len(sc.args) > 1:
            q = dns_qname(unquote(sc.args[1]).encode("utf-8", "surrogateescape"))
            if q:
                sa["qname"] = q
        if sa is None:
            sa = _dns_send(sc)          # connected UDP socket to a resolver: the datagram has the name
        if sa is None:
            return None
        # attempts count, even if they fail (the app tried to reach out)
        return Observation("net", sc.pid, {"syscall": name, **sa, "result": sc.ret}, sc.frames)
    return None


def parse_argv(txt: str) -> list[str]:
    txt = txt.strip()
    if not (txt.startswith("[") and "]" in txt):
        return []
    inner = txt[1:txt.rfind("]")]
    out, cur, in_str, i = [], [], False, 0
    while i < len(inner):
        c = inner[i]
        if in_str:
            cur.append(c)
            if c == "\\" and i + 1 < len(inner):
                cur.append(inner[i + 1]); i += 2; continue
            if c == '"':
                in_str = False
                out.append(unquote("".join(cur))); cur = []
        elif c == '"':
            in_str = True
            cur = ['"']
        i += 1
    return out
