"""Where in the app's code: native call stacks for the syscall-backed oracle events (file / proc / net).

The sidecar observes from outside the process, so its evidence used to carry ``stack: []``. With
``native_stack`` on, strace runs with ``-k`` and prints the call stack of every traced syscall; this module
turns those raw frames into the evidence ``stack`` the rest of the system already understands
(``[{file, line, func}, ...]``, outermost first, the innermost app frame last: ``stack[-1]`` is the sink, see
``pipeline/incident.py``). It is the compiled-language counterpart of ``phptrace.py`` (PHP, Xdebug).

What it does with a frame ``(binary, function, offset, address)``:

1. drops frames that are not the app's code: the C library, the dynamic loader, interpreters and VMs
   (python, node, php, java, ...), libc entry points and wrappers of a static binary, anything matching
   ``exclude``; with ``include`` set, only those paths are kept;
2. resolves ``file:line`` with ``addr2line`` when the binary has debug info (``-g``). strace reports the ELF
   file *offset*, not the virtual address, so the address is first mapped through the binary's PT_LOAD
   segments (PIE: identical; non-PIE and static: ``vaddr = offset + p_vaddr - p_offset``);
3. otherwise keeps the frame as ``{file: <binary>, line: 0, func}`` (a symbol table is enough for the
   function name; a stripped binary gives nothing and the event keeps ``stack: []``).

Never changes a verdict: any failure here yields a shorter or empty stack.
"""
from __future__ import annotations

import fnmatch
import logging
import os
import re
import struct
import subprocess

log = logging.getLogger("sidecar.nativestack")

# libraries and runtimes: frames inside them are not the app's code (the app frame that called them is the sink)
SYSTEM_LIBS = ("ld-*.so*", "ld-linux*", "ld-musl*", "libc.so*", "libc-*.so*", "libpthread*", "libm.so*",
               "libm-*", "libdl*", "librt*", "libresolv*", "libnss_*", "libstdc++*", "libgcc_s*", "libssl*",
               "libcrypto*", "libz.so*", "libcurl*", "libuv*", "libjvm*", "libpython*", "[vdso]", "[vsyscall]")
INTERPRETERS = ("python*", "node", "nodejs", "php", "php-*", "php7*", "php8*", "java", "ruby*", "perl*",
                "dotnet", "sh", "bash", "dash", "ash", "busybox")
# libc internals and entry points that show up under the app's own binary when it is statically linked
LIBC_NAMES = re.compile(r"^(?:_start|_dl_\w+|_IO_\w+|"
                        r"__\w+|"           # glibc internals: __libc_*, __GI_*, __internal_syscall_cancel, __open64...
                        r"(?:open|openat|open64|fopen|fopen64|creat|execve|execv|execvp|execl|execlp|system|"
                        r"popen|connect|sendto|sendmsg|getaddrinfo|posix_spawn\w*)(?:@\w+)?)$")
_DISCRIMINATOR = re.compile(r"\s*\(discriminator \d+\)\s*$")


def load_segments(path: str) -> list[tuple[int, int, int]]:
    """PT_LOAD segments of an ELF as (file offset, file size, virtual address); [] if not 64-bit little-endian."""
    try:
        with open(path, "rb") as f:
            hdr = f.read(64)
            if len(hdr) < 64 or hdr[:4] != b"\x7fELF" or hdr[4] != 2 or hdr[5] != 1:
                return []
            phoff = struct.unpack_from("<Q", hdr, 0x20)[0]
            phentsize, phnum = struct.unpack_from("<HH", hdr, 0x36)
            f.seek(phoff)
            data = f.read(phentsize * phnum)
    except OSError:
        return []
    segs = []
    for i in range(phnum):
        if (i + 1) * phentsize > len(data):
            break
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", data, i * phentsize)
        if p_type == 1:
            segs.append((p_offset, p_filesz, p_vaddr))
    return segs


def vaddr_of(segments, offset: int) -> int | None:
    """Virtual address of a file offset (what addr2line wants), None if no loaded segment holds it."""
    for off, size, vaddr in segments:
        if off <= offset < off + max(size, 1):
            return vaddr + (offset - off)
    return None


def run_addr2line(binary: str, path: str, vaddrs: list[int], timeout: float = 5.0) -> list[tuple[str, str, int]]:
    """One addr2line call for several addresses of one binary -> [(function, file, line)] ('' / 0 = unknown)."""
    cmd = [binary, "-e", path, "-f", "-C", "-a"] + [hex(a) for a in vaddrs]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return [("", "", 0)] * len(vaddrs)
    lines = out.splitlines()
    res = []
    for i in range(len(vaddrs)):
        chunk = lines[i * 3:i * 3 + 3]
        if len(chunk) < 3:
            res.append(("", "", 0))
            continue
        func, loc = chunk[1].strip(), _DISCRIMINATOR.sub("", chunk[2].strip())
        file, _, line = loc.rpartition(":")
        if not file or file.startswith("??") or not line.isdigit():
            res.append((func if func != "??" else "", "", 0))
        else:
            res.append((func if func != "??" else "", file, int(line)))
    return res


class Stacker:
    """raw frames (innermost first, as strace -k prints them) -> evidence stack (outermost first)."""

    def __init__(self, root=lambda: "/", include=(), exclude=(), path_map=None, addr2line: str = "addr2line",
                 max_frames: int = 24, runner=None):
        self.root = root                     # callable: where the sidecar sees the app's filesystem
        self.include = [p for p in include if p]
        self.exclude = [p for p in exclude if p]
        self.path_map = [(a, b) for a, b in (path_map or [])]
        self.addr2line = addr2line
        self.max_frames = max_frames
        self.runner = runner or run_addr2line
        self._segments: dict[str, list] = {}
        self._cache: dict[tuple, tuple] = {}

    @classmethod
    def from_config(cls, cfg: dict | bool | None, root=lambda: "/") -> "Stacker | None":
        if not cfg:
            return None
        c = {} if cfg is True else dict(cfg)
        if c.get("enabled") is False:
            return None
        return cls(root=root, include=c.get("include") or (), exclude=c.get("exclude") or (),
                   path_map=c.get("path_map"), addr2line=c.get("addr2line") or "addr2line",
                   max_frames=int(c.get("max_frames") or 24))

    # ---------------------------------------------------------------- filtering
    def _is_app(self, path: str) -> bool:
        if not path:
            return False
        base = os.path.basename(path)
        if self.include:
            return any(fnmatch.fnmatchcase(path, p) for p in self.include)
        if any(fnmatch.fnmatchcase(path, p) for p in self.exclude):
            return False
        return not any(fnmatch.fnmatchcase(base, p) for p in SYSTEM_LIBS + INTERPRETERS)

    def _real(self, path: str) -> str:
        root = self.root() or "/"
        return path if root == "/" else root.rstrip("/") + path

    def _mapped(self, file: str) -> str:
        for a, b in self.path_map:
            if file == a or file.startswith(a.rstrip("/") + "/"):
                return b.rstrip("/") + file[len(a.rstrip("/")):]
        return file

    # ---------------------------------------------------------------- resolution
    def _resolve(self, path: str, offsets: list[int]) -> dict[int, tuple[str, str, int]]:
        """{file offset: (function, source file, line)} for the offsets strace printed for one binary."""
        real = self._real(path)
        if real not in self._segments:
            self._segments[real] = load_segments(real)
        segs = self._segments[real]
        out, todo = {}, []
        for off in dict.fromkeys(offsets):
            hit = self._cache.get((real, off))
            if hit is not None:
                out[off] = hit
                continue
            va = vaddr_of(segs, off) if segs else None
            if va is not None:
                todo.append((off, va))
        if todo:
            try:
                got = self.runner(self.addr2line, real, [va for _o, va in todo])
            except Exception:   # noqa: BLE001 - no addr2line / it failed: the frames keep their function names
                log.warning("addr2line failed for %s; function names only", real)
                return out
            for (off, _va), r in zip(todo, got):
                self._cache[(real, off)] = r
                out[off] = r
        return out

    def __call__(self, frames) -> list[dict]:
        try:
            return self._stack(list(frames or ()))
        except Exception:   # noqa: BLE001 - evidence must never fail because of its call stack
            log.exception("native stack unavailable")
            return []

    def _stack(self, frames) -> list[dict]:
        app = [f for f in frames if self._is_app(f[0])]
        by_bin: dict[str, list] = {}
        for path, _func, _in_func, addr in app:
            by_bin.setdefault(path, []).append(addr)   # strace's [0x..] is the file offset
        resolved = {p: self._resolve(p, offs) for p, offs in by_bin.items()}
        # a binary with debug info for the app's code but not for the C library it links statically: there,
        # a frame that does not resolve to a source file is libc (``__internal_syscall_cancel``), not the app
        debug = {p for p, r in resolved.items() if any(v[1] for v in r.values())}
        out = []
        for path, func, _in_func, addr in app:       # innermost first
            fn, file, line = resolved.get(path, {}).get(addr, ("", "", 0))
            if file:
                out.append({"file": self._mapped(file), "line": line, "func": func or fn})
                continue
            name = func or fn
            if path in debug or not name or LIBC_NAMES.match(name):
                continue                              # no debug info: keep only named, non-libc frames
            out.append({"file": path, "line": 0, "func": name})
        out.reverse()                                 # outermost first, the innermost app frame (the sink) last
        return out[-self.max_frames:]
