"""Where in the app's code, for Java servlet apps (Tomcat), without instrumenting the JVM.

strace -k is useless for a JVM (its frames are the VM's, not the app's). What is deterministic from outside is
the *entry point* of a request: the deployment descriptor (``WEB-INF/web.xml``) says which servlet class serves
each URL, and the compiled class carries the line table of its methods. So for a request ``POST /ScadaBR/httpds``:

    web.xml            /httpds -> com.serotonin.mango.web.servlet.HttpDataSourceServlet
    HttpDataSourceServlet.class   SourceFile + LineNumberTable of doPost
    =>  [{file: src/com/serotonin/mango/web/servlet/HttpDataSourceServlet.java, line: <doPost>, func: doPost}]

This is a static resolution, not a runtime stack: it names the servlet that handled the request and its HTTP entry
method, which is the file the fix belongs in for the common case of a handler that does the work itself, and it
lets the patch stage start from the live evidence instead of a hand-written sink. It never changes a verdict.
"""
from __future__ import annotations

import logging
import os
import struct
import xml.etree.ElementTree as ET

log = logging.getLogger("sidecar.servlets")

MAX_XML = 4 << 20
HTTP_METHODS = {"GET": "doGet", "HEAD": "doHead", "POST": "doPost", "PUT": "doPut", "DELETE": "doDelete",
                "OPTIONS": "doOptions", "TRACE": "doTrace"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(el) -> str:
    return (el.text or "").strip()


class ServletMap:
    """servlet-name -> class and url-pattern -> servlet-name, with the matching rules of Servlet spec 12.1."""

    def __init__(self, classes: dict, mappings: list):
        self.classes = classes
        self.mappings = mappings            # [(url-pattern, servlet-name)]

    @classmethod
    def from_web_xml(cls, text: str) -> "ServletMap":
        if len(text) > MAX_XML or "<!ENTITY" in text:
            raise ValueError("web.xml too large or declaring entities")
        root = ET.fromstring(text)
        classes, mappings = {}, []
        for el in root:
            kind = _local(el.tag)
            if kind == "servlet":
                name = klass = ""
                for c in el:
                    if _local(c.tag) == "servlet-name":
                        name = _text(c)
                    elif _local(c.tag) == "servlet-class":
                        klass = _text(c)
                if name and klass:
                    classes[name] = klass
            elif kind == "servlet-mapping":
                name, pats = "", []
                for c in el:
                    if _local(c.tag) == "servlet-name":
                        name = _text(c)
                    elif _local(c.tag) == "url-pattern":
                        pats.append(_text(c))
                mappings += [(p, name) for p in pats if name]
        return cls(classes, mappings)

    def resolve(self, path: str) -> str | None:
        """The servlet class for a context-relative path: exact match, longest /* prefix, *.ext, default."""
        path = path.split("?", 1)[0].split(";", 1)[0] or "/"
        for pat, name in self.mappings:
            if pat == path and pat != "/" and not pat.endswith("/*") and not pat.startswith("*."):
                return self.classes.get(name)
        best = None
        for pat, name in self.mappings:
            if pat.endswith("/*"):
                pre = pat[:-2]
                if (path == pre or path.startswith(pre + "/")) and (best is None or len(pre) > len(best[0])):
                    best = (pre, name)
        if best:
            return self.classes.get(best[1])
        last = path.rsplit("/", 1)[-1]
        if "." in last:
            ext = "*." + last.rsplit(".", 1)[1]
            for pat, name in self.mappings:
                if pat == ext:
                    return self.classes.get(name)
        for pat, name in self.mappings:
            if pat == "/":
                return self.classes.get(name)
        return None


class _Cursor:
    def __init__(self, data: bytes):
        self.d, self.p = data, 0

    def u1(self):
        v = self.d[self.p]; self.p += 1; return v

    def u2(self):
        v = struct.unpack_from(">H", self.d, self.p)[0]; self.p += 2; return v

    def u4(self):
        v = struct.unpack_from(">I", self.d, self.p)[0]; self.p += 4; return v

    def skip(self, n):
        self.p += n


def class_info(data: bytes) -> dict:
    """{"source": SourceFile attribute or None, "methods": {name: first source line}} of a .class file.
    Methods without a LineNumberTable (compiled with -g:none) are absent."""
    c = _Cursor(data)
    if c.u4() != 0xCAFEBABE:
        raise ValueError("not a class file")
    c.skip(4)                                               # minor, major
    n = c.u2()
    pool, i = [None] * n, 1
    while i < n:
        tag = c.u1()
        if tag == 1:                                        # Utf8
            ln = c.u2()
            pool[i] = c.d[c.p:c.p + ln].decode("utf-8", "replace")
            c.skip(ln)
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            c.skip(4)
        elif tag in (5, 6):                                 # long, double take two slots
            c.skip(8)
            i += 1
        elif tag in (7, 8, 16, 19, 20):
            c.skip(2)
        elif tag == 15:
            c.skip(3)
        else:
            raise ValueError("unknown constant pool tag %d" % tag)
        i += 1
    c.skip(6)                                               # access, this, super
    c.skip(2 * c.u2())                                      # interfaces
    for _ in range(c.u2()):                                 # fields: access, name, descriptor, attributes
        c.skip(6)
        for _ in range(c.u2()):
            c.skip(2)
            c.skip(c.u4())
    methods: dict[str, int] = {}
    for _ in range(c.u2()):
        c.skip(2)
        name = pool[c.u2()] or ""
        c.skip(2)
        for _ in range(c.u2()):
            attr, alen = pool[c.u2()], c.u4()
            end = c.p + alen
            if attr == "Code":
                c.skip(4)                                   # max_stack, max_locals
                c.skip(c.u4())                              # bytecode
                c.skip(8 * c.u2())                          # exception table
                for _ in range(c.u2()):
                    cattr, clen = pool[c.u2()], c.u4()
                    cend = c.p + clen
                    if cattr == "LineNumberTable":
                        lines = []
                        for _ in range(c.u2()):
                            c.skip(2)
                            lines.append(c.u2())
                        if lines:
                            methods[name] = min(methods.get(name, 1 << 30), min(lines))
                    c.p = cend
            c.p = end
    source = None
    for _ in range(c.u2()):
        attr, alen = pool[c.u2()], c.u4()
        end = c.p + alen
        if attr == "SourceFile":
            source = pool[c.u2()]
        c.p = end
    return {"source": source, "methods": methods}


class ServletIndex:
    """(HTTP method, request path) -> evidence stack naming the servlet that handled it."""

    def __init__(self, servlets: ServletMap, classes_dir: str, context: str = "", src_root: str = "src"):
        self.servlets, self.classes_dir = servlets, classes_dir
        self.context = "/" + context.strip("/") if context.strip("/") else ""
        self.src_root = src_root.strip("/")
        self._info: dict[str, dict | None] = {}

    @classmethod
    def load(cls, web_xml: str, classes_dir: str, context: str = "", src_root: str = "src") -> "ServletIndex | None":
        try:
            with open(web_xml, encoding="utf-8", errors="replace") as f:
                return cls(ServletMap.from_web_xml(f.read()), classes_dir, context, src_root)
        except (OSError, ValueError, ET.ParseError) as e:
            log.warning("servlet index unavailable (%s): %r", web_xml, e)
            return None

    def _class_info(self, klass: str) -> dict | None:
        if klass not in self._info:
            try:
                with open(os.path.join(self.classes_dir, *klass.split(".")) + ".class", "rb") as f:
                    self._info[klass] = class_info(f.read())
            except (OSError, ValueError, struct.error, IndexError):
                self._info[klass] = None
        return self._info[klass]

    def stack(self, method: str, path: str) -> list[dict]:
        try:
            rel = path.split("?", 1)[0]
            if self.context and (rel == self.context or rel.startswith(self.context + "/")):
                rel = rel[len(self.context):] or "/"
            klass = self.servlets.resolve(rel)
            if not klass:
                return []
            pkg, _, simple = klass.rpartition(".")
            info = self._class_info(klass)
            if info is None:        # not in WEB-INF/classes: a library's servlet (Spring, DWR...), not the app's code
                return []
            source = info["source"] or (simple.split("$")[0] + ".java")
            wanted = HTTP_METHODS.get(method.upper(), "service")
            lines = info["methods"]
            func = next((m for m in (wanted, "doGet" if wanted == "doHead" else "", "service") if m in lines), wanted)
            file = "/".join(p for p in (self.src_root, pkg.replace(".", "/"), source) if p)
            return [{"file": file, "line": int(lines.get(func, 1)), "func": func}]
        except Exception:   # noqa: BLE001 - evidence must never fail because of its entry point
            log.exception("servlet entry point unavailable")
            return []
