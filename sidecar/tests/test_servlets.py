"""Entry point of a request in a Java servlet app, from web.xml and the compiled class (sidecar/servlets.py)."""
import os
import struct

import pytest

from sidecar import servlets

WEB_XML = """<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="2.5">
  <servlet><servlet-name>recv</servlet-name><servlet-class>com.acme.web.ReceiverServlet</servlet-class></servlet>
  <servlet><servlet-name>api</servlet-name><servlet-class>com.acme.web.ApiServlet</servlet-class></servlet>
  <servlet><servlet-name>pages</servlet-name><servlet-class>com.acme.web.PageServlet</servlet-class></servlet>
  <servlet><servlet-name>lib</servlet-name><servlet-class>org.vendor.DispatcherServlet</servlet-class></servlet>
  <servlet-mapping><servlet-name>recv</servlet-name><url-pattern>/receiver</url-pattern></servlet-mapping>
  <servlet-mapping><servlet-name>api</servlet-name><url-pattern>/api/*</url-pattern></servlet-mapping>
  <servlet-mapping><servlet-name>pages</servlet-name><url-pattern>*.htm</url-pattern></servlet-mapping>
  <servlet-mapping><servlet-name>lib</servlet-name><url-pattern>/</url-pattern></servlet-mapping>
</web-app>
"""


def make_class(source, methods, pkg_class="com/acme/web/Foo"):
    """A minimal valid .class: constant pool, the given methods ({name: [source lines] or None for no
    LineNumberTable}) each with a Code attribute, and a SourceFile attribute."""
    pool = []

    def utf8(s):
        b = s.encode()
        pool.append(b"\x01" + struct.pack(">H", len(b)) + b)
        return len(pool)

    def klass(name_idx):
        pool.append(b"\x07" + struct.pack(">H", name_idx))
        return len(pool)

    this_idx = klass(utf8(pkg_class))
    code_attr, lnt, sf, src = utf8("Code"), utf8("LineNumberTable"), utf8("SourceFile"), utf8(source)
    blobs = []
    for name, lines in methods.items():
        name_i, desc_i = utf8(name), utf8("()V")
        code = b"\xb1"
        inner = b""
        if lines is not None:
            table = struct.pack(">H", len(lines)) + b"".join(struct.pack(">HH", i, ln) for i, ln in enumerate(lines))
            inner = struct.pack(">HI", lnt, len(table)) + table
        body = (struct.pack(">HHI", 1, 1, len(code)) + code + struct.pack(">H", 0)
                + struct.pack(">H", 1 if lines is not None else 0) + inner)
        blobs.append(struct.pack(">HHHH", 1, name_i, desc_i, 1) + struct.pack(">HI", code_attr, len(body)) + body)
    out = struct.pack(">IHH", 0xCAFEBABE, 0, 52) + struct.pack(">H", len(pool) + 1) + b"".join(pool)
    out += struct.pack(">HHHH", 0x21, this_idx, 0, 0)                         # access, this, super, interfaces
    out += struct.pack(">H", 0)                                               # fields
    out += struct.pack(">H", len(blobs)) + b"".join(blobs)
    out += struct.pack(">H", 1) + struct.pack(">HI", sf, 2) + struct.pack(">H", src)
    return out


# ------------------------------------------------------------------ url -> servlet class
def smap():
    return servlets.ServletMap.from_web_xml(WEB_XML)


def test_exact_prefix_extension_and_default_matching():
    m = smap()
    assert m.resolve("/receiver") == "com.acme.web.ReceiverServlet"                  # exact
    assert m.resolve("/api") == "com.acme.web.ApiServlet"                            # /api/* matches /api itself
    assert m.resolve("/api/v1/users") == "com.acme.web.ApiServlet"                   # longest prefix
    assert m.resolve("/pages/home.htm") == "com.acme.web.PageServlet"                # extension
    assert m.resolve("/other/thing") == "org.vendor.DispatcherServlet"               # the default servlet "/"
    assert m.resolve("/receiver?x=1;jsessionid=abc") == "com.acme.web.ReceiverServlet"


def test_precedence_exact_over_prefix_over_extension():
    xml = ("<web-app><servlet><servlet-name>a</servlet-name><servlet-class>A</servlet-class></servlet>"
           "<servlet><servlet-name>b</servlet-name><servlet-class>B</servlet-class></servlet>"
           "<servlet><servlet-name>c</servlet-name><servlet-class>C</servlet-class></servlet>"
           "<servlet-mapping><servlet-name>a</servlet-name><url-pattern>/x/y.htm</url-pattern></servlet-mapping>"
           "<servlet-mapping><servlet-name>b</servlet-name><url-pattern>/x/*</url-pattern></servlet-mapping>"
           "<servlet-mapping><servlet-name>c</servlet-name><url-pattern>*.htm</url-pattern></servlet-mapping></web-app>")
    m = servlets.ServletMap.from_web_xml(xml)
    assert m.resolve("/x/y.htm") == "A" and m.resolve("/x/z.htm") == "B" and m.resolve("/q.htm") == "C"


def test_no_match_and_no_namespace():
    xml = ("<web-app><servlet><servlet-name>a</servlet-name><servlet-class>A</servlet-class></servlet>"
           "<servlet-mapping><servlet-name>a</servlet-name><url-pattern>/only</url-pattern></servlet-mapping></web-app>")
    m = servlets.ServletMap.from_web_xml(xml)
    assert m.resolve("/only") == "A" and m.resolve("/nothing") is None


def test_a_web_xml_that_declares_entities_is_refused():
    with pytest.raises(ValueError):
        servlets.ServletMap.from_web_xml('<!DOCTYPE x [<!ENTITY a "b">]><web-app/>')


# ------------------------------------------------------------------ class file
def test_class_info_reads_source_file_and_the_first_line_of_each_method():
    info = servlets.class_info(make_class("ReceiverServlet.java", {"doGet": [79, 80], "doPost": [84, 85, 90], "bare": None}))
    assert info["source"] == "ReceiverServlet.java"
    assert info["methods"] == {"doGet": 79, "doPost": 84}                           # no table -> absent


def test_class_info_rejects_garbage():
    with pytest.raises(ValueError):
        servlets.class_info(b"not a class file at all")


# ------------------------------------------------------------------ the evidence stack
@pytest.fixture
def index(tmp_path):
    cdir = tmp_path / "classes" / "com" / "acme" / "web"
    cdir.mkdir(parents=True)
    (cdir / "ReceiverServlet.class").write_bytes(make_class("ReceiverServlet.java", {"doGet": [79], "doPost": [84], "doImpl": [89]}))
    (cdir / "ApiServlet.class").write_bytes(make_class("ApiServlet.java", {"service": [20]}))
    (cdir / "PageServlet.class").write_bytes(make_class("PageServlet.java", {"doGet": [10]}))
    (tmp_path / "web.xml").write_text(WEB_XML)
    return servlets.ServletIndex.load(str(tmp_path / "web.xml"), str(tmp_path / "classes"), context="/App")


def test_stack_names_the_servlet_and_its_http_entry_method(index):
    assert index.stack("GET", "/App/receiver?a=1") == [
        {"file": "src/com/acme/web/ReceiverServlet.java", "line": 79, "func": "doGet"}]
    assert index.stack("POST", "/App/receiver") == [
        {"file": "src/com/acme/web/ReceiverServlet.java", "line": 84, "func": "doPost"}]


def test_a_method_the_servlet_does_not_override_falls_back(index):
    assert index.stack("DELETE", "/App/api/x")[0]["func"] == "service"              # only service() is defined
    assert index.stack("HEAD", "/App/pages/a.htm")[0]["func"] == "doGet"             # HEAD runs doGet
    assert index.stack("PUT", "/App/pages/a.htm") == [
        {"file": "src/com/acme/web/PageServlet.java", "line": 1, "func": "doPut"}]   # no such method: the class, line 1


def test_a_librarys_servlet_is_not_the_apps_code(index):
    assert index.stack("GET", "/App/anything/else") == []                            # DispatcherServlet is in a jar
    assert index.stack("GET", "/App/zzz") == []


def test_context_is_optional_and_src_root_configurable(tmp_path, index):
    plain = servlets.ServletIndex(index.servlets, index.classes_dir, context="", src_root="app/src/main/java")
    assert plain.stack("GET", "/receiver")[0]["file"] == "app/src/main/java/com/acme/web/ReceiverServlet.java"


def test_load_failures_are_not_fatal(tmp_path):
    assert servlets.ServletIndex.load(str(tmp_path / "missing.xml"), str(tmp_path)) is None
    (tmp_path / "bad.xml").write_text("<web-app><oops")
    assert servlets.ServletIndex.load(str(tmp_path / "bad.xml"), str(tmp_path)) is None


def test_a_corrupt_class_gives_no_stack_instead_of_an_error(tmp_path):
    cdir = tmp_path / "classes" / "com" / "acme" / "web"
    cdir.mkdir(parents=True)
    (cdir / "ReceiverServlet.class").write_bytes(b"\xca\xfe\xba\xbe truncated")
    (tmp_path / "web.xml").write_text(WEB_XML)
    idx = servlets.ServletIndex.load(str(tmp_path / "web.xml"), str(tmp_path / "classes"))
    assert idx.stack("GET", "/receiver") == []


REAL = os.environ.get("SCADABR_WEBINF", "")   # an extracted ScadaBR 1.2 WEB-INF (web.xml + classes/): manual check


@pytest.mark.skipif(not os.path.isfile(os.path.join(REAL, "web.xml")), reason="set SCADABR_WEBINF to check against ScadaBR")
def test_real_scadabr_artifacts():
    idx = servlets.ServletIndex.load(os.path.join(REAL, "web.xml"), os.path.join(REAL, "classes"), context="/ScadaBR")
    assert idx.stack("POST", "/ScadaBR/httpds") == [
        {"file": "src/com/serotonin/mango/web/servlet/HttpDataSourceServlet.java", "line": 84, "func": "doPost"}]
