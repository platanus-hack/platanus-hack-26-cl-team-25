"""Unit tests for the out-of-process file oracle and the incident builder (no docker needed)."""
from cve_replay.oracle import FileEscapeOracle, parse_opens, parse_execs
from cve_replay.incident import build_incident
from cve_replay.targets import TARGETS

ROOTS = ["/usr/local/apache2/htdocs", "/usr/local/apache2/cgi-bin"]

LEGIT = '\n'.join([
    '9 100.1 open("/usr/local/apache2/htdocs/index.html", O_RDONLY) = 4',
    '9 100.2 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 5',   # NSS at boot/legit
])
ATTACK = '\n'.join([
    '9 200.1 open("/etc/passwd", O_RDONLY) = 7',          # the traversal read
    '9 200.2 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)',
])


def test_parse_handles_open_and_openat():
    opens = parse_opens(LEGIT)
    assert [o.path for o in opens] == ["/usr/local/apache2/htdocs/index.html", "/etc/passwd"]
    assert all(o.ok for o in opens)


def test_failed_open_is_not_ok():
    opens = parse_opens(ATTACK)
    assert opens[0].ok is True and opens[1].ok is False


def test_oracle_fires_on_escape_outside_roots():
    orc = FileEscapeOracle(ROOTS)
    events = orc.check(ATTACK)
    # only the successful out-of-roots open fires; the EACCES one does not
    assert [e["detail"]["opened"] for e in events] == ["/etc/passwd"]


def test_oracle_does_not_fire_inside_roots():
    orc = FileEscapeOracle(ROOTS)
    assert orc.check('9 1.0 open("/usr/local/apache2/htdocs/a.html", O_RDONLY) = 4') == []


def test_prewarm_suppresses_legit_requests_not_the_attack():
    # a file a legit request opens outside roots must be suppressed; /etc/passwd here is ONLY
    # in the attack window, so it still fires (mirrors the real detect windowing).
    orc = FileEscapeOracle(ROOTS)
    orc.prewarm('9 1.0 open("/var/log/apache/other.log", O_RDONLY) = 4')
    assert orc.check('9 2.0 open("/var/log/apache/other.log", O_RDONLY) = 4') == []
    assert [e["detail"]["opened"] for e in orc.check(ATTACK)] == ["/etc/passwd"]


def test_incident_shape_is_generic():
    t = TARGETS["apache-2.4.49"]
    events = [{"oracle": "file", "detail": {"opened": "/etc/passwd", "outside_roots": True}}]
    inc = build_incident(t, {"method": "GET", "path": t.poc_path, "status": 200}, events)
    assert inc["lang"] == "c"
    assert inc["vuln_class"] == "traversal"
    assert inc["editable_files"] == ["server/util.c"]
    assert inc["app_subdirs"] == ["server", "include", "os"]


def test_prompt_never_reveals_the_cve_or_project():
    # The core defensibility claim: the model only sees runtime evidence, never the CVE/project.
    from patcher import core
    t = TARGETS["apache-2.4.49"]
    events = [{"oracle": "file", "detail": {"opened": "/etc/passwd", "outside_roots": True}}]
    inc = build_incident(t, {"method": "GET", "path": t.poc_path, "status": 200}, events)
    prompt = core.render_prompt(inc, feedback=None, attempt=1, editable=["server/util.c"]).lower()
    for term in ("apache", "httpd", "cve", "41773", "2.4.49"):
        assert term not in prompt, f"prompt leaks {term!r}"
