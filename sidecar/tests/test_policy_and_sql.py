"""Protected-path rule, file markers, docker-mode tracer, statement-log source, structure rule, learn mode."""
import asyncio
import json

import httpx
import pytest

from immune_contracts import wire
from sidecar import config as cfgmod
from sidecar import observer, strace
from sidecar.identity import Identity
from sidecar.learn import H_LEARN, learn_message, replay
from sidecar.observer import Observer
from sidecar.server import Sidecar
from sidecar.sqllog import Baseline, LogFollower, LogParser, fingerprint, structure_events
from sidecar.strace import Observation
from sidecar.tracer import docker_cmd


def window(o: Observer, *obs):
    o.begin()
    for x in obs:
        o.on_obs(x)
    return o.system_events(o.end())


def f(path, **kw):
    return Observation("file", 1, dict({"path": path, "realpath": path}, **kw))


# --- file / proc / net rules ------------------------------------------------------------------------------
def test_protected_rule_fires_only_on_protected_paths_and_counts_attempts():
    o = Observer([], protected=["/etc/shadow", "/root/*"])
    ev = window(o, f("/usr/share/grafana/public/x.js"), f("/root/.ssh/id_rsa"), f("/etc/shadow", result="EACCES"))
    assert [e["detail"] for e in ev] == [{"path": "/root/.ssh/id_rsa", "realpath": "/root/.ssh/id_rsa"},
                                         {"path": "/etc/shadow", "realpath": "/etc/shadow", "result": "EACCES"}]
    # default rule (allowed roots): everything outside fires, a failed open never does
    assert [e["detail"]["path"] for e in window(Observer(["/app"]), f("/app/a"), f("/etc/hostname"),
                                                f("/etc/shadow", result="EACCES"))] == ["/etc/hostname"]


def test_warmup_allowlist_applies_to_protected_paths():
    o = Observer([], protected=["/var/lib/grafana/grafana.db"])
    o.learning = True
    o.on_obs(f("/var/lib/grafana/grafana.db"))
    o.learning = False
    assert window(o, f("/var/lib/grafana/grafana.db")) == []


def test_exec_and_net_allowlists():
    o = Observer([], exec_allow=["/usr/bin/git"], net_allow=["*:53", "10.0.0.5:5432"])
    net = lambda a, p: Observation("net", 1, {"family": "AF_INET", "address": a, "port": p, "syscall": "connect"})
    ev = window(o, Observation("exec", 1, {"path": "/usr/bin/git", "argv": ["git", "log"]}),
                Observation("exec", 2, {"path": "/bin/sh", "argv": ["sh", "-c", "id"]}),
                net("10.0.0.2", 53), net("10.0.0.5", 5432), net("203.0.113.9", 4444))
    assert [(e["oracle"], e["detail"].get("path") or e["detail"]["address"]) for e in ev] == [
        ("proc", "/bin/sh"), ("net", "203.0.113.9")]


def test_background_is_learnt_but_not_right_after_a_request():
    o = Observer([], protected=["/etc/passwd", "/etc/shadow"], learn_background=True, quiet_s=1.0)
    o.on_obs(f("/etc/passwd"))                      # the app on its own, nothing in flight
    assert window(o, f("/etc/passwd")) == []
    o.on_obs(f("/etc/shadow"))                      # a late line of the request that just ended: not learnt
    assert len(window(o, f("/etc/shadow"))) == 1
    assert len(window(Observer([], protected=["/etc/passwd"]), f("/etc/passwd"))) == 1      # off by default


def test_failed_opens_are_observations_only_when_asked():
    sc = strace.Parser().feed('openat(AT_FDCWD</usr/share/grafana>, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)')
    assert strace.observe(sc) is None
    assert strace.observe(sc, attempts=True).detail == {"path": "/etc/shadow", "realpath": "/etc/shadow",
                                                        "result": "EACCES"}


# --- file markers -----------------------------------------------------------------------------------------
def test_markers_file_holds_owner_and_file_markers(tmp_path):
    p = tmp_path / "markers.json"
    p.write_text(json.dumps({"MKAAAAAAAAAA": 2, "MKBBBBBBBBBB": {"path": "/etc/grafana/grafana.ini", "what": "key"}}))
    assert Identity().markers({}, str(p)) == {"MKAAAAAAAAAA": 2}
    fm = observer.load_file_markers(str(p))
    assert fm == {"MKBBBBBBBBBB": {"path": "/etc/grafana/grafana.ini", "what": "key"}}
    cfg = cfgmod.from_dict({"app_port": 1, "protected_paths": ["/etc/shadow"], "prod_ignore": ["/etc/shadow"]})
    assert observer.from_config(cfg, fm).protected == ["/etc/shadow", "/etc/grafana/grafana.ini"]
    assert observer.from_config(cfg, fm, extra_allow=cfg.prod_ignore).protected == ["/etc/grafana/grafana.ini"]


def test_marker_in_response_merges_with_the_syscall_event():
    fm = {"MKBBBBBBBBBB": {"path": "/etc/grafana/grafana.ini"}}
    ini = {"oracle": "file", "detail": {"path": "../grafana.ini", "realpath": "/etc/grafana/grafana.ini"}, "stack": []}
    sh = {"oracle": "file", "detail": {"path": "/etc/shadow", "realpath": "/etc/shadow", "result": "EACCES"}, "stack": []}
    ev = observer.marker_events(fm, {}, b"secret_key = MKBBBBBBBBBB\n", [ini, sh])
    assert ev == [{"oracle": "file", "stack": [], "detail": {"path": "/etc/grafana/grafana.ini", "marker": "MKBBBBBBBBBB",
                                                           "realpath": "/etc/grafana/grafana.ini",
                                                           "observed": "response+syscall"}}, sh]
    assert observer.marker_events(fm, {}, b"MKBBBBBBBBBB", [])[0]["detail"]["observed"] == "response"
    assert observer.marker_events(fm, {}, b"nothing", [ini]) == [ini]


# --- docker mode ------------------------------------------------------------------------------------------
def test_docker_tracer_is_confined():
    cmd = docker_cmd("immune-lab-shadow", "immune-strace:1", "immune-lab-shadow-strace", "immune.lab=grafana")
    assert "--pid=container:immune-lab-shadow" in cmd and cmd[cmd.index("--network") + 1] == "none"
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL" and "--privileged" not in cmd
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--cap-add"] == ["SYS_PTRACE", "KILL"]
    assert cmd[-2:] == ["-p", "1"] and "-qq" not in cmd and "-f" in cmd


def test_config_keys():
    c = cfgmod.from_dict({"app_port": 3901, "mode": "docker", "container": "x", "learn_background": True,
                          "sql_log": {"cmd": "docker logs -f db", "dialect": "mysql"}, "sql_baseline": "/b.json"})
    assert (c.mode, c.container, c.sql_log_cmd, c.sql_dialect, c.sql_baseline) == (
        "docker", "x", "docker logs -f db", "mysql", "/b.json")
    assert cfgmod.load(None, env={"SQL_LOG_CMD": "tail -F q.log"}).sql_log_cmd == "tail -F q.log"


# --- statement log ----------------------------------------------------------------------------------------
def test_log_parsers():
    pg, out = LogParser("postgres"), []
    for line in ["1795286000.100 [77] LOG:  statement: SELECT 1",
                 "1795286000.200 [77] LOG:  execute <unnamed>: SELECT *",
                 "\tFROM users WHERE id = $1",
                 "1795286000.200 [77] DETAIL:  parameters: $1 = '5'",
                 "1795286000.300 [78] LOG:  checkpoint starting: time",
                 "1795286000.400 [77] ERROR:  syntax error at or near \"x\"",
                 "1795286000.400 [77] STATEMENT:  SELECT x x"]:
        out += pg.feed(line)
    out += pg.flush()
    assert out == [(False, "SELECT 1"), (False, "SELECT *\nFROM users WHERE id = $1"), (True, "SELECT x x")]
    my, out = LogParser("mysql"), []
    for line in ["2026-11-21T15:40:01.250000Z\t   12 Connect\troot@localhost on app using Socket",
                 "2026-11-21T15:40:01.500000Z\t   12 Query\tSELECT *",
                 "FROM users WHERE id = 5",
                 "2026-11-21T15:40:02.000000Z\t   12 Execute\tSELECT 2",
                 "2026-11-21T15:40:03.000000Z\t   12 Quit\t"]:
        out += my.feed(line)
    assert out == [(False, "SELECT *\nFROM users WHERE id = 5"), (False, "SELECT 2")]


def test_follower_feeds_the_observer_and_flushes_at_window_edges():
    o = Observer([])
    fol = LogFollower("true", "postgres", o.on_statement)
    fol.feed("1795286100.100 [1] LOG:  statement: DELETE FROM sessions WHERE expires < 17")    # scheduled job
    fol.flush()                                     # start of a request: it belongs to no request
    rec = o.begin()
    fol.feed("1795286100.500 [1] LOG:  statement: SELECT 1")
    fol.feed("1795286100.600 [1] ERROR:  syntax error")
    fol.feed("1795286100.600 [1] STATEMENT:  SELECT 'x")
    fol.flush()
    o.end()
    assert rec.statements == ["SELECT 1"] and [s for s, _ in rec.failed] == ["SELECT 'x"]
    assert o.take_background_sql() == ["DELETE FROM sessions WHERE expires < 17"] and o.take_background_sql() == []


# --- structure rule ---------------------------------------------------------------------------------------
@pytest.mark.parametrize("a,b,same", [
    ("SELECT name FROM items WHERE id = 5", "select name  from ITEMS where id = 912", True),
    ("SELECT * FROM u WHERE name = 'ana'", "SELECT * FROM u WHERE name = 'O''Brien'", True),
    ("SELECT * FROM u WHERE id = $1", "SELECT * FROM u WHERE id = 7", True),
    ("SELECT * FROM u WHERE id IN (1)", "SELECT * FROM u WHERE id IN (1, 2, 3, 4)", True),
    ("INSERT INTO t (a, b) VALUES (1, 'x')", "INSERT INTO t (a, b) VALUES (1, 'x'), (2, 'y'), (3, 'z')", True),
    ("SELECT * FROM u WHERE balance > -5", "SELECT * FROM u WHERE balance > 5", True),
    ("SELECT name FROM items WHERE id = 5", "SELECT name FROM items WHERE id = 5 AND 1=1", False),
    ("SELECT name FROM items WHERE id = 5", "SELECT name FROM items WHERE id = 5 AND SLEEP(5)", False),
    ("SELECT name FROM items WHERE id = 5", "SELECT name FROM items WHERE id = 5 -- x", False),
    ("SELECT name FROM items WHERE id = 5", "SELECT name FROM items WHERE id = 5 UNION SELECT pw FROM users", False),
    ("SELECT * FROM u WHERE name = 'a'", "SELECT * FROM u WHERE name = 'a' OR '1'='1'", False),
    ("SELECT * FROM u ORDER BY name", "SELECT * FROM u ORDER BY created", False),      # a different column is new
    ("SELECT a - 5 FROM t", "SELECT a FROM t", False),                                 # binary minus is kept
])
def test_fingerprint(a, b, same):
    assert (fingerprint(a) == fingerprint(b)) is same


def test_baseline_learns_flags_and_persists(tmp_path):
    path = str(tmp_path / "baseline.json")
    b = Baseline(path)
    legit = "SELECT name FROM items WHERE id = 5"
    second_order = "SELECT * FROM orders WHERE owner = 'bob' OR 1=1"        # the value came from the database
    assert structure_events(b, [second_order]) == []                        # rule off: nothing learnt yet
    assert b.add([fingerprint(legit), fingerprint("SELECT * FROM orders WHERE owner = 'ana'")], from_request=True) == 2
    ev = structure_events(b, [legit.replace("5", "77"), second_order, second_order])
    assert [(e["oracle"], e["detail"]["reason"]) for e in ev] == [("sql", "new_structure")]
    assert "or ? = ?" in ev[0]["detail"]["structure"] and ev[0]["stack"] == []
    assert structure_events(b, [second_order], skip={second_order}) == []   # already an event of the taint rule
    again = Baseline(path)
    assert again.ready and len(structure_events(again, [legit, second_order])) == 1


# --- the sidecar, end to end against a fake app (no tracer, statements fed like the log follower does) ------
Q = "SELECT name FROM items WHERE id = %s"


async def serve(statements_for, tmp_path=None, key="k"):
    """A sidecar in front of a fake app whose handler 'executes' statements_for(target) on the observer."""
    pushed = []

    async def app(r, w):
        line = (await r.readline()).decode()
        while (await r.readline()) not in (b"\r\n", b""):
            pass
        for s in statements_for(line.split()[1]):
            sc.obs.on_statement(s, True, None, "log")
        w.write(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")
        await w.drain()
        w.close()
    srv = await asyncio.start_server(app, "127.0.0.1", 0)
    cfg = cfgmod.from_dict({"app_port": srv.sockets[0].getsockname()[1], "grace_ms": 0})
    cfg.trace, cfg.clone_key, cfg.clone_id = False, key, "c1"
    sc = Sidecar(cfg)

    async def push(evidence):
        pushed.append(evidence)
    sc._push, cfg.collector_url = push, "http://collector"
    return sc, srv, pushed


async def call(sc, target: bytes, headers=()):
    path, _, query = target.partition(b"?")
    from urllib.parse import unquote
    status, out, body, _ = await sc.handle("GET", unquote(path.decode()), path, query,
                                           [(k.encode(), v.encode()) for k, v in headers], b"")
    return {k.decode(): v.decode() for k, v in out}


async def test_taint_fires_without_constants_only_on_multi_token_matches():
    sc, srv, pushed = await serve(lambda t: [Q % "5 AND 1=(SELECT 1 FROM pg_sleep(5))"] if "pg_sleep" in t
                                  else ["SELECT name FROM items WHERE kind = 'name'"])
    async with srv:
        h = await call(sc, b"/api/items?id=5%20AND%201%3D(SELECT%201%20FROM%20pg_sleep(5))")
        assert h[wire.H_VERDICT] == "oracle" and pushed[0]["events"][0]["detail"]["param"] == "id"
        # "name" equals an identifier the app wrote: without the app's constants that is not evidence
        assert (await call(sc, b"/api/items?kind=name"))[wire.H_VERDICT] == "clean" and len(pushed) == 1


async def test_learn_mode_needs_a_valid_signature_and_structure_rule_fires():
    novel = "SELECT * FROM audit WHERE actor = 'x' AND 1=1"
    for signed in (True, False):
        sc, srv, pushed = await serve(lambda t: [novel])
        sc.baseline.add([fingerprint("SELECT 1")], from_request=True)
        sig = wire.sign("k", learn_message("GET", b"/audit")) if signed else "0" * 64
        async with srv:
            h = await call(sc, b"/audit", [("x-imm-mode", "learn"), (H_LEARN, sig)])
        if signed:
            assert h[wire.H_VERDICT] == "clean" and h["x-imm-learnt"] == "1" and not pushed
            assert fingerprint(novel) in sc.baseline.known
        else:       # treated as a normal request: the unknown structure fires
            assert h[wire.H_VERDICT] == "oracle" and pushed[0]["events"][0]["detail"]["reason"] == "new_structure"


def test_learn_replays_only_clean_recordings():
    sent = []

    def app(req: httpx.Request):
        sent.append((req.method, req.extensions.get("target"), req.headers.get(wire.H_MODE),
                     wire.check("k", learn_message(req.method, req.extensions["target"]), req.headers.get(H_LEARN))))
        return httpx.Response(200, headers={"x-imm-learnt": "2"})
    base = {"method": "GET", "path": "/api/items", "query": "id=5", "headers": {"host": "x", "cookie": "sid=1"},
            "body_b64": "", "class": "clean", "reasons": [], "route": "prod", "status": 200}
    recs = [base, dict(base), dict(base, query="id=6", **{"class": "suspect"}, reasons=["grammar:query.id"]),
            dict(base, query="id=7", status=500), dict(base, query="id=8", route="clone")]
    out = replay("http://sc:1", "k", recs, httpx.Client(transport=httpx.MockTransport(app)))
    assert sent == [("GET", b"/api/items?id=5", "learn", True)]
    assert out == {"replayed": 1, "learnt": 2, "skipped": 4, "errors": 0}
