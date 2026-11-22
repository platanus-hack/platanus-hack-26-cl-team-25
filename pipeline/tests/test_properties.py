"""The positive properties of the three classes (pipeline/properties.py) and the poc gate, against a fake
runner: one adequate fix per class passes, inadequate ones (a blacklist of the captured payload, the feature
removed, ...) fail, and a check that would compare nothing fails closed. No app code, no containers."""
import types
from urllib.parse import parse_qsl

import pytest

from pipeline import gates, properties
from pipeline.properties import norm_sql

ROOT = "/app/static/manuals"


# ------------------------------------------------------------------ norm_sql
def test_norm_sql_keeps_structure_and_drops_values():
    a = norm_sql("select id, name from products where name LIKE '%abc%' and price > 10")
    b = norm_sql("SELECT id,name\n  FROM products WHERE name LIKE '%usb hub%' AND price > 99")
    assert a == b == "SELECT id , name FROM products WHERE name LIKE ? AND price > ?"
    assert norm_sql("SELECT 1 WHERE a = ?") == norm_sql("SELECT 1 WHERE a = 'x'")           # bound or literal: a value


def test_norm_sql_shows_injected_structure():
    base = norm_sql("SELECT id FROM users WHERE email = 'a@b' AND password_hash = 'h'")
    assert norm_sql("SELECT id FROM users WHERE email = 'x' OR '1'='1' AND password_hash = 'h'") != base
    cut = norm_sql("SELECT id FROM users WHERE email = 'admin' --' AND password_hash = 'h'")
    assert cut != base and cut.endswith("COMMENT")
    assert norm_sql("SELECT id FROM t WHERE a = 'x' UNION SELECT NULL") != norm_sql("SELECT id FROM t WHERE a = 'x'")


# ------------------------------------------------------------------ sqli
SQLI = {"vuln_class": "sqli", "method": "GET", "route": "/api/products", "param": {"in": "query", "name": "q"},
        "request": {"method": "GET", "path": "/api/products", "query": "q=zz%27%20OR%20%271%27%3D%271", "headers": {}}}
SQLI_POC = {"requests": [dict(SQLI["request"], uid=None, role=None)]}
PAYLOAD = "zz' OR '1'='1"
AUTH_STMT = {"sql": "SELECT id FROM sessions WHERE token = ?", "params": ["t"]}


class PlainV:
    """v.run for `plain` jobs: app(release, value) -> (status, [executed statements])."""
    def __init__(self, app, param="q"):
        self.app, self.param, self.cache, self.jobs = app, param, {}, []

    def run(self, release, job):
        self.jobs.append((release, job))
        out = []
        for rq in job["requests"]:
            status, sql = self.app(release, dict(parse_qsl(rq["query"], keep_blank_values=True)).get(self.param))
            out.append({"name": rq["name"], "status": status, "sql": sql, "opens": []})
        return {"results": out, "roots": []}


def concatenated(release, q):
    return 200, [{"sql": "SELECT id FROM products WHERE name LIKE '%" + q + "%'", "params": []}]


def parameterised(release, q):
    return 200, [{"sql": "SELECT id FROM products WHERE name LIKE ?", "params": ["%" + q + "%"]}]


def blacklist_payload(release, q):          # only the captured value is refused
    return (400, []) if q == PAYLOAD else concatenated(release, q)


def reject_quotes(release, q):              # correct statement, but an apostrophe is refused
    return (400, []) if "'" in q else parameterised(release, q)


def strip_quotes(release, q):
    return parameterised(release, q.replace("'", ""))


def endpoint_removed(release, q):
    return 404, []


def ignores_the_parameter(release, q):      # the query no longer filters: every input "passes" trivially
    return 200, [AUTH_STMT, {"sql": "SELECT id FROM products", "params": []}]


def crashes_on_backslash(release, q):
    return (500, []) if q == "\\" else parameterised(release, q)


def test_sqli_adequate_fix_passes():
    v = PlainV(parameterised)
    ok, detail = properties.check(v, SQLI, SQLI_POC, "base", "patched")
    assert ok and "identical for %d metacharacter inputs" % len(properties.SQL_META) in detail and "O'Brien" in detail
    assert [r for r, _j in v.jobs] == ["patched"]                    # the property is judged on the patched release


@pytest.mark.parametrize("app,why", [
    (concatenated, "changed the query structure"),
    (blacklist_payload, "changed the query structure"),
    (reject_quotes, "handled differently"),
    (strip_quotes, "does not reach the database intact"),
    (endpoint_removed, "executes no SQL statement"),
    (ignores_the_parameter, "never reaches an executed statement"),
    (crashes_on_backslash, "server error 500"),
], ids=lambda x: getattr(x, "__name__", None))
def test_sqli_inadequate_fixes_fail(app, why):
    ok, detail = properties.check(PlainV(app), SQLI, SQLI_POC, "base", "patched")
    assert not ok and why in detail, detail


def test_sqli_without_a_parameter_fails_closed():
    ok, detail = properties.check(PlainV(parameterised), dict(SQLI, param=None), SQLI_POC, "base", "patched")
    assert not ok and "no injectable parameter" in detail


def test_unknown_class_fails_closed():
    ok, detail = properties.check(PlainV(parameterised), dict(SQLI, vuln_class="other"), SQLI_POC, "base", "patched")
    assert not ok and "no positive property" in detail


# ------------------------------------------------------------------ traversal
TRAV = {"vuln_class": "traversal", "method": "GET", "route": "/api/files/download", "param": {"in": "query", "name": "name"},
        "request": {"method": "GET", "path": "/api/files/download", "query": "name=..%2F..%2Fetc%2Fhostname", "headers": {}}}
TRAV_POC = {"requests": [dict(TRAV["request"], uid=None, role=None)]}
FILES = {"guide.txt": "sha-guide", "usb-hub.v2.txt": "sha-hub", "es/guia.txt": "sha-guia"}
CAPTURED = properties.TRAVERSAL[0]


class FileV:
    """v.run for `plain` jobs on a file endpoint: app(release, name) -> (status, sha, [opened paths])."""
    def __init__(self, app, files=FILES):
        self.app, self.files, self.cache, self.jobs = app, files, {}, []

    def run(self, release, job):
        self.jobs.append((release, job))
        reqs_ = list(job["requests"])
        if job.get("expand"):       # the runner lists every file under the allowed roots
            reqs_ = [dict(job["expand"]["base"], query="name=" + n, name="cand:" + n, expect_sha=s)
                     for n, s in self.files.items()] + reqs_
        out = []
        for rq in reqs_:
            status, sha, opens = self.app(release, dict(parse_qsl(rq["query"], keep_blank_values=True)).get("name"))
            out.append({"name": rq["name"], "status": status, "sha": sha, "opens": opens, "expect_sha": rq.get("expect_sha")})
        return {"results": out, "roots": [ROOT], "warm_opens": []}


def joins_blindly(release, name):
    if name in FILES:
        return 200, FILES[name], [ROOT + "/" + name]
    if ".." in name or name.startswith("/"):
        return 200, "sha-leak", ["/etc/hostname"]
    return 404, "sha-404", []


def contained(release, name):               # resolved path must stay inside the root
    if release == "base" or name in FILES:
        return joins_blindly(release, name)
    return 404, "sha-404", []


def blacklist_captured(release, name):
    return (404, "sha-404", []) if release != "base" and name == CAPTURED else joins_blindly(release, name)


def downloads_removed(release, name):
    return joins_blindly(release, name) if release == "base" else (404, "sha-404", [])


def mangles_dotted_names(release, name):    # keeps the first and last dot part: usb-hub.v2.txt -> usb-hub.txt
    if release != "base" and name.count(".") >= 2:
        return 404, "sha-404", []
    return contained(release, name)


def test_traversal_adequate_fix_passes():
    v = FileV(contained)
    ok, detail = properties.check(v, TRAV, TRAV_POC, "base", "patched")
    assert ok, detail
    assert "%d traversal inputs opened nothing outside %s" % (len(properties.TRAVERSAL), ROOT) in detail
    assert "3 legitimate names (1 with 2+ dots, e.g. usb-hub.v2.txt)" in detail
    assert [r for r, _j in v.jobs] == ["base", "patched"]             # legit names come from the unpatched release


@pytest.mark.parametrize("app,why", [
    (joins_blindly, "opened /etc/hostname (outside"),
    (blacklist_captured, "opened /etc/hostname (outside"),
    (downloads_removed, "no longer served identically: guide.txt (status 404)"),
    (mangles_dotted_names, "no longer served identically: usb-hub.v2.txt (status 404)"),
], ids=lambda x: getattr(x, "__name__", None))
def test_traversal_inadequate_fixes_fail(app, why):
    ok, detail = properties.check(FileV(app), TRAV, TRAV_POC, "base", "patched")
    assert not ok and why in detail, detail


def test_traversal_without_a_legitimate_file_fails_closed():
    ok, detail = properties.check(FileV(contained, files={}), TRAV, TRAV_POC, "base", "patched")
    assert not ok and "no legitimate value found on the unpatched release" in detail
    ok, detail = properties.check(FileV(contained), dict(TRAV, param=None), TRAV_POC, "base", "patched")
    assert not ok and "no file parameter" in detail


# ------------------------------------------------------------------ idor (owner-scoped resources)
MAN = {"seed_max_uid": 60, "admin": {"id": 1}, "legit_users": [{"id": 2}, {"id": 3}],
       "canaries": {"order_id": [12, 31]}, "ownership": {"orders": {"1": 2, "2": 3, "12": 7, "31": 19}}}
OWNER = {1: 2, 2: 3, 5: 6, 12: 7, 31: 19}
IDOR = {"vuln_class": "idor", "method": "GET", "route": "/api/orders/{order_id}", "param": {"in": "path", "name": "order_id"},
        "request": {"method": "GET", "path": "/api/orders/5", "query": "", "headers": {}}}
IDOR_POC = {"requests": [dict(IDOR["request"], uid=61, role="user")]}


class HarnessV:
    """v.run for `harness` jobs: app(release, order id, uid) -> (status, marker owners, verdict)."""
    def __init__(self, app, manifest=MAN):
        self.app, self.man, self.cache, self.jobs = app, manifest, {}, []

    def manifest(self, base_dir):
        return self.man

    def run(self, release, job):
        self.jobs.append((release, job))
        out = []
        for s in job["sequences"]:
            rq = s["requests"][-1]
            st, owners, verdict = self.app(release, int(rq["path"].rsplit("/", 1)[1]), rq.get("uid"))
            out.append({"name": s["name"], "runs": [[{"status": st, "verdict": verdict, "events": [],
                                                       "marker_owners": owners}]]})
        return {"sequences": out, "manifest": self.man}


def no_owner_check(release, oid, uid):
    if uid is None:
        return 401, [], "inconclusive"
    if oid not in OWNER:
        return 404, [], "clean"
    return 200, [OWNER[oid]], "clean" if uid in (OWNER[oid], 1) else "oracle"


def owner_check(release, oid, uid):
    if release != "base" and uid is not None and oid in OWNER and uid not in (OWNER[oid], 1):
        return 404, [], "clean"
    return no_owner_check(release, oid, uid)


def blocks_only_the_poc_id(release, oid, uid):
    return (404, [], "clean") if release != "base" and oid == 5 else no_owner_check(release, oid, uid)


def denies_everyone(release, oid, uid):
    return no_owner_check(release, oid, uid) if release == "base" or uid is None else (404, [], "clean")


def forbids_but_still_leaks(release, oid, uid):     # 403 status, body still carries the other user's data
    st, owners, verdict = no_owner_check(release, oid, uid)
    return (403, owners, verdict) if release != "base" and verdict == "oracle" else (st, owners, verdict)


def opens_to_anonymous(release, oid, uid):
    if release != "base" and uid is None:
        return 200, [], "clean"
    return owner_check(release, oid, uid)


def test_idor_adequate_fix_passes():
    v = HarnessV(owner_check)
    ok, detail = properties.check(v, IDOR, IDOR_POC, "base", "patched")
    assert ok, detail
    # resources 12, 31 (canaries), 1, 2 (owned by trusted users) and 5 (the PoC's): owner 2xx; another seed user and
    # a new user denied for each
    assert "matrix over 5 resources: 5 owner reads get 2xx with only their data, 10 non-owner reads" in detail
    assert "anonymous status 401 unchanged" in detail
    assert [r for r, _j in v.jobs] == ["base", "patched"]


@pytest.mark.parametrize("app,why", [
    (no_owner_check, "gets 200 (want 403/404)"),
    (blocks_only_the_poc_id, "gets 200 (want 403/404)"),
    (denies_everyone, "gets 404 instead of 2xx"),
    (forbids_but_still_leaks, "still receives another user's data"),
    (opens_to_anonymous, "anonymous request now gets 200 (was 401)"),
], ids=lambda x: getattr(x, "__name__", None))
def test_idor_inadequate_fixes_fail(app, why):
    ok, detail = properties.check(HarnessV(app), IDOR, IDOR_POC, "base", "patched")
    assert not ok and why in detail, detail


def test_idor_blocking_only_the_poc_id_names_the_other_resources():
    ok, detail = properties.check(HarnessV(blocks_only_the_poc_id), IDOR, IDOR_POC, "base", "patched")
    assert not ok and "order_id=12" in detail and "order_id=5 " not in detail, detail


def test_idor_with_fewer_than_two_owned_resources_fails_closed():
    def one_resource(release, oid, uid):
        return owner_check(release, oid, uid) if oid == 5 else (404, [], "clean")
    ok, detail = properties.check(HarnessV(one_resource), IDOR, IDOR_POC, "base", "patched")
    assert not ok and "fewer than 2 resources with an identifiable owner" in detail

    def unmarked(release, oid, uid):                # responses carry no ownership marker: owners unknown
        st, _owners, verdict = owner_check(release, oid, uid)
        return st, [], verdict
    ok, detail = properties.check(HarnessV(unmarked), IDOR, IDOR_POC, "base", "patched")
    assert not ok and "cannot build the matrix" in detail
    ok, detail = properties.check(HarnessV(owner_check), dict(IDOR, param=None), IDOR_POC, "base", "patched")
    assert not ok and "no resource parameter" in detail


# ------------------------------------------------------------------ poc gate
class Runner:
    """runner.run for `harness` jobs: fires(release, request) -> list of oracle events of the last request."""
    def __init__(self, fires):
        self.fires, self.jobs = fires, []

    def run(self, release, job, timeout=None):
        self.jobs.append((release, job))
        out = []
        for s in job["sequences"]:
            evs = self.fires(release, s["requests"][-1])
            run = [{"status": 200 if evs else 404, "events": evs, "verdict": "oracle" if evs else "clean"}]
            out.append({"name": s["name"], "runs": [run] * int(s.get("repeat", 1))})
        return {"sequences": out, "manifest": {}}


def sql_event(file="victim/app/db.py", line=25):
    return {"oracle": "sql", "detail": {}, "stack": [{"file": "victim/app/products.py", "line": 23}, {"file": file, "line": line}]}


def rq(q):
    return {"method": "GET", "path": "/api/products", "query": "q=" + q, "headers": {}, "body_b64": "", "uid": None, "role": None}


POC = {"requests": [rq("poc")], "state_b64": None, "expect": {"oracle": "sql", "sink": {"file": "victim/app/db.py", "line": 25}}}
REPRO = {"counted": [{"name": "m0:a", "request": rq("a")}, {"name": "p1:b", "request": rq("b")}], "ignored": ["m2:c"]}


def poc_gate(fires):
    v = gates.Validator(types.SimpleNamespace(), runner=Runner(fires))
    return v, v.gate_poc({"poc": POC, "repro": REPRO, "patched_dir": "patched"})


def test_poc_gate_passes_when_nothing_fires_on_the_patched_release():
    v, (ok, detail) = poc_gate(lambda release, r: [])
    assert ok and "the PoC and 2 variant(s)" in detail and "1 variant(s) did not fire before and were not counted" in detail
    release, job = v.runner.jobs[0]
    assert release == "patched" and [s["name"] for s in job["sequences"]] == ["poc", "v:m0:a", "v:p1:b"]


def test_poc_gate_fails_when_the_poc_still_fires():
    _v, (ok, detail) = poc_gate(lambda release, r: [sql_event()] if r["query"] == "q=poc" else [])
    assert not ok and detail == "the PoC still fires the sql oracle (status 200, at victim/app/db.py:25)"


def test_poc_gate_fails_when_only_a_variant_still_fires():
    """A fix that handles exactly the captured value: the PoC is quiet, a counted variant is not."""
    _v, (ok, detail) = poc_gate(lambda release, r: [sql_event()] if r["query"] == "q=b" else [])
    assert not ok and detail.startswith("variant p1:b still fires the sql oracle")


def test_poc_gate_fails_on_any_oracle_not_only_the_incidents():
    _v, (ok, detail) = poc_gate(lambda release, r: [{"oracle": "file", "detail": {}, "stack": []}] if r["query"] == "q=a" else [])
    assert not ok and "variant m0:a still fires the file oracle" in detail
