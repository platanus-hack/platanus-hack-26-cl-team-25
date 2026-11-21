"""Generic runtime (app.runtime generic): language-neutral policy gate, sink location, incident parameter fallback.
No Docker, no LLM: the judge runner itself is exercised live by `immune up` on examples/tareas-node."""
import os
import shutil

import pytest

from pipeline import diffs, incident
from pipeline.generic import check_generic
from pipeline.generic_patch import locate, render

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLE = os.path.join(ROOT, "examples", "tareas-node")
DIRS = ["src"]


@pytest.fixture()
def rel(tmp_path):
    d = tmp_path / "rel"
    d.mkdir()
    for p in ("src", "test"):
        shutil.copytree(os.path.join(SAMPLE, p), d / p)
    for p in ("package.json", "server.js"):
        shutil.copy2(os.path.join(SAMPLE, p), d / p)
    return str(d)


def patched(rel, edits):
    diff = diffs.make(rel, edits)
    work = diffs.copy_release(rel, paths=["src", "test", "package.json", "server.js"])
    diffs.apply(diff, work)
    return diff, work


def read(rel, p):
    with open(os.path.join(rel, p)) as f:
        return f.read()


FIX = ('    sql += " AND (title ILIKE \'%" + term + "%\' OR notes ILIKE \'%" + term + "%\')";',
       '    sql += " AND (title ILIKE $1 OR notes ILIKE $1)";')


def test_policy_accepts_a_parameterised_fix(rel):
    src = read(rel, "src/tasks.js")
    assert FIX[0] in src
    diff, work = patched(rel, {"src/tasks.js": src.replace(FIX[0], FIX[1])})
    ok, detail, v = check_generic(diff, rel, work, dirs=DIRS)
    assert ok, detail
    assert "src/tasks.js" in detail


@pytest.mark.parametrize("path,new,why", [
    ("src/tasks.js", "const cp = require(\"child_process\");\n", "new import"),
    ("src/tasks.js", "const k = process.env.SECRET_KEY;\n", "process.env"),
    ("src/tasks.js", "const t = \"Zq8f3LkP2mXv9RtY7wQe4\";\n", "high-entropy"),
    ("package.json", None, "only files under"),
    ("test/api.test.js", None, "only files under"),
    ("server.js", None, "only files under"),
])
def test_policy_rejections(rel, path, new, why):
    src = read(rel, path)
    edited = (new + src) if new else src + "\n// x\n"
    diff, work = patched(rel, {path: edited})
    ok, detail, _ = check_generic(diff, rel, work, dirs=DIRS)
    assert not ok and why in detail, detail


def test_policy_rejects_tests_and_dependency_files_inside_source_dirs(rel):
    os.makedirs(os.path.join(rel, "src", "__tests__"))
    for p in ("src/__tests__/a.test.js", "src/package-lock.json"):
        with open(os.path.join(rel, p), "w") as f:
            f.write("x\n")
    for p, why in (("src/__tests__/a.test.js", "test files"), ("src/package-lock.json", "dependency/build")):
        diff, work = patched(rel, {p: "y\n"})
        ok, detail, _ = check_generic(diff, rel, work, dirs=DIRS)
        assert not ok and why in detail, detail


def test_policy_rejects_new_files_and_dropped_auth(rel):
    diff = diffs.make(rel, {"src/new.js": "module.exports = 1;\n"})
    ok, detail, _ = check_generic(diff, rel, rel, dirs=DIRS)
    assert not ok and "creating or deleting" in detail
    src = read(rel, "src/app.js")
    edited = src.replace("    await auth.requireUser(req);\n    const f = await files.read", "    const f = await files.read")
    assert edited != src
    diff, work = patched(rel, {"src/app.js": edited})
    ok, detail, _ = check_generic(diff, rel, work, dirs=DIRS)
    assert not ok and "fewer authentication" in detail


class _Cfg:
    class app:
        source_dirs = ["src"]
    shadow = type("S", (), {"columns": os.path.join(SAMPLE, ".immune", "shadow", "columns.yaml")})()
    project_dir = SAMPLE


def test_locate_sql_file_owner(rel):
    sql = {"vuln_class": "sqli", "route": "/api/tasks/search", "param": {"in": "query", "name": "q"},
           "evidence": {"events": [{"oracle": "sql", "detail": {
               "input": "zz') OR 1=1 -- ", "statement": "SELECT id, title, status, due_date FROM tasks WHERE user_id = 12 "
               "AND (title ILIKE '%zz') OR 1=1 -- %' OR notes ILIKE '%zz') OR 1=1 -- %') ORDER BY due_date NULLS LAST, id LIMIT 50"}}]}}
    ed, why = locate(rel, sql, _Cfg)
    assert ed[0] == "src/tasks.js" and "src/app.js" in ed
    trav = {"vuln_class": "traversal", "route": "/api/files/download", "param": {"in": "query", "name": "name"},
            "evidence": {"events": [{"oracle": "file", "detail": {"path": "/etc/hostname"}}]}}
    ed, _ = locate(rel, trav, _Cfg)
    assert ed[0] == "src/files.js" and "src/app.js" in ed
    idor = {"vuln_class": "idor", "route": "/api/tasks/{task_id}/export", "param": {"in": "path", "name": "task_id"},
            "evidence": {"events": [{"oracle": "owner", "detail": {"marker_owner": 1, "requester": 14}}]}}
    ed, _ = locate(rel, idor, _Cfg)
    assert "src/exporter.js" in ed[:2]
    text = render(idor, ed, ["Attempt 1 was rejected by the properties gate: x"], 2)
    assert "JavaScript" in text and "src/exporter.js" in text and "Previous attempt rejected" in text


def test_file_param_when_the_app_normalises_the_path():
    ev = {"detail": {"path": "/etc/hostname"}}
    req = {"query": "name=..%2F..%2F..%2F..%2Fetc%2Fhostname"}
    assert incident.derive_param("file", ev, req, "/api/files/download", {}) == {"in": "query", "name": "name"}
    assert incident.derive_param("file", ev, {"query": "name=guia-rapida.txt"}, "/api/files/download", {}) is None
