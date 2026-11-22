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


@pytest.mark.parametrize("new,why", [
    # a comment marker inside a string literal must not hide the rest of the line
    ("var h = '#'; const cp = require('child_process'); cp.execSync('id');\n", "new import(s)/require(s) child_process"),
    ("var u = \"http://x\"; const k = process.env.SECRET_KEY;\n", "new use of process.env"),
    ("var q = 'it\\'s // fine'; eval(q);\n", "new use of eval"),
    # bracket access to the same members
    ("const k = process['env'].SECRET_KEY;\n", "new computed member access"),
    ("const k = process[`env`];\n", "new computed member access"),
    ("const k = global['pro' + 'cess'];\n", "new computed member access"),
    ("const f = [].filter['constructor']('return 1');\n", "new computed member access"),
    # no parser: a `//` inside a regular-expression literal looks like a comment; code after it is still seen
    ("const r = /[//]/; require('child_process').execSync('id');\n", "a comment contains code-shaped"),
])
def test_policy_lexes_strings_before_comments_and_sees_bracket_access(rel, new, why):
    src = read(rel, "src/tasks.js")
    diff, work = patched(rel, {"src/tasks.js": new + src})
    ok, detail, _ = check_generic(diff, rel, work, dirs=DIRS)
    assert not ok and why in detail, detail


def test_policy_accepts_prose_comments_and_markers_inside_strings(rel):
    src = read(rel, "src/tasks.js")
    note = ("// bound parameter: don't build the statement by hand; fetch the rows as before (system of record)\n"
            "/* the '#' and \"//\" below are data */\nconst marks = ['#', \"//\", `/*`];\n")
    diff, work = patched(rel, {"src/tasks.js": note + src.replace(FIX[0], FIX[1])})
    ok, detail, _ = check_generic(diff, rel, work, dirs=DIRS)
    assert ok, detail


def test_lex_comment_syntax_depends_on_the_language():
    from pipeline.generic import lex
    assert lex("a = '#'; b()  // c\n/* d */ e", ".js") == ("a = '#'; b()   \n  e", "// c\n/* d */")
    assert lex("#include <stdlib.h>\nx(); // y", ".c")[0] == "#include <stdlib.h>\nx();  "
    assert lex("x = 1  # note\ny = 7 // 2", ".rb") == ("x = 1   \ny = 7 // 2", "# note")
    assert lex("SELECT 1 -- note", ".sql") == ("SELECT 1  ", "-- note")


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
