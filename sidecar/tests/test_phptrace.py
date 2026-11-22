"""PHP call stacks for oracle events from Xdebug trace format 1."""
import os

from sidecar import phptrace

ROOT = "/var/www/localhost/htdocs/openemr"


def row(level, num, func, user, file, line, args=(), include=""):
    return "\t".join([str(level), str(num), "0", "0.001", "400000", func, "1" if user else "0", include, file,
                      str(line), str(len(args)), *args]) + "\n"


TRACE = [
    "Version: 3.5.0\n", "File format: 4\n", "TRACE START [2026-11-21 10:00:00.000000]\n",
    row(1, 1, "{main}", 1, ROOT + "/interface/patient_file/summary/demographics.php", 0),
    row(2, 2, "require_once", 1, ROOT + "/interface/patient_file/summary/demographics.php", 12,
        include=ROOT + "/interface/globals.php"),
    row(2, 3, "sqlStatement", 1, ROOT + "/interface/patient_file/summary/demographics.php", 88,
        ["'SELECT * FROM patient_data WHERE pid = ?'", "[0 => '1 OR 1=1']"]),
    row(3, 4, "sqlStatementNoLog", 1, ROOT + "/library/sql.inc.php", 140,
        ["'SELECT * FROM patient_data WHERE pid = ?'", "[...]"]),
    row(4, 5, "ADODB_mysqli->Execute", 1, ROOT + "/library/sql.inc.php", 210,
        ["'SELECT * FROM patient_data WHERE pid = ?'", "[...]"]),
    row(5, 6, "mysqli_query", 0, ROOT + "/vendor/adodb/adodb-php/drivers/adodb-mysqli.inc.php", 1170,
        ["class mysqli {}", "'SELECT * FROM patient_data WHERE pid = 1 OR 1=1'"]),
    row(2, 7, "file_get_contents", 0, ROOT + "/controller.php", 40, ["'" + ROOT + "/sites/default/documents/../../../../etc/passwd'"]),
    row(2, 8, "shell_exec", 0, ROOT + "/interface/main/backup.php", 300, ["'mysqldump -u x'"]),
    "TRACE END   [2026-11-21 10:00:00.100000]\n",
]


def tracer(tmp_path):
    d = tmp_path / "proc" / "tmp" / "immune-trace"
    d.mkdir(parents=True)
    (d / "trace.1.xt").write_text("".join(TRACE))
    return phptrace.CallTracer("/tmp/immune-trace", [ROOT + "/interface", ROOT + "/library", ROOT + "/src",
                                                     ROOT + "/controller.php"], root=str(tmp_path / "proc"))


def test_sql_event_points_at_the_apps_call_site(tmp_path):
    t = tracer(tmp_path)
    ev = [{"oracle": "sql", "detail": {"statement": "SELECT * FROM patient_data WHERE pid = 1 OR 1=1"}, "stack": []}]
    assert t.attach(ev) == 1
    sink = ev[0]["stack"][-1]
    assert sink["file"].endswith("/library/sql.inc.php") and sink["line"] == 210
    assert ev[0]["stack"][0]["func"] == "{main}"
    assert any(f["file"].endswith("demographics.php") and f["line"] == 88 for f in ev[0]["stack"])
    assert not any("/vendor/" in f["file"] for f in ev[0]["stack"])


def test_file_proc_and_owner_events(tmp_path):
    t = tracer(tmp_path)
    ev = [{"oracle": "file", "detail": {"path": "/etc/passwd", "realpath": "/etc/passwd"}, "stack": []},
          {"oracle": "proc", "detail": {"path": "/usr/bin/mysqldump", "argv": ["mysqldump", "-u", "x"]}, "stack": []},
          {"oracle": "owner", "detail": {"marker_owner": 3, "requester": 2}, "stack": []}]
    assert t.attach(ev) == 2
    assert ev[0]["stack"][-1] == {"file": ROOT + "/controller.php", "line": 40, "func": "file_get_contents"}
    assert ev[1]["stack"][-1]["file"].endswith("/interface/main/backup.php")
    assert ev[2]["stack"] == [{"file": ROOT + "/interface/patient_file/summary/demographics.php", "line": 0,
                               "func": "{main}"}]


def test_clear_and_missing_traces(tmp_path):
    t = tracer(tmp_path)
    t.clear()
    assert not os.listdir(tmp_path / "proc" / "tmp" / "immune-trace")
    ev = [{"oracle": "sql", "detail": {"statement": "SELECT 1"}, "stack": []}]
    assert t.attach(ev) == 0 and ev[0]["stack"] == []


def test_php_string_and_bound_sql_matching():
    assert phptrace.php_string("'O\\'Brien \\\\ x'") == "O'Brien \\ x"
    assert phptrace.php_string("NULL") is None
    assert phptrace.sql_matches("SELECT * FROM t WHERE a = ? AND b = ?", "select * from t where a = 'x' and b = 3")
    assert not phptrace.sql_matches("SELECT * FROM other WHERE a = ?", "select * from t where a = 'x'")
