import os

import pytest

from pipeline.extfix import Attempt, ExtFix, GateFail, diff_stats, load_target

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARGET = os.path.join(ROOT, "labs", "grafana-cve-2021-43798", "target.yaml")

DIFF = """diff --git a/pkg/api/plugins.go b/pkg/api/plugins.go
--- a/pkg/api/plugins.go
+++ b/pkg/api/plugins.go
@@ -281,3 +281,6 @@ func (hs *HTTPServer) getPluginAssets(c *models.ReqContext) {
-	requestedFile := filepath.Clean(web.Params(c.Req)["*"])
+	requestedFile := filepath.Clean(filepath.Join("/", web.Params(c.Req)["*"]))
+	if rel, err := filepath.Rel("/", requestedFile); err == nil {
+		requestedFile = rel
+	}
"""

INC = {"incident": "inc-1", "vuln_class": "traversal", "method": "GET", "route": "/public/plugins/{pluginId}/{path*}",
       "param": {"in": "path", "name": "path"},
       "request": {"method": "GET", "path": "/public/plugins/alertlist/../../../../etc/grafana/grafana.ini", "query": ""},
       "evidence": {"events": [{"oracle": "file", "detail": {"path": "/etc/grafana/grafana.ini"}, "stack": []}]}}


@pytest.fixture
def fx():
    return ExtFix(load_target(TARGET), "run", lambda *a: None, lambda *a: None, "http://gw:1", "t", "http://gw:2")


def test_diff_stats():
    files, lines = diff_stats(DIFF)
    assert files == ["pkg/api/plugins.go"] and lines == 5


def test_policy_accepts_small_fix(fx):
    assert "1 file" in fx.g_policy(INC, Attempt(1, diff=DIFF))


@pytest.mark.parametrize("diff,why", [
    ("", "empty"),
    (DIFF.replace("pkg/api/plugins.go", "pkg/api/plugins_test.go"), "outside"),
    (DIFF.replace("pkg/api/plugins.go", "go.mod"), "outside"),
    (DIFF + '+import "os/exec"\n', "os/exec"),
    (DIFF + "".join("+x%d\n" % i for i in range(80)), "changed lines"),
])
def test_policy_rejects(fx, diff, why):
    with pytest.raises(GateFail) as e:
        fx.g_policy(INC, Attempt(1, diff=diff))
    assert e.value.gate == "policy" and why in e.value.detail


def test_prompt_never_leaks_the_advisory_or_upstream_fix(fx):
    p = fx.prompt(INC, ["attempt 1 rejected by the poc gate: still leaks"], 2)
    assert "CVE" not in p and "8.3.1" not in p and "43798" not in p
    assert "/etc/grafana/grafana.ini" in p and "pkg/api" in p and "rejected by the poc gate" in p


def test_published_events_match_the_bus_contract(fx):
    import inspect, re
    from pipeline.bus import FIELDS
    src = inspect.getsource(ExtFix)
    for type_, keys in re.findall(r'self\.publish\("([a-z.]+)", \{(.*?)\}\)', src, flags=re.S):
        if type_ in FIELDS and "**" not in keys:
            got = set(re.findall(r'"([a-z_]+)":', keys))
            assert got == FIELDS[type_], (type_, got)


def test_prompt_and_describe_cover_proc_and_net_events(fx):
    from pipeline.extfix import describe
    proc = {"oracle": "proc", "detail": {"path": "/bin/sh", "argv": ["sh", "-c", "id"]}, "stack": []}
    net = {"oracle": "net", "detail": {"family": "AF_INET", "address": "169.254.169.254", "port": 80,
                                       "syscall": "connect"}, "stack": []}
    blind = {"oracle": "file", "detail": {"path": "/etc/shadow", "realpath": "/etc/shadow", "result": "EACCES"}}
    assert "executed the program `sh -c id`" in describe(proc)
    assert "connection to `169.254.169.254:80`" in describe(net) and "failed" not in describe(net)
    assert "opened `/etc/shadow`" in describe(blind) and "EACCES" in describe(blind)
    inc = dict(INC, oracle="proc", evidence={"events": [blind, proc]})
    p = fx.prompt(inc, [], 1)
    assert "executed the program" in p and "choose the program that runs" in p
