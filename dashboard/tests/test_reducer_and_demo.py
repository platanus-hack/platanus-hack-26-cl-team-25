import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import dashboard.demo_events as demo
from dashboard.server import create_app

HERE = Path(__file__).resolve().parent
NODE = shutil.which("node")


class FakePoster(demo.Poster):
    def __init__(self, client, token):
        super().__init__("http://x", token, 1e9)
        self.c = client

    def _post(self, path, body):
        r = self.c.post(path, json=body, headers={"x-bus-token": self.token})
        assert r.status_code == 200, r.text
        return r.json()


def test_demo_script_events_are_valid_and_complete(tmp_path):
    c = TestClient(create_app(str(tmp_path / "e.jsonl"), "t"))
    p = FakePoster(c, "t")
    demo.run(p)
    evs = c.get("/events").json()["events"]
    assert len(evs) == p.n > 100
    types = {e["type"] for e in evs}
    for needed in ["oracle.fired", "rule.active", "patch.diff", "gate.result", "pr.merged", "deploy.done", "verify.result", "incident.closed", "attack.attempt", "request.routed"]:
        assert needed in types
    assert any("onerror" in json.dumps(e) for e in evs)
    assert {e["run"] for e in evs} == {demo.RUN}
    # no reference of the script can become a link on the page (static/state.js only links plain github.com urls)
    assert "github.com" not in json.dumps(evs)
    assert {e["data"]["url"] for e in evs if e["type"] in ("pr.opened", "pr.merged")} == {demo.PR_URL % 1, demo.PR_URL % 2}


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_page_marks_the_demo_script_as_scripted(tmp_path):
    c = TestClient(create_app(str(tmp_path / "e.jsonl"), "t"))
    demo.run(FakePoster(c, "t"))
    (tmp_path / "evs.json").write_text(json.dumps(c.get("/events").json()["events"]))
    out = subprocess.run([NODE, str(HERE / "reducer.test.js"), str(tmp_path / "evs.json")], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


def test_demo_run_id_is_the_one_the_page_labels_as_scripted():
    js = (HERE.parent / "static" / "state.js").read_text()
    assert re.search(r"SCRIPTED_RUN = '([^']+)'", js).group(1) == demo.RUN
    html = (HERE.parent / "static" / "index.html").read_text()
    assert re.search(r'<div class="chip flag" id="scripted" hidden>DEMO · datos guionados</div>', html)
    assert 'id="run" hidden' in html and "en vivo" not in html.lower()
    app = (HERE.parent / "static" / "app.js").read_text()
    assert "'En vivo'" not in app and "S.connLabel(st)" in app      # the page never writes "En vivo" on its own


@pytest.mark.parametrize("url,ok", [
    ("http://127.0.0.1:8090", True), ("http://localhost:8090", True), ("http://[::1]:8090", True), ("http://127.5.5.5", True),
    ("https://inmune.example.com", False), ("http://10.0.0.5:8090", False), ("http://0.0.0.0:8090", False),
    ("http://localhost.evil.example", False), ("http://127.0.0.1.evil.example", False), ("", False), ("not a url", False),
])
def test_demo_loopback_check(url, ok):
    assert demo.is_loopback(url) is ok


def test_demo_refuses_a_dashboard_that_is_not_local(monkeypatch, capsys):
    posted = []
    monkeypatch.setattr(demo.Poster, "_post", lambda self, path, body: posted.append((self.url, path)) or {})
    monkeypatch.setattr(demo.time, "sleep", lambda s: None)
    assert demo.main(["--url", "https://inmune.example.com", "--token", "t", "--clear"]) == 2
    assert posted == [] and "scripted" in capsys.readouterr().err
    assert demo.main(["--url", "https://inmune.example.com", "--token", "t", "--i-know-this-is-scripted"]) == 0
    assert posted and {u for u, _ in posted} == {"https://inmune.example.com"}
    posted.clear()
    assert demo.main(["--url", "http://127.0.0.1:1", "--token", "t"]) == 0 and posted      # local: no flag needed
    assert "without a stack" in demo.__doc__ and "invented" in demo.__doc__


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_reducer_node():
    out = subprocess.run([NODE, str(HERE / "reducer.test.js")], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "reducer ok" in out.stdout
