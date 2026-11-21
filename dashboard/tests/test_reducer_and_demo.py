import json
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
    (tmp_path / "evs.json").write_text(json.dumps(evs))
    if NODE:
        out = subprocess.run([NODE, str(HERE / "reducer.test.js"), str(tmp_path / "evs.json")], capture_output=True, text=True)
        assert out.returncode == 0, out.stdout + out.stderr


@pytest.mark.skipif(not NODE, reason="node not installed")
def test_reducer_node():
    out = subprocess.run([NODE, str(HERE / "reducer.test.js")], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "reducer ok" in out.stdout
