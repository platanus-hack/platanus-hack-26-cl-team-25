import json
import re
from pathlib import Path

from starlette.testclient import TestClient

from dashboard.server import create_app

STATIC = Path(__file__).resolve().parent.parent / "static"
FORBIDDEN = ["innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "eval(", "new function", "settimeout(\"", "settimeout('"]


def test_no_dangerous_sinks_or_external_urls():
    for f in STATIC.iterdir():
        if f.suffix == ".woff2":
            continue
        txt = f.read_text()
        low = txt.lower()
        for bad in FORBIDDEN:
            assert bad not in low, f"{f.name} contains {bad}"
        for url in re.findall(r"""(?:https?:)?//[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s"')]*""", txt):
            # the only allowed literal is the github allow-list prefix in JS
            # ... and the SVG namespace, a constant that is never fetched
            assert url.startswith("https://github.com/") or url == "http://www.w3.org/2000/svg", f"{f.name} references {url}"
        if f.suffix == ".css":
            assert "@import" not in low
            # the only urls a stylesheet may load are the two self-hosted fonts
            assert set(re.findall(r"url\(([^)]*)\)", low)) <= {'"/static/inter.woff2"', '"/static/mono.woff2"'}


def test_html_has_no_inline_script_or_handlers():
    html = (STATIC / "index.html").read_text()
    for m in re.finditer(r"<script\b([^>]*)>", html, re.I):
        assert "src=" in m.group(1)
    assert not re.search(r"\son\w+\s*=", html, re.I)
    assert "style=" not in html.lower()
    srcs = re.findall(r'(?:src|href)="([^"]+)"', html)
    assert srcs and all(s.startswith("/static/") for s in srcs)


def test_served_with_csp(tmp_path):
    c = TestClient(create_app(str(tmp_path / "e.jsonl"), "t"))
    for path in ["/", "/static/app.js", "/static/state.js", "/static/style.css"]:
        r = c.get(path)
        assert r.status_code == 200, path
        assert "default-src 'self'" in r.headers["content-security-policy"]
        assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert "text/html" in c.get("/").headers["content-type"]
    page = c.get("/").text
    assert "<title>Immune</title>" in page and "<h1>Immune</h1>" in page and "Sistema inmune" not in page


def test_attack_panel_is_hidden_until_the_page_has_attack_events():
    html = (STATIC / "index.html").read_text()
    panel = re.search(r'<section class="block" id="panel-attacks"([^>]*)>(.*?)</section>', html, re.S)
    assert "hidden" in panel.group(1)                       # nothing in a live run emits attack.attempt
    assert 'class="empty"' not in panel.group(2)            # and there is no empty placeholder
    app = (STATIC / "app.js").read_text()
    assert "show($('panel-attacks'), S.showAttacks(st));" in app


def test_public_replay_uses_only_display_metadata_from_the_recorded_run():
    c = TestClient(create_app())
    response = c.get("/static/replay.json")
    assert response.status_code == 200
    replay = response.json()
    fixture = Path(__file__).parent / "fixtures" / "real_run.jsonl"
    source = {row["seq"]: row for row in map(json.loads, fixture.read_text(encoding="utf-8").splitlines())}
    fields = {
        "request.classified": {"method", "class"},
        "request.routed": {"route", "status", "ms"},
        "oracle.fired": set(),
        "incident.opened": {"origin", "vuln_class"},
        "rule.active": set(),
        "patch.attempt": {"attempt"},
        "gate.result": {"gate", "ok"},
        "deploy.started": set(),
        "upstream.switched": set(),
        "deploy.done": {"ok"},
        "verify.result": {"exploit_blocked_on_prod"},
        "incident.closed": {"outcome"},
    }
    events = replay["events"]
    assert [event["seq"] for event in events] == sorted({event["seq"] for event in events})
    assert [event["at"] for event in events] == sorted(event["at"] for event in events)
    start = source[events[0]["seq"]]["ts"]
    for event in events:
        row = source[event["seq"]]
        assert row["run"] == replay["run"]
        assert event["type"] == row["type"]
        assert event["at"] == round(row["ts"] - start, 3)
        assert set(event) <= {"seq", "type", "at", "rid", "incident"} | fields[row["type"]]
        assert all(event.get(key) == row["data"].get(key) for key in fields[row["type"]])
        if "rid" in event:
            assert event["rid"] == row["rid"][:8]
        if event["type"] in {"deploy.started", "upstream.switched", "deploy.done"}:
            assert any(
                merge["type"] == "pr.merged"
                and merge["incident"] == event["incident"]
                and merge["data"]["sha"].startswith(row["data"]["release"])
                for merge in source.values()
            )
    assert sum(event["type"] == "incident.closed" and event["outcome"] == "patched" for event in events) == 3
    assert c.get("/health").json()["events"] == 0
