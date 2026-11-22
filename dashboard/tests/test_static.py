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
    assert "<title>Inmune</title>" in page and "<h1>Inmune</h1>" in page and "Sistema inmune" not in page


def test_attack_panel_is_hidden_until_the_page_has_attack_events():
    html = (STATIC / "index.html").read_text()
    panel = re.search(r'<section class="block" id="panel-attacks"([^>]*)>(.*?)</section>', html, re.S)
    assert "hidden" in panel.group(1)                       # nothing in a live run emits attack.attempt
    assert 'class="empty"' not in panel.group(2)            # and there is no empty placeholder
    app = (STATIC / "app.js").read_text()
    assert "show($('panel-attacks'), S.showAttacks(st));" in app
