"""Replay targets: a non-Python codebase, an explicit editable set, and the guarantee that the
prompt never names the vulnerability. Default (Python) behaviour must be untouched."""
import os

from patcher import core


def _incident(**over):
    inc = {
        "incident": "replay-traversal-go",
        "vuln_class": "traversal",
        "lang": "go",
        "method": "GET",
        "route": "/public/plugins/{pluginId}/{path*}",
        "param": {"in": "path", "name": "*"},
        "sink": {"file": "pkg/api/plugins.go", "line": 284, "func": "getPluginAssets"},
        "app_subdirs": ["pkg/api"],
        "editable_files": ["pkg/api/plugins.go"],
        "evidence": {"events": [{"oracle": "file",
                                 "detail": {"opened": "/etc/grafana/grafana.ini"},
                                 "stack": [{"file": "pkg/api/plugins.go", "line": 276,
                                            "func": "getPluginAssets"}]}]},
    }
    inc.update(over)
    return inc


def test_go_incident_uses_the_go_prompts():
    prompt = core.render_prompt(_incident(), None, 1, ["pkg/api/plugins.go"])
    assert "written in Go" in prompt
    assert "pkg/api/plugins.go" in prompt


def test_prompt_never_names_the_vulnerability():
    prompt = core.render_prompt(_incident(), None, 1, ["pkg/api/plugins.go"]).lower()
    for term in ("cve", "43798", "8.3.1", "advisory", "upstream fix"):
        assert term not in prompt, f"prompt leaks {term!r}"


def test_explicit_editable_files_win_over_source_dirs(tmp_path):
    (tmp_path / "pkg" / "api").mkdir(parents=True)
    (tmp_path / "pkg" / "api" / "plugins.go").write_text("package api\n")
    files = core.editable_files(_incident(), str(tmp_path))
    assert files == [os.path.normpath("pkg/api/plugins.go")]


def test_explicit_editable_files_must_exist(tmp_path):
    assert core.editable_files(_incident(), str(tmp_path)) == []


def test_default_language_is_unchanged():
    assert core._templates(None) == ("fix.md", "classes.md")
    assert core._templates("py") == ("fix.md", "classes.md")
    assert core._templates("go") == ("fix_go.md", "classes_go.md")
