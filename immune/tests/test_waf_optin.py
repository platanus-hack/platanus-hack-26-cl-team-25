"""`immune up` starts the WAF only when IMMUNE_WAF asks for it (deploy/compose.yaml, profile `waf`)."""
from immune import __main__ as cli
from immune import config as icfg


def test_waf_is_off_unless_asked(monkeypatch):
    cfg = icfg.load(cli.HOME)
    monkeypatch.delenv("IMMUNE_WAF", raising=False)
    monkeypatch.delenv("COMPOSE_PROFILES", raising=False)
    env = cli.compose_env(cfg, "/dev/null", "r")
    assert "IMMUNE_WAF_URL" not in env and env.get("COMPOSE_PROFILES") != "waf"
    monkeypatch.setenv("IMMUNE_WAF", "1")
    env = cli.compose_env(cfg, "/dev/null", "r")
    assert env["IMMUNE_WAF_URL"] == "http://waf:8080" and env["COMPOSE_PROFILES"] == "waf"


def test_dashboard_subtitle_comes_from_the_environment(monkeypatch):
    cfg = icfg.load(cli.HOME)
    monkeypatch.setenv("DASHBOARD_SUBTITLE", "Planta norte")
    assert cli.compose_env(cfg, "/dev/null", "r")["DASHBOARD_SUBTITLE"] == "Planta norte"
