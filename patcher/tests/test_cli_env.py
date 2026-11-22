"""The CLI process of the patcher gets an allowlisted environment and, optionally, its own identity."""
from patcher import claude_cli

STACK = {"PATH": "/usr/bin", "HOME": "/home/u", "ADMIN_TOKEN": "a", "BUS_TOKEN": "b", "PROD_APP_SECRET": "p",
         "SHADOW_APP_SECRET": "s", "GH_TOKEN": "g", "GITHUB_TOKEN": "g2", "BUS_URL": "http://x",
         "ANTHROPIC_BASE_URL": "https://proxy", "CLAUDE_BIN": "/bin/claude", "AWS_REGION": "us-east-1"}


def test_stack_secrets_never_reach_the_cli():
    env = claude_cli.child_env(STACK)
    for k in ("ADMIN_TOKEN", "BUS_TOKEN", "PROD_APP_SECRET", "SHADOW_APP_SECRET", "GH_TOKEN", "GITHUB_TOKEN",
              "BUS_URL", "CLAUDE_BIN"):
        assert k not in env
    assert env["PATH"] == "/usr/bin" and env["HOME"] == "/home/u"
    assert env["ANTHROPIC_BASE_URL"] == "https://proxy" and env["AWS_REGION"] == "us-east-1"


def test_own_config_dir_and_key():
    env = claude_cli.child_env(dict(STACK, PATCHER_CLAUDE_CONFIG_DIR="/srv/patcher-claude",
                                    PATCHER_ANTHROPIC_API_KEY="sk-own", ANTHROPIC_AUTH_TOKEN="op"))
    assert env["CLAUDE_CONFIG_DIR"] == "/srv/patcher-claude"
    assert env["ANTHROPIC_API_KEY"] == "sk-own"
    assert "ANTHROPIC_AUTH_TOKEN" not in env
    assert not any(k.startswith("PATCHER_") for k in env)


def test_identity_never_prints_a_secret():
    assert "sk-own" not in claude_cli.identity({"PATCHER_ANTHROPIC_API_KEY": "sk-own"})
    assert "operator" in claude_cli.identity({})
    assert "own Claude login" in claude_cli.identity({"PATCHER_CLAUDE_CONFIG_DIR": "/d"})
