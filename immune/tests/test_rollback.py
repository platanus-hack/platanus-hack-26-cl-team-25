"""`immune rollback`: which release goes back, and that it stops automatic merges."""
import os
import time
from types import SimpleNamespace

import pytest

import immune.__main__ as cli


def _cfg(tmp_path, autopatch="merge"):
    return SimpleNamespace(rt=lambda *p: os.path.join(str(tmp_path), *p),
                           release_dir=lambda r: os.path.join(str(tmp_path), "releases", r),
                           autopatch=autopatch, ports={"fleet": 1})


def _releases(tmp_path, names):
    now = time.time()
    for i, n in enumerate(names):
        d = tmp_path / "releases" / n
        d.mkdir(parents=True)
        os.utime(d, (now - 100 + i, now - 100 + i))


def test_previous_release_is_the_one_built_before(tmp_path):
    _releases(tmp_path, ["t0", "aaa", "bbb", "ccc"])
    cfg = _cfg(tmp_path)
    assert cli.previous_release(cfg, "ccc") == "bbb"
    assert cli.previous_release(cfg, "aaa") == "t0"
    assert cli.previous_release(cfg, "t0") is None
    assert cli.previous_release(cfg, "pruned") == "ccc"


def test_rollback_deploys_the_previous_release_and_caps_autopatch(tmp_path, monkeypatch):
    _releases(tmp_path, ["t0", "aaa"])
    calls, sets = [], []
    monkeypatch.setattr(cli, "stack_secrets", lambda cfg: {"ADMIN_TOKEN": "t"})
    monkeypatch.setattr(cli, "cmd_set", lambda cfg, k, v: sets.append((k, v)))

    def http(method, url, body=None, token="", timeout=5.0):
        calls.append((method, url.rsplit("/", 1)[-1], body))
        if method == "GET":
            return {"prod": {"release": "aaa"}}
        return {"ok": True, "release": body["release"]}
    monkeypatch.setattr(cli, "http", http)
    assert cli.cmd_rollback(_cfg(tmp_path), None, False) == 0
    assert calls[-1] == ("POST", "deploy", {"release": "t0"})
    assert sets == [("autopatch", "pr")]


def test_rollback_refuses_an_unknown_release(tmp_path, monkeypatch):
    _releases(tmp_path, ["t0"])
    monkeypatch.setattr(cli, "stack_secrets", lambda cfg: {"ADMIN_TOKEN": "t"})
    monkeypatch.setattr(cli, "http", lambda *a, **k: {"prod": {"release": "t0"}})
    with pytest.raises(cli.CliError):
        cli.cmd_rollback(_cfg(tmp_path), "nope", True)
