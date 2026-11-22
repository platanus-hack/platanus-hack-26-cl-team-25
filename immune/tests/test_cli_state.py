"""`immune reset` never deletes a live database it cannot regenerate; `immune status` reports an unreachable
fleet as a problem; every project (the built-in demo too) gets random per-machine secrets."""
import os
import types

import yaml

from immune import __main__ as cli
from immune import config as icfg


def _project(tmp_path, prod_db, seed_command=""):
    p = tmp_path / "proj"
    (p / "app").mkdir(parents=True)
    (p / "app" / "main.py").write_text("app = None\n")
    (p / ".immune").mkdir()
    (p / ".immune" / "openapi.yaml").write_text("openapi: 3.0.3\npaths: {}\n")
    raw = {"version": 1, "name": "seedy", "runtime_dir": "rt",
           "app": {"release_paths": ["app"], "source_dirs": ["app"], "asgi": "app.main:app", "port": 8000},
           "data": {"prod_db": prod_db}, "auth": {"kind": "none"}, "openapi": ".immune/openapi.yaml",
           "shadow": {"profile": "profile"}}
    if seed_command:
        raw["data"]["seed_command"] = seed_command
    with open(p / ".immune" / "config.yaml", "w") as f:
        yaml.safe_dump(raw, f)
    return icfg.load(str(p))


def _put(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


SEED_CMD = ("python -c \"import sys; open(sys.argv[1], 'w').write('regenerated'); "
            "open(sys.argv[2], 'w').write('{}')\" {prod_db} {markers}")


def test_seed_regenerates_a_demo_database_that_has_a_seed_command(tmp_path, monkeypatch):
    monkeypatch.delenv("T0_REF", raising=False)
    cfg = _project(tmp_path, "rt/data/prod/app.db", SEED_CMD)
    _put(cfg.data.prod_db, "old")
    _put(cfg.rt("data", "stale.json"), "x")
    run_id = cli.seed(cfg)
    assert open(cfg.data.prod_db).read() == "regenerated"           # the demo database is rebuilt at every reset
    assert not os.path.exists(cfg.rt("data", "stale.json"))
    assert open(cfg.rt("run_id")).read().strip() == run_id
    assert os.path.isfile(os.path.join(cfg.release_dir("t0"), "app", "main.py"))
    assert os.path.isfile(cfg.markers_path)


def test_seed_keeps_a_live_database_under_runtime_data_when_nothing_can_regenerate_it(tmp_path, monkeypatch):
    monkeypatch.delenv("T0_REF", raising=False)
    cfg = _project(tmp_path, "rt/data/prod/app.db")
    built = []
    monkeypatch.setattr("immune.shadowdata.build", lambda c: built.append(open(c.data.prod_db).read()))
    _put(cfg.data.prod_db, "live rows")
    _put(cfg.data.prod_db + "-wal", "journal")
    _put(cfg.rt("data", "prod", "other.tmp"), "x")
    _put(cfg.rt("data", "shadow", "seed.db"), "old shadow")
    _put(cfg.rt("data", "manifest.json"), "{}")
    cli.seed(cfg)
    assert open(cfg.data.prod_db).read() == "live rows" and built == ["live rows"]
    assert open(cfg.data.prod_db + "-wal").read() == "journal"
    for gone in (("data", "prod", "other.tmp"), ("data", "shadow", "seed.db"), ("data", "manifest.json")):
        assert not os.path.exists(cfg.rt(*gone)), gone               # everything else under data/ is rebuilt


def test_seed_never_touches_a_database_outside_the_runtime(tmp_path, monkeypatch):
    monkeypatch.delenv("T0_REF", raising=False)
    cfg = _project(tmp_path, "data/app.db")
    monkeypatch.setattr("immune.shadowdata.build", lambda c: None)
    _put(cfg.data.prod_db, "live rows")
    _put(cfg.rt("data", "stale.json"), "x")
    cli.seed(cfg)
    assert open(cfg.data.prod_db).read() == "live rows"
    assert not os.path.exists(cfg.rt("data", "stale.json"))
    # with a seed_command the command writes next to it, never over it
    cfg = _project(tmp_path / "b", "data/app.db", SEED_CMD)
    _put(cfg.data.prod_db, "live rows")
    cli.seed(cfg)
    assert open(cfg.data.prod_db).read() == "live rows"


def test_status_is_not_healthy_when_the_fleet_is_unreachable(tmp_path, monkeypatch, capsys):
    cfg = types.SimpleNamespace(name="t", prefix="immune-t", rt=lambda *a: str(tmp_path.joinpath(*a)),
                                ports={"gateway": 1, "admin": 2, "dashboard": 3, "fleet": 4})

    def http(method, url, **kw):
        if url.endswith("/state"):
            raise OSError("connection refused")
        return {}
    monkeypatch.setattr(cli, "docker", lambda *a, **kw: "")
    monkeypatch.setattr(cli, "host_pids", lambda cfg, name: (10, 11))
    monkeypatch.setattr(cli, "stack_secrets", lambda cfg: {"ADMIN_TOKEN": "t"})
    monkeypatch.setattr(cli, "http", http)
    assert cli.cmd_status(cfg) == 1
    out = capsys.readouterr().out
    assert "fleet     UNREACHABLE" in out and "NOT HEALTHY: fleet is unreachable" in out and "\nhealthy" not in out


def _secret_cfg(tmp_path):
    rt = tmp_path / "runtime"
    return types.SimpleNamespace(project_dir=str(tmp_path), runtime_dir=str(rt), rt=lambda *a: str(rt.joinpath(*a)),
                                 auth=types.SimpleNamespace(kind="immune-token"))


def test_the_builtin_demo_gets_random_secrets_not_the_committed_ones(tmp_path, monkeypatch):
    for k in cli.SECRET_KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(cli, "HOME", str(tmp_path))                 # the project is IMMUNE_HOME: the built-in demo
    cfg = _secret_cfg(tmp_path)
    sec = cli.stack_secrets(cfg)
    committed = cli._env_file(cli.DEMO_ENV)
    assert set(sec) == set(cli.SECRET_KEYS)
    assert all(len(v) == 32 and v != committed[k] for k, v in sec.items())
    assert len(set(sec.values())) == len(sec)
    assert oct(os.stat(cfg.rt("secrets.env")).st_mode)[-3:] == "600"
    assert cli.stack_secrets(cfg) == sec                            # generated once


def test_a_stack_that_is_already_running_keeps_the_secrets_it_was_started_with(tmp_path, monkeypatch):
    for k in cli.SECRET_KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(cli, "HOME", str(tmp_path))
    cfg = _secret_cfg(tmp_path)
    running = {k: "old-%d" % i for i, k in enumerate(cli.SECRET_KEYS)}
    _put(cfg.rt("stack", "containers.env"), "".join("%s=%s\n" % kv for kv in running.items())
         + "BUS_URL=http://dashboard:8090\n")
    assert cli.stack_secrets(cfg) == running                        # no secrets.env yet: adopted, then persisted
    assert cli._env_file(cfg.rt("secrets.env")) == running
