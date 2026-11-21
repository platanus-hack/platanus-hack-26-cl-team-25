"""`immune up` resumes a stack that already ran instead of going back to t0; port conflicts are named."""
import json
import os
import socket
import types

import pytest

from immune import __main__ as cli


def project(tmp_path, runtime="python-asgi", ports=None):
    rt = tmp_path / "runtime"

    def path(*a):
        return str(rt.joinpath(*a))
    return types.SimpleNamespace(
        name="t", prefix="immune-t", rt=path, release_dir=lambda r: path("releases", r), ports=ports or {},
        dot_immune=str(tmp_path / ".immune"), app=types.SimpleNamespace(runtime=runtime))


def record(cfg, run_id="0101-000000", state_run=None, release="abc123"):
    os.makedirs(cfg.rt("stack"), exist_ok=True)
    open(cfg.rt("run_id"), "w").write(run_id + "\n")
    json.dump({"run_id": state_run or run_id, "active": "green", "release": release, "pool_size": 4},
              open(cfg.rt("stack", "fleet-state.json"), "w"))


def test_a_recorded_run_is_resumed(tmp_path):
    cfg = project(tmp_path)
    assert cli.existing_run(cfg) is None                        # never ran
    record(cfg)
    assert cli.existing_run(cfg) is None                        # the recorded release is not on disk
    os.makedirs(cfg.release_dir("abc123"))
    assert cli.existing_run(cfg) == "0101-000000"


def test_state_of_another_run_or_garbage_is_not_resumed(tmp_path):
    cfg = project(tmp_path)
    os.makedirs(cfg.release_dir("abc123"))
    record(cfg, state_run="0909-999999")                        # fleet state left by an older run
    assert cli.existing_run(cfg) is None
    open(cfg.rt("stack", "fleet-state.json"), "w").write("{broken")
    assert cli.existing_run(cfg) is None


def test_port_conflict_names_the_port_and_the_config_key(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    busy = s.getsockname()[1]
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    free_port = free.getsockname()[1]
    free.close()
    cfg = project(tmp_path, ports={"gateway": busy, "dashboard": free_port})
    try:
        cli.check_ports(cfg, ["dashboard"])                     # free: nothing to say
        with pytest.raises(cli.CliError) as e:
            cli.check_ports(cfg, ["gateway", "dashboard"])
        assert "%d (ports.gateway)" % busy in str(e.value) and "config.yaml" in str(e.value)
        assert "ports.dashboard" not in str(e.value)
    finally:
        s.close()


def test_unit_names_are_safe_for_systemd(tmp_path):
    cfg = project(tmp_path)
    cfg.name = "my app/1"
    assert cli._unit(cfg, "fleet") == "immune-my-app-1-fleet"
