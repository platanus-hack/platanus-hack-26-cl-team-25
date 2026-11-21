import time

import pytest
from fastapi.testclient import TestClient

from fleet.app import create_app
from fleet.manager import FleetError
from .conftest import TOKEN, sh

NOTES = "import sqlite3;print(sqlite3.connect('/data/app.db').execute('select count(*) from notes').fetchone()[0])"
ADD = "import sqlite3;c=sqlite3.connect('/data/app.db');c.execute(\"insert into notes(user_id,body) values (1,'before deploy')\");c.commit()"


def ctr(env, name):
    return env.dk.containers.get(f"wp4-{name}")


def test_reset_layout_and_hardening(env):
    res = env.fleet.reset("r1", 2)
    assert res["ok"] and not res["gateway_errors"]
    prod = ctr(env, "prod-blue")
    run = env.cfg.run_id
    assert prod.labels["immune.run"] == run and prod.labels["immune.role"] == "prod"
    nets = prod.attrs["NetworkSettings"]["Networks"]
    assert list(nets) == [env.cfg.prodnet] and "prod-blue" in nets[env.cfg.prodnet]["Aliases"]
    assert env.nets[0].attrs["Internal"] and env.nets[1].attrs["Internal"]
    for c in [prod, ctr(env, "clone-1"), ctr(env, "clone-2")]:
        hc = c.attrs["HostConfig"]
        assert hc["ReadonlyRootfs"] and hc["CapDrop"] == ["ALL"] and "no-new-privileges:true" in hc["SecurityOpt"]
        assert hc["PidsLimit"] > 0 and hc["Memory"] > 0 and "/tmp" in hc["Tmpfs"]
    mounts = {m["Destination"]: m for m in prod.attrs["Mounts"]}
    assert mounts["/srv"]["RW"] is False and mounts["/srv/fixture_app"]["RW"] is False
    assert mounts["/srv/fixture_app"]["Source"].endswith("releases/r1/fixture_app")
    assert mounts["/data"]["RW"] is True and mounts["/data"]["Source"] == env.prod
    envs = dict(e.split("=", 1) for e in prod.attrs["Config"]["Env"])
    assert envs["APP_SECRET"] == "ps" and envs["APP_DB"] == "/data/app.db" and envs["APP_STATIC"] == "/srv/fixture_app/static"
    for n in (1, 2):
        c = ctr(env, f"clone-{n}")
        assert c.labels["immune.role"] == "clone" and c.labels["immune.run"] == run
        assert list(c.attrs["NetworkSettings"]["Networks"]) == [env.cfg.clonenet]
        e = dict(x.split("=", 1) for x in c.attrs["Config"]["Env"])
        assert e["CLONE_ID"] == f"clone-{n}" and len(e["CLONE_KEY"]) >= 32 and e["COLLECTOR_URL"] == "http://gateway:9000"
        assert e["SHADOW_SEED_DB"] == "/seed/seed.db" and e["APP_DB"] == "/data/app.db" and e["RELEASE"] == "r1"
        assert e["APP_SECRET"] == "ss"
        m = {x["Destination"]: x for x in c.attrs["Mounts"]}
        assert m["/seed"]["RW"] is False and "/data" in c.attrs["HostConfig"]["Tmpfs"]
    gw = env.gw
    assert sorted(c["addr"] for c in gw.puts[-1]) == ["wp4-clone-1:8000", "wp4-clone-2:8000"]
    assert gw.upstream == {"addr": "prod-blue:8000", "release": "r1"} and gw.resets == 1
    assert env.fleet.state()["prod"] == {"active": "blue", "release": "r1"}


def test_deploy_switches_and_keeps_data(env):
    env.fleet.reset("r1", 2)
    code, _ = sh(ctr(env, "prod-blue"), ADD)
    assert code == 0
    res = env.fleet.deploy("r2")
    assert res["ok"] and not res["rolled_back"] and res["active"] == "green"
    assert env.gw.upstream == {"addr": "prod-green:8000", "release": "r2"}
    code, out = sh(ctr(env, "prod-green"), NOTES)
    assert code == 0 and out.strip() == "3"  # 2 seed + the one written before the deploy
    names = [c.name for c in env.dk.containers.list(all=True, filters={"label": f"immune.run={env.cfg.run_id}"})]
    assert "wp4-prod-blue" not in names and "wp4-prod-green" in names
    assert {c["release"] for c in env.gw.puts[-1]} == {"r2"} and len(env.gw.puts[-1]) == 2
    clones = [c for c in env.fleet.state()["clones"]]
    assert len(clones) == 2 and all(c["release"] == "r2" for c in clones)
    assert sorted(n for n in names if "clone" in n) == sorted(c["name"] for c in clones)


def test_deploy_skips_captive_clones(env):
    env.fleet.reset("r1", 2)
    env.gw.pool["clone-1"]["state"] = "captive"
    res = env.fleet.deploy("r2")
    assert res["ok"]
    st = {c["id"]: c["release"] for c in env.fleet.state()["clones"]}
    assert st["clone-1"] == "r1" and len(st) == 2 and "clone-2" not in st
    ctr(env, "clone-1")  # still there


def test_unhealthy_release_never_becomes_upstream(env):
    env.fleet.reset("r1", 1)
    before = list(env.gw.upstreams)
    res = env.fleet.deploy("rbad")
    assert not res["ok"] and not res["rolled_back"] and "health" in res["detail"]
    assert env.gw.upstreams == before
    assert env.fleet.state()["prod"] == {"active": "blue", "release": "r1"}
    assert not [c for c in env.dk.containers.list(all=True) if c.name == "wp4-prod-green"]
    ctr(env, "prod-blue")


def test_rising_5xx_rolls_back(env):
    env.fleet.reset("r1", 1)
    env.gw.bump_after_switch = 5
    res = env.fleet.deploy("r2")
    assert not res["ok"] and res["rolled_back"]
    assert env.gw.upstream == {"addr": "prod-blue:8000", "release": "r1"}
    assert env.fleet.state()["prod"] == {"active": "blue", "release": "r1"}
    assert not [c for c in env.dk.containers.list(all=True) if c.name == "wp4-prod-green"]
    ctr(env, "prod-blue")


def test_retired_clone_replaced_via_api_loop(env):
    cfg = env.cfg
    with TestClient(create_app(cfg, env.fleet)) as cl:
        h = {"x-admin-token": TOKEN}
        assert cl.get("/state").status_code == 401
        assert cl.post("/reset", json={"release": "r1", "pool_size": 2}, headers=h).json()["ok"]
        old = ctr(env, "clone-1").id
        env.gw.pool["clone-1"]["state"] = "retired"
        for _ in range(60):
            ids = {c["id"] for c in cl.get("/state", headers=h).json()["clones"]}
            if "clone-3" in ids and "clone-1" not in ids and "clone-3" in env.gw.pool and "clone-1" not in env.gw.pool:
                break
            time.sleep(0.5)
        else:
            pytest.fail(f"not replaced: {ids}")
        assert ids == {"clone-2", "clone-3"}
        assert not [c for c in env.dk.containers.list(all=True) if c.id == old]
        assert ctr(env, "clone-3").labels["immune.role"] == "clone"
        assert cl.post("/deploy", json={"release": "../x"}, headers=h).status_code == 400


def test_never_removes_unlabelled(env):
    other = env.dk.containers.create("immune-base:1", ["sleep", "300"], name="wp4-other")
    clash = env.dk.containers.create("immune-base:1", ["sleep", "300"], name="wp4-prod-blue")
    try:
        with pytest.raises(FleetError):
            env.fleet.reset("r1", 1)
        env.dk.containers.get("wp4-prod-blue")  # untouched
        clash.remove(force=True)
        env.fleet.reset("r1", 1)  # reset sweeps only labelled containers
        env.dk.containers.get("wp4-other")
    finally:
        for c in (other, clash):
            try:
                c.remove(force=True)
            except Exception:
                pass


def test_gateway_down(env):
    env.gw.stop()
    env.cfg.gateway_url = "http://127.0.0.1:1"
    env.fleet.gw.cfg = env.cfg
    res = env.fleet.reset("r1", 2)
    assert res["ok"] and res["gateway_errors"]
    victim = ctr(env, "clone-1")
    victim.remove(force=True)
    for _ in range(3):
        env.fleet.reconcile_once()  # must not raise, keeps retrying the gateway
    st = env.fleet.state()
    assert len(st["clones"]) == 2 and not st["gateway_ok"]
    assert "clone-1" not in {c["id"] for c in st["clones"]}
    for c in st["clones"]:
        env.dk.containers.get(c["name"])
