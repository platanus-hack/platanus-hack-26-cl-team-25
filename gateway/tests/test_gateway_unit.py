import asyncio, json

from immune_contracts import authtoken

from gateway import l0
from gateway.core import Config, Gateway


def test_l0_paths_and_content():
    for p in ("/.env", "/wp-login.php", "/actuator/env", "/.git/config", "/phpmyadmin/", "/phpmyadmin/index.php"):
        assert l0.is_scanner_path(p), p
        status, ctype, body = l0.respond(p, "s")
        assert status == 200 and body
    assert not l0.is_scanner_path("/api/products") and not l0.is_scanner_path("/random")
    assert l0.respond("/.env", "a") == l0.respond("/.env", "a") != l0.respond("/.env", "b")
    json.loads(l0.respond("/actuator/env", "s")[2])


def test_missing_manifest_is_tolerated_and_reloaded(tmp_path):
    path = tmp_path / "manifest.json"
    gw = Gateway(Config(manifest_path=str(path), prod_secret="p", shadow_secret="s"))
    assert gw.manifest.seed_max_uid == 0 and gw.manifest.canaries == {}
    assert gw.identify({"authorization": "Bearer " + authtoken.mint("p", 3)}).trusted is False
    path.write_text(json.dumps({"seed_max_uid": 5, "canaries": {"order_id": [9]}}))
    gw.reload_manifest()
    assert gw.manifest.seed_max_uid == 5 and gw.manifest.canaries == {"order_id": {"9"}}
    who = gw.identify({"authorization": "Bearer " + authtoken.mint("p", 3)})
    assert who.uid == 3 and who.trusted
    assert gw.identify({"authorization": "Bearer " + authtoken.mint("s", 3, ttl=-100)}).honeytoken  # expired honeytoken
    assert gw.identify({"authorization": "Bearer garbage"}).uid is None


async def test_upstream_switch_drains_in_flight():
    gw = Gateway(Config(prod_addr="a:1"))
    await gw.start()
    try:
        gw.inflight = 1; gw.idle.clear()          # one prod request in flight
        task = asyncio.create_task(gw.switch_upstream("b:2", "r2"))
        await asyncio.sleep(0.05)
        assert not task.done() and gw.upstream["addr"] == "a:1" and not gw.gate.is_set()
        gw.inflight = 0; gw.idle.set()
        await asyncio.wait_for(task, 1)
        assert gw.upstream == {"addr": "b:2", "release": "r2"} and gw.gate.is_set()
        assert gw.stats["prod_requests"] == 0 and gw.stats["release"] == "r2"
    finally:
        await gw.stop()
