"""The canary decision, without Docker: a scripted gateway and the Fleet methods that judge it."""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fleet.manager import Fleet, GatewayError  # noqa: E402


class Gw:
    def __init__(self, views, supported=True):
        self.views, self.supported, self.started, self.stopped = list(views), supported, [], 0

    def start_canary(self, addr, release, weight):
        if not self.supported:
            raise GatewayError("POST /_admin/canary: 404")
        self.started.append((addr, release, weight))

    def stop_canary(self):
        self.stopped += 1

    def stats(self):
        v = self.views.pop(0) if len(self.views) > 1 else self.views[0]
        return {"canary": v}


def fleet(gw, **over):
    f = Fleet.__new__(Fleet)
    cfg = dict(canary_weight=0.1, canary_s=0.4, canary_min_requests=20, watch_poll_s=0.05)
    cfg.update(over)
    f.cfg, f.gw = types.SimpleNamespace(**cfg), gw
    f._addr = lambda colour: "prod-%s:8000" % colour
    return f


def view(release="r2", **sides):
    side = lambda **kw: {"requests": 0, "5xx": 0, "4xx": 0, "conn_errors": 0, **kw}  # noqa: E731
    return {"release": release, "canary": side(**sides.get("canary", {})), "stable": side(**sides.get("stable", {}))}


def test_same_behaviour_with_enough_traffic_passes():
    gw = Gw([view(canary={"requests": 40, "4xx": 4}, stable={"requests": 360, "4xx": 40})])
    out = fleet(gw)._canary("r2", "green")
    assert out["verdict"] == "ok" and gw.started == [("prod-green:8000", "r2", 0.1)] and gw.stopped == 0


def test_more_5xx_than_the_current_release_aborts_before_the_window_ends():
    gw = Gw([view(canary={"requests": 30, "5xx": 9}, stable={"requests": 270, "5xx": 1})])
    out = fleet(gw, canary_s=30)._canary("r2", "green")
    assert out["verdict"] == "worse" and "5xx" in out["detail"] and gw.stopped == 1 and out["seconds"] < 5


def test_a_fix_that_refuses_legitimate_requests_aborts_on_4xx():
    gw = Gw([view(canary={"requests": 40, "4xx": 16}, stable={"requests": 360, "4xx": 18})])
    out = fleet(gw)._canary("r2", "green")
    assert out["verdict"] == "worse" and "4xx" in out["detail"] and gw.stopped == 1


def test_errors_the_current_release_also_has_are_not_held_against_the_canary():
    gw = Gw([view(canary={"requests": 40, "5xx": 4, "4xx": 12}, stable={"requests": 360, "5xx": 36, "4xx": 100})])
    assert fleet(gw)._canary("r2", "green")["verdict"] == "ok"


def test_too_little_traffic_proves_nothing_and_falls_back_to_the_plain_watch():
    gw = Gw([view(canary={"requests": 3, "5xx": 3}, stable={"requests": 30})])
    out = fleet(gw)._canary("r2", "green")
    assert out["verdict"] == "skipped" and "3 request" in out["detail"] and gw.stopped == 0


def test_no_traffic_at_all_does_not_wait_for_the_whole_window():
    out = fleet(Gw([view()]), canary_s=30)._canary("r2", "green")
    assert out["verdict"] == "skipped" and out["seconds"] < 5


def test_off_unsupported_or_lost_canary_is_skipped():
    gw = Gw([view()])
    assert fleet(gw, canary_weight=0)._canary("r2", "green")["verdict"] == "skipped" and gw.started == []
    assert fleet(Gw([view()], supported=False))._canary("r2", "green")["verdict"] == "skipped"
    assert fleet(Gw([None]))._canary("r2", "green")["detail"] == "the gateway lost the canary"
    assert fleet(Gw([view(release="other")]))._canary("r2", "green")["verdict"] == "skipped"


# ---------------------------------------------------------------- against a real gateway, over HTTP

def _real_gateway(handler):
    """A real Gateway (admin API on a local port, mocked releases behind it) and a thread sending it prod traffic."""
    import asyncio
    import socket
    import threading
    import time

    import httpx
    import uvicorn

    from gateway.classifier import Who
    from gateway.core import Config as GwConfig, Ctx, Gateway

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    box, stop = {}, threading.Event()

    async def main():
        gw = Gateway(GwConfig(prod_addr="prod-blue:8000", admin_token="t"))
        await gw.start()
        await gw.prod_client.aclose()
        gw.prod_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        server = uvicorn.Server(uvicorn.Config(gw.admin_app(), host="127.0.0.1", port=port, log_level="error"))
        serve = asyncio.create_task(server.serve())
        box["gw"] = gw
        while not stop.is_set():
            await gw.to_prod(Ctx(rid="r", t0=0.0, method="GET", raw_path="/x", query="", headers=[], hmap={},
                                 body=b"", who=Who(), session="s", cookie_session=None, new_sid=None))
            await asyncio.sleep(0.002)
        server.should_exit = True
        await serve
        await gw.stop()

    th = threading.Thread(target=lambda: asyncio.run(main()), daemon=True)
    th.start()
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            if httpx.get("http://127.0.0.1:%d/_admin/canary" % port, headers={"x-admin-token": "t"}).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.05)
    return box, port, lambda: (stop.set(), th.join(10))


def _fleet_for(port, **over):
    from fleet.manager import Gateway as GwClient
    f = fleet(None, **over)
    f.gw = GwClient(types.SimpleNamespace(gateway_url="http://127.0.0.1:%d" % port, admin_token="t"))
    return f


def test_real_gateway_broken_release_is_dropped_and_clients_stay_on_the_old_one():
    import httpx
    box, port, close = _real_gateway(lambda r: httpx.Response(500 if r.url.host == "prod-green" else 200))
    try:
        out = _fleet_for(port, canary_weight=0.2, canary_s=20)._canary("r2", "green")
        assert out["verdict"] == "worse" and out["seconds"] < 10, out
        assert out["canary"]["5xx"] == out["canary"]["requests"] >= 20 and out["stable"]["5xx"] == 0
        gw = box["gw"]
        assert gw.canary is None and gw.upstream["addr"] == "prod-blue:8000" and gw.stats["prod_5xx"] == 0
    finally:
        close()


def test_real_gateway_healthy_release_passes_and_the_switch_promotes_it():
    import httpx
    box, port, close = _real_gateway(lambda r: httpx.Response(200))
    try:
        f = _fleet_for(port, canary_weight=0.2, canary_s=1.5)
        out = f._canary("r2", "green")
        assert out["verdict"] == "ok" and out["canary"]["requests"] >= 20, out
        assert box["gw"].canary is not None                      # still serving its share until the switch
        f.gw.set_upstream("prod-green:8000", "r2")
        assert box["gw"].canary is None and box["gw"].upstream == {"addr": "prod-green:8000", "release": "r2"}
    finally:
        close()
