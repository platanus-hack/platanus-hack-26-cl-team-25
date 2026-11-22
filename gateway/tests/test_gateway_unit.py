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


# ---------------------------------------------------------------- state across a gateway restart
RULE = {"id": "rule-inc-0001", "incident": "inc-0001", "method": "GET", "route": "/api/products", "scope": "param",
        "param": {"in": "query", "name": "q"}, "ttl_s": 600}


async def test_restart_restores_upstream_rules_and_mode(tmp_path):
    from gateway.classifier import Rule
    path = tmp_path / "stack" / "gateway-state.json"
    cfg = Config(prod_addr="prod-blue:8000", prod_release="t0", run_id="run-1", state_path=str(path))
    gw = Gateway(cfg)
    await gw.start()
    try:
        await gw.switch_upstream("prod-green:8000", "abc123")
        gw.rules["rule-inc-0001"] = Rule(RULE)
        short = Rule(dict(RULE, id="rule-short", ttl_s=1))
        short.expires -= 5                                    # already expired when the gateway comes back
        gw.rules["rule-short"] = short
        gw.mode = "observe"
        gw.save_state()
    finally:
        await gw.stop()
    again = Gateway(Config(prod_addr="prod-blue:8000", prod_release="t0", run_id="run-1", state_path=str(path)))
    assert again.upstream == {"addr": "prod-green:8000", "release": "abc123"} and again.mode == "observe"
    assert list(again.rules) == ["rule-inc-0001"]
    r = again.rules["rule-inc-0001"]
    assert 590 < r.expires - __import__("time").time() <= 600 and r.applies("GET", "/api/products") is not None
    assert again.stats["release"] == "abc123"


def test_state_of_another_run_is_ignored(tmp_path):
    path = tmp_path / "gateway-state.json"
    path.write_text(json.dumps({"run_id": "old-run", "upstream": {"addr": "prod-green:8000", "release": "x"},
                                "mode": "observe", "rules": [dict(RULE, _expires=9e12)]}))
    gw = Gateway(Config(prod_addr="prod-blue:8000", prod_release="t0", run_id="new-run", state_path=str(path)))
    assert gw.upstream == {"addr": "prod-blue:8000", "release": "t0"} and gw.mode == "enforce" and not gw.rules


def test_unreadable_state_never_stops_the_gateway(tmp_path):
    path = tmp_path / "gateway-state.json"
    path.write_text("{not json")
    assert Gateway(Config(prod_addr="a:1", run_id="r", state_path=str(path))).upstream["addr"] == "a:1"
    path.write_text(json.dumps({"run_id": "r", "upstream": {"addr": 7}, "mode": "nope", "rules": [{"id": "x"}, 3]}))
    gw = Gateway(Config(prod_addr="a:1", run_id="r", state_path=str(path)))
    assert gw.upstream["addr"] == "a:1" and gw.mode == "enforce" and not gw.rules


def test_recording_is_bounded(tmp_path):
    from gateway.core import Recorder
    path = tmp_path / "rec" / "requests.jsonl"
    r = Recorder(str(path), max_bytes=2000)
    for i in range(100):
        r.write({"rid": "r%03d" % i, "pad": "x" * 50})
    files = sorted(p.name for p in path.parent.iterdir())
    assert files == ["requests.jsonl", "requests.jsonl.1"]
    assert path.stat().st_size < 2000 and (path.parent / "requests.jsonl.1").stat().st_size < 2200
    assert '"rid":"r099"' in path.read_text()                 # the newest lines are in the live file


# ---------------------------------------------------------------- malformed input and flaky upstream
import httpx
import pytest

from gateway.core import BadRequest, Ctx
from gateway.classifier import Who


def _scope(path=b"/api/products", headers=()):
    return {"type": "http", "method": "POST", "raw_path": path, "path": path.decode("latin-1"), "query_string": b"",
            "headers": list(headers)}


async def test_requests_that_cannot_be_read_are_refused_before_prod(monkeypatch):
    import gateway.core as core
    gw = Gateway(Config(prod_addr="a:1"))

    async def empty():
        return {"type": "http.request", "body": b"", "more_body": False}

    for scope, status in ((_scope(b"http://other.example/api/products"), 400),
                          (_scope(headers=[(b"content-length", str(core.MAX_BODY + 1).encode())]), 413),
                          (_scope(headers=[(b"content-length", b"abc")]), 400)):
        with pytest.raises(BadRequest) as e:
            await gw._read(scope, empty)
        assert e.value.status == status

    async def big():
        return {"type": "http.request", "body": b"x" * (1024 * 1024), "more_body": True}
    with pytest.raises(BadRequest) as e:           # no content-length (chunked) and it never ends
        await gw._read(_scope(), big)
    assert e.value.status == 413

    async def never():
        await asyncio.sleep(60)
    monkeypatch.setattr(core, "BODY_TIMEOUT_S", 0.2)
    with pytest.raises(BadRequest) as e:           # declared a body, never sent it
        await gw._read(_scope(), never)
    assert e.value.status == 408


def _ctx(method="GET", headers=()):
    return Ctx(rid="r1", t0=0.0, method=method, raw_path="/api/products", query="", headers=list(headers), hmap={},
               body=b"", who=Who(), session="gwsid:x", cookie_session=None, new_sid=None)


async def _gw_with(handler):
    gw = Gateway(Config(prod_addr="prod-blue:8000"))
    await gw.start()
    await gw.prod_client.aclose()
    gw.prod_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return gw


async def test_stale_upstream_connection_is_retried_only_when_safe():
    calls = []

    def handler(request):
        calls.append(request.method)
        if len(calls) == 1:
            raise httpx.RemoteProtocolError("Server disconnected without sending a response.")
        return httpx.Response(200, json={"ok": True})

    gw = await _gw_with(handler)
    try:
        up = await gw.to_prod(_ctx("GET"))
        assert up.status == 200 and calls == ["GET", "GET"] and gw.stats["prod_5xx"] == 0
        calls.clear()
        up = await gw.to_prod(_ctx("POST"))             # may have been executed: never replayed
        assert up.status == 502 and calls == ["POST"] and gw.stats["prod_5xx"] == 1
    finally:
        await gw.stop()


async def test_refused_connection_is_retried_for_any_method():
    calls = []

    def handler(request):
        calls.append(request.method)
        if len(calls) == 1:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(201)

    gw = await _gw_with(handler)
    try:
        assert (await gw.to_prod(_ctx("POST"))).status == 201 and calls == ["POST", "POST"]
    finally:
        await gw.stop()


async def test_unforwardable_request_is_a_400_and_not_a_production_error():
    gw = await _gw_with(lambda request: httpx.Response(200))
    try:
        up = await gw.to_prod(_ctx("GET", headers=[("cookie", "a=Āā")]))   # not encodable on the wire
        assert up.status == 400
        assert gw.stats["prod_5xx"] == 0 and gw.stats["prod_conn_errors"] == 0 and gw.stats["prod_requests"] == 0
    finally:
        await gw.stop()


async def test_events_that_matter_survive_a_bus_outage():
    from gateway.bus import Bus
    got, up = [], {"ok": False}

    async def app(scope, receive, send):
        body = b""
        while True:
            m = await receive()
            body += m.get("body", b"")
            if not m.get("more_body"):
                break
        if up["ok"]:
            got.extend(json.loads(body))
        await send({"type": "http.response.start", "status": 200 if up["ok"] else 503, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    bus = Bus("http://bus", "t", "run")
    bus.start()
    bus._task.cancel()

    async def worker():      # the real worker, over an in-memory transport
        import gateway.bus as gb
        orig = gb.httpx.AsyncClient
        gb.httpx.AsyncClient = lambda **kw: orig(transport=httpx.ASGITransport(app=app))
        try:
            await bus._worker()
        finally:
            gb.httpx.AsyncClient = orig
    task = asyncio.create_task(worker())
    try:
        bus.publish("request.classified", {"class": "clean"}, rid="r1")
        bus.publish("oracle.fired", {"verdict": "oracle"}, rid="r1")
        await asyncio.sleep(1.0)                    # bus down: telemetry dropped, the oracle event kept
        assert got == [] and bus.dropped == 1 and len(bus._kept) == 1
        up["ok"] = True
        bus.publish("request.routed", {"route": "prod"}, rid="r2")
        await asyncio.sleep(1.0)
        assert [e["type"] for e in got] == ["oracle.fired", "request.routed"]      # older first
        assert bus._kept == [] and bus.sent == 2
        up["ok"] = False
        bus.retry_s = 0.3
        bus.publish("rule.active", {"id": "x"})
        await asyncio.sleep(1.5)                    # down for longer than retry_s: given up, counted
        assert bus._kept == [] and bus.dropped == 2
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)     # let it restore httpx.AsyncClient


# ---------------------------------------------------------------- canary (a share of prod traffic on a new release)

async def test_canary_takes_its_share_and_is_counted_apart_from_the_stable_release():
    def handler(request):
        return httpx.Response(500 if request.url.host == "prod-green" else 200)

    gw = await _gw_with(handler)
    try:
        gw.start_canary("prod-green:8000", "r2", 0.25)
        for _ in range(400):
            await gw.to_prod(_ctx("GET"))
        view = gw.canary_view()
        can, stable = view["canary"], view["stable"]
        assert can["requests"] + stable["requests"] == 400 and 50 < can["requests"] < 160
        assert can["5xx"] == can["requests"] and stable["5xx"] == 0
        # the stable counters the deploy watch reads never saw the canary's errors
        assert gw.stats["prod_5xx"] == 0 and gw.stats["prod_requests"] == stable["requests"]
        gw.stop_canary("aborted")
        assert gw.canary is None
        await gw.to_prod(_ctx("GET"))
        assert gw.stats["prod_requests"] == stable["requests"] + 1
    finally:
        await gw.stop()


async def test_canary_that_refuses_connections_loses_the_request_and_the_client_does_not():
    def handler(request):
        if request.url.host == "prod-green":
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200)

    gw = await _gw_with(handler)
    try:
        gw.start_canary("prod-green:8000", "r2", 1.0)
        up = await gw.to_prod(_ctx("POST"))
        assert up.status == 200                                   # answered by the stable release
        can = gw.canary_view()["canary"]
        assert can == {"requests": 1, "5xx": 1, "4xx": 0, "conn_errors": 1}
        assert gw.stats["prod_requests"] == 1 and gw.stats["prod_5xx"] == 0
    finally:
        await gw.stop()


async def test_switching_to_the_canary_promotes_it_and_a_restart_forgets_it(tmp_path):
    gw = await _gw_with(lambda request: httpx.Response(404 if request.url.host == "prod-green" else 200))
    try:
        gw.start_canary("prod-green:8000", "r2", 1.0)
        ctx = _ctx("GET")
        await gw.to_prod(ctx)
        assert ctx.release == "r2" and gw.canary_view()["canary"]["4xx"] == 1
        await gw.switch_upstream("prod-green:8000", "r2")
        assert gw.canary is None and gw.upstream == {"addr": "prod-green:8000", "release": "r2"}
        assert "canary" not in gw._state_doc()
    finally:
        await gw.stop()
