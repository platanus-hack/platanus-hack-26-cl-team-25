import httpx

from immune_contracts import wire
from sidecar.httpds.core import Config, Sidecar, consumed_points, verdict_of

MANIFEST = {"point_params": ["tank_level", "pump_cmd"], "reserved_keys": ["__device", "__time"],
            "reserved_prefixes": ["__point", "__value", "__time"]}


def scope(path, query=b"", method="GET", headers=()):
    return {"type": "http", "method": method, "path": path, "raw_path": path.encode(), "query_string": query,
            "headers": [(k.encode(), v.encode()) for k, v in headers]}


def make(body: bytes, status=200):
    seen, pushed = {}, []

    def app(req: httpx.Request):
        seen["target"] = req.extensions.get("target")
        return httpx.Response(status, content=body)

    def collector(req: httpx.Request):
        pushed.append((req.headers.get(wire.H_SIGNATURE), req.content))
        return httpx.Response(200, json={"ok": True})

    sc = Sidecar(Config(upstream="shadow:8080", manifest=MANIFEST, clone_key="k", collector_url="http://gw:9000"))
    sc.client = httpx.AsyncClient(transport=httpx.MockTransport(app))
    sc.push_client = httpx.AsyncClient(transport=httpx.MockTransport(collector))
    return sc, seen, pushed


def test_consumed_points_discriminates_landed_from_ignored():
    # ScadaBR leaves a "Unconsumed key" line for every parameter no point took.
    assert consumed_points("__device=gw1&tank_level=777", b"", MANIFEST) == ["tank_level"]
    assert consumed_points("__device=gw1&tank_level=777", b"Unconsumed key: tank_level\n", MANIFEST) == []
    assert consumed_points("__device=gw1&unknown=1", b"Unconsumed key: unknown\n", MANIFEST) == []
    # reserved keys are never points
    assert consumed_points("__device=gw1&__time=123", b"", MANIFEST) == []


async def test_landed_injection_is_oracle_and_pushes_signed_evidence():
    sc, seen, pushed = make(b"")  # empty body == every parameter consumed
    status, headers, _ = await sc.handle(
        scope("/ScadaBR/httpds", b"__device=gw1&tank_level=777",
              headers=[("x-imm-rid", "r1"), ("x-imm-mode", "L1")]), b"")
    h = dict(headers)
    assert status == 200 and h[wire.H_VERDICT] == "oracle" and h[wire.H_EVENTS] == "1"
    assert len(pushed) == 1 and pushed[0][0]  # signed
    assert wire.check("k", pushed[0][1], pushed[0][0])


async def test_ignored_injection_is_clean_no_push():
    sc, _, pushed = make(b"Unconsumed key: tank_level\n")
    status, headers, _ = await sc.handle(
        scope("/ScadaBR/httpds", b"__device=evil&tank_level=777", headers=[("x-imm-rid", "r2")]), b"")
    h = dict(headers)
    assert status == 200 and h[wire.H_VERDICT] == "clean" and h[wire.H_EVENTS] == "0"
    assert pushed == []


async def test_non_httpds_route_never_fires():
    sc, _, pushed = make(b"<html>login</html>")
    _, headers, _ = await sc.handle(scope("/ScadaBR/login.htm", headers=[("x-imm-rid", "r3")]), b"")
    assert dict(headers)[wire.H_VERDICT] == "clean" and pushed == []


async def test_post_form_receiver_is_scanned():
    sc, _, pushed = make(b"")
    _, headers, _ = await sc.handle(
        scope("/ScadaBR/httpds", b"", method="POST",
              headers=[("x-imm-rid", "r4"), ("content-type", "application/x-www-form-urlencoded")]),
        b"__device=gw1&pump_cmd=1")
    assert dict(headers)[wire.H_VERDICT] == "oracle"


def test_verdict_inconclusive_on_error_status():
    assert verdict_of(404, []) == wire.VERDICT_INCONCLUSIVE
    assert verdict_of(500, []) == wire.VERDICT_INCONCLUSIVE
    assert verdict_of(200, []) == wire.VERDICT_CLEAN


# ---- where in the app's code: the servlet that handled the request (sidecar/servlets.py) ----
def _servlet_index(tmp_path):
    from sidecar import servlets
    from sidecar.tests.test_servlets import make_class
    cdir = tmp_path / "classes" / "com" / "acme"
    cdir.mkdir(parents=True)
    (cdir / "HttpDataSourceServlet.class").write_bytes(
        make_class("HttpDataSourceServlet.java", {"doGet": [79], "doPost": [84]}, "com/acme/HttpDataSourceServlet"))
    (tmp_path / "web.xml").write_text(
        "<web-app><servlet><servlet-name>h</servlet-name><servlet-class>com.acme.HttpDataSourceServlet</servlet-class>"
        "</servlet><servlet-mapping><servlet-name>h</servlet-name><url-pattern>/httpds</url-pattern>"
        "</servlet-mapping></web-app>")
    return servlets.ServletIndex.load(str(tmp_path / "web.xml"), str(tmp_path / "classes"), context="/ScadaBR")


async def test_oracle_event_names_the_servlet_that_handled_the_request(tmp_path):
    sc, _, pushed = make(b"")
    sc.cfg.servlets = _servlet_index(tmp_path)
    await sc.handle(scope("/ScadaBR/httpds", b"__device=gw1&tank_level=777", headers=[("x-imm-rid", "r1")]), b"")
    import json
    evidence = json.loads(pushed[0][1])
    assert evidence["events"][0]["stack"] == [
        {"file": "src/com/acme/HttpDataSourceServlet.java", "line": 79, "func": "doGet"}]


async def test_stack_stays_empty_without_a_servlet_index():
    sc, _, pushed = make(b"")
    await sc.handle(scope("/ScadaBR/httpds", b"__device=gw1&tank_level=777", headers=[("x-imm-rid", "r1")]), b"")
    import json
    assert json.loads(pushed[0][1])["events"][0]["stack"] == []
