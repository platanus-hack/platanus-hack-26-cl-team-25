"""The OWASP-CRS WAF client is fail-open, and an anomaly upgrades an otherwise-clean request to suspect
(so it detonates in a clone) -- it never blocks."""
import httpx

from gateway.classifier import CLEAN, SUSPECT, Result, Who
from gateway.core import Ctx, Gateway, Config
from gateway.waf import WafClient


def client(handler):
    c = WafClient("http://waf:8080")
    c.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c


async def test_waf_client_reports_anomaly():
    c = client(lambda req: httpx.Response(200, json={"anomalous": True, "rule_id": 949110}))
    v = await c.check("GET", "/search", "q=1' OR '1'='1", {"host": "x"}, b"")
    assert v and v["anomalous"] is True and v["rule_id"] == 949110


async def test_waf_client_is_fail_open_on_error_and_non_200():
    down = client(lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused")))
    assert await down.check("GET", "/x", "", {}, b"") is None          # connection error -> None
    bad = client(lambda req: httpx.Response(502, text="bad gateway"))
    assert await bad.check("GET", "/x", "", {}, b"") is None           # non-200 -> None


def _ctx(res):
    return Ctx(rid="r", t0=0.0, method="GET", raw_path="/search", query="q=1' OR '1'='1", headers=[],
               hmap={"host": "x"}, body=b"", who=Who(), session="s", cookie_session=None, new_sid=None, res=res)


async def test_clean_request_is_upgraded_to_suspect_on_anomaly():
    gw = Gateway(Config(admin_token="t"))
    gw.waf = client(lambda req: httpx.Response(200, json={"anomalous": True, "rule_id": 949110}))
    ctx = _ctx(Result(cls=CLEAN))
    await gw._waf_upgrade(ctx)
    assert ctx.res.cls == SUSPECT and "waf:949110" in ctx.res.reasons


async def test_clean_stays_clean_when_waf_is_off_or_benign():
    gw = Gateway(Config(admin_token="t"))                              # no waf_url -> gw.waf is None
    ctx = _ctx(Result(cls=CLEAN))
    await gw._waf_upgrade(ctx)
    assert ctx.res.cls == CLEAN
    gw.waf = client(lambda req: httpx.Response(200, json={"anomalous": False}))
    await gw._waf_upgrade(ctx)
    assert ctx.res.cls == CLEAN
