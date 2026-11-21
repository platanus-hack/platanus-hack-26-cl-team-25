import json

import httpx
import pytest

from immune_contracts import wire
from sidecar.core import Config, Sidecar, verdict_of

MARKERS = {"MKAAAAAAAAAA": {"path": "/etc/grafana/grafana.ini"}}


def scope(path, headers=()):
    return {"type": "http", "method": "GET", "path": path, "raw_path": path.encode(), "query_string": b"",
            "headers": [(k.encode(), v.encode()) for k, v in headers]}


def make(body: bytes, status=200):
    seen, pushed = {}, []

    def app(req: httpx.Request):
        seen["target"] = req.extensions.get("target")
        seen["headers"] = dict(req.headers)
        return httpx.Response(status, content=body)

    def collector(req: httpx.Request):
        pushed.append((req.headers.get(wire.H_SIGNATURE), req.content))
        return httpx.Response(200, json={"ok": True})

    sc = Sidecar(Config(upstream="shadow:3000", markers=MARKERS, clone_key="k", collector_url="http://gw:9000"))
    sc.client = httpx.AsyncClient(transport=httpx.MockTransport(app))
    sc.push_client = httpx.AsyncClient(transport=httpx.MockTransport(collector))
    return sc, seen, pushed


async def test_marker_in_response_is_oracle_and_pushes_signed_evidence():
    sc, seen, pushed = make(b"[security]\nsecret_key = MKAAAAAAAAAA\n")
    path = "/public/plugins/x/../../etc/grafana/grafana.ini"
    status, headers, _ = await sc.handle(scope(path, [("x-imm-rid", "r1"), ("x-imm-mode", "L1"), ("accept", "*/*")]), b"")
    h = dict(headers)
    assert status == 200 and h[wire.H_VERDICT] == "oracle" and h[wire.H_EVENTS] == "1"
    assert seen["target"] == path.encode()                       # dot segments reach the shadow app unchanged
    assert not any(k.startswith("x-imm-") for k in seen["headers"])
    sig, raw = pushed[0]
    assert wire.check("k", raw, sig)
    ev = json.loads(raw)
    assert ev["rid"] == "r1" and ev["events"][0]["oracle"] == "file"
    assert ev["events"][0]["detail"]["path"] == "/etc/grafana/grafana.ini"


async def test_no_marker_is_clean_and_nothing_pushed():
    sc, _, pushed = make(b'{"id":"alertlist"}')
    _, headers, _ = await sc.handle(scope("/public/plugins/alertlist/plugin.json"), b"")
    assert dict(headers)[wire.H_VERDICT] == "clean" and not pushed


@pytest.mark.parametrize("status,events,v", [(404, [], "inconclusive"), (500, [], "inconclusive"),
                                             (302, [], "clean"), (404, [1], "oracle")])
def test_verdict(status, events, v):
    assert verdict_of(status, events) == v
