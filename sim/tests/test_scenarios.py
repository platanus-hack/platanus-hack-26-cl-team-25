import json
import re

import yaml

from .conftest import ROOT
from sim.scenarios import SCENARIOS


def run_all(client, manifest):
    return [s for sc in SCENARIOS for s in sc(client, manifest)]


class Spy:
    """Wraps a TestClient and records every (method, path) sent."""

    def __init__(self, client):
        self._c = client
        self.seen = []

    def request(self, method, url, **kw):
        self.seen.append((method.upper(), url.split("?")[0]))
        return self._c.request(method, url, **kw)

    def __getattr__(self, name):
        return getattr(self._c, name)


def test_deterministic_on_fresh_seeds(make_client, manifest):
    a = run_all(make_client(), manifest)
    b = run_all(make_client(), manifest)
    assert a and json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_step_shape_and_no_volatile_values(make_client, manifest):
    steps = run_all(make_client(), manifest)
    for s in steps:
        assert set(s) == {"step", "method", "path", "status", "body"}
    blob = json.dumps(steps)
    assert not re.search(r"[A-Za-z0-9_-]{16,}\.[0-9a-f]{64}", blob)
    assert "<token>" in blob
    assert not re.search(r"MK[A-Z0-9]{10}", blob)
    assert not any(s["status"] >= 500 for s in steps), [s for s in steps if s["status"] >= 500]


def test_awkward_inputs_and_expected_statuses(make_client, manifest):
    steps = {s["step"]: s for s in run_all(make_client(), manifest)}
    assert steps["register O'Brien"]["status"] == 201
    assert steps["mistyped url"]["status"] == 404
    assert steps["me without token"]["status"] == 401
    assert steps["admin orders as user"]["status"] == 403
    assert steps["admin orders (seeded rows)"]["status"] == 200
    assert steps["search normal word"]["status"] == 200 and steps["search normal word"]["body"]["total"] > 0
    assert steps["search with hyphen"]["body"]["total"] > 0
    assert steps["manual audifonos.pro.guia.txt"]["status"] == 200
    note = steps["own order"]["body"]["note"]
    assert "María" in note and "'" in note
    assert not any("'" in s["path"].split("?", 1)[-1] for s in steps.values() if s["path"].startswith("/api/products?"))


def test_covers_every_openapi_route(make_client, manifest):
    spec = yaml.safe_load(open(ROOT + "/contracts/openapi.yaml"))
    wanted = {}
    for path, ops in spec["paths"].items():
        rx = re.compile("^" + re.sub(r"\{[^}]+\}", r"[^/]+", path) + "$")
        for method in ops:
            wanted[(method.upper(), path)] = rx
    spy = Spy(make_client())
    for sc in SCENARIOS:
        sc(spy, manifest)
    hit = {key for key, rx in wanted.items() for m, p in spy.seen if m == key[0] and rx.match(p)}
    assert hit == set(wanted), "not covered: %s" % sorted(set(wanted) - hit)
