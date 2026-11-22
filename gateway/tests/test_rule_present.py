"""A `param_present` rule: every request that carries the parameter is detonated; the grammar only decides an
inconclusive clone. Rules have no ttl by default and survive a gateway restart."""
import json

import httpx
from starlette.testclient import TestClient

from gateway.core import Config, Gateway

from .test_auth_observe import ADMIN, world  # noqa: F401  (world is a fixture)

AUTH = {"kind": "immune-token"}
RULE = {"id": "rule-i1", "incident": "i1", "method": "GET", "route": "/search",
        "param": {"in": "query", "name": "q"}, "scope": "param_present", "ttl_s": None}


def rule_state(w):
    return httpx.get(w.admin + "/_admin/rules", headers=ADMIN).json()["rules"][0]


def test_every_request_with_the_parameter_is_detonated(world):
    w = world(AUTH)
    assert httpx.post(w.admin + "/_admin/rules", json=RULE, headers=ADMIN).status_code == 201
    assert rule_state(w)["expires_in"] is None                       # no clock: it lives until it is deleted
    with httpx.Client(base_url=w.url) as c:
        # a plain value: clean for the base classifier, detonated because of the rule, then served by prod
        assert c.get("/search", params={"q": "usb"}).json() == {"from": "prod"}
        assert [x["query"] for x in w.clone_seen] == ["q=usb"]
        # the parameter is absent: the rule does not apply
        assert c.get("/search").json() == {"from": "prod"}
        assert len(w.clone_seen) == 1
        # inconclusive clone, value inside the grammar (a real user's 401 in the shadow): prod answers
        assert c.get("/search", params={"q": "UNSURE"}).json() == {"from": "prod"}
        # inconclusive clone, value outside the grammar: denied
        assert c.get("/search", params={"q": "UNSURE' --"}).status_code == 404
        assert rule_state(w)["stats"] == {"hits": 3, "oracle": 0, "denied": 1}
        # only letters and spaces, so no character check would stop it: the clone's oracle does
        seen = len(w.prod_seen)
        r = c.get("/search", params={"q": "ATTACK UNION SELECT email FROM users"})
        assert r.json()["synthetic"] is True and len(w.prod_seen) == seen
        assert rule_state(w)["stats"] == {"hits": 4, "oracle": 1, "denied": 1}
    # no clone to ask: a confirmed-vulnerable point fails closed, and the rule counts it
    httpx.put(w.admin + "/_admin/pool", headers=ADMIN, json={"clones": []})
    assert httpx.get(w.url + "/search", params={"q": "usb"}).status_code == 404
    assert rule_state(w)["stats"]["denied"] == 2
    # written next to the recordings on every change
    stored = json.loads((w.record.parent / "rules.json").read_text())["rules"]
    assert [(x["rule"]["id"], x["expires"]) for x in stored] == [("rule-i1", None)]
    assert httpx.delete(w.admin + "/_admin/rules/rule-i1", headers=ADMIN).status_code == 200
    assert json.loads((w.record.parent / "rules.json").read_text()) == {"rules": []}


def test_rules_survive_a_restart(tmp_path):
    path = tmp_path / "state" / "rules.json"
    cfg = Config(rules_path=str(path), admin_token="adm")
    gw = Gateway(cfg)
    with TestClient(gw.admin_app()) as c:
        timed = {"id": "t", "method": "GET", "route": "/a", "scope": "all", "ttl_s": 600}
        gone = {"id": "g", "method": "GET", "route": "/b", "scope": "all", "ttl_s": 600}
        assert c.post("/_admin/rules", json=[RULE, timed, gone], headers=ADMIN).status_code == 201
        assert c.delete("/_admin/rules/g", headers=ADMIN).status_code == 200
    again = Gateway(cfg)                                              # a new process reading the same file
    assert sorted(again.rules) == ["rule-i1", "t"]
    assert again.rules["rule-i1"].scope == "param_present" and again.rules["rule-i1"].expires == float("inf")
    assert again.rules["t"].expires == gw.rules["t"].expires          # the ttl clock is not restarted
    again.rules["t"].expires = 0                                      # expiry is persisted too
    again.expire_rules()
    assert sorted(Gateway(cfg).rules) == ["rule-i1"]
    path.write_text("not json")                                       # a damaged file never stops the gateway
    assert Gateway(cfg).rules == {}


def test_rules_path_defaults_next_to_the_recordings():
    assert Config.from_env({"RECORD_PATH": "/runtime/recordings/requests.jsonl"}).rules_path == \
        "/runtime/recordings/rules.json"
    assert Config.from_env({"RECORD_PATH": "/r/x.jsonl", "RULES_PATH": "/s/rules.json"}).rules_path == "/s/rules.json"
    assert Config.from_env({}).rules_path == ""
