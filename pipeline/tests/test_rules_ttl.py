"""PIPELINE_RULE_TTL_S reaches every rule the pipeline posts, the patcher-derived one included."""
from pipeline import rules

INC = {"incident": "inc-0001", "method": "GET", "route": "/api/items", "param": {"in": "query", "name": "q"},
       "vuln_class": "sqli"}
RULE = {"id": "r1", "incident": "inc-0001", "method": "GET", "route": "/api/items",
        "param": {"in": "query", "name": "q"}, "grammar": "^[a-z]+$", "scope": "param", "ttl_s": None}


def test_operator_ttl_applies_to_a_rule_without_its_own():
    rule, note = rules.finalize(dict(RULE), INC, {}, 600)
    assert note == "" and rule["ttl_s"] == 600


def test_a_rule_with_its_own_ttl_keeps_it_and_no_ttl_stays_null():
    assert rules.finalize(dict(RULE, ttl_s=30), INC, {}, 600)[0]["ttl_s"] == 30
    assert rules.finalize(dict(RULE), INC, {}, None)[0]["ttl_s"] is None
