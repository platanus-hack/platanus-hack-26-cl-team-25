"""immune.metrics: incidents by origin (audit t0 = audit.finding) and detection metrics from bus + recording."""
from immune import metrics


def ev(type_, data, ts, incident=None, rid=None):
    return {"type": type_, "ts": ts, "incident": incident, "rid": rid, "data": data}


def test_audit_incident_t0_is_its_finding_and_origin_is_reported():
    evs = [
        ev("oracle.fired", {"rid": "r1"}, 1.0, rid="r1"),
        ev("incident.opened", {"incident": "i1", "vuln_class": "sqli", "route": "/p", "evidence_rid": "r1",
                               "origin": "live", "method": "GET", "param": {"in": "query", "name": "q"}}, 2.0, "i1"),
        ev("rule.active", {"id": "x"}, 3.0, "i1"), ev("patch.diff", {}, 4.0, "i1"), ev("pr.merged", {}, 5.0, "i1"),
        ev("upstream.switched", {}, 6.0), ev("verify.result", {"exploit_blocked_on_prod": True}, 7.0, "i1"),
        ev("incident.closed", {"outcome": "patched"}, 7.5, "i1"),
        ev("audit.finding", {"incident": "i2", "parent": "i1", "route": "/login", "param": {}}, 10.0, "i2"),
        ev("incident.opened", {"incident": "i2", "vuln_class": "sqli", "route": "/login", "evidence_rid": "audit-i1-1",
                               "origin": "audit", "parent": "i1"}, 12.0, "i2"),
        ev("rule.active", {"id": "y"}, 13.0, "i2"), ev("patch.diff", {}, 14.0, "i2"), ev("pr.merged", {}, 15.0, "i2"),
        ev("upstream.switched", {}, 16.0), ev("incident.closed", {"outcome": "patched"}, 17.0, "i2"),
    ]
    rows = {r["incident"]: r for r in metrics.incidents(evs)}
    assert rows["i1"]["origin"] == "live" and rows["i1"]["queue"] == 1.0
    assert rows["i2"]["origin"] == "audit" and rows["i2"]["parent"] == "i1"
    assert rows["i2"]["queue"] == 2.0 and rows["i2"]["identified_to_prod_wall"] == 6.0 and rows["i2"]["to_prod"] == 4.0
    d = metrics.detection(evs)
    assert d["incidents_by_origin"] == {"live": 1, "audit": 1}


def test_detection_counts_detonations_and_clean_share_from_bus_and_recording():
    evs = [ev("request.routed", {"route": "prod", "verdict": None}, 1, rid="a"),
           ev("request.routed", {"route": "prod", "verdict": "clean"}, 2, rid="b"),
           ev("request.routed", {"route": "shadow_l1", "verdict": "oracle"}, 3, rid="c"),
           ev("request.routed", {"route": "prod", "verdict": "no_clone"}, 4, rid="d"),
           ev("audit.done", {"incident": "i", "checked": 8, "findings": 1, "seconds": 5.5}, 5)]
    rec = [{"rid": "b", "verdict": "clean"},                       # same request as on the bus: counted once
           {"rid": "e", "verdict": "inconclusive"},                # bus event lost: the recording has it
           {"rid": "f", "verdict": "clean"},
           {"rid": "g", "aftercheck": "oracle", "method": "GET"}]  # after-check line, not a request
    d = metrics.detection(evs, rec)
    assert d["requests"] == 6 and d["detonated"] == 4 and d["no_clone"] == 1 and d["aftercheck_oracle"] == 1
    assert d["detonated_by_verdict"] == {"clean": 2, "oracle": 1, "inconclusive": 1} and d["clean_share"] == 0.5
    assert d["audits"] == {"n": 1, "checked": 8, "findings": 1, "seconds": 5.5}
    lines = metrics.detection_lines(d)
    assert "50%" in lines[1] and "live 0, audit 0" in lines[2]
    assert metrics.detection([], [])["clean_share"] is None
