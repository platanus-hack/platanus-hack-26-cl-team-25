"""The patcher's incident is built from the live bus events, with the sink the oracle located."""
from patcher import core
from pipeline import incident, liveincident

STACK = [{"file": "src/com/acme/ReceiverServlet.java", "line": 79, "func": "doGet"}]


def events(stack=STACK, uid=None):
    fired = {"type": "oracle.fired", "rid": "r1", "incident": None,
             "data": {"rid": "r1", "uid": uid, "role": None, "status": 200,
                      "request": {"method": "GET", "path": "/App/receiver", "query": "tank=9", "headers": {}, "body_b64": ""},
                      "events": [{"oracle": "owner", "detail": {"consumed": ["tank"]}, "stack": stack}]}}
    spec = {"paths": {"/App/receiver": {"get": {"responses": {"200": {"description": "ok"}}}}}}
    opened_data = incident.build(fired, spec)
    opened = {"type": "incident.opened", "incident": "inc-0001", "rid": "r1", "data": {
        "incident": "inc-0001", "vuln_class": opened_data["vuln_class"], "method": "GET", "route": "/App/receiver",
        "param": None, "sink": opened_data["sink"], "evidence_rid": "r1", "request": opened_data["request"]}}
    return [fired, opened]


def test_incident_carries_the_sink_the_oracle_located():
    inc = liveincident.from_events(events(), "inc-0001", lang="java")
    assert inc["sink"] == {"file": "src/com/acme/ReceiverServlet.java", "line": 79, "func": "doGet"}
    assert inc["editable_files"] == ["src/com/acme/ReceiverServlet.java"] and inc["app_subdirs"] == ["src"]
    assert inc["lang"] == "java" and inc["anon"] is True and inc["method"] == "GET" and inc["route"] == "/App/receiver"
    assert inc["evidence"]["events"][0]["stack"] == STACK                      # what the patcher is shown


def test_a_request_with_an_identity_is_not_anonymous():
    assert liveincident.from_events(events(uid=7), "inc-0001")["anon"] is False


def test_no_sink_located_means_no_live_incident():
    assert liveincident.from_events(events(stack=[]), "inc-0001") is None      # the caller keeps its fallback
    assert liveincident.from_events(events(), "inc-9999") is None
    assert liveincident.from_events([], "inc-0001") is None


def test_the_patcher_makes_exactly_that_file_editable(tmp_path):
    inc = liveincident.from_events(events(), "inc-0001")
    f = tmp_path / "src/com/acme/ReceiverServlet.java"
    f.parent.mkdir(parents=True)
    f.write_text("class X {}")
    assert core.editable_files(inc, str(tmp_path)) == ["src/com/acme/ReceiverServlet.java"]
    assert "ReceiverServlet.java:79" in core.render_prompt(inc, None, 1, ["src/com/acme/ReceiverServlet.java"])
