"""Multi-step (stored) taint across a captive session (shadow/taint.py): second-order SQL injection and stored XSS.

These are the unit tests of the tracker in isolation; test_oracles.py drives the same logic end to end through the
Engine over a two-request captive session (the stored-attack shape the pitch promised)."""
from shadow import taint


def tracker(*observations):
    """A tracker that has already seen each (rid, [(loc, param, value), ...])."""
    t = taint.TaintTracker()
    for rid, ins in observations:
        t.observe(rid, {"method": "POST", "path": "/note", "query": "", "headers": {}, "body_b64": ""}, ins)
    return t


# ------------------------------------------------------------------ bookkeeping
def test_observe_keeps_only_long_string_values_once():
    t = tracker(("r1", [("json", "body", "x' OR '1'='1"), ("json", "n", 7), ("json", "s", "ab")]))
    # the integer and the 2-char string are dropped (not strings / shorter than MIN_VALUE); the long one is kept once
    t.observe("r2", {"method": "POST", "path": "/note", "query": "", "headers": {}, "body_b64": ""},
              [("json", "body", "x' OR '1'='1")])
    assert [s["value"] for s in t.seen] == ["x' OR '1'='1"]
    assert t.seen[0]["origin"]["rid"] == "r1"


def test_reset_clears_everything():
    t = tracker(("r1", [("json", "body", "x' OR '1'='1")]))
    t.reset()
    assert t.seen == [] and t.second_order_sql([("SELECT 1", [])], None, "sqlite", set()) == []


# ------------------------------------------------------------------ second-order SQL
def test_second_order_sql_fires_for_a_stored_value_breaking_out_of_a_literal():
    t = tracker(("plant", [("json", "body", "x' OR '1'='1")]))
    stmts = [("SELECT id FROM items WHERE name = 'x' OR '1'='1'", [{"file": "app.py", "line": 9, "func": "q"}])]
    out = t.second_order_sql(stmts, None, "sqlite", current_values=set())
    assert len(out) == 1
    e = out[0]
    assert e["oracle"] == "sql"
    assert e["detail"]["second_order"] is True and e["detail"]["origin_rid"] == "plant"
    assert e["origin"]["rid"] == "plant"
    assert e["stack"][0]["func"] == "q"       # the sink of the request where it fired survives


def test_second_order_ignores_a_value_that_is_also_in_the_current_request():
    # the value is the current request's own input -> first-order, not second-order (left to the per-request check)
    t = tracker(("plant", [("json", "body", "x' OR '1'='1")]))
    stmts = [("SELECT id FROM items WHERE name = 'x' OR '1'='1'", [])]
    assert t.second_order_sql(stmts, None, "sqlite", current_values={"x' OR '1'='1"}) == []


def test_second_order_quiet_for_a_parameterised_statement():
    t = tracker(("plant", [("json", "body", "x' OR '1'='1")]))
    assert t.second_order_sql([("SELECT id FROM items WHERE name = ?", [])], None, "sqlite", set()) == []


# ------------------------------------------------------------------ stored / reflected XSS
HTML = "text/html; charset=utf-8"


def page(body_inner):
    return ("<html><body>%s</body></html>" % body_inner).encode()


def test_stored_xss_fires_for_a_planted_markup_value_reflected_unescaped():
    t = tracker(("plant", [("json", "body", "<script>alert(1)</script>")]))
    out = t.stored_xss(page("<div><script>alert(1)</script></div>"), HTML, current_inputs=[],
                       stack=[{"file": "app.py", "line": 4, "func": "wall"}])
    assert len(out) == 1
    e = out[0]
    assert e["oracle"] == "xss"
    assert e["detail"]["stored"] is True and e["detail"]["origin_rid"] == "plant"
    assert e["stack"][0]["func"] == "wall"


def test_reflected_xss_fires_for_the_current_requests_own_input():
    t = taint.TaintTracker()
    out = t.stored_xss(page("<img src=x onerror=alert(1)>"), HTML,
                       current_inputs=[("query", "q", "<img src=x onerror=alert(1)>")], stack=[])
    assert len(out) == 1 and out[0]["detail"]["stored"] is False
    assert "origin_rid" not in out[0]["detail"] and "origin" not in out[0]


def test_stored_xss_quiet_when_the_value_is_only_there_escaped():
    import html
    t = tracker(("plant", [("json", "body", "<script>alert(1)</script>")]))
    escaped = html.escape("<script>alert(1)</script>", quote=True)
    assert t.stored_xss(page("<div>%s</div>" % escaped), HTML, current_inputs=[]) == []


def test_stored_xss_quiet_without_markup_or_on_a_non_html_response():
    t = tracker(("plant", [("json", "body", "just a plain note")]))
    assert t.stored_xss(page("just a plain note"), HTML, current_inputs=[]) == []
    t2 = tracker(("plant", [("json", "body", "<script>alert(1)</script>")]))
    assert t2.stored_xss(b'{"body":"<script>alert(1)</script>"}', "application/json", current_inputs=[]) == []
