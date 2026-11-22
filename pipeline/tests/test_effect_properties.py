"""The positive property of the input -> effect classes (pipeline/properties.py, gate `properties`).

A fake validator plays the app: `vulnerable` fires the class's oracle for any attack payload, `fixed` fires nothing,
and the wrong fixes are the ones the gate must reject (a patch that only blocks the captured value, one that breaks the
benign value, one that removes the effect but still lets the raw channel fire)."""
import pytest

from immune_contracts import classes, payloads
from pipeline import properties, reqs

# class -> (oracle the app fires, the request's input)
CASES = {
    "ssrf": ("ssrf", {"in": "query", "name": "url"}),
    "cmdi": ("cmdi", {"in": "query", "name": "host"}),
    "ssti": ("ssti", {"in": "query", "name": "tpl"}),
    "deser": ("deser", {"in": "cookie", "name": "session"}),
    "xxe": ("xxe", {"in": "body", "name": "body"}),
    "redirect": ("redirect", {"in": "query", "name": "next"}),
}


def incident(cls):
    param = CASES[cls][1]
    base = {"method": "GET", "path": "/x", "query": "", "headers": {}, "body_b64": "", "uid": None, "role": None}
    base = reqs.set_value(base, param, "seed")
    return ({"vuln_class": cls, "method": "GET", "route": "/x", "param": param, "request": base},
            {"requests": [base], "expect": {"oracle": CASES[cls][0]}})


class App:
    """A release: `behaviour(value) -> (status, [oracle kinds fired])`."""
    def __init__(self, behaviour):
        self.behaviour = behaviour


class Validator:
    def __init__(self, releases, param=None):
        self.releases, self.param, self.cache, self.jobs = releases, param, {}, []

    def run(self, release_dir, job, timeout=None):
        self.jobs.append((release_dir, job))
        assert job["kind"] == "harness"
        out = []
        for s in job["sequences"]:
            value = reqs.get_value(s["requests"][-1], self.param)        # what the request carries in the input
            status, fired = self.releases[release_dir].behaviour(value)
            out.append({"name": s["name"], "runs": [[{"status": status, "verdict": "oracle" if fired else "clean",
                                                       "events": [{"oracle": k, "detail": {}, "stack": []} for k in fired],
                                                       "marker_owners": []}]]})
        return {"sequences": out, "manifest": {}}


def run_check(cls, patched):
    oracle = CASES[cls][0]
    benign = payloads.BENIGN[cls]
    vulnerable = App(lambda v: (200, [] if v == benign else [oracle]))
    inc, poc = incident(cls)
    v = Validator({"base": vulnerable, "patched": patched}, CASES[cls][1])
    return properties.check(v, inc, poc, "base", "patched"), v


@pytest.mark.parametrize("cls", sorted(CASES))
def test_a_real_fix_passes(cls):
    (ok, detail), v = run_check(cls, App(lambda val: (200, [])))
    assert ok, detail
    assert "%d %s payloads" % (len(payloads.BATTERY[cls]), cls) in detail and "benign value keeps its status 200" in detail


@pytest.mark.parametrize("cls", sorted(CASES))
def test_an_unfixed_app_fails_and_names_the_input(cls):
    oracle = CASES[cls][0]
    (ok, detail), _ = run_check(cls, App(lambda v: (200, [] if v == payloads.BENIGN[cls] else [oracle])))
    assert not ok and "still fires %s" % oracle in detail and "param %s" % CASES[cls][1]["name"] in detail


@pytest.mark.parametrize("cls", sorted(CASES))
def test_a_fix_that_only_blocks_the_captured_value_fails(cls):
    first = payloads.BATTERY[cls][0]
    oracle = CASES[cls][0]
    patched = App(lambda v: (200, [oracle] if v != first and v != payloads.BENIGN[cls] else []))
    (ok, detail), _ = run_check(cls, patched)
    assert not ok and "still fires" in detail


@pytest.mark.parametrize("cls", sorted(CASES))
def test_a_fix_that_breaks_the_benign_value_fails(cls):
    benign = payloads.BENIGN[cls]
    (ok, detail), _ = run_check(cls, App(lambda v: (403, [])))              # everything refused: the endpoint is dead
    assert not ok and "the benign value answers 403, it answered 200 before" in detail


@pytest.mark.parametrize("cls", sorted(CASES))
def test_the_raw_channel_counts_as_the_effect(cls):
    # the input -> effect correlation can be lost (the app re-encodes the input), the effect still happened
    raw = [k for k in classes.FAMILY[cls] if k != CASES[cls][0]]
    if not raw:
        pytest.skip("%s has no raw channel in its family" % cls)
    (ok, detail), _ = run_check(cls, App(lambda v: (200, [] if v == payloads.BENIGN[cls] else [raw[0]])))
    assert not ok and "still fires %s" % raw[0] in detail


def test_a_benign_value_that_fires_is_rejected():
    oracle = CASES["cmdi"][0]
    (ok, detail), _ = run_check("cmdi", App(lambda v: (200, [oracle])))
    assert not ok and "the benign value 'abc' fires cmdi" in detail


def test_an_incident_without_a_parameter_cannot_be_checked():
    inc, poc = incident("ssrf")
    inc["param"] = None
    ok, detail = properties.check(Validator({}), inc, poc, "base", "patched")
    assert not ok and "no input parameter" in detail


def test_the_unpatched_baseline_is_measured_once_per_incident():
    (ok, _d), v = run_check("ssrf", App(lambda val: (200, [])))
    assert ok and [r for r, _j in v.jobs].count("base") == 1 and [r for r, _j in v.jobs].count("patched") == 1


def test_every_class_has_a_check_a_battery_and_a_benign_value():
    for cls in classes.EFFECT_CLASSES:
        assert cls in properties.CHECKS and payloads.BATTERY[cls] and payloads.BENIGN[cls]
        assert set(classes.FAMILY[cls]) <= {"ssrf", "cmdi", "ssti", "deser", "xxe", "redirect", "proc", "net", "file"}
