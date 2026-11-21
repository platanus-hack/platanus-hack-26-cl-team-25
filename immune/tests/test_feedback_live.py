import os
import time

import pytest

from immune.initsteps import docker
from immune.tests import journeys
from immune.tests.test_deploy_init import _victim_project


class _Res:
    def __init__(self):
        self.ok, self.reason, self.text, self.denials = True, "", "fake", []


@pytest.mark.docker
def test_doctor_failure_is_fed_back_to_the_owning_step(tmp_path):
    ok, why = docker.available()
    if not ok:
        pytest.skip(why)
    from immune.init import Init
    calls = []

    def fake(prompt, work, editable):
        step = "profile" if ".immune/profile.py" in editable else ("marks" if "marks" in editable[0] else "columns")
        calls.append((step, prompt))
        if step == "profile":
            p = os.path.join(work, ".immune", "profile.py")
            src = open(p).read()
            if "check 2 (profile identity) FAILED" in prompt:
                src = src.replace("return 'not-a-valid-token'  # broken\n    authtoken.mint(", "return authtoken.mint(")
            else:
                src = src.replace("return authtoken.mint(", "return 'not-a-valid-token'  # broken\n    authtoken.mint(")
            open(p, "w").write(src)
        return _Res()

    proj = _victim_project(tmp_path)
    lines = []
    rc = Init(proj, use_llm=True, out=lines.append, runner=fake).run()
    text = "\n".join(lines)
    assert rc == 0, text
    steps = [s for s, _ in calls]
    assert steps.count("profile") == 2 and steps.count("columns") == 1 and steps.count("marks") == 1, steps
    second = [p for s, p in calls if s == "profile"][1]
    assert "check 2 (profile identity) FAILED" in second and "CHECKS-" in second
    assert "doctor round 1: 6/7 checks pass; failing: 2(profile)" in text
    assert "doctor round 2: 7/7 checks pass" in text
    assert lines[-1].startswith("READY: ")


@pytest.mark.live
def test_live_init_on_builtin_app_unknown(tmp_path):
    """Acceptance A: the built-in app as an unknown project (no contracts/openapi.yaml, no hand-written profile
    used): real LLM steps, doctor green, and the generated profile + seed reproduce the VULNS.md oracles."""
    ok, why = docker.available()
    if not ok:
        pytest.skip(why)
    from immune.init import Init
    proj = _victim_project(tmp_path)
    lines = []
    t0 = time.monotonic()
    init = Init(proj, use_llm=True, out=lines.append)
    rc = init.run()
    text = "\n".join(lines)
    print(text)
    assert rc == 0, text
    assert len(init.llm_calls) >= 3 and all(c["ok"] for c in init.llm_calls)
    assert "7/7 checks pass" in text
    reqs, exp = journeys.victim_requests(journeys.manifest(proj))
    rows = journeys.evaluate(journeys.run(proj, reqs), exp)
    for r in rows:
        print("%-24s expected %-6s got %s" % r[:3])
    assert all(r[3] for r in rows), rows
    assert any(r[0] == "legit login" for r in rows), "the generated profile should expose hash_password"
    print("init %.0fs, %d LLM calls" % (time.monotonic() - t0, len(init.llm_calls)))
