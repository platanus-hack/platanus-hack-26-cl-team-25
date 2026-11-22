"""What `immune init` leaves behind and says: .immune/.gitignore, the LLM-fallback note, doctor check 5."""
import os
import types

from immune import doctor
from immune.init import Init
from immune.initsteps import report


def test_init_writes_a_gitignore_for_secrets_and_runtime_and_keeps_an_existing_one(tmp_path):
    it = Init(str(tmp_path), use_llm=False, out=lambda s: None)
    assert it.write_gitignore() is True
    lines = open(tmp_path / ".immune" / ".gitignore").read().splitlines()
    assert "runtime/" in lines and "deploy/immune.env" in lines       # secrets.env, seed, markers; deploy secrets
    assert not any(x in lines for x in ("config.yaml", "profile.py", "*"))
    (tmp_path / ".immune" / ".gitignore").write_text("mine\n")
    assert it.write_gitignore() is False
    assert open(tmp_path / ".immune" / ".gitignore").read() == "mine\n"


def _stubbed(tmp_path, lines, fallback):
    """Init whose steps are stubs; step 4 ends as an LLM step would after three failed calls."""
    it = Init(str(tmp_path), use_llm=True, out=lines.append)

    def step4():
        it.step_state["columns"] = {"source": "draft-fallback" if fallback else "llm",
                                    "errors": ["LLM call failed: not logged in"] if fallback else []}
        return True
    it.step1_detect = it.step2_openapi = it.step3_database = lambda: True
    it.write_config = it.step5_profile = it.step6_marks = it.step8_doctor = lambda *a, **k: None
    it.step4_columns = step4
    it.step7_shadow = lambda: (True, "")
    it.step9_deploy = lambda: it.deploy.update(ready_command="immune up --project X")
    return it


def test_init_says_which_steps_kept_heuristic_drafts_because_the_llm_was_unavailable(tmp_path):
    lines = []
    it = _stubbed(tmp_path, lines, fallback=True)
    assert it.run() == 0
    assert lines[-1] == "READY: immune up --project X"
    note = lines[-2]
    assert note.startswith("NOTE: LLM unavailable for step(s) columns") and "not logged in" in note
    assert "heuristic drafts" in note
    os.makedirs(tmp_path / ".immune", exist_ok=True)
    text = report.write(it)
    assert "**Not adapted by the LLM:** LLM unavailable for step(s) columns" in text
    lines = []
    assert _stubbed(tmp_path, lines, fallback=False).run() == 0
    assert not any(x.startswith("NOTE:") for x in lines)


def _reset(monkeypatch, reset):
    monkeypatch.setattr(doctor.hostrun, "harness", lambda cfg, release, job: {
        "ok": True, "reset": reset,
        "results": [{"name": n, "oracles": [n], "status": 200, "verdict": "oracle", "body": ""} for n in ("sql", "file")]})
    cfg = types.SimpleNamespace(app=types.SimpleNamespace(health="/health"))
    return doctor.checks45(cfg, "/nowhere", {"seed_max_uid": 3}, {})[1]


def test_check5_warns_when_no_write_was_made_so_no_reset_was_exercised(tmp_path, monkeypatch):
    c5 = _reset(monkeypatch, {"start_equals_seed": True, "restored": True, "mutated_by_L2": False})
    assert c5["id"] == 5 and c5["ok"] and c5["status"] == "warn" and "NOT exercised" in c5["reason"]
    assert doctor.format_line(c5).strip().startswith("[warn]") or "warn" in doctor.format_line(c5)
    c5 = _reset(monkeypatch, {"start_equals_seed": True, "restored": True, "mutated_by_L2": True})
    assert c5["ok"] and c5["status"] == "pass"
    c5 = _reset(monkeypatch, {"start_equals_seed": True, "restored": False, "mutated_by_L2": True})
    assert not c5["ok"] and c5["status"] == "fail"
