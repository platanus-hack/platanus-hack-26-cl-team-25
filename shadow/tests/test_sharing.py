"""Group-shared access in the owner oracle (shadow/sharing.json, written by immune.shadowdata)."""
import json

import pytest


def _harness(tmp_path, monkeypatch, sharing=True):
    from group_app import seed
    from shadow.harness import Harness
    s = str(tmp_path / "seed.db")
    seed.make(s)
    if sharing:
        (tmp_path / "sharing.json").write_text(json.dumps({"version": 1, "routes": {
            "team_id": {"group_table": "teams", "table": "memberships", "member": "user_id", "group": "team_id"}}}))
    monkeypatch.setenv("APP_DB", str(tmp_path / "work.db"))
    monkeypatch.setenv("APP_SECRET", "sec")
    monkeypatch.delenv("SHADOW_SHARING_PATH", raising=False)
    return Harness(profile="group_app.profile", seed_db=s, state=None)


def owners(r):
    return sorted(e["detail"]["marker_owner"] for e in r.events if e["oracle"] == "owner")


@pytest.fixture()
def h(tmp_path, monkeypatch):
    hh = _harness(tmp_path, monkeypatch)
    yield hh
    hh.close()


def test_member_reads_own_group_is_clean(h):
    r = h.send("GET", "/teams/1/members", uid=1)
    assert r.status == 200 and r.verdict == "clean", r.events
    assert h.send("GET", "/teams/2/members", uid=3).verdict == "clean"


def test_non_member_still_fires(h):
    assert owners(h.send("GET", "/teams/1/members", uid=3)) == [1, 2]
    assert owners(h.send("GET", "/teams/1/members", uid=5)) == [1, 2]
    assert owners(h.send("GET", "/teams/2/members", uid=1)) == [3]
    assert owners(h.send("GET", "/teams/1/members", uid=999)) == [1, 2]       # a fresh user


def test_only_members_of_the_addressed_group_are_exempt(h):
    # member of team 1 asking team 1, but the response carries users outside the group
    assert owners(h.send("GET", "/teams/1/everyone", uid=1)) == [3, 4, 5]


def test_undeclared_parameter_is_unchanged(h):
    assert owners(h.send("GET", "/other/1/members", uid=1)) == [2]


def test_admin_and_anonymous_unchanged(h):
    assert h.send("GET", "/teams/1/members", uid=4, role="admin").verdict == "clean"
    assert h.send("GET", "/teams/1/members").status == 401


def test_follows_the_clone_database(h):
    # membership added in L2 state counts on the next request (the oracle reads the clone's own db)
    import sqlite3
    assert owners(h.send("GET", "/teams/1/members", uid=5, mode="L2")) == [1, 2]      # not a member yet
    c = sqlite3.connect(h.engine.db_path)
    c.execute("INSERT INTO memberships VALUES (5, 1)")
    c.commit()
    c.close()
    assert owners(h.send("GET", "/teams/1/members", uid=5)) == []


def test_without_sharing_file_nothing_changes(tmp_path, monkeypatch):
    hh = _harness(tmp_path, monkeypatch, sharing=False)
    try:
        assert owners(hh.send("GET", "/teams/1/members", uid=1)) == [2]
    finally:
        hh.close()
