import json
import subprocess
from unittest.mock import Mock

import pytest

from fleet.fuxa import FuxaFleet
from immune import fuxa


@pytest.fixture
def fleet(tmp_path):
    fleet = FuxaFleet(tmp_path)
    for policy in fuxa.OPERATIONS.values():
        path = fleet.source / policy["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f'router.post("{policy["route"]}", function(req, res) {{\n'
            f'    {policy["anchor"]} test);\n'
            '});\n',
            encoding="utf-8",
        )
    (fleet.source / "server/package.json").write_text('{"version":"1.2.9-2654"}', encoding="utf-8")
    (fleet.source / "server/events.js").write_text("socket.on(Events.IoEventTypes.STATUS, handler);", encoding="utf-8")
    fuxa.write_json(tmp_path / "profile.json", fuxa.inventory(fleet.source))
    return fleet


def effect(revision):
    return {
        "revision": revision, "operation": "settings.write", "boundary": "write-settings",
        "type": "effect", "id": "da45a254-f9d2-46ba-a864-b8fb549fbec9", "role": "member", "decision": "observed",
    }


def test_profile_and_morgan_signals(fleet, tmp_path):
    operations = fleet.profile()["operations"]
    assert sum(row["coverage"] != "pending" for row in operations) == 2
    assert any(row["transport"] == "socket.io" and row["coverage"] == "pending" for row in operations)
    log = tmp_path / "access.log"
    log.write_text(
        '127.0.0.1 - - [sample] "POST /api/settings?private=secret HTTP/1.1" 401 0 "-" "-"\n'
        "POST /api/runSysFunction \x1b[31m403\x1b[0m 2 ms - 0\n"
        "POST /api/settings 200 2 ms - 0\nGET /unrelated 403 2 ms - 0\nunrecognized\n",
        encoding="utf-8",
    )
    report = fuxa.access_report(log, fleet.profile())
    assert (report["read"], report["recognized"], report["discarded"]) == (5, 4, 1)
    assert [row["status"] for row in report["alerts"]] == [401, 403]
    assert "secret" not in json.dumps(report)
    log.write_text("", encoding="utf-8")
    assert fuxa.access_report(log, fleet.profile())["coverage"] == "insufficient"


def test_only_observed_violations_propose_patch(fleet):
    baseline = fleet.make_release(set())
    fleet.active = Mock(return_value=baseline)
    fleet.promote = Mock(return_value=None)
    event = effect(baseline)
    assert fleet.incident({**event, "role": "admin"})["status"] == "ignored"
    assert fleet.incident({**event, "revision": "stale"})["status"] == "ignored"
    assert fleet.incident({**event, "decision": "blocked"})["status"] == "ignored"
    assert fuxa.assess({**event, "role": "unknown"}, baseline) == "insufficient"
    result = fleet.incident(event)
    assert result["status"] == "deployed"
    assert fleet.meta(result["candidate"])["enforced"] == ["settings.write"]
    patch = (fleet.root / "incidents" / event["id"] / "candidate.diff").read_text(encoding="utf-8")
    assert patch.count("+") >= 1 and '"enforce"' in patch
    assert fleet.incident(event) == result
    fleet.promote.assert_called_once_with(baseline, result["candidate"])


def test_watch_keeps_cursor_and_ignores_unstructured_lines(fleet, capsys):
    revision = fleet.make_release(set())
    event = effect(revision)
    fleet.active = Mock(return_value=revision)
    fleet.incident = Mock(return_value={"status": "failed"})
    fleet.docker = Mock(side_effect=[
        "container-id", json.dumps({"offset": 200, "entries": [
            "arbitrary log line",
            json.dumps({**event, "type": "http", "status": 403}),
            json.dumps(event),
        ]}),
        "container-id", json.dumps({"offset": 200, "entries": []}),
    ])
    assert fleet.watch(None) == ("container-id", 200)
    assert fleet.watch(None) == ("container-id", 200)
    assert fleet.docker.call_args.args[-1] == "200"
    assert json.loads(capsys.readouterr().out.splitlines()[0])["status"] == "alert"
    fleet.incident.assert_called_once_with(event)


def test_dashboard_loads_incidents_with_live_status(fleet):
    from immune.fuxa_dashboard import Feed

    revision = fleet.make_release(set())
    fleet.active = Mock(return_value=revision)
    fleet.promote = Mock(return_value=None)
    fleet.incident(effect(revision), synthetic=True)
    fuxa.write_json(fleet.root / "watch-cursor.json", ["container", 0])
    feed = Feed(fleet.root)
    feed.fleet = fleet
    batch = feed.collect()
    assert [item["type"] for item in batch] == [
        "fuxa.status", "incident.opened", "patch.attempt", "patch.diff", "deploy.done", "incident.closed",
    ]
    assert batch[0]["data"]["active"] == revision
    assert batch[0]["data"]["monitor"]
    assert batch[1]["data"]["fuxa"]["synthetic"]
    assert batch[-1]["data"]["outcome"] == "patched"
    assert feed.collect() == []


@pytest.mark.parametrize("failure", ["test", "direct", "gateway", None])
def test_rollout_validates_before_switch_and_restores_previous_revision(fleet, failure):
    fuxa.write_json(fleet.root / "deployment.json", {"port": 1881, "smoke": {"/": "expected"}})
    active = ["baseline"]
    changes = []

    def activate(revision):
        active[0] = revision
        changes.append(revision)

    def check(revision, smoke, port):
        if failure == "gateway" and revision == "candidate":
            raise RuntimeError("failed through gateway")

    fleet.active = lambda: active[0]
    fleet.activate = activate
    fleet.test = Mock(side_effect=RuntimeError("test failed") if failure == "test" else None)
    fleet.start = Mock()
    fleet.remove = Mock()
    fleet.gateway_smoke = check
    fleet.local_smoke = Mock(return_value={"/": "changed" if failure == "direct" else "expected"})
    if failure:
        with pytest.raises(RuntimeError):
            fleet.promote("baseline", "candidate")
        assert active[0] == "baseline"
        assert changes == (["candidate", "baseline"] if failure == "gateway" else [])
        if failure == "test":
            fleet.start.assert_not_called()
        else:
            fleet.remove.assert_called_once_with(fleet.backend("candidate"))
    else:
        fleet.promote("baseline", "candidate")
        assert changes == ["candidate"]
        fleet.remove.assert_called_once_with(fleet.backend("baseline"))


def test_instrumented_guards_in_node(fleet, monkeypatch, tmp_path):
    import shutil

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the JavaScript guard checks")
    helper = tmp_path / "auth.cjs"
    helper.write_text("exports.adminGroups = [-1, 255];", encoding="utf-8")
    monkeypatch.setenv("IMMUNE_FUXA_AUTH_HELPER", str(helper))
    for enforced in (set(), {"settings.write"}, set(fuxa.OPERATIONS)):
        revision = fleet.make_release(enforced)
        monkeypatch.setenv("IMMUNE_FUXA_CHECK_ROOT", str(fleet.releases / revision / "server"))
        subprocess.run([node, str(fuxa.ASSETS / "check.cjs"), ",".join(sorted(enforced))], check=True, timeout=10)
