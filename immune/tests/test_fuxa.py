import json
import subprocess
import uuid
from unittest.mock import Mock

import pytest

from fleet.fuxa import FuxaFleet, FuxaRollback
from immune import fuxa


@pytest.fixture
def fleet(tmp_path):
    fleet = FuxaFleet(tmp_path)
    for file, changes in fuxa.PROTECTED_FILES.items():
        path = fleet.source / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(changes), encoding="utf-8")
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
    # Every inventory entry declares who may execute it and which effect to observe.
    assert all({"role", "effect"} <= set(row) for row in operations)
    assert next(row for row in operations if row["coverage"] == "settings.write")["effect"] == "write-settings"
    assert next(row for row in operations if row["transport"] == "socket.io")["effect"] == "event"
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
    fleet.promote.assert_called_once_with(baseline, result["candidate"], gates=result["gates"])


def test_patch_review_validates_then_waits_for_approval(fleet):
    from immune.fuxa_dashboard import Feed

    baseline = fleet.make_release(set())
    fleet.active = Mock(return_value=baseline)
    fleet.promote = Mock(return_value=None)
    fleet.build = Mock()
    fleet.test = Mock()
    assert fleet.patch_mode() == "auto"
    assert fleet.patch_mode("review") == "review"
    observed = effect(baseline)
    record = fleet.incident(observed)
    assert record["status"] == "review"
    fleet.test.assert_called_once_with(record["candidate"])
    fleet.promote.assert_not_called()
    feed = Feed(fleet.root)
    feed.fleet = fleet
    assert feed.collect()[-1]["type"] == "fuxa.review"
    fleet.active.return_value = "e" * 12
    with pytest.raises(RuntimeError, match="cambió"):
        fleet.approve(record["id"])
    fleet.active.return_value = baseline
    assert fleet.approve(record["id"])["status"] == "deployed"
    fleet.promote.assert_called_once_with(baseline, record["candidate"], gates=record["gates"])
    assert feed.collect()[-1]["data"]["outcome"] == "patched"


def test_coverage_distinguishes_protected_and_partial_inventory():
    profile = {"operations": [
        {"file": "server/runtime/index.js", "event": "DEVICE_VALUES", "coverage": "pending"},
        {"file": "server/runtime/index.js", "event": "DAQ_QUERY", "coverage": "pending"},
        {"file": "server/api/scheduler/index.js", "method": "POST", "route": "/api/scheduler", "coverage": "pending"},
        {"file": "server/api/scheduler/index.js", "method": "GET", "route": "/api/scheduler", "coverage": "pending"},
        {"file": "server/api/index.js", "coverage": "settings.write"},
    ]}
    assert fuxa.coverage_counts(profile, []) == {"pending": 4, "partial": 0}
    assert fuxa.coverage_counts(profile, list(fuxa.POLICY_REASONS)) == {"pending": 1, "partial": 1}


def test_audit_reports_gaps_and_detects_detached_controls(fleet):
    revision = fleet.make_release({"settings.write"})
    release = fleet.releases / revision
    metadata = fleet.meta(revision)
    report = fuxa.audit_coverage(fleet.profile(), release, metadata)
    # settings.write is enforced; the factory scheduler controls are wired but
    # only observed (protected_enforced is empty), so they count as observe.
    assert report["counts"]["enforced"] == 1
    assert report["counts"]["observe"] == 3
    assert report["counts"]["event_review"] == 1
    assert report["findings"] == [
        {"category": "event_review", "event": "STATUS", "file": "server/events.js", "line": 1,
         "role": "admin", "effect": "event"}
    ]
    source = release / fuxa.OPERATIONS["settings.write"]["file"]
    source.write_text(source.read_text(encoding="utf-8").replace("return res.status(403).end();", "return;"),
                      encoding="utf-8")
    with pytest.raises(ValueError, match="settings.write"):
        fuxa.audit_coverage(fleet.profile(), release, metadata)


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


def test_live_runtime_selects_the_only_active_deployment(tmp_path, monkeypatch):
    default = tmp_path / "fuxa"
    other = tmp_path / "fuxa-verified"
    alternate = tmp_path / "fuxa-alternate"
    for root in (default, other, alternate):
        root.mkdir()
        fuxa.write_json(root / "profile.json", {})
        fuxa.write_json(root / "deployment.json", {})

    running = {FuxaFleet(other).gateway}
    monkeypatch.setattr(FuxaFleet, "docker", lambda self, *args, **kwargs: "\n".join(running))
    monkeypatch.setattr(FuxaFleet, "active", lambda self: "d" * 12 if self.gateway in running else None)

    assert fuxa.live_runtime(default) == other
    running.add(FuxaFleet(alternate).gateway)
    with pytest.raises(ValueError, match="--runtime"):
        fuxa.live_runtime(default)
    running.add(FuxaFleet(default).gateway)
    assert fuxa.live_runtime(default) == default
    running.clear()
    assert fuxa.live_runtime(default) == default


@pytest.mark.parametrize("rollback", [False, True])
def test_dashboard_loads_incidents_with_live_status(fleet, rollback):
    from immune.fuxa_dashboard import Feed

    revision = fleet.make_release(set())
    fleet.active = Mock(return_value=revision)
    fleet.promote = Mock(return_value=None)
    if rollback:
        fleet.promote.side_effect = RuntimeError("synthetic post-switch verification failure")
    fleet.incident(effect(revision), synthetic=True)
    fuxa.write_json(fleet.root / "watch-cursor.json", ["container", 0])
    feed = Feed(fleet.root)
    feed.fleet = fleet
    batch = feed.collect()
    assert [item["type"] for item in batch[:6]] == [
        "fuxa.status", "request.classified", "incident.opened", "oracle.fired", "patch.attempt", "patch.diff",
    ]
    analysis = batch[3]
    assert analysis["incident"] == analysis["rid"] == batch[2]["data"]["evidence_rid"]
    assert analysis["data"]["events"][0]["detail"]["role"] == "usuario sin privilegios"
    assert [item["type"] for item in batch[-2:]] == ["deploy.done", "incident.closed"]
    assert batch[0]["data"]["active"] == revision
    assert batch[0]["data"]["monitor"]
    assert batch[1]["data"]["class"] == "simulation"
    assert batch[2]["data"]["fuxa"]["synthetic"]
    gates = [item for item in batch if item["type"] == "gate.result"]
    expected_gates = {"policy", "tests"} if rollback else {"policy"}
    assert {item["data"]["gate"] for item in gates} == expected_gates
    assert gates[0]["data"]["ok"] is True
    if rollback:
        assert gates[1]["data"]["ok"] is False
    assert batch[-2]["data"]["rolled_back"] is rollback
    assert batch[-1]["data"]["outcome"] == ("rolled_back" if rollback else "patched")
    assert feed.collect() == []


def test_dashboard_publishes_confirmed_and_suspicious_detections(fleet):
    from immune.fuxa_dashboard import Feed

    revision = fleet.make_release(set())
    fleet.active = Mock(return_value=revision)
    fleet.promote = Mock(return_value=None)
    observed = effect(revision)
    fleet.incident(observed)
    assert fuxa.assess({**observed, "decision": "blocked"}, revision) == "blocked"
    assert fuxa.assess({**observed, "decision": "blocked", "role": "unknown"}, revision) == "insufficient"
    signals = [
        {"id": "suspicious", "operation": observed["operation"], "status": "alert", "http_status": 401, "ts": 40},
        {"id": "blocked", "operation": observed["operation"], "status": "blocked", "http_status": 403, "ts": 42},
        {"id": "allowed", "reason": "historian_query", "status": "authorized", "http_status": None, "ts": 43},
        {"id": "offline", "reason": "scheduler_authorization", "status": "unavailable", "http_status": 503, "ts": 44},
    ]
    (fleet.root / "signals.jsonl").write_text("".join(json.dumps(row) + "\n" for row in signals), encoding="utf-8")
    feed = Feed(fleet.root)
    feed.fleet = fleet
    detections = [event for event in feed.collect() if event["type"] == "request.classified"]
    assert [(event["rid"], event["data"]["class"], event["data"].get("status")) for event in detections] == [
        (observed["id"], "evidence", None), ("suspicious", "suspect", 401), ("blocked", "blocked", 403),
        ("allowed", "authorized", None), ("offline", "unavailable", 503),
    ]
    assert feed.collect() == []


def test_dashboard_correlates_operation_verdict(fleet):
    from immune.fuxa_dashboard import Feed

    revision = fleet.make_release(set())
    fleet.active = Mock(return_value=revision)
    gateway_row = {"type": "fuxa.request", "id": "op-1", "sid": "s1", "ts": 10, "method": "POST",
                   "path": "/socket.io", "status": 200, "transport": "http", "ms": 3, "reason": "tag_write"}
    fleet.docker = Mock(return_value=json.dumps(gateway_row))
    feed = Feed(fleet.root)
    feed.fleet = fleet
    batch = feed.collect()
    delivery = [item for item in batch if item["type"] == "request.classified"][-1]
    assert delivery["rid"] == "op-1"
    assert delivery["data"]["class"] == "suspect"
    # The Socket.IO verdict joins the gateway request that delivered the event:
    # one operation, one row.
    signals = [{"id": "pol-1", "status": "authorized", "reason": "tag_write", "session": "s1",
                "verdict": "permitida", "http_status": None, "ts": 20}]
    (fleet.root / "signals.jsonl").write_text("".join(json.dumps(row) + "\n" for row in signals), encoding="utf-8")
    merged = [item for item in feed.collect() if item["type"] == "request.classified"][-1]
    assert merged["rid"] == "op-1"
    assert merged["data"]["class"] == "authorized"
    assert merged["data"]["verdict"] == "permitida"
    # The live panel sees the verdict on the same request row.
    snapshot = feed.requests()
    assert snapshot["requests"][0]["verdict"] == "authorized"


def test_dashboard_publishes_session_restrictions(fleet):
    from immune.fuxa_dashboard import Feed

    fleet.active = Mock(return_value=fleet.make_release(set()))
    signals = [
        {"id": "r1", "status": "restricted", "session": "sid:a", "operations": ["tag_write"],
         "reason": "repeated-denied-operations", "expires": 1000, "verdict": "sesión restringida",
         "http_status": 403, "ts": 10},
        {"id": "r2", "status": "restricted", "session": "sid:b", "operations": ["historian_query"],
         "reason": "repeated-denied-operations", "expires": 2000, "verdict": "sesión restringida",
         "http_status": 403, "ts": 11},
        {"id": "r3", "status": "released", "session": "sid:a", "reason": "ttl",
         "verdict": "restricción vencida", "http_status": None, "ts": 12},
    ]
    (fleet.root / "signals.jsonl").write_text("".join(json.dumps(row) + "\n" for row in signals), encoding="utf-8")
    feed = Feed(fleet.root)
    feed.fleet = fleet
    batch = feed.collect()
    kinds = [(item["type"], item["data"].get("session")) for item in batch
             if item["type"].startswith("session.")]
    assert kinds == [("session.restricted", "sid:a"), ("session.restricted", "sid:b"),
                     ("session.released", "sid:a")]
    active = feed.restrictions_snapshot()
    assert [row["session"] for row in active] == ["sid:b"]
    assert feed.collect() == []


def test_watch_records_verdicts_and_session_containment(fleet):
    revision = fleet.make_release(set())
    fleet.active = Mock(return_value=revision)
    entries = [
        json.dumps({"id": str(uuid.uuid4()), "type": "policy_decision", "revision": revision,
                    "reason": "tag_write", "decision": "allow", "session": "sid:x"}),
        json.dumps({"id": str(uuid.uuid4()), "type": "policy_decision", "revision": revision,
                    "reason": "tag_write", "decision": "contained", "session": "sid:x"}),
        json.dumps({"id": str(uuid.uuid4()), "type": "session_restricted", "revision": revision,
                    "session": "sid:x", "operations": ["tag_write"],
                    "reason": "repeated-denied-operations", "expires": 1000}),
        json.dumps({"id": str(uuid.uuid4()), "type": "session_released", "revision": revision,
                    "session": "sid:x", "reason": "ttl"}),
    ]
    fleet.docker = Mock(side_effect=[
        "container-id", json.dumps({"offset": 40, "entries": entries}),
        "container-id", json.dumps({"offset": 40, "entries": []}),
    ])
    fleet.watch(None)
    signals = [json.loads(line) for line in
               (fleet.root / "signals.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["status"] for row in signals] == ["authorized", "blocked", "restricted", "released"]
    assert [row["verdict"] for row in signals] == [
        "permitida", "bloqueada", "sesión restringida", "restricción vencida"
    ]
    assert signals[2]["operations"] == ["tag_write"] and signals[2]["expires"] == 1000


def test_watch_opens_incident_for_observed_factory_control(fleet):
    """An unprivileged role reaching a factory control in observation is the
    evidence: watch must open the incident (not silently drop it)."""
    revision = fleet.make_release(set())
    fleet.active = Mock(return_value=revision)
    fleet.promote = Mock(return_value=None)
    fleet.activate_rule = Mock(return_value=None)
    ident = str(uuid.uuid4())
    entries = [json.dumps({"id": ident, "type": "policy_decision", "revision": revision,
                           "reason": "scheduler_authorization", "decision": "observed",
                           "role": "unprivileged", "session": "token:abc"})]
    def docker(*args, **_):
        if args[:2] == ("exec", fleet.backend(revision)) and "/immune/read-events.cjs" in args:
            return json.dumps({"offset": 10, "entries": entries})
        return "container-id" if args[0] == "inspect" else None
    fleet.docker = Mock(side_effect=docker)
    fleet.watch(None)
    record = json.loads((fleet.root / "incidents" / ident / "incident.json").read_text(encoding="utf-8"))
    assert record["status"] == "deployed"
    assert record["operation"] == "scheduler_authorization" and record["session"] == "token:abc"
    assert "scheduler_authorization" in fleet.meta(record["candidate"])["enforced"]
    assert fleet.meta(record["candidate"])["controls"] == fleet.meta(revision)["controls"]


def test_session_routes_never_get_admin_guards(fleet):
    path = fleet.source / "server/api/auth/index.js"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('const runtime = 1;\nauthApp.post("/api/signin", fn);\nauthApp.post("/api/heartbeat", fn);\n',
                    encoding="utf-8")
    profile = fuxa.inventory(fleet.source)
    assert not any(c["route"] in fuxa.SESSION_ROUTES for c in fuxa.route_controls(profile, fleet.source).values())


def test_route_control_release_and_incident(fleet):
    path = fleet.source / "server/api/device/index.js"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        'const runtime = require("../runtime");\n'
        'router.post("/api/device", secureFnc, function(req, res) {\n'
        '    saveDevice(req, res);\n});\n',
        encoding="utf-8",
    )
    fuxa.write_json(fleet.root / "profile.json", fuxa.inventory(fleet.source))
    baseline = fleet.make_release(set())
    code = (fleet.releases / baseline / "server/api/device/index.js").read_text(encoding="utf-8")
    assert ('immuneMonitor.routeGuard("route.post.api-device", "observe", req, res, next, '
            'typeof runtime === "undefined" ? null : runtime)') in code
    audit = fuxa.audit_coverage(fleet.profile(), fleet.releases / baseline, fleet.meta(baseline))
    assert audit["counts"]["observe"] == 5
    assert audit["counts"]["event_review"] == 1
    fleet.active = Mock(return_value=baseline)
    fleet.promote = Mock(return_value=None)
    event = {
        "id": str(uuid.uuid4()), "revision": baseline, "type": "effect", "boundary": "write-route",
        "operation": "route.post.api-device", "role": "member", "decision": "observed",
    }
    assert fuxa.assess(event, baseline, fleet.meta(baseline)["controls"]) == "incident"
    result = fleet.incident(event)
    assert result["status"] == "deployed"
    assert result["gates"]["policy"]["ok"]
    assert "route.post.api-device" in fleet.meta(result["candidate"])["enforced"]
    enforced_code = (fleet.releases / result["candidate"] / "server/api/device/index.js").read_text(encoding="utf-8")
    assert '"enforce", req, res, next' in enforced_code


def test_route_control_skips_routes_without_resolvable_context(fleet):
    path = fleet.source / "server/api/hidden/index.js"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('router.post("/api/hidden", function(req, res) {\n    doIt();\n});\n', encoding="utf-8")
    profile = fuxa.inventory(fleet.source)
    assert fuxa.route_controls(profile, fleet.source) == {}
    fuxa.write_json(fleet.root / "profile.json", profile)
    baseline = fleet.make_release(set())
    assert fleet.meta(baseline)["controls"] == {}
    assert not (fleet.releases / baseline / "server/api/hidden/index.js").exists()


def test_containment_restricts_denied_operations_in_node(fleet):
    import shutil

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the containment checks")
    script = fleet.root / "containment-check.cjs"
    script.write_text(r"""
const assert = require('node:assert/strict');
const { createContainment } = require(process.argv[2]);

let moment = 0;
const events = [];
const containment = createContainment({
    threshold: 3, window: 120000, ttl: 900000, now: () => moment,
    emit: (type, payload) => events.push({ type, ...payload }),
});
const session = 'sid:synthetic';
assert.equal(containment.check(session, 'tag_write'), false);
for (let attempt = 0; attempt < 3; attempt++) {
    moment += 1000;
    assert.equal(containment.observe(session, 'tag_write'), attempt === 2);
}
const restricted = events.find(item => item.type === 'session_restricted');
assert.equal(restricted.session, session);
assert.deepEqual(restricted.operations, ['tag_write']);
assert.equal(restricted.reason, 'repeated-denied-operations');
assert.equal(restricted.expires, Math.round((3000 + 900000) / 1000));
assert.equal(containment.check(session, 'tag_write'), true);
// Ordinary activity, like reading the HMI, stays available.
assert.equal(containment.check(session, 'historian_query'), false);
containment.observe(session, 'historian_query');
assert.equal(containment.check(session, 'historian_query'), true);
assert.equal(containment.active().length, 1);
moment += 900001;
assert.equal(containment.check(session, 'tag_write'), false);
assert.deepEqual(events.filter(item => item.type === 'session_released'),
    [{ type: 'session_released', session, reason: 'ttl' }]);
console.log('ok');
""", encoding="utf-8")
    subprocess.run([node, str(script), str(fuxa.ASSETS / "containment.cjs")], check=True, timeout=10)


def test_route_guard_blocks_before_effect_in_node(fleet, monkeypatch, tmp_path):
    import shutil

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the route guard checks")
    helper = tmp_path / "auth.cjs"
    helper.write_text("exports.adminGroups = [255];", encoding="utf-8")
    monkeypatch.setenv("IMMUNE_FUXA_AUTH_HELPER", str(helper))
    source = fleet.source / "server/api/device/index.js"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        'const runtime = require("../runtime");\n'
        'router.post("/api/device", secureFnc, function(req, res) {\n'
        '    saveDevice(req, res);\n});\n',
        encoding="utf-8",
    )
    fuxa.write_json(fleet.root / "profile.json", fuxa.inventory(fleet.source))
    script = tmp_path / "route-guard-check.cjs"
    script.write_text(r"""
const assert = require('node:assert/strict');
const fs = require('node:fs');
const monitor = require(process.argv[2]);
const events = [];
const print = console.log;
console.log = line => events.push(JSON.parse(line.slice('IMMUNE_FUXA '.length)));
try {
    const runtime = {
        settings: { secureEnabled: true },
        users: { getUserCache: id => ({ groups: id === 'administrator' ? 255 : 2 }) },
    };
    const makeRes = () => {
        const res = { code: 200, end() { return res; } };
        res.status = code => { res.code = code; return res; };
        return res;
    };
    let steps = 0;
    for (const mode of ['observe', 'enforce']) {
        for (const [userId, role, allowed] of [
            ['administrator', 'admin', true], ['viewer', 'member', false], [null, 'anonymous', false],
        ]) {
            const req = { headers: { 'x-immune-op-id': '11111111-2222-3333-4444-555555555555' }, userId };
            const res = makeRes();
            let passed = false;
            monitor.routeGuard('route.post.api-device', mode, req, res, () => { passed = true; }, runtime);
            const decision = mode === 'observe' ? 'observed' : allowed ? 'allowed' : 'blocked';
            assert.equal(passed, allowed || mode === 'observe');
            assert.equal(res.code, allowed || mode === 'observe' ? 200 : 403);
            assert.equal(events[steps].id, '11111111-2222-3333-4444-555555555555');
            assert.equal(events[steps].operation, 'route.post.api-device');
            assert.equal(events[steps].boundary, 'write-route');
            assert.equal(events[steps].role, role);
            assert.equal(events[steps].decision, decision);
            steps++;
        }
    }
    // Fail-closed: without a resolvable runtime the effect is stopped in enforce mode.
    const req = { headers: {}, userId: 'administrator' };
    const res = makeRes();
    let passed = false;
    monitor.routeGuard('route.post.api-device', 'enforce', req, res, () => { passed = true; }, null);
    assert.equal(passed, false);
    assert.equal(res.code, 403);
    assert.equal(events[steps].role, 'unknown');
    assert.equal(events[steps].decision, 'blocked');
    steps++;
    console.log = print;
    console.log(JSON.stringify({ steps }));
} finally {
    console.log = print;
}
""", encoding="utf-8")
    result = subprocess.run([node, str(script), str(fuxa.ASSETS / "observe.cjs")], check=True,
                            capture_output=True, text=True, timeout=10)
    assert json.loads(result.stdout.strip().splitlines()[-1])["steps"] == 7


def test_dashboard_reads_recent_gateway_requests(fleet):
    from immune.fuxa_dashboard import Feed

    original = {"type": "fuxa.request", "ts": 42, "method": "GET", "path": "/api/version",
                "status": 200, "transport": "http", "ms": 5, "extra": "discard"}
    rejected = {**original, "ts": 43, "path": "/api/users", "status": 401}
    latest = {**original, "ts": 44, "status": None}
    fleet.docker = Mock(return_value="\n".join([
        "noise", '{"type":"fuxa.request"}', json.dumps(original), json.dumps(rejected), json.dumps(latest)
    ]))
    feed = Feed(fleet.root)
    feed.fleet = fleet
    snapshot = feed.requests()
    assert snapshot["available"]
    assert [(row["ts"], row["class"]) for row in snapshot["requests"]] == [
        (44, "clean"), (43, "suspect"), (42, "clean")
    ]
    assert "discard" not in json.dumps(snapshot)


def test_dashboard_emits_gateway_signal_once_on_successful_response(fleet):
    from immune.fuxa_dashboard import Feed

    fleet.active = Mock(return_value=fleet.make_release(set()))
    fleet.docker = Mock(return_value=json.dumps({
        "type": "fuxa.request", "id": "gateway-test", "ts": 42, "method": "POST",
        "path": "/socket.io", "status": 200, "transport": "http", "ms": 5, "reason": "historian_query",
    }))
    feed = Feed(fleet.root)
    feed.fleet = fleet
    detection = feed.collect()[-1]
    assert detection["type"] == "request.classified"
    assert detection["data"]["class"] == "suspect"
    assert detection["data"]["reason"] == "historian_query"
    assert feed.collect() == []


def test_gateway_inspects_polling_without_forwarding_fixture(tmp_path):
    import shutil

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the gateway checks")
    script = tmp_path / "gateway-check.cjs"
    script.write_text(r"""
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { PassThrough } = require('node:stream');
const { watchRequest } = require(process.argv[2]);

async function inspect(body, version) {
    const request = Object.assign(new PassThrough(), {
        method: 'POST', url: '/socket.io/?transport=polling&EIO=' + version, headers: {},
    });
    const signal = watchRequest(request, '/socket.io', 'http');
    const end = once(request, 'end');
    request.write(body.slice(0, 5));
    request.end(body.slice(5));
    await end;
    return signal();
}

async function main() {
    const fixture = '42' + JSON.stringify(['daq-query', { fixture: true }]);
    assert.equal(await inspect('2\x1e' + fixture, '4'), 'historian_query');
    assert.equal(await inspect('1:2' + fixture.length + ':' + fixture, '3'), 'historian_query');
    assert.equal(await inspect('42' + JSON.stringify(['status', { fixture: 'daq-query' }]), '4'), null);
    assert.equal(await inspect('x'.repeat(65537), '4'), 'not_inspected');
    assert.equal(watchRequest({ method: 'POST', headers: {} }, '/api/scheduler', 'http')(), 'scheduler_without_token');
    assert.equal(watchRequest({}, '/socket.io', 'websocket')(), 'not_inspected');
}

main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
""", encoding="utf-8")
    subprocess.run([node, str(script), str(fuxa.ASSETS / "gateway-signals.cjs")], check=True, timeout=10)


def test_validation_report_requires_the_entire_suite(fleet):
    revision = fleet.make_release(set())
    report_path = fleet.releases / revision / "policy-validation.json"
    sample = {"checks": 39, "identities": 7, "evaluator": "metadata", "operations": list(fuxa.POLICY_REASONS)}
    fleet.ensure_network = Mock()
    fleet.docker = Mock(side_effect=["", json.dumps(sample), RuntimeError("FUXA suite failed")])
    with pytest.raises(RuntimeError, match="FUXA suite failed"):
        fleet.test(revision)
    assert not report_path.exists()
    fleet.docker.side_effect = ["", json.dumps(sample), ""]
    fleet.test(revision)
    assert json.loads(report_path.read_text(encoding="utf-8")) == sample


def test_validate_active_uses_the_running_image(fleet):
    image = "sha256:" + "a" * 64
    fleet.active = Mock(return_value="d" * 12)
    fleet.docker = Mock(return_value=image + "\n")
    fleet.test = Mock()
    fleet.deployment = Mock(return_value={"port": 1881, "smoke": {}})
    fleet.gateway_smoke = Mock()
    fleet.verify_legitimate = Mock()
    fleet.status = Mock(return_value={"active": "d" * 12})
    assert fleet.validate_active() == {"active": "d" * 12}
    fleet.test.assert_called_once_with("d" * 12, image=image)
    fleet.verify_legitimate.assert_called_once_with("d" * 12, 1881)


@pytest.mark.parametrize("failure", ["test", "direct", "state", "gateway", "legitimate", None])
@pytest.mark.parametrize("previous", [None, "state-old"])
def test_rollout_validates_before_switch_and_restores_previous_revision(fleet, failure, previous):
    settings = {"port": 1881, "smoke": {"/": "expected"}, "state_volume": previous}
    fuxa.write_json(fleet.root / "deployment.json", settings)
    active = ["baseline"]
    changes = []

    def activate(revision):
        active[0] = revision
        changes.append(revision)

    def check(revision, smoke, port):
        if failure == "gateway" and revision == "candidate":
            raise RuntimeError("failed through gateway")

    def check_legitimate(revision, port):
        if failure == "legitimate" and revision == "candidate":
            raise RuntimeError("failed legitimate flow")

    fleet.active = lambda: active[0]
    fleet.activate = activate
    fleet.build = Mock()
    fleet.docker = Mock()
    fleet.copy_state = Mock()
    fleet.state_volume = Mock(return_value="state-new")
    fleet.state_mount = Mock()
    fleet.state_signature = Mock(side_effect=[("key", "project"), ("other" if failure == "state" else "key", "project")])
    fleet.test = Mock(side_effect=RuntimeError("test failed") if failure == "test" else None)
    fleet.start = Mock()
    fleet.remove = Mock()
    fleet.gateway_smoke = check
    fleet.verify_legitimate = check_legitimate
    fleet.local_smoke = Mock(return_value={"/": "changed" if failure == "direct" else "expected"})
    if failure:
        with pytest.raises(FuxaRollback if failure in ("gateway", "legitimate") else RuntimeError):
            fleet.promote("baseline", "candidate")
        assert active[0] == "baseline"
        assert changes == (["candidate", "baseline"] if failure in ("gateway", "legitimate") else [])
        if failure == "test":
            fleet.start.assert_not_called()
            fleet.copy_state.assert_not_called()
        else:
            fleet.remove.assert_called_once_with(fleet.backend("candidate"))
            assert fleet.deployment() == settings
            if previous:
                fleet.docker.assert_any_call("start", fleet.backend("baseline"))
            else:
                fleet.docker.assert_any_call("network", "connect", fleet.internal, fleet.backend("baseline"))
    else:
        fleet.promote("baseline", "candidate")
        assert changes == ["candidate"]
        assert fleet.deployment()["state_volume"] == "state-new"
        fleet.remove.assert_called_once_with(fleet.backend("baseline"))
    if failure != "test":
        fleet.copy_state.assert_called_once_with("baseline", previous, "state-new")
        fleet.start.assert_called_once_with("candidate", "state-new")


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
