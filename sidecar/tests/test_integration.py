"""Integration tests with real containers (private --internal network, names p4-*): the Node demo app
runs unmodified from node:22-alpine, the sidecar (immune-sidecar:1) attaches to it through a shared PID
namespace. Same cases as acceptance/wp2_shadow/test_shadow.py where they apply.

Run: .venv/bin/pytest sidecar/tests/test_integration.py -q
"""
import base64
import json
import os
import shutil
import time

import httpx
import jsonschema
import pytest

from immune_contracts import wire
from sidecar.tests.dockerenv import ROOT, Stack

pytestmark = [pytest.mark.docker,
              pytest.mark.skipif(shutil.which("docker") is None, reason="needs docker")]

UNION = "x' UNION SELECT id, body FROM notes--"


@pytest.fixture(scope="module")
def stack():
    s = Stack(tag="it" + os.urandom(2).hex()).up()
    yield s
    print(s.logs(s.sc)[-4000:])
    s.down()


def get(s, path, params=None, headers=None, mode="L1", rid="r", uid=None, role="user", **kw):
    h = {wire.H_RID: rid, wire.H_MODE: mode, **(headers or {})}
    if uid is not None:
        h[wire.H_UID] = str(uid); h[wire.H_ROLE] = role
    return httpx.get(s.url + path, params=params, headers=h, timeout=20, **kw)


def kinds(r, s=None):
    return int(r.headers[wire.H_EVENTS])


def last_evidence(s):
    got = s.evidence()
    return json.loads(got[-1]["body"]) if got else None


def test_concat_search_quote_breaking_fires_sql(stack):
    stack.clear_evidence()
    r = get(stack, "/search", {"q": UNION}, rid="sqli")
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle"
    ev = last_evidence(stack)
    sql = [e for e in ev["events"] if e["oracle"] == "sql"]
    assert sql and "UNION" in sql[0]["detail"]["statement"] and sql[0]["detail"]["param"] == "q"
    assert sql[0]["stack"] == []
    assert "owner" in [e["oracle"] for e in ev["events"]]  # the dump of private rows to an anonymous caller


def test_comment_injection_fires(stack):
    r = get(stack, "/search", {"q": "cable'--"})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle"


def test_benign_search_clean(stack):
    r = get(stack, "/search", {"q": "usb"})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "clean" and r.headers[wire.H_EVENTS] == "0"


def test_same_input_on_parameterised_search_is_clean(stack):
    r = get(stack, "/safe-search", {"q": UNION})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "clean"


def test_obrien_parameterised_clean_and_concat_inconclusive(stack):
    r = get(stack, "/safe-search", {"q": "O'Brien"})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "clean" and b"stout" in r.content
    r = get(stack, "/search", {"q": "O'Brien"})  # syntax error: the statement never executed
    assert r.status_code >= 500 and r.headers[wire.H_VERDICT] == "inconclusive"


def test_download_outside_root_fires_file(stack):
    stack.clear_evidence()
    r = get(stack, "/download", {"name": "../../etc/hostname"}, rid="trav")
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle"
    ev = last_evidence(stack)
    f = [e for e in ev["events"] if e["oracle"] == "file"]
    # node's path.join already normalised the name, so the syscall argument is the final path
    assert f[0]["detail"] == {"path": "/etc/hostname", "realpath": "/etc/hostname"}
    assert r.content.strip() == httpx.get(stack.url + "/download", params={"name": "../../etc/hostname"},
                                          headers={wire.H_MODE: "L1"}).content.strip()


def test_safe_download_traversal_is_inconclusive(stack):
    r = get(stack, "/safe-download", {"name": "../../etc/hostname"})
    assert r.status_code == 404 and r.headers[wire.H_VERDICT] == "inconclusive"


def test_legit_download_with_dots_clean_twice(stack):
    for _ in range(2):
        r = get(stack, "/download", {"name": "manual.v1.txt"})
        assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "clean" and r.content.startswith(b"manual v1")


def test_owner_oracle(stack):
    stack.clear_evidence()
    r = get(stack, "/notes/2", uid=1, rid="own")
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle" and r.headers[wire.H_EVENTS] == "1"
    ev = last_evidence(stack)
    assert [e["oracle"] for e in ev["events"]] == ["owner"]
    assert ev["events"][0]["detail"] == {"marker_owner": 2, "requester": 1}
    assert get(stack, "/notes/1", uid=1).headers[wire.H_VERDICT] == "clean"
    assert get(stack, "/notes/2", uid=1, role="admin").headers[wire.H_VERDICT] == "clean"


def test_identity_replaces_client_token(stack):
    r = get(stack, "/notes/1", uid=1, headers={"authorization": "Bearer garbage-prod-token"})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "clean"
    assert get(stack, "/notes/1").status_code == 401  # no x-imm-uid: client headers untouched


def test_unknown_user_is_created_and_judged(stack):
    r = get(stack, "/notes/1", uid=99)
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle"


def test_fixed_endpoint_is_inconclusive(stack):
    r = get(stack, "/safe-notes/2", uid=1)
    assert r.status_code == 404 and r.headers[wire.H_VERDICT] == "inconclusive"


def test_l1_resets_and_l2_keeps_state(stack):
    hd = {wire.H_RID: "w", wire.H_UID: "1", wire.H_ROLE: "user", "content-type": "application/json"}
    r = httpx.post(stack.url + "/notes", json={"body": "hello"}, headers={**hd, wire.H_MODE: "L1"}, timeout=20)
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "clean"
    nid = r.json()["id"]
    assert get(stack, f"/safe-notes/{nid}", uid=1, mode="L1").status_code == 404  # gone after the reset
    r = httpx.post(stack.url + "/notes", json={"body": "hello"}, headers={**hd, wire.H_MODE: "L2"}, timeout=20)
    nid = r.json()["id"]
    assert get(stack, f"/safe-notes/{nid}", uid=1, mode="L2").status_code == 200
    assert get(stack, f"/safe-notes/{nid}", uid=1, mode="L1").status_code == 200  # L1 after L2 still sees it...
    assert get(stack, f"/safe-notes/{nid}", uid=1, mode="L1").status_code == 404  # ...and then it is reset


def test_proc_and_net_oracles(stack):
    r = get(stack, "/lookup", {"host": "x; id"})
    assert r.headers[wire.H_VERDICT] == "oracle" and b"uid=0" in r.content
    r = get(stack, "/fetch", {"url": "http://10.1.2.3/"})
    assert r.headers[wire.H_VERDICT] == "oracle"


def test_grace_period_catches_deferred_effect_and_bounds_it(stack):
    # the app answers, then opens the file 5 ms later (not awaited): inside the 30 ms grace window
    r = get(stack, "/deferred", {"name": "../../etc/hostname", "delay": "5"})
    assert r.status_code == 202 and r.headers[wire.H_VERDICT] == "oracle"
    # 300 ms later is outside the window: not attributed to this request, and dropped (no request in flight)
    r = get(stack, "/deferred", {"name": "../../etc/hostname", "delay": "300"})
    assert r.headers[wire.H_VERDICT] == "clean"
    time.sleep(0.5)
    assert get(stack, "/health").headers[wire.H_VERDICT] == "clean"  # the late open did not leak into this one


def test_evidence_signed_schema_valid_and_pushed_before_response(stack):
    stack.clear_evidence()
    r = get(stack, "/download", {"name": "../../etc/hostname"}, rid="r2", mode="L2",
            headers={"x-imm-extra": "secret", "x-custom": "v"})
    assert r.headers[wire.H_VERDICT] == "oracle" and int(r.headers[wire.H_EVENTS]) >= 1
    got = stack.evidence()
    assert len(got) == 1  # already there when the response arrived
    headers, body = got[0]["headers"], got[0]["body"].encode()
    assert headers[wire.H_CLONE_ID] == "c1" and wire.check("k1", body, headers[wire.H_SIGNATURE])
    ev = json.loads(body)
    schema = json.load(open(os.path.join(ROOT, "contracts/schemas/evidence.schema.json")))
    jsonschema.validate(ev, schema)
    assert ev["rid"] == "r2" and ev["mode"] == "L2" and ev["release"] == "t0" and ev["clone"] == "c1"
    assert ev["pre_state_b64"] is None  # CONTRACT_GAP: no sqlite pre-state for Postgres
    assert not any(k.startswith("x-imm-") for k in ev["request"]["headers"])
    assert ev["request"]["headers"]["x-custom"] == "v"
    assert not any(k.lower().startswith("x-imm-") and k.lower() not in (wire.H_VERDICT, wire.H_EVENTS)
                   for k in r.headers)


def test_collector_down_does_not_break_response():
    s = Stack(tag="cd" + os.urandom(2).hex(), collector=False, collector_url="http://127.0.0.1:9").up()
    try:
        t = time.time()
        r = get(s, "/search", {"q": "cable'--"})
        assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle" and time.time() - t < 3
        assert "push failed" in s.logs(s.sc)
    finally:
        s.down()



def test_zz_tracer_death_fails_closed(stack):
    """Last user of the module stack: kill strace; the sidecar must stop judging (never a false clean)."""
    from sidecar.tests.dockerenv import sh
    sh("docker", "exec", stack.sc, "pkill", "-KILL", "strace")
    time.sleep(0.3)
    r = get(stack, "/download", {"name": "../../etc/hostname"})
    assert r.status_code == 503 and r.headers[wire.H_VERDICT] == "inconclusive"
    # the app itself keeps running untraced (the kernel detaches tracees when the tracer dies)
    assert sh("docker", "inspect", "-f", "{{.State.Running}}", stack.app) == "true"

# ---- compiled, statically linked app (C, own Postgres client, identity via identity_command) ----
@pytest.fixture(scope="module")
def cstack():
    s = Stack(tag="c" + os.urandom(2).hex(), app="c").up()
    yield s
    print(s.logs(s.sc)[-3000:])
    s.down()


def test_c_sql_oracle_and_parameterised(cstack):
    r = get(cstack, "/search", {"q": UNION})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle" and b"MKBBBBBBBBB2" in r.content
    assert get(cstack, "/search", {"q": "usb"}).headers[wire.H_VERDICT] == "clean"
    assert get(cstack, "/safe-search", {"q": UNION}).headers[wire.H_VERDICT] == "clean"
    r = get(cstack, "/safe-search", {"q": "O'Brien"})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "clean" and b"stout" in r.content
    assert get(cstack, "/search", {"q": "O'Brien"}).headers[wire.H_VERDICT] == "inconclusive"


def test_c_file_oracle(cstack):
    r = get(cstack, "/download", {"name": "../../etc/hostname"})
    assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle"
    for _ in range(2):
        assert get(cstack, "/download", {"name": "manual.v1.txt"}).headers[wire.H_VERDICT] == "clean"
    assert get(cstack, "/safe-download", {"name": "../../etc/hostname"}).headers[wire.H_VERDICT] == "inconclusive"


@pytest.fixture(scope="module")
def cdynstack():
    s = Stack(tag="d" + os.urandom(2).hex(), app="cdyn").up()
    yield s
    print(s.logs(s.sc)[-3000:])
    s.down()


def test_c_file_event_carries_the_native_stack_of_the_sink(cdynstack):
    """The compiled app is observed from outside, yet the evidence says where in its code the file was opened:
    strace -k frames + addr2line (the demo is built with -g and linked dynamically: strace's unwinder loses the
    frames of a static glibc), mapped back to the repo path."""
    cdynstack.clear_evidence()
    r = get(cdynstack, "/download", {"name": "../../etc/hostname"}, rid="c-stack")
    assert r.headers[wire.H_VERDICT] == "oracle"
    ev = next(e for e in last_evidence(cdynstack)["events"] if e["oracle"] == "file")
    stack = ev["stack"]
    assert stack, "native_stack is on: the file event must carry frames"
    sink = stack[-1]
    # fopen() in serve_file(), called from handle() (the compiler may inline the former into the latter)
    assert sink["file"] == "sidecar/examples/c/app.c" and sink["func"] in ("serve_file", "handle")
    assert 162 <= sink["line"] <= 163
    assert all(set(f) == {"file", "line", "func"} and isinstance(f["line"], int) for f in stack)


def test_c_owner_oracle_via_identity_command(cstack):
    assert get(cstack, "/notes/2", uid=1).headers[wire.H_VERDICT] == "oracle"
    assert get(cstack, "/notes/1", uid=1).headers[wire.H_VERDICT] == "clean"
    assert get(cstack, "/notes/1").status_code == 401  # without x-imm-uid nothing is injected
    assert get(cstack, "/safe-notes/2", uid=1).headers[wire.H_VERDICT] == "inconclusive"


# ---- launch mode: the sidecar starts the app as its traced child; no capabilities at all ----
def test_launch_mode_without_capabilities(tmp_path):
    from sidecar.tests.dockerenv import ip_of, sh, wait_until
    tag = os.urandom(2).hex()
    net, name = f"p4-lnet-{tag}", f"p4-launch-{tag}"
    cfg = {"listen_port": 8000, "app_port": 3000, "mode": "launch",
           "command": ["python3", "/opt/immune/sidecar/examples/pyhttp/app.py"],
           "allowed_file_roots": ["/opt/immune/sidecar/examples/pyhttp/static"],
           "warmup_paths": ["/download?name=manual.v1.txt"]}
    (tmp_path / "sidecar.json").write_text(json.dumps(cfg))
    os.chmod(tmp_path, 0o755); os.chmod(tmp_path / "sidecar.json", 0o644)
    sh("docker", "network", "create", "--internal", net)
    try:
        sh("docker", "run", "-d", "--name", name, "--network", net, "--cap-drop", "ALL", "--read-only",
           "-v", f"{ROOT}:/opt/immune:ro", "-v", f"{tmp_path}:/cfg:ro", "-e", "PYTHONPATH=/opt/immune",
           "immune-sidecar:1", "python", "-m", "sidecar", "--config", "/cfg/sidecar.json")
        url = f"http://{ip_of(name, net)}:8000"
        wait_until(lambda: httpx.get(url + "/health", timeout=2).status_code == 200, 60, 0.3, "launch sidecar")
        h = {wire.H_MODE: "L1"}
        for _ in range(2):
            assert httpx.get(url + "/download", params={"name": "manual.v1.txt"}, headers=h).headers[wire.H_VERDICT] == "clean"
        r = httpx.get(url + "/download", params={"name": "../../../../../../etc/hostname"}, headers=h)
        assert r.status_code == 200 and r.headers[wire.H_VERDICT] == "oracle"
        assert httpx.get(url + "/lookup", params={"host": "x"}, headers=h).headers[wire.H_VERDICT] == "oracle"
        assert "--seccomp-bpf" in subprocess_logs(name)
    finally:
        sh("docker", "rm", "-f", name, check=False)
        sh("docker", "network", "rm", net, check=False)


def subprocess_logs(name):
    import subprocess
    return subprocess.run(["docker", "logs", name], capture_output=True, text=True).stderr
