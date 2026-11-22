"""`immune doctor`: verification of a project's adaptation (contracts/product.md §5, checks 1-7, plus 8:
the generated legit scenarios are deterministic).

    python -m immune.doctor [--project DIR] [--json] [--only 1,2]
    python -m immune.doctor --prereqs [--json]     host prerequisites only (no project needed; install.sh runs it)
    from immune import doctor; checks = doctor.run(project)

Each check -> {"id", "name", "ok", "reason" (one line), "owner" (the init step that owns the failing
artefact: columns | profile | marks | config | none), "detail"}.

Target code is never imported in this process: checks 2-5 drive shadow.harness in a clean child
interpreter (immune.initsteps.harness_runner) on a fresh release copy; checks 1 and 7 run in
`docker run --rm --network none` containers on immune-base:1.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

import yaml

from immune import _cfg, shadowdata
from immune.initsteps import docker, openapi as oa, sandbox

NAMES = {1: "config, release, clone health", 2: "profile identity", 3: "legitimate GETs are clean",
         4: "synthetic canaries", 5: "L1 reset", 6: "no real data in the shadow", 7: "tests in the runner",
         8: "legit scenarios deterministic"}
SECRET = sandbox.SHADOW_SECRET


def _check(i, ok, reason, owner="none", detail=None, status=None):
    return {"id": i, "name": NAMES[i], "ok": bool(ok), "status": status or ("pass" if ok else "fail"),
            "reason": reason, "owner": owner if not ok else "none", "detail": detail or {}}


def build_release(cfg, dst: str | None = None) -> str:
    """Copy app.release_paths + .immune/<profile>.py into a fresh directory (the doctor's release)."""
    dst = dst or tempfile.mkdtemp(prefix="immune-release-")
    ign = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache")
    for rel in cfg.app.release_paths:
        src = os.path.join(cfg.project_dir, rel)
        out = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        if os.path.isdir(src):
            shutil.copytree(src, out, ignore=ign, symlinks=False)
        else:
            shutil.copyfile(src, out)
    for mod in (cfg.shadow.profile, cfg.scenarios):
        src = os.path.join(cfg.project_dir, ".immune", (mod or "").replace(".", "/") + ".py")
        if mod and os.path.isfile(src):
            os.makedirs(os.path.join(dst, ".immune"), exist_ok=True)
            shutil.copyfile(src, os.path.join(dst, ".immune", os.path.basename(src)))
    return dst


def _manifest(cfg) -> dict:
    try:
        with open(cfg.manifest_path) as f:
            return json.load(f)
    except Exception:
        return {}


def _columns(cfg) -> dict:
    try:
        with open(_cfg.columns_path(cfg)) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _openapi(cfg) -> dict:
    try:
        with open(cfg.openapi) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def legit_uid(m: dict) -> int:
    lu = m.get("legit_users") or []
    if lu:
        return int(lu[0]["id"])
    return int(m.get("seed_max_uid") or 0) or 1


def container_env(cfg, db="/data/app.db") -> dict:
    env = cfg.app_env(db=db, secret=SECRET, root=_cfg.CONTAINER_APP)
    env.update({"APP_DB": db, "APP_SECRET": env.get("APP_SECRET", SECRET), "SHADOW_SEED_DB": "/seed/shadow/seed.db",
                "MARKERS_PATH": "/seed/markers.json", "CLONE_ID": "doctor", "RELEASE": "doctor",
                "PYTHONPATH": "/app:/opt/immune:/app/.immune", "PYTHONDONTWRITEBYTECODE": "1"})
    return env


# ------------------------------------------------------------------------------------------- checks
def check1(cfg, release) -> dict:
    missing = [p for p in cfg.app.release_paths if not os.path.exists(os.path.join(release, p))]
    if missing:
        return _check(1, False, "release incomplete: missing %s" % missing, "config")
    if not os.path.isfile(cfg.shadow_seed):
        return _check(1, False, "no shadow seed at %s (shadow data not built)" % cfg.shadow_seed, "columns")
    ok, why = docker.available()
    if not ok:
        return _check(1, False, "cannot start a clone container: %s" % why, "none")
    data = os.path.dirname(cfg.manifest_path)
    rc, out, err = docker.run([(release, "/app", "ro"), docker.HOME_MOUNT, (data, "/seed", "ro")],
                              docker.boot("immune.initsteps.clone_probe", ["/app", "/opt/immune"]),
                              env=container_env(cfg), stdin=json.dumps({"profile": cfg.shadow.profile,
                                                                         "health": cfg.app.health, "port": 8000}),
                              timeout=180)
    res = docker.last_json(out) or {}
    if res.get("ok"):
        return _check(1, True, "config valid; release built; clone container answered %s %s (verdict %s) in %ss"
                      % (cfg.app.health, res.get("status"), res.get("verdict"), res.get("seconds")), detail=res)
    log = (res.get("log") or err or out or "")[-600:]
    return _check(1, False, "clone did not answer %s: %s" % (cfg.app.health, res.get("error") or ("exit %s" % rc)),
                  "profile", {"log": log})


def _job1(cfg, m, doc):
    uid = legit_uid(m)
    fresh = int(m.get("seed_max_uid") or 0) + 50
    reqs = []
    for p in oa.param_free_gets(doc):
        reqs.append({"name": "anon %s" % p, "path": p})
        reqs.append({"name": "user %s" % p, "path": p, "uid": uid, "role": "user"})
        reqs.append({"name": "fresh %s" % p, "path": p, "uid": fresh, "role": "user"})
    return {"requests": reqs}, uid, fresh


def checks23(cfg, release, m, doc) -> list[dict]:
    job, uid, fresh = _job1(cfg, m, doc)
    res = sandbox.harness(cfg, release, job)
    if not res.get("ok"):
        err = "harness could not host the app: %s" % res.get("error")
        tail = (res.get("trace") or res.get("stderr_tail") or "")[-800:]
        return [_check(2, False, err, "profile", {"trace": tail}), _check(3, False, err, "profile", {"trace": tail})]
    by = {r["name"]: r for r in res["results"]}
    # 2: an authenticated route: anonymous -> 401/403, fresh identity from ensure_user+mint_token -> 2xx
    paths = oa.param_free_gets(doc)
    if cfg.auth.kind == "introspect" and cfg.auth.path in paths:
        paths = [cfg.auth.path] + [p for p in paths if p != cfg.auth.path]
    c2 = None
    tried = []
    for p in paths:
        a, f = by.get("anon %s" % p), by.get("fresh %s" % p)
        if not a or not f or a["status"] not in (401, 403):
            continue
        tried.append("%s anon=%s minted=%s" % (p, a["status"], f["status"]))
        if 200 <= f["status"] < 300:
            if cfg.auth.kind == "introspect" and p == cfg.auth.path:
                try:
                    got = json.loads(f["body"]).get(cfg.auth.uid_field)
                except Exception:
                    got = None
                if str(got) != str(fresh):
                    c2 = _check(2, False, "%s with a minted token for uid %d returned %s=%r" % (p, fresh, cfg.auth.uid_field, got),
                                "profile", {"response": f["body"][:300]})
                    break
            c2 = _check(2, True, "ensure_user+mint_token(uid=%d) accepted on %s (anonymous %d, minted %d)"
                        % (fresh, p, a["status"], f["status"]))
            break
    if c2 is None:
        if cfg.auth.kind == "none":
            c2 = _check(2, True, "auth.kind none: nothing to verify")
        elif tried:
            c2 = _check(2, False, "a minted identity was rejected on every authenticated route: %s" % "; ".join(tried[:4]),
                        "profile", {"responses": {t: by.get("fresh %s" % t.split()[0], {}).get("body", "")[:200]
                                                  for t in tried[:3]}})
        else:
            c2 = _check(2, False, "no parameter-free GET route answers 401/403 anonymously; cannot verify the identity",
                        "profile")
    # 3: legitimate GETs (anonymous and as a seeded user) are clean (inconclusive only for 401/404)
    bad = []
    for r in res["results"]:
        if r["name"].startswith("fresh "):
            continue
        if r["verdict"] == "clean" or (r["verdict"] == "inconclusive" and r["status"] in (401, 404)):
            continue
        bad.append(r)
    if bad:
        owners = {"owner": "profile", "file": "profile", "sql": "none"}
        own = next((owners.get(o, "profile") for b in bad for o in b["oracles"]), "profile")
        desc = "; ".join("%s -> %s %s%s" % (b["name"], b["status"], b["verdict"],
                                            (" " + ",".join(b["oracles"])) if b["oracles"] else "") for b in bad[:5])
        c3 = _check(3, False, desc, own, {"failures": [{k: b[k] for k in ("name", "status", "verdict", "oracles",
                                                                             "events", "body")} for b in bad[:5]]})
    else:
        n = len([r for r in res["results"] if not r["name"].startswith("fresh ")])
        c3 = _check(3, True, "%d legitimate GETs on %d parameter-free routes: clean/expected" % (n, n // 2))
    return [c2, c3]


def _owner_target(cols) -> dict | None:
    ut, uc = cols.get("users_table"), cols.get("user_id_column") or "id"
    t = (cols.get("tables") or {})
    priv = (t.get(ut) or {}).get("private") or []
    if ut and priv:
        pick = next((c for c in priv if "name" in c.lower()), None) or next((c for c in priv if "mail" in c.lower()), priv[0])
        return {"table": ut, "column": pick, "owner_col": uc}
    for name, spec in t.items():
        if isinstance(spec, dict) and isinstance(spec.get("owner"), str) and spec.get("private"):
            return {"table": name, "column": spec["private"][0], "owner_col": spec["owner"]}
    return None


def checks45(cfg, release, m, cols) -> list[dict]:
    uid = legit_uid(m)
    target = _owner_target(cols)
    reqs = [{"name": "sql", "path": "/__immune_selftest__/sql", "query": "q=zz%27%20OR%20%271%27%3D%271"},
            {"name": "file", "path": "/__immune_selftest__/file"}]
    if target:
        reqs.append({"name": "owner", "path": "/__immune_selftest__/owner", "query": "exclude=%d" % uid, "uid": uid,
                     "role": "user"})
    job = {"selftest": {"owner": target}, "requests": reqs,
           "reset_check": {"uid": int(m.get("seed_max_uid") or 0) + 777, "path": cfg.app.health}}
    res = sandbox.harness(cfg, release, job)
    if not res.get("ok"):
        err = res.get("error") or ""
        gap = "CONTRACT_GAP: the harness cannot host the self-test shim (%s)" % err
        return [_check(4, False, gap, "none", {"trace": (res.get("trace") or "")[-800:]}),
                _check(5, False, "harness failed: %s" % err, "profile")]
    by = {r["name"]: r for r in res["results"]}
    missing = []
    for kind in ("sql", "file", "owner"):
        r = by.get(kind)
        if r is None:
            missing.append("%s: no owner-scoped private column to read (columns.yaml)" % kind)
        elif kind not in r["oracles"]:
            missing.append("%s: oracle did not fire (status %s, verdict %s, body %s)" % (kind, r["status"], r["verdict"],
                                                                                      r["body"][:120]))
    if missing:
        own = "columns" if any(x.startswith("owner") for x in missing) else \
            ("profile" if any(x.startswith("file") for x in missing) else "none")
        c4 = _check(4, False, "; ".join(missing), own, {"results": res["results"]})
    else:
        c4 = _check(4, True, "string-built SQL, open outside the roots and a foreign marker each fired their oracle")
    rs = res.get("reset") or {}
    if rs.get("start_equals_seed") and rs.get("restored") and rs.get("mutated_by_L2"):
        c5 = _check(5, True, "L2 write (ensure_user) changed the db; the next L1 request restored the seed state")
    elif rs.get("start_equals_seed") and rs.get("restored"):
        c5 = _check(5, True, "database equals the seed after an L1 request (ensure_user did not write in L2)",
                    status="pass")
    else:
        c5 = _check(5, False, "reset: %s" % rs, "none", rs)
    return [c4, c5]


def check6(cfg) -> dict:
    cols = _cfg.columns_path(cfg)
    if not os.path.isfile(cfg.data.prod_db):
        return _check(6, False, "production database %s not found" % cfg.data.prod_db, "config")
    if not os.path.isfile(cfg.shadow_seed):
        return _check(6, False, "no shadow seed at %s" % cfg.shadow_seed, "columns")
    if not os.path.isfile(cols):
        if cfg.data.seed_command:
            return _check(6, True, "shadow produced by data.seed_command; no columns.yaml to sample from", status="skip")
        return _check(6, False, "no columns.yaml", "columns")
    try:
        leaks = shadowdata.leak_check(cfg.data.prod_db, cfg.shadow_seed, cols)
    except Exception as e:  # noqa: BLE001
        return _check(6, False, "leak check failed: %s" % e, "columns")
    if leaks:
        return _check(6, False, "%d sampled real value(s) found in the shadow: %s" % (
            len(leaks), ", ".join("%s found in %s" % (x["column"], x["found_in"]) for x in leaks[:5])), "columns",
            {"leaks": leaks[:20]})
    c = shadowdata.load_columns(cols)
    n = sum(len((s or {}).get("private") or []) + len((s or {}).get("secret") or [])
            for s in (c.get("tables") or {}).values() if isinstance(s, dict))
    return _check(6, True, "no sampled real value of %d private/secret columns appears in the shadow seed" % n)


def check7(cfg, release) -> dict:
    if not cfg.tests_command:
        return _check(7, True, "no tests: autopatch capped at pr", status="warn")
    ok, why = docker.available()
    if not ok:
        return _check(7, False, "cannot run the tests in a runner container: %s" % why)
    t0 = time.monotonic()
    rc, out, err = docker.run([(release, "/app", "ro"), docker.HOME_MOUNT], ["sh", "-c", cfg.tests_command],
                              env={"PYTHONPATH": "/app:/opt/immune", "PYTHONDONTWRITEBYTECODE": "1"}, timeout=900)
    tail = ((out or "") + (err or "")).strip().splitlines()
    summary = [ln for ln in tail if re.search(r"\b(passed|failed|error|no tests ran)\b", ln)]
    last = (summary or tail or [""])[-1].strip()
    if rc == 0:
        return _check(7, True, "`%s` passed in the runner (%ds): %s" % (cfg.tests_command, time.monotonic() - t0, last[:160]))
    return _check(7, False, "`%s` exit %s: %s" % (cfg.tests_command, rc, last[:200]), "none",
                  {"tail": "\n".join(tail[-30:])})


def check8(cfg, release) -> dict:
    """The `scenarios` module runs twice in the pipeline's runner (fresh prod-like seed, frozen clock) with
    identical output, and covers at least one route; otherwise the legit gate cannot be trusted."""
    if not cfg.scenarios:
        return _check(8, True, "no scenarios: the legit gate replays recordings (no coverage caps autopatch at pr)",
                      status="warn")
    ok, why = docker.available()
    if not ok:
        return _check(8, False, "cannot run the scenarios in a runner container: %s" % why)
    from pipeline.config import Config as PConfig
    from pipeline.runner import Runner, RunnerError
    pc = PConfig(app=cfg, repo_dir=_cfg.IMMUNE_HOME, runtime_dir=cfg.runtime_dir, runner_prefix="immunedoctor-runner")
    job = {"kind": "scenarios", "module": cfg.scenarios}
    try:
        runs = [Runner(pc).run(release, dict(job), timeout=300) for _ in range(2)]
    except RunnerError as e:
        return _check(8, False, "scenarios module %s did not run: %s" % (cfg.scenarios, str(e)[:300]), "none")
    a, b = (r.get("scenarios") or [] for r in runs)
    broken = [s["name"] + ": " + s["error"] for s in a if s.get("error")]
    if broken:
        return _check(8, False, "scenario(s) crash on the unpatched release: %s" % "; ".join(broken[:3]), "none",
                      {"errors": broken[:10]})
    if json.dumps(a, sort_keys=True, default=str) != json.dumps(b, sort_keys=True, default=str):
        diff = next((x["name"] for x, y in zip(a, b) if x != y), "(different number of scenarios)")
        return _check(8, False, "two runs of %s differ (first difference in %s): not deterministic" % (cfg.scenarios, diff),
                      "none")
    steps = [st for s in a for st in s.get("steps") or []]
    if not steps:
        return _check(8, False, "%s produced no step: no route is covered" % cfg.scenarios, "none")
    routes = sorted({st.get("path") for st in steps if st.get("path")})
    bad = sorted({"%s %s" % (st.get("path"), st.get("status")) for st in steps if (st.get("status") or 0) >= 500})
    if bad:
        return _check(8, False, "legitimate journeys hit server errors on the unpatched release: %s" % ", ".join(bad[:5]),
                      "none")
    return _check(8, True, "%s: %d scenarios, %d steps over %d paths, identical in two runs" % (
        cfg.scenarios, len(a), len(steps), len(routes)))


def run(project: str | None = None, only: list[int] | None = None) -> list[dict]:
    want = set(only or range(1, 9))
    try:
        cfg = _cfg.load(project)
    except Exception as e:  # noqa: BLE001
        return [_check(1, False, "config invalid: %s" % str(e).replace("\n", " "), "config")]
    m, cols, doc = _manifest(cfg), _columns(cfg), _openapi(cfg)
    release = build_release(cfg)
    out = []
    try:
        if 1 in want:
            out.append(check1(cfg, release))
        if want & {2, 3}:
            out += [c for c in checks23(cfg, release, m, doc) if c["id"] in want]
        if want & {4, 5}:
            out += [c for c in checks45(cfg, release, m, cols) if c["id"] in want]
        if 6 in want:
            out.append(check6(cfg))
        if 7 in want:
            out.append(check7(cfg, release))
        if 8 in want:
            out.append(check8(cfg, release))
    finally:
        shutil.rmtree(release, ignore_errors=True)
    return out


# ------------------------------------------------------------------------------------- prerequisites
def _tool(argv: list[str]) -> tuple[bool, str]:
    """(found and runs, first line of its output or the reason)."""
    exe = argv[0] if os.path.isabs(argv[0]) else shutil.which(argv[0])
    if not exe:
        return False, "not found on PATH"
    try:
        p = subprocess.run([exe] + argv[1:], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    line = ((p.stdout or p.stderr or "").strip().splitlines() or [""])[0]
    return p.returncode == 0, line[:120] if p.returncode == 0 else (line[:160] or "exit %d" % p.returncode)


def _claude_bin() -> str:
    try:
        from patcher.claude_cli import claude_bin
        return claude_bin()
    except Exception:  # noqa: BLE001
        return os.environ.get("CLAUDE_BIN") or "claude"


def prereqs() -> list[dict]:
    """What the product needs on this host, beyond a project. required=False rows only limit a feature.
    Each row: {"name", "ok", "required", "reason", "fix" (what to do, when not ok), "needed_for"}."""
    out = []

    def add(name, ok, required, reason, needed_for, fix):
        out.append({"name": name, "ok": bool(ok), "required": required, "reason": reason, "needed_for": needed_for,
                    "fix": "" if ok else fix})

    ok, why = _tool(["docker", "info", "--format", "server {{.ServerVersion}}"])
    add("docker", ok, True, why, "everything", "install Docker Engine, start the daemon and make it usable without sudo "
        "(docker group)")
    docker_ok = ok
    ok, why = _tool(["docker", "compose", "version", "--short"]) if docker_ok else (False, "docker not usable")
    add("docker compose", ok, True, why, "immune up", "install the Compose plugin (docker-compose-plugin / docker-compose-v2)")
    for img, required, needed_for, fix in (
            (docker.IMAGE, True, "immune up, init, doctor", "run ./install.sh in the immune checkout"),
            ("immune-sidecar:1", False, "apps with app.runtime: generic", "run ./install.sh in the immune checkout"),
            ("immune-cbuild:1", False, "immune anticipate", "IMMUNE_WITH_ANTICIPATE=1 ./install.sh")):
        ok, why = _tool(["docker", "image", "inspect", img, "--format", "present"]) if docker_ok else (False, "docker not usable")
        add("image " + img, ok, required, why if ok else "not built", needed_for, fix)
    ok, why = _tool(["git", "--version"])
    add("git", ok, True, why, "building and applying patches", "install git")
    ok, why = _tool([_claude_bin(), "--version"])
    add("claude CLI", ok, False, why, "LLM steps of immune init, automatic patches",
        "install Claude Code (https://claude.com/claude-code) and log in once with `claude`, or set CLAUDE_BIN; "
        "without it: `immune init --no-llm`, and incidents stop at the blocking rule")
    ok, why = _tool(["gh", "--version"])
    add("gh CLI", ok, False, why, "repo.target: github (pull requests)", "install GitHub CLI and run `gh auth login`")
    return out


def format_prereq(r: dict) -> str:
    tag = "ok" if r["ok"] else ("FAIL" if r["required"] else "warn")
    tail = r["reason"] if r["ok"] else "%s; needed for: %s. Fix: %s" % (r["reason"], r["needed_for"], r["fix"])
    return "  [%-4s] %-22s %s" % (tag, r["name"], tail)


def format_line(c: dict) -> str:
    tag = {"pass": "ok", "fail": "FAIL", "warn": "warn", "skip": "skip"}.get(c["status"], c["status"])
    return "  [%-4s] %d %-30s %s" % (tag, c["id"], c["name"], c["reason"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="immune doctor")
    ap.add_argument("--project", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", default="", help="comma-separated check numbers")
    ap.add_argument("--prereqs", action="store_true", help="check the host prerequisites only (no project needed)")
    a = ap.parse_args(argv)
    if a.prereqs:
        rows = prereqs()
        ok = all(r["ok"] for r in rows if r["required"])
        if a.json:
            print(json.dumps({"ok": ok, "prereqs": rows}, indent=1))
        else:
            for r in rows:
                print(format_prereq(r))
            missing = [r["name"] for r in rows if not r["ok"] and r["required"]]
            optional = [r["name"] for r in rows if not r["ok"] and not r["required"]]
            print("prerequisites: %s%s" % ("ok" if ok else "MISSING " + ", ".join(missing),
                                           ("; optional not available: " + ", ".join(optional)) if optional else ""))
        return 0 if ok else 1
    only = [int(x) for x in a.only.split(",") if x.strip()] or None
    checks = run(os.path.abspath(a.project) if a.project else None, only)
    ok = all(c["ok"] for c in checks)
    if a.json:
        print(json.dumps({"ok": ok, "checks": checks}, indent=1, default=str))
    else:
        for c in checks:
            print(format_line(c))
        print("doctor: %s" % ("all checks passed" if ok else "%d check(s) failed" % sum(not c["ok"] for c in checks)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
