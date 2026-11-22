"""Patch stage for an external app: LLM fix -> CI in a sandbox -> PR -> merge -> blue/green.

Written for the Grafana lab (labs/grafana-cve-2021-43798) and exercised only there. The target file
(labs/<lab>/target.yaml) gives the repository, source dirs, build and test commands, routes and ports, but
parts of this module are specific to that lab and to Go: the containers carry the label `immune.lab=grafana`
and mount `grafana.ini` and the Grafana provisioning directory, the editable files are `*.go`, the policy
gate recognises tests by the `_test.go` suffix, and `verify` reads the prod secret from `grafana.ini`.
Another app needs those parts moved into the target file first. One attempt:

  workspace   git worktree of the current release commit
  propose     confined `claude -p` (Read everywhere, Edit only non-test files under source_dirs); never sees
              the advisory or the upstream fix
  CI gates    policy  -> diff inside source_dirs, no tests touched, size limits
              build   -> sandbox container, --network none, pre-filled module cache
              tests   -> the project's own tests, same sandbox
              poc     -> candidate app (shadow config + patched build): regression request and variants
                         leak no marker
              legit   -> candidate vs current shadow: same status (and body where declared) on legit routes
  PR          branch immune/<run>/fix-<incident>, gate results as checks; merge --no-ff into immune/base
  deploy      start the idle colour on the merged build, health + smoke, switch the gateway upstream,
              watch prod 5xx for watch_s, roll back on errors; then refresh the shadow on the same build
  verify      regression request against prod (direct and through the gateway) returns no prod secret

The upstream fix (official_ref) is used only after merge, for the side-by-side comparison in the PR record.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass

import httpx
import yaml

from patcher import claude_cli
from sidecar import config as sidecar_config
from sidecar import observer as sidecar_observer
from sidecar.tracer import Tracer

from . import poc as pocmod
from .config import REPO_ROOT

GATES = ("policy", "build", "tests", "poc", "legit")
BOT = ["-c", "user.name=immune-bot", "-c", "user.email=immune-bot@localhost"]


class GateFail(Exception):
    def __init__(self, gate: str, detail: str):
        super().__init__(detail)
        self.gate, self.detail = gate, detail


# ------------------------------------------------------------------ target
def _abs(p: str) -> str:
    return p if os.path.isabs(p) else os.path.join(REPO_ROOT, p)


def load_target(path: str) -> dict:
    with open(path) as f:
        t = yaml.safe_load(f)
    t["_path"] = os.path.abspath(path)
    t["repo_dir"] = _abs(t["repo_dir"])
    t["sandbox"]["cache"] = _abs(t["sandbox"]["cache"])
    t["deploy"]["runtime"] = _abs(t["deploy"]["runtime"])
    return t


# ------------------------------------------------------------------ helpers
def sh(args: list, timeout: float = 120, cwd: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
    if check and r.returncode != 0:
        raise RuntimeError("%s: %s" % (" ".join(args[:3]), (r.stderr or r.stdout).strip()[-600:]))
    return r


def git(repo: str, *args, check=True, timeout=300) -> str:
    return sh(["git", "-C", repo, "-c", "core.hooksPath=/dev/null", *BOT, *args], timeout=timeout, check=check).stdout


def tail(text: str, n: int = 1500) -> str:
    text = (text or "").strip()
    return text if len(text) <= n else "…" + text[-n:]


def diff_stats(diff: str) -> tuple[list, int]:
    files = re.findall(r"^\+\+\+ b/(.+)$", diff, flags=re.M)
    lines = sum(1 for l in diff.splitlines() if (l.startswith("+") or l.startswith("-"))
                and not l.startswith(("+++", "---")))
    return files, lines


def raw_get(base: str, target: str, timeout: float = 10.0) -> httpx.Response:
    """GET with the exact request target (dot segments kept)."""
    with httpx.Client(timeout=timeout) as c:
        return c.send(c.build_request("GET", httpx.URL(base + "/").copy_with(raw_path=target.encode("latin-1")),
                                      extensions={"target": target.encode("latin-1")}))


def wait_health(base: str, path: str, timeout: float = 90.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if httpx.get(base + path, timeout=2).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return False


def describe(event: dict) -> str:
    """One oracle event in words, for the prompt and the gate output."""
    d, how = event.get("detail") or {}, ""
    if d.get("observed", "syscall") != "response":      # only a marker in the response carries observed=response
        how = " (seen as a system call of the app process%s)" % (
            "; the call failed with %s, the attempt is the bug" % d["result"]
            if event.get("oracle") == "file" and d.get("result") else "")
    if event.get("oracle") == "proc":
        if "argv" not in d:
            return "the app started a new process (%s)%s" % (d.get("syscall", "fork"), how)
        return "the app executed the program `%s`%s" % (" ".join(d.get("argv") or [d.get("path", "?")])[:200], how)
    if event.get("oracle") == "net":
        return "the app opened a connection to `%s:%s`%s" % (d.get("address", "?"), d.get("port", "?"), how)
    verb = "returned the contents of" if "response" in str(d.get("observed", "")) else "opened"
    return "the app %s `%s`, a file outside what this route serves%s" % (verb, d.get("path", "?"), how)


TASK = {
    "file": "guarantees the resolved file stays inside the directory the route serves, for any encoding of the\n"
            "   input; requests outside it must get the route's normal not-found response, without opening the file.\n"
            "   Legitimate files (including names with dots and nested folders) must keep working.",
    "proc": "guarantees request input can never choose the program that runs or add arguments or shell syntax to\n"
            "   it; invalid input must get the route's normal error response. Legitimate requests must keep working.",
    "net": "guarantees request input can never make the server connect to a destination the route is not meant\n"
           "   to reach; such requests must get the route's normal error response. Legitimate requests must keep working.",
}


@dataclass
class Attempt:
    n: int
    diff: str = ""
    source: str = "llm"
    notes: str = ""
    work: str = ""
    artifact: str = ""
    commit: str = ""


# ------------------------------------------------------------------ the stage
class ExtFix:
    def __init__(self, target: dict, run_id: str, publish, note, gw_url: str, admin_token: str, data_url: str,
                 max_attempts: int = 3, patcher_timeout_s: float = 600):
        self.t, self.run_id, self.publish, self.note = target, run_id, publish, note
        self.gw_url, self.admin_token, self.data_url = gw_url.rstrip("/"), admin_token, data_url.rstrip("/")
        self.max_attempts, self.patcher_timeout_s = max_attempts, patcher_timeout_s
        d = target["deploy"]
        self.rt = d["runtime"]
        self.prefix = d.get("name_prefix", "immune-lab")
        self.state_path = os.path.join(self.rt, "deploy.json")

    # ---------------------------------------------------------- deploy state
    def state(self) -> dict:
        try:
            with open(self.state_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {"active": "blue", "release": "t0", "commit": None, "artifact": None}

    def save_state(self, st: dict):
        with open(self.state_path, "w") as f:
            json.dump(st, f, indent=1)

    def base_commit(self) -> str:
        repo, ref = self.t["repo_dir"], "immune/base"
        if not git(repo, "rev-parse", "--verify", "-q", ref, check=False).strip():
            git(repo, "branch", ref, self.t["base_ref"] + "^{commit}")
        st = self.state()
        return st.get("commit") or git(repo, "rev-parse", ref).strip()

    # ---------------------------------------------------------- containers
    def container(self, name: str, port: int, config: str, artifact: str | None):
        cfg = os.path.join(self.rt, config)
        app = self.t["app"]
        sh(["docker", "rm", "-fv", name], check=False)
        args = ["docker", "run", "-d", "--name", name, "--label", "immune.lab=grafana",
                "-p", "127.0.0.1:%d:%d" % (port, app["port"]),
                "-v", "%s/grafana.ini:/etc/grafana/grafana.ini:ro" % cfg, "-v", "%s/passwd:/etc/passwd:ro" % cfg,
                "-v", "%s/provisioning:/etc/grafana/provisioning:ro" % cfg]
        if artifact:
            args += ["-v", "%s:%s:ro" % (artifact, app["binary"])]
        sh(args + [app["image"]])
        if not wait_health("http://127.0.0.1:%d" % port, app["health"]):
            logs = sh(["docker", "logs", "--tail", "30", name], check=False)
            raise RuntimeError("%s did not become healthy: %s" % (name, tail(logs.stdout + logs.stderr, 600)))

    def sandbox(self, work: str, command: str, out_dir: str | None = None) -> subprocess.CompletedProcess:
        sb = self.t["sandbox"]
        args = ["docker", "run", "--rm", "--network", "none", "--memory", sb.get("memory", "8g"),
                "--pids-limit", "4096", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                "-u", "%d:%d" % (os.getuid(), os.getgid()), "-e", "HOME=/tmp", "-e", "GOPROXY=off",
                "-v", "%s:/cache" % sb["cache"], "-v", "%s:/src:ro" % work]
        if out_dir:
            args += ["-v", "%s:/out" % out_dir]
        return sh(args + [sb["image"], "sh", "-c", command], timeout=sb.get("timeout_s", 1500), check=False)

    # ---------------------------------------------------------- propose
    def editable(self, work: str) -> list:
        out = []
        for d in self.t["source_dirs"]:
            for p in glob.glob(os.path.join(work, d, "**", "*.go"), recursive=True):
                if not p.endswith("_test.go"):
                    out.append(os.path.relpath(p, work))
        return sorted(out)

    def prompt(self, inc: dict, feedback: list, attempt: int) -> str:
        ev = inc["evidence"]
        prim = next((e for e in ev.get("events") or [] if e.get("oracle") == inc.get("oracle")),
                    (ev.get("events") or [{}])[0])
        rq = inc["request"]
        lines = [
            "You are fixing a confirmed security bug in %s (%s). The repository is your working directory."
            % (self.t["name"], self.t.get("language", "")),
            "",
            "Confirmed by execution in an isolated copy of the app (not a guess):",
            "- vulnerability class: %s" % inc["vuln_class"],
            "- route: %s %s (parameter `%s`)" % (inc["method"], inc["route"], (inc.get("param") or {}).get("name")),
            "- while serving the request below, %s:" % describe(prim),
            "",
            "````", "%s %s%s" % (rq["method"], rq["path"], ("?" + rq["query"]) if rq.get("query") else ""), "````",
            "",
            "Task:",
            "1. Find the handler that serves this route (start from the route registration).",
            "2. Make the smallest change that " + TASK.get(prim.get("oracle"), TASK["file"]),
            "3. Edit only non-test files under: %s. Do not touch tests, build files or dependencies." %
            ", ".join(self.t["source_dirs"]),
            "4. Standard library only. Keep the code style of the file.",
            "",
            "When done, reply with one short paragraph: which function you changed and why it is now safe.",
        ]
        if feedback:
            lines += ["", "Previous attempts were rejected by the CI gates (attempt %d now):" % attempt]
            lines += ["- " + f for f in feedback[-3:]]
        return "\n".join(lines)

    def propose(self, inc: dict, feedback: list, a: Attempt):
        res = claude_cli.run(self.prompt(inc, feedback, a.n), a.work, self.editable(a.work),
                             timeout=self.patcher_timeout_s)
        a.notes = (res.text or res.reason)[:2000]
        a.diff = git(a.work, "diff")
        if not res.ok and not a.diff:
            raise GateFail("policy", "patch generator failed: %s" % res.reason)

    # ---------------------------------------------------------- gates
    def g_policy(self, inc, a: Attempt) -> str:
        files, lines = diff_stats(a.diff)
        pol = self.t.get("policy") or {}
        if not files:
            raise GateFail("policy", "empty diff")
        for f in files:
            if f.endswith("_test.go") or not any(f.startswith(d.rstrip("/") + "/") for d in self.t["source_dirs"]):
                raise GateFail("policy", "edits outside the allowed area: %s" % f)
        if len(files) > pol.get("max_files", 2):
            raise GateFail("policy", "%d files changed (max %d)" % (len(files), pol.get("max_files", 2)))
        if lines > pol.get("max_lines", 60):
            raise GateFail("policy", "%d changed lines (max %d)" % (lines, pol.get("max_lines", 60)))
        added = "\n".join(l for l in a.diff.splitlines() if l.startswith("+"))
        for bad in ('"os/exec"', '"net/http"', '"unsafe"', "//go:"):
            if bad in added:
                raise GateFail("policy", "the diff adds %s" % bad)
        return "%d file(s), %d changed lines: %s" % (len(files), lines, ", ".join(files))

    def g_build(self, inc, a: Attempt) -> str:
        out = os.path.join(self.rt, "builds", "%s-a%d" % (inc["incident"], a.n))
        shutil.rmtree(out, ignore_errors=True)
        os.makedirs(out)
        cmd = self.t["sandbox"]["build"].replace("{commit}", "%s-a%d" % (inc["incident"], a.n))
        t = time.time()
        r = self.sandbox(a.work, cmd, out)
        art = os.path.join(out, self.t["sandbox"]["artifact"])
        if r.returncode != 0 or not os.path.isfile(art):
            raise GateFail("build", "build failed (exit %d): %s" % (r.returncode, tail(r.stdout + r.stderr)))
        a.artifact = art
        return "built in %.0fs (sandbox, no network)" % (time.time() - t)

    def g_tests(self, inc, a: Attempt) -> str:
        t = time.time()
        r = self.sandbox(a.work, self.t["sandbox"]["tests"] + " 2>&1")
        if r.returncode != 0:
            raise GateFail("tests", "tests failed (exit %d): %s" % (r.returncode, tail(r.stdout + r.stderr)))
        ok = [l for l in r.stdout.splitlines() if l.startswith("ok")]
        return "%s (%.0fs)" % (ok[-1] if ok else "passed", time.time() - t)

    def candidate(self, a: Attempt) -> str:
        c = self.t["deploy"]["candidate"]
        self.container("%s-candidate" % self.prefix, c["port"], c["config"], a.artifact)
        return "http://127.0.0.1:%d" % c["port"]

    def g_poc(self, inc, a: Attempt, base: str) -> str:
        """No oracle may fire on the candidate: no marker in a response and, with `oracles` configured, no
        protected file opened, program executed or address connected while serving the request."""
        markers = sidecar_observer.load_file_markers(os.path.join(self.rt, "shadow", "markers.json"))
        p = inc["poc"]
        reqs = [("regression", p["requests"][-1])] + pocmod.mutate(inc, p)
        orc = self.t.get("oracles")
        obs = tracer = None
        grace = 0.0
        if orc:     # the sidecar's own observer and tracer (same config as the shadow's sidecar), on the candidate
            cfg = sidecar_config.load(orc["config"], env={})
            obs = sidecar_observer.from_config(cfg, markers)
            tracer = Tracer(obs.on_obs, mode="docker", container="%s-candidate" % self.prefix,
                            image=cfg.tracer_image, label=cfg.tracer_label, attempts=bool(obs.protected))
            grace = max(cfg.grace_ms, 50) / 1000
        try:
            if tracer:
                tracer.start(15)
                obs.learning = True     # warm-up: what a legitimate request opens is not a finding
                for _ in range(2):
                    raw_get(base, self.t["app"]["health"])
                time.sleep(grace)
                obs.learning = False
            for name, rq in reqs:
                target = rq["path"] + ("?" + rq["query"] if rq.get("query") else "")
                if obs:
                    obs.begin()
                r = raw_get(base, target)
                system = []
                if obs:
                    time.sleep(grace)
                    system = obs.system_events(obs.end())
                events = sidecar_observer.marker_events(markers, dict(r.headers), r.content, system)
                if events:
                    raise GateFail("poc", "%s still fires the %s oracle (status %d): %s; request: %s" % (
                        name, events[0]["oracle"], r.status_code, describe(events[0]), target))
        finally:
            if tracer:
                tracer.stop()
        return "regression + %d variants: no oracle fires (%s)" % (
            len(reqs) - 1, "response markers + syscalls" if tracer else "response markers")

    def g_legit(self, inc, a: Attempt, base: str) -> str:
        ref = "http://127.0.0.1:%d" % self.t["deploy"]["shadow"]["port"]
        bad = []
        for item in self.t.get("legit") or []:
            x, y = raw_get(ref, item["path"]), raw_get(base, item["path"])
            if x.status_code != y.status_code:
                bad.append("%s: status %d -> %d" % (item["path"], x.status_code, y.status_code))
            elif item.get("compare") == "body" and x.content != y.content:
                bad.append("%s: body changed" % item["path"])
        if bad:
            raise GateFail("legit", "; ".join(bad))
        return "%d legit routes identical to the current release" % len(self.t.get("legit") or [])

    # ---------------------------------------------------------- PR + merge
    def open_pr(self, inc, a: Attempt, results: list) -> dict:
        branch = "immune/%s/fix-%s" % (self.run_id, inc["incident"])
        git(a.work, "checkout", "-q", "-B", branch)
        git(a.work, "add", "-A")
        checks = "\n".join("- [%s] %s: %s" % ("x" if ok else " ", g, d) for g, ok, d in results)
        git(a.work, "commit", "-q", "-m", "fix(%s): %s on %s %s\n\nIncident %s, attempt %d.\n\nCI:\n%s\n" % (
            inc["vuln_class"], inc["vuln_class"], inc["method"], inc["route"], inc["incident"], a.n, checks))
        a.commit = git(a.work, "rev-parse", "HEAD").strip()
        return {"branch": branch, "url": "local:%s@%s" % (branch, a.commit[:12]), "commit": a.commit}

    def merge(self, inc, a: Attempt, pr: dict) -> str:
        fix_tree = git(a.work, "rev-parse", "HEAD^{tree}").strip()
        git(a.work, "checkout", "-q", "immune/base")
        git(a.work, "merge", "-q", "--no-ff", "-m", "Merge %s (incident %s)" % (pr["branch"], inc["incident"]),
            pr["branch"])
        sha = git(a.work, "rev-parse", "HEAD").strip()
        if git(a.work, "rev-parse", "HEAD^{tree}").strip() != fix_tree:
            raise RuntimeError("merged tree differs from the tested tree; refusing to deploy an untested build")
        git(a.work, "checkout", "-q", "--detach")
        return sha

    def comparison(self, ours: str) -> dict:
        repo, base, off = self.t["repo_dir"], self.t["base_ref"], self.t.get("official_ref")
        if not off or not git(repo, "rev-parse", "--verify", "-q", off + "^{commit}", check=False).strip():
            return {}
        files, _ = diff_stats(ours)
        official = git(repo, "diff", base, off, "--", *files) if files else ""
        stat = git(repo, "diff", "--stat", base, off, "--", "pkg/")
        return {"official_ref": off, "official_diff": official, "official_stat": stat.strip(),
                "same_files": bool(official.strip())}

    def write_pr_record(self, inc, a: Attempt, pr: dict, results: list, cmp: dict, sha: str | None) -> str:
        d = os.path.join(self.rt, "prs")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "%s.md" % inc["incident"])
        rows = "\n".join("| %s | %s | %s |" % (g, "pass" if ok else "FAIL", det.replace("|", "\\|")[:300])
                         for g, ok, det in results)
        parts = [
            "# %s — %s on `%s %s`" % (inc["incident"], inc["vuln_class"], inc["method"], inc["route"]), "",
            "Branch `%s` → `immune/base`%s" % (pr["branch"], (" — merged as `%s`" % sha[:12]) if sha else ""), "",
            "## CI", "", "| gate | result | detail |", "|---|---|---|", rows, "",
            "## Patch (ours, attempt %d)" % a.n, "", "```diff", a.diff.rstrip(), "```", "",
            "Patcher notes: " + (a.notes or "").strip(), ""]
        if cmp:
            parts += ["## Upstream fix (`%s`), same files, for comparison" % cmp["official_ref"], "",
                      "```diff", (cmp.get("official_diff") or "(the upstream fix touches other files)").rstrip(), "```",
                      "", "```", cmp.get("official_stat", ""), "```", ""]
        with open(path, "w") as f:
            f.write("\n".join(parts))
        return path

    # ---------------------------------------------------------- deploy
    def admin(self, method: str, path: str, **kw) -> httpx.Response:
        return httpx.request(method, self.gw_url + path, headers={"x-admin-token": self.admin_token},
                             timeout=kw.pop("timeout", 30), **kw)

    def blue_green(self, inc, release: str, artifact: str) -> dict:
        d = self.t["deploy"]
        st = self.state()
        old, new = st["active"], ("green" if st["active"] == "blue" else "blue")
        port, old_port = d["prod"][new], d["prod"][old]
        name = "%s-prod-%s" % (self.prefix, new)
        rel_dir = os.path.join(self.rt, "releases", release)
        os.makedirs(rel_dir, exist_ok=True)
        binary = os.path.join(rel_dir, os.path.basename(artifact))
        shutil.copy2(artifact, binary)
        self.publish("deploy.started", {"release": release})
        self.note(inc, "deploy %s: starting %s" % (release, new))
        self.container(name, port, d["prod"]["config"], binary)
        smoke = [i["path"] for i in self.t.get("legit") or []]
        for p in smoke:
            a, b = raw_get("http://127.0.0.1:%d" % old_port, p), raw_get("http://127.0.0.1:%d" % port, p)
            if a.status_code != b.status_code:
                sh(["docker", "rm", "-fv", name], check=False)
                return {"ok": False, "rolled_back": False, "detail": "smoke %s: %d vs %d" % (p, a.status_code,
                                                                                            b.status_code)}
        r = self.admin("POST", "/_admin/upstream", json={"addr": "127.0.0.1:%d" % port, "release": release})
        if r.status_code >= 300:
            sh(["docker", "rm", "-fv", name], check=False)
            return {"ok": False, "rolled_back": False, "detail": "upstream switch -> %d" % r.status_code}
        end = time.time() + float(d.get("watch_s", 20))
        while time.time() < end:
            s = self.admin("GET", "/_admin/stats").json()
            if s.get("prod_5xx", 0) or s.get("prod_conn_errors", 0):
                self.admin("POST", "/_admin/upstream", json={"addr": "127.0.0.1:%d" % old_port,
                                                              "release": st["release"]})
                sh(["docker", "rm", "-fv", name], check=False)
                return {"ok": False, "rolled_back": True, "detail": "prod errors after switch: %s" % s}
            time.sleep(1)
        sh(["docker", "rm", "-fv", "%s-prod-%s" % (self.prefix, old)], check=False)
        self.save_state({"active": new, "release": release, "commit": None, "artifact": binary})
        # the shadow must run what prod runs
        self.container("%s-shadow" % self.prefix, d["shadow"]["port"], d["shadow"]["config"], binary)
        return {"ok": True, "rolled_back": False, "detail": "%s live on %s (port %d)" % (release, new, port)}

    def verify(self, inc) -> dict:
        d = self.t["deploy"]
        ini = open(os.path.join(self.rt, "prod", "grafana.ini")).read()
        secrets = re.findall(r"^\s*(?:admin_password|secret_key|password)\s*=\s*(\S+)", ini, flags=re.M)
        rq = inc["poc"]["requests"][-1]
        target = rq["path"] + ("?" + rq["query"] if rq.get("query") else "")
        st = self.state()
        direct = raw_get("http://127.0.0.1:%d" % d["prod"][st["active"]], target)
        via_gw = raw_get(self.data_url, target)
        leak = lambda r: any(s.encode() in r.content for s in secrets)     # noqa: E731
        return {"exploit_blocked_on_prod": not leak(direct) and not leak(via_gw),
                "direct_status": direct.status_code, "gateway_status": via_gw.status_code}

    # ---------------------------------------------------------- driver
    def run(self, inc: dict) -> dict:
        """-> {"outcome": "patched"|"rule_only", "reason": str, ...}. Never leaves a worktree behind."""
        repo = self.t["repo_dir"]
        base = self.base_commit()
        feedback = []
        for n in range(1, self.max_attempts + 1):
            a = Attempt(n=n, work=os.path.join(self.rt, "work", "%s-a%d" % (inc["incident"], n)))
            shutil.rmtree(a.work, ignore_errors=True)
            git(repo, "worktree", "prune")
            git(repo, "worktree", "add", "-q", "--detach", a.work, base)
            results, cand = [], None
            try:
                self.publish("patch.attempt", {"incident": inc["incident"], "attempt": n, "source": "llm"})
                t = time.time()
                self.propose(inc, feedback, a)
                self.note(inc, "attempt %d: patch proposed in %.0fs" % (n, time.time() - t))
                self.publish("patch.diff", {"incident": inc["incident"], "attempt": n, "diff": a.diff})
                for gate in GATES:
                    t = time.time()
                    if gate in ("poc", "legit") and cand is None:
                        cand = self.candidate(a)
                    fn = getattr(self, "g_" + gate)
                    detail = fn(inc, a, cand) if gate in ("poc", "legit") else fn(inc, a)
                    results.append((gate, True, detail))
                    self.publish("gate.result", {"incident": inc["incident"], "attempt": n, "gate": gate, "ok": True,
                                                 "detail": detail})
                    self.note(inc, "attempt %d gate %s ok (%.0fs): %s" % (n, gate, time.time() - t, detail))
            except GateFail as e:
                results.append((e.gate, False, e.detail))
                self.publish("gate.result", {"incident": inc["incident"], "attempt": n, "gate": e.gate, "ok": False,
                                             "detail": e.detail})
                self.note(inc, "attempt %d rejected by %s: %s" % (n, e.gate, e.detail[:300]))
                feedback.append("attempt %d rejected by the %s gate: %s" % (n, e.gate, e.detail[:800]))
                self._cleanup(a, cand)
                continue
            except Exception:
                self._cleanup(a, cand)
                raise
            # all gates green: PR, merge, deploy
            sh(["docker", "rm", "-fv", "%s-candidate" % self.prefix], check=False)
            pr = self.open_pr(inc, a, results)
            self.publish("pr.opened", {"incident": inc["incident"], "url": pr["url"], "branch": pr["branch"]})
            sha = self.merge(inc, a, pr)
            self.publish("pr.merged", {"incident": inc["incident"], "url": pr["url"], "sha": sha})
            cmp = self.comparison(a.diff)
            record = self.write_pr_record(inc, a, pr, results, cmp, sha)
            release = sha[:12]
            dep = self.blue_green(inc, release, a.artifact)
            self.publish("deploy.done", {"release": release, **dep})
            self._cleanup(a, None)
            if not dep["ok"]:
                return {"outcome": "rule_only", "reason": "deploy failed: %s; the rule stays active" % dep["detail"],
                        "pr": record}
            st = self.state()
            st["commit"] = sha
            self.save_state(st)
            ver = self.verify(inc)
            self.publish("verify.result", {"incident": inc["incident"],
                                           "exploit_blocked_on_prod": ver["exploit_blocked_on_prod"]})
            self.note(inc, "verify: %s" % ver)
            if not ver["exploit_blocked_on_prod"]:
                return {"outcome": "rule_only", "reason": "verification failed after deploy: %s" % ver, "pr": record}
            return {"outcome": "patched", "reason": "release %s live (%s); PR record %s" % (release, dep["detail"],
                                                                                          record),
                    "release": release, "pr": record, "verify": ver}
        return {"outcome": "rule_only", "reason": "no patch passed CI after %d attempts; the rule stays active"
                % self.max_attempts}

    def _cleanup(self, a: Attempt, cand):
        if cand:
            sh(["docker", "rm", "-fv", "%s-candidate" % self.prefix], check=False)
        sh(["git", "-C", self.t["repo_dir"], "worktree", "remove", "--force", a.work], check=False)

