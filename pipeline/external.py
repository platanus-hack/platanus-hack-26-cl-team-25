"""Incident flow for an app we did not write and cannot run in the in-process harness.

Two modes:
- judge (app.runtime generic, no REPRO_URL): the full flow of `orchestrator.Pipeline` (PoC 3/3, rule, LLM
  fix, five gates, PR, blue/green deploy, verify), with every runner job executed on ephemeral clone
  triples (app image + Postgres + observer; `pipeline/generic.py`) and the patch
  generator `pipeline/generic_patch.py`.
- reproduction only (REPRO_URL set, e.g. labs/grafana-cve-2021-43798): oracle.fired -> incident -> PoC
  replayed 3 times against a reserved shadow clone through its sidecar. 3/3: containment rule -> patch
  (pipeline/extfix.py). Less (0/3 included, it did fire once): containment rule, no automatic fix, closed
  `rule_only` / `escalated` for a person (Pipeline.escalate).

Selected with PIPELINE_APP=external, or automatically for app.runtime generic (pipeline/__main__.py).
"""
from __future__ import annotations

import os
import shlex
import subprocess
import time
import uuid

import httpx

from immune_contracts import events as E, wire

from . import poc as pocmod, reqs, rules
from .config import REPO_ROOT
from .extfix import ExtFix
from .orchestrator import Closed, Pipeline

HOP = {"host", "content-length", "connection", "transfer-encoding"}


class ExternalPipeline(Pipeline):
    def __init__(self, *a, repro_url: str = "", runs: int = 3, target: dict | None = None, **kw):
        if not repro_url:
            from .generic import JudgeValidator
            if kw.get("validator") is None:
                kw["validator"] = JudgeValidator(a[0])
            if kw.get("patcher") is None:
                from . import generic_patch
                kw["patcher"] = generic_patch
        super().__init__(*a, **kw)
        self.target = target
        self.repro_url = (repro_url or "").rstrip("/")
        self.runs = runs

    def current_release(self) -> str:
        if not self.repro_url:
            return super().current_release()
        return self.state.data.get("current_release") or self.cfg.base_release

    def replay(self, req: dict, tag: str) -> str:
        """Send one PoC request to the reproduction clone; -> its verdict."""
        target = req["path"] + ("?" + req["query"] if req.get("query") else "")
        headers = [(k, v) for k, v in (req.get("headers") or {}).items() if k.lower() not in HOP
                   and not k.lower().startswith(wire.INTERNAL_PREFIX)]
        headers += [(wire.H_RID, "repro-%s-%s" % (tag, uuid.uuid4().hex[:8])), (wire.H_MODE, "L1")]
        url = httpx.URL(self.repro_url + "/")
        with httpx.Client(timeout=self.cfg.http_timeout_s * 3) as c:
            r = c.send(c.build_request(req["method"], url.copy_with(raw_path=target.encode("latin-1")),
                                       headers=headers, content=reqs.body_of(req) or None,
                                       extensions={"target": target.encode("latin-1")}))
        return (r.headers.get(wire.H_VERDICT) or wire.VERDICT_INCONCLUSIVE).lower()

    def _flow(self, inc):
        if not self.repro_url:
            return super()._flow(inc)      # judge mode: the whole flow, judged on clone triples
        iid = inc["incident"]
        self.publish(E.INCIDENT_OPENED, self.opened_data(inc), inc)
        release = self.current_release()
        inc["base_release"] = release
        self.note(inc, "opened (external app, release %s)" % release)

        # 1. regression case, reproduced on a fresh shadow clone
        p = pocmod.build(inc, release)
        inc["poc"] = p
        t = time.time()
        hits = 0
        for i in range(self.runs):
            try:
                v = self.replay(p["requests"][-1], "%s-%d" % (iid, i))
            except httpx.HTTPError as e:
                self.note(inc, "repro run %d failed: %s" % (i, e))
                v = "error"
            hits += v == wire.VERDICT_ORACLE
        rep = {"reproducible": hits == self.runs, "runs": hits, "counted": []}
        inc["repro"] = rep
        inc["t"]["poc_s"] = round(time.time() - t, 2)
        self.publish(E.POC_READY, {"incident": iid, "reproducible": rep["reproducible"], "runs": hits, "poc": p}, inc)
        self.state.save()
        if not rep["reproducible"]:
            self.escalate(inc, p, hits, self.runs)
        self.note(inc, "PoC reproduces %d/%d on the shadow clone" % (hits, self.runs))

        # 2. containment rule (built-in derivation: this mode loads no patch generator)
        rule, why = rules.finalize(None, inc, self.spec, self.cfg.rule_ttl_s)
        self.gw.post_rule(rule)
        inc["rule"] = rule
        inc["rule_posted"] = time.time()
        self.note(inc, "rule %s posted (%s %s)" % (rule["id"], rule["scope"], rule.get("param")))
        self.state.save()

        # 3. patch. The generic 5-gate flow (extfix) is Python-only; a non-Python app (e.g. the ScadaBR Java
        # lab) can instead name an external patch command (EXTERNAL_PATCH_CMD) that builds, verifies and
        # deploys its own fix and publishes its own patch/gate/deploy events. Either path: a verified fix
        # removes the rule; a failure leaves the rule in place and closes rule_only.
        if not self.target:
            cmd = os.environ.get("EXTERNAL_PATCH_CMD", "").strip()
            if not cmd:
                raise Closed("rule_only", "contained by rule %s; no patch target configured "
                             "(EXTERNAL_TARGET / EXTERNAL_PATCH_CMD)" % rule["id"])
            out = self._run_patch_cmd(cmd, inc)
        else:
            fx = ExtFix(self.target, self.cfg.run_id, lambda t, d: self.publish(t, d, inc), self.note,
                        self.cfg.gateway_admin_url, self.cfg.admin_token, self.cfg.gateway_url,
                        max_attempts=self.cfg.max_attempts, patcher_timeout_s=self.cfg.patcher_timeout_s)
            out = fx.run(inc)
            inc["fix"] = {k: v for k, v in out.items() if k != "outcome"}
        if out["outcome"] == "patched":
            inc["t"]["verified"] = time.time()
            try:
                self.gw.delete_rule(rule["id"])
                self.note(inc, "rule %s removed: the fix is live" % rule["id"])
            except Exception as e:  # noqa: BLE001
                self.note(inc, "could not remove rule %s: %s" % (rule["id"], e))
        raise Closed(out["outcome"], out["reason"])

    def _run_patch_cmd(self, cmd: str, inc) -> dict:
        """Run an external patch command (e.g. the ScadaBR lab's Java build+verify). It is given the live
        incident and run id and publishes its own patch/gate/deploy events to the bus; we read only its exit
        code. 0 -> patched (and we then remove the rule); non-zero -> the rule stays and we close rule_only."""
        argv = shlex.split(cmd) + ["--incident", inc["incident"], "--run", self.cfg.run_id]
        self.note(inc, "external patch command: %s" % " ".join(argv))
        t = time.time()
        try:
            r = subprocess.run(argv, cwd=REPO_ROOT, capture_output=True, text=True,
                               timeout=self.cfg.patcher_timeout_s + self.cfg.deploy_timeout_s)
        except subprocess.TimeoutExpired:
            return {"outcome": "rule_only", "reason": "external patch command timed out; the rule stays active"}
        except OSError as e:
            return {"outcome": "rule_only", "reason": "external patch command could not start (%s); rule stays" % e}
        inc["t"]["patch_s"] = round(time.time() - t, 2)
        tail = (r.stderr or r.stdout or "").strip()[-600:]
        inc["fix"] = {"cmd": " ".join(argv), "code": r.returncode, "out": tail}
        if r.returncode == 0:
            return {"outcome": "patched", "reason": "external patch verified and deployed"}
        return {"outcome": "rule_only",
                "reason": "external patch did not verify (exit %d); the rule stays active" % r.returncode}

