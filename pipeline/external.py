"""Incident flow for an app we did not write and cannot run in the in-process harness (any language).

oracle.fired (from the sidecar) -> incident -> PoC reproduced 3/3 against a shadow clone through its sidecar
-> containment rule on the gateway -> closed `rule_only` (the patch stage for non-Python runtimes is next).

Selected with PIPELINE_APP=external; REPRO_URL is the sidecar of a shadow clone reserved for reproduction.
"""
from __future__ import annotations

import time
import uuid

import httpx

from immune_contracts import events as E, wire

from . import poc as pocmod, reqs, rules
from .extfix import ExtFix
from .orchestrator import Closed, Pipeline

HOP = {"host", "content-length", "connection", "transfer-encoding"}


class ExternalPipeline(Pipeline):
    def __init__(self, *a, repro_url: str, runs: int = 3, target: dict | None = None, **kw):
        super().__init__(*a, **kw)
        self.target = target
        self.repro_url = repro_url.rstrip("/")
        self.runs = runs

    def current_release(self) -> str:
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
        iid = inc["incident"]
        self.publish(E.INCIDENT_OPENED, {k: inc[k] for k in ("incident", "vuln_class", "method", "route", "param",
                                                            "sink", "evidence_rid", "request")}, inc)
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
            raise Closed("not_reproducible", "the PoC fired the %s oracle in %d/%d runs on the shadow clone"
                         % (p["expect"]["oracle"], hits, self.runs))
        self.note(inc, "PoC reproduces %d/%d on the shadow clone" % (hits, self.runs))

        # 2. containment rule (built-in derivation; the LLM patcher is Python-only for now)
        rule, why = rules.finalize(None, inc, self.spec, self.cfg.rule_ttl_s)
        self.gw.post_rule(rule)
        inc["rule"] = rule
        inc["rule_posted"] = time.time()
        self.note(inc, "rule %s posted (%s %s)" % (rule["id"], rule["scope"], rule.get("param")))
        self.state.save()

        # 3. patch: LLM fix -> CI in a sandbox -> PR -> merge -> blue/green -> verify (pipeline/extfix.py)
        if not self.target:
            raise Closed("rule_only", "contained by rule %s; no patch target configured (EXTERNAL_TARGET)"
                         % rule["id"])
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

