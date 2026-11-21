"""Incident lifecycle: oracle.fired -> incident -> PoC (3/3) -> rule -> fix loop (5 gates) -> PR ->
merge -> release -> blue/green deploy -> verify -> closed.

One incident at a time; the rest wait in a persistent queue. Dedupe key: oracle kind + method +
route template + parameter. Patched / rule_only incidents are never reopened; not_reproducible ones
may reopen after PIPELINE_REOPEN_COOLDOWN_S.
"""
from __future__ import annotations

import importlib
import json
import logging
import os
import shutil
import threading
import time
import traceback

from immune_contracts import events as E

from . import incident as incmod, openapi, poc as pocmod, rules, verify
from .gates import GATES, Validator
from .repo import RepoError

log = logging.getLogger("pipeline")


class Closed(Exception):
    """Raised inside the flow to close the incident with an outcome."""

    def __init__(self, outcome: str, reason: str):
        super().__init__(reason)
        self.outcome, self.reason = outcome, reason


def _call_with_timeout(fn, timeout: float, *a, **kw):
    box = {}

    def target():
        try:
            box["v"] = fn(*a, **kw)
        except BaseException as e:  # noqa: BLE001
            box["e"] = e
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError("%s did not return within %.0fs" % (getattr(fn, "__name__", "call"), timeout))
    if "e" in box:
        raise box["e"]
    return box.get("v")


def _fence(text: str) -> str:
    """Markdown code block that attacker text cannot break out of."""
    text = str(text)
    fence = "````"
    while fence in text:
        fence += "`"
    return "%s\n%s\n%s" % (fence, text, fence)


class Pipeline:
    def __init__(self, cfg, state, publisher, gateway, fleet, repo, validator: Validator | None = None,
                 patcher=None, spec: dict | None = None, local_fallback=None):
        self.cfg, self.state, self.bus = cfg, state, publisher
        self.local_fallback = local_fallback   # () -> LocalRepo, used when a GitHub target fails
        self.gw, self.fleet, self.repo = gateway, fleet, repo
        self.v = validator or Validator(cfg)
        self.spec = spec if spec is not None else openapi.load(cfg.openapi_path)
        self._patcher = patcher
        self._patcher_err = None
        self.timings = {}

    # ------------------------------------------------------------ dependencies
    @property
    def patcher(self):
        if self._patcher is None and self._patcher_err is None:
            try:
                self._patcher = importlib.import_module(self.cfg.patcher_module)
            except Exception as e:  # noqa: BLE001
                self._patcher_err = "%s: %s" % (type(e).__name__, e)
                log.error("patcher module %s unavailable: %s", self.cfg.patcher_module, e)
        return self._patcher

    def manifest(self) -> dict:
        try:
            with open(self.cfg.manifest_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def current_release(self) -> str:
        try:
            rel = (self.fleet.state().get("prod") or {}).get("release")
            if rel and os.path.isdir(os.path.join(self.cfg.release_dir(rel), "victim")):
                return rel
        except Exception as e:  # noqa: BLE001
            log.info("fleet state unavailable (%s); using the last known release", e)
        return self.state.data.get("current_release") or self.cfg.base_release

    # ------------------------------------------------------------ intake (bus thread)
    def on_event(self, seq: int, ev: dict) -> None:
        if ev.get("type") != E.ORACLE_FIRED:
            self.state.touch_seq(seq)
            return
        try:
            self.enqueue(ev)
        except Exception as e:  # noqa: BLE001
            log.warning("ignored malformed oracle.fired seq=%s: %s", seq, e)
        self.state.touch_seq(seq, force=True)

    def on_reset(self) -> None:
        log.info("bus store was cleared; following from seq 0")
        with self.state.lock:
            self.state.data["last_seq"] = 0
            self.state.save()

    def enqueue(self, ev: dict) -> str | None:
        """Turn an oracle.fired event into a queued incident, or count it as a duplicate. -> incident id or None."""
        sk = incmod.build(ev, self.spec, self.manifest())
        with self.state.lock:
            d = self.state.data
            existing = d["keys"].get(sk["key"])
            if existing:
                old = d["incidents"].get(existing)
                if old is not None:
                    old["hits"] = old.get("hits", 1) + 1
                    reopen = (old.get("status") == "closed" and old.get("outcome") == "not_reproducible"
                              and time.time() - (old.get("closed_at") or 0) > self.cfg.reopen_cooldown_s)
                    if not reopen:
                        self.state.save()
                        return None
            iid = self.state.new_id()
            sk.update(incident=iid, status="queued", hits=1, queued_at=time.time(), attempts=[], log=[])
            d["incidents"][iid] = sk
            d["keys"][sk["key"]] = iid
            d["queue"].append(iid)
            self.state.save()
        log.info("queued %s: %s %s %s param=%s", iid, sk["vuln_class"], sk["method"], sk["route"], sk["param"])
        return iid

    # ------------------------------------------------------------ main loop step
    def paused(self) -> bool:
        return os.path.exists(self.cfg.pause_file)

    def resume_interrupted(self) -> None:
        """An incident left 'open' by a crash/restart is re-queued at the front and redone from the start."""
        with self.state.lock:
            d = self.state.data
            for iid, inc in d["incidents"].items():
                if inc.get("status") == "open":
                    inc["status"] = "queued"
                    inc.setdefault("log", []).append("restarted while open; redoing from the start")
                    if iid not in d["queue"]:
                        d["queue"].insert(0, iid)
            self.state.save()

    def step(self) -> str | None:
        """Process the next queued incident (unless paused). -> incident id or None."""
        if self.paused():
            return None
        with self.state.lock:
            q = self.state.data["queue"]
            if not q:
                return None
            iid = q.pop(0)
            self.state.data["incidents"][iid]["status"] = "open"
            self.state.save()
        self.process(iid)
        return iid

    # ------------------------------------------------------------ one incident
    def publish(self, type_, data, inc):
        return self.bus.publish(type_, data, incident=inc["incident"], rid=inc.get("evidence_rid"))

    def note(self, inc, msg):
        log.info("[%s] %s", inc["incident"], msg)
        inc.setdefault("log", []).append("%.1f %s" % (time.time(), msg))

    def process(self, iid: str) -> dict:
        inc = self.state.incident(iid)
        inc["t"] = {"start": time.time()}
        inc["rule_posted"] = None
        try:
            self._flow(inc)
        except Closed as c:
            self.close(inc, c.outcome, c.reason)
        except Exception as e:  # noqa: BLE001
            log.error("[%s] failed: %s\n%s", iid, e, traceback.format_exc())
            self.close(inc, "rule_only", "pipeline error: %s: %s" % (type(e).__name__, e))
        finally:
            for d in inc.pop("_tmp", []):
                shutil.rmtree(d, ignore_errors=True)
        return inc

    def close(self, inc, outcome: str, reason: str):
        t0 = inc.get("first_seen") or inc["t"]["start"]
        str_ = round(inc["rule_posted"] - t0, 1) if inc.get("rule_posted") else None
        stp = round(inc["t"]["verified"] - t0, 1) if outcome == "patched" and inc["t"].get("verified") else None
        inc.update(status="closed", outcome=outcome, reason=reason, closed_at=time.time(),
                   seconds_to_rule=str_, seconds_to_patch=stp)
        self.note(inc, "closed %s: %s" % (outcome, reason))
        self.publish(E.INCIDENT_CLOSED, {"incident": inc["incident"], "outcome": outcome,
                                         "seconds_to_rule": str_, "seconds_to_patch": stp}, inc)
        self.state.save()

    def _flow(self, inc):
        cfg = self.cfg
        iid = inc["incident"]
        self.publish(E.INCIDENT_OPENED, {k: inc[k] for k in ("incident", "vuln_class", "method", "route", "param",
                                                            "sink", "evidence_rid", "request")}, inc)
        release = self.current_release()
        base_dir = cfg.release_dir(release)
        if not os.path.isdir(os.path.join(base_dir, "victim")):
            raise RuntimeError("release dir %s has no victim/" % base_dir)
        inc["base_release"] = release
        self.note(inc, "opened on release %s" % release)

        # 1. regression case, 3/3
        p = pocmod.build(inc, release)
        inc["poc"] = p
        extra = []
        pm = self.patcher
        if pm is not None and hasattr(pm, "variants"):
            try:
                extra = _call_with_timeout(pm.variants, 60, p, inc["evidence"]) or []
            except Exception as e:  # noqa: BLE001
                self.note(inc, "patcher.variants failed: %s" % e)
        t = time.time()
        rep = self.v.reproduce(inc, p, base_dir, extra)
        inc["repro"] = rep
        inc["t"]["poc_s"] = round(time.time() - t, 2)
        self.publish(E.POC_READY, {"incident": iid, "reproducible": rep["reproducible"], "runs": rep["runs"], "poc": p}, inc)
        self.state.save()
        if not rep["reproducible"]:
            raise Closed("not_reproducible", "the PoC triggered the %s oracle in %d/3 runs on release %s"
                         % (p["expect"]["oracle"], rep["runs"], release))
        self.note(inc, "PoC reproduces 3/3; %d variants counted" % len(rep["counted"]))

        # 2. containment rule
        raw = None
        if pm is not None and hasattr(pm, "derive_rule"):
            try:
                raw = _call_with_timeout(pm.derive_rule, 30, incmod.public(inc), self.spec)
            except Exception as e:  # noqa: BLE001
                self.note(inc, "patcher.derive_rule failed: %s" % e)
        rule, why = rules.finalize(raw, inc, self.spec, cfg.rule_ttl_s)
        if why:
            self.note(inc, why)
        self.gw.post_rule(rule)
        inc["rule"] = rule
        inc["rule_posted"] = time.time()
        self.note(inc, "rule %s posted (%s)" % (rule["id"], rule["scope"]))
        self.state.save()

        # 3. fix loop
        if pm is None:
            raise Closed("rule_only", "patch generator unavailable (%s); the rule stays active" % self._patcher_err)
        try:
            self.repo.ensure_base()
        except Exception as e:  # noqa: BLE001
            raise Closed("rule_only", "repository target unavailable: %s" % e)
        feedback, change, patched_dir, attempt_ok = [], None, None, False
        for attempt in range(1, cfg.max_attempts + 1):
            t = time.time()
            try:
                out = _call_with_timeout(pm.propose, cfg.patcher_timeout_s, base_dir, incmod.public(inc), list(feedback),
                                         attempt) or {}
            except Exception as e:  # noqa: BLE001
                out = {"diff": "", "source": "llm", "notes": "patch generator failed: %s" % e}
            src = out.get("source") if out.get("source") in ("llm", "fallback") else "llm"
            diff = out.get("diff") if isinstance(out.get("diff"), str) else ""
            rec = {"attempt": attempt, "source": src, "notes": str(out.get("notes") or "")[:2000],
                   "propose_s": round(time.time() - t, 1), "gates": []}
            inc["attempts"].append(rec)
            self.publish(E.PATCH_ATTEMPT, {"incident": iid, "attempt": attempt, "source": src}, inc)
            self.publish(E.PATCH_DIFF, {"incident": iid, "attempt": attempt, "diff": diff}, inc)
            holder = {"change": change, "pending": []}

            def on_result(gate, ok, detail, secs, attempt=attempt, rec=rec, holder=holder):
                rec["gates"].append({"gate": gate, "ok": ok, "detail": detail, "seconds": secs})
                self.publish(E.GATE_RESULT, {"incident": iid, "attempt": attempt, "gate": gate, "ok": ok,
                                             "detail": detail}, inc)
                if holder["change"] is not None and holder["change"].attempt == attempt:
                    self._report(holder["change"], gate, ok, detail)
                else:
                    holder["pending"].append((gate, ok, detail))

            def after_policy(pdir, attempt=attempt, diff=diff, holder=holder):
                holder["change"] = self._open_change(inc, attempt, diff, pdir, holder["change"])
                for g, o, d in holder["pending"]:
                    self._report(holder["change"], g, o, d)
                holder["pending"] = []

            ok, results, pdir = self.v.validate(inc, p, rep, base_dir, diff, on_result, after_policy, keep=True)
            change = holder["change"] or change
            if pdir:
                inc.setdefault("_tmp", []).append(pdir)
            if ok:
                patched_dir, attempt_ok, good_diff = pdir, True, diff
                break
            g, _o, d, _s = results[-1]
            feedback.append("Attempt %d was rejected by the %s gate: %s" % (attempt, g, d))
            self.note(inc, "attempt %d rejected by %s" % (attempt, g))
        if not attempt_ok:
            reason = "no patch passed the gates after %d attempts; the rule stays active" % cfg.max_attempts
            if change is not None:
                self._safe(self.repo.abandon, change, reason + "\n\n" + "\n".join(feedback))
            raise Closed("rule_only", reason)
        if change is None:
            raise Closed("rule_only", "the pull request could not be opened; the rule stays active")

        # 4. merge + release
        try:
            sha = self.repo.merge(change)
        except Exception as e:  # noqa: BLE001
            if not self._use_local("merge failed: %s" % e, inc):
                raise Closed("rule_only", "merge failed: %s" % e)
            change = self._open_change(inc, change.attempt, good_diff, patched_dir, None)
            for g in inc["attempts"][-1]["gates"]:
                self._report(change, g["gate"], g["ok"], g["detail"])
            sha = self.repo.merge(change)
        inc["t"]["merged"] = time.time()
        self.publish(E.PR_MERGED, {"incident": iid, "url": change.url, "sha": sha}, inc)
        new_rel = sha[:12]
        self.repo.materialise(sha, cfg.release_dir(new_rel))
        inc["release"] = new_rel
        self.note(inc, "merged %s -> release %s" % (sha[:12], new_rel))
        self.state.save()

        # 5. deploy
        t = time.time()
        try:
            res = self.fleet.deploy(new_rel, timeout=cfg.deploy_timeout_s)
        except Exception as e:  # noqa: BLE001
            res = {"ok": False, "rolled_back": False, "detail": "deploy call failed: %s" % e}
        inc["t"]["deploy_s"] = round(time.time() - t, 1)
        inc["deploy"] = res
        if not res.get("ok"):
            self._safe(self.repo.revert, change, sha, "deploy of %s failed: %s" % (new_rel, res.get("detail")))
            raise Closed("rule_only", "deploy of %s %s: %s; the rule stays active" % (
                new_rel, "rolled back" if res.get("rolled_back") else "failed", res.get("detail")))
        with self.state.lock:
            self.state.data["current_release"] = new_rel
        self.state.save()

        # 6. rule off, verify
        try:
            self.gw.delete_rule(inc["rule"]["id"])
        except Exception as e:  # noqa: BLE001
            self.note(inc, "rule delete failed: %s" % e)
        t = time.time()
        try:
            r_ok, r_detail = verify.in_runner(self.v, p, rep, cfg.release_dir(new_rel))
        except Exception as e:  # noqa: BLE001
            r_ok, r_detail = False, "runner verification failed: %s" % e
        try:
            g_ok, g_detail = verify.through_gateway(cfg, inc, self.gw, self.manifest())
        except Exception as e:  # noqa: BLE001
            g_ok, g_detail = False, "gateway verification failed: %s" % e
        inc["t"]["verify_s"] = round(time.time() - t, 1)
        inc["t"]["verified"] = time.time()
        inc["verify"] = {"runner": [r_ok, r_detail], "gateway": [g_ok, g_detail]}
        self.note(inc, "verify: runner %s (%s); gateway %s (%s)" % (r_ok, r_detail, g_ok, g_detail))
        self.publish(E.VERIFY_RESULT, {"incident": iid, "exploit_blocked_on_prod": bool(r_ok and g_ok)}, inc)
        if not (r_ok and g_ok):
            try:
                self.gw.post_rule(inc["rule"])
            except Exception as e:  # noqa: BLE001
                self.note(inc, "re-posting the rule failed: %s" % e)
            self._safe(self.repo.comment, change, "Verification failed: %s; %s. The rule was re-activated." % (r_detail, g_detail))
            raise Closed("rule_only", "deployed, but verification failed (%s; %s); rule re-activated" % (r_detail, g_detail))
        self._safe(self.repo.comment, change, self._timings_comment(inc))
        raise Closed("patched", "release %s deployed and verified" % new_rel)

    # ------------------------------------------------------------ repo helpers
    def _safe(self, fn, *a):
        try:
            return fn(*a)
        except Exception as e:  # noqa: BLE001
            log.warning("repo %s failed: %s", getattr(fn, "__name__", fn), e)
            return None

    def _use_local(self, why: str, inc) -> bool:
        """GitHub failed: continue this and later incidents on the local repo target."""
        if getattr(self.repo, "kind", "local") == "local" or self.local_fallback is None:
            return False
        self.note(inc, "%s; continuing on the local repo target" % why)
        self.repo = self.local_fallback()
        self.repo.ensure_base()
        return True

    def _report(self, change, gate, ok, detail):
        self._safe(self.repo.report, change, gate, ok, detail)

    def _open_change(self, inc, attempt, diff, patched_dir, previous):
        title = "fix(%s): %s %s param %s" % (inc["vuln_class"], inc["method"], inc["route"],
                                              (inc.get("param") or {}).get("name", "-"))
        try:
            change = self.repo.open_change(inc["incident"], attempt, diff, patched_dir, title, self._pr_body(inc))
        except Exception as e:  # noqa: BLE001
            if not self._use_local("opening the pull request failed: %s" % e, inc):
                raise RuntimeError("could not open the pull request: %s" % e)
            previous = None
            change = self.repo.open_change(inc["incident"], attempt, diff, patched_dir, title, self._pr_body(inc))
        if previous is None or previous.url != change.url:
            self.publish(E.PR_OPENED, {"incident": inc["incident"], "url": change.url, "branch": change.branch}, inc)
        inc["pr"] = change.to_dict()
        return change

    def _pr_body(self, inc) -> str:
        ev = inc["evidence"]
        prim = incmod.primary_event(ev) or {}
        poc_view = dict(inc.get("poc") or {})
        if poc_view.get("state_b64"):
            poc_view["state_b64"] = "<%d bytes of sqlite state>" % len(poc_view["state_b64"])
        lines = [
            "Automatic fix for incident **%s** (%s), opened by the immune pipeline. The request below is attacker "
            "input, shown verbatim as data." % (inc["incident"], inc["vuln_class"]),
            "", "| | |", "|---|---|",
            "| endpoint | `%s %s` |" % (inc["method"], inc["route"]),
            "| parameter | `%s` |" % json.dumps(inc.get("param")),
            "| oracle | `%s` |" % prim.get("oracle"),
            "| sink | `%s:%s` |" % (inc["sink"]["file"], inc["sink"]["line"]),
            "| evidence rid | `%s` |" % inc.get("evidence_rid"),
            "| release | `%s` |" % inc.get("base_release"),
            "", "**Captured request**", _fence(json.dumps(ev.get("request"), indent=1)[:4000]),
            "", "**Oracle detail**", _fence(json.dumps(prim.get("detail"), indent=1)[:3000]),
            "", "**Stack** (outermost first)", _fence("\n".join("%s:%s %s" % (f.get("file"), f.get("line"), f.get("func"))
                                                              for f in prim.get("stack") or [])),
            "", "**Regression case (PoC)**", _fence(json.dumps(poc_view, indent=1)[:6000]),
            "", "Each validation gate is reported as a commit status `immune/<gate>`: %s." % ", ".join(GATES),
        ]
        return "\n".join(lines)

    def _timings_comment(self, inc) -> str:
        t0 = inc.get("first_seen") or inc["t"]["start"]
        rows = ["| step | seconds |", "|---|---|"]
        rows.append("| oracle -> rule | %.1f |" % ((inc.get("rule_posted") or t0) - t0))
        rows.append("| PoC reproduction (3 runs + %d variants) | %.1f |" % (len(inc["repro"]["counted"]) + len(inc["repro"]["ignored"]), inc["t"].get("poc_s", 0)))
        for a in inc["attempts"]:
            rows.append("| attempt %d: patch generation (%s) | %.1f |" % (a["attempt"], a["source"], a["propose_s"]))
            for g in a["gates"]:
                rows.append("| attempt %d: gate %s (%s) | %.1f |" % (a["attempt"], g["gate"], "ok" if g["ok"] else "rejected", g["seconds"]))
        rows.append("| deploy (blue/green + watch) | %.1f |" % inc["t"].get("deploy_s", 0))
        rows.append("| verification | %.1f |" % inc["t"].get("verify_s", 0))
        rows.append("| **oracle -> verified patch** | **%.1f** |" % (inc["t"]["verified"] - t0))
        v = inc.get("verify") or {}
        return "\n".join(["Deployed as release `%s` and verified." % inc.get("release"), "",
                          "- runner: %s" % (v.get("runner") or ["", ""])[1],
                          "- gateway: %s" % (v.get("gateway") or ["", ""])[1], ""] + rows)
