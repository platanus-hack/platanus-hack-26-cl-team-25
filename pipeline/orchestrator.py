"""Incident lifecycle: oracle.fired -> incident -> PoC (3/3) -> rule -> fix loop (5 gates) -> PR ->
merge -> release -> blue/green deploy -> verify -> closed.

One incident at a time; the rest wait in a persistent queue. Dedupe key: oracle kind + method +
route template + parameter. Patched / rule_only incidents are never reopened; not_reproducible ones
may reopen after PIPELINE_REOPEN_COOLDOWN_S.

Outcomes: `patched`; `rule_only` (a containment rule was posted and stays active); `not_reproducible`;
`error` (the flow failed before any rule was posted: nothing contains the incident; it is retried like
any transient close).
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

from . import audit as auditmod, bus as busmod, incident as incmod, openapi, poc as pocmod, reqs, rules, verify
from .corpus import Corpus
from .gates import GATES, Validator

log = logging.getLogger("pipeline")


TRANSIENT = "transient"     # outcome_detail: closed for a reason that may not hold later (see retry_transient)
SOURCES = {"llm": "written by the LLM", "fallback": "pre-written fallback diff (the LLM was unavailable or "
           "produced no diff)", "unknown": "unknown (the patch generator did not say)"}


def patch_source(out: dict) -> str:
    """`source` of a patcher.propose result; anything but the two defined values is reported as unknown,
    never as the LLM's work."""
    src = out.get("source") if isinstance(out, dict) else None
    return src if src in ("llm", "fallback") else "unknown"


class Closed(Exception):
    """Raised inside the flow to close the incident with an outcome."""

    def __init__(self, outcome: str, reason: str, detail: str | None = None):
        super().__init__(reason)
        self.outcome, self.reason, self.detail = outcome, reason, detail


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
        self.corpus = Corpus(os.path.join(cfg.runtime_dir, "corpus"))

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
            if rel and self.cfg.project.release_complete(self.cfg.release_dir(rel)):
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
                    # an `error` close left nothing in place: once its own retries are spent, a new hit reopens it
                    again = old.get("outcome") == "not_reproducible" or (
                        old.get("outcome") == "error" and int(old.get("retries") or 0) >= self.cfg.max_retries)
                    reopen = (old.get("status") == "closed" and again
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

    # ------------------------------------------------------------ upkeep between incidents
    def maintain(self, every: float = 20.0) -> None:
        """Called from the main loop when idle. Keeps the promise made when an incident closes without a patch
        ("the rule stays active"), and gives a second chance to incidents that failed for a transient reason."""
        now = time.time()
        if now - getattr(self, "_maintained", 0.0) < every:
            return
        self._maintained = now
        try:
            self.bus.flush()            # events the bus could not take earlier
        except Exception as e:  # noqa: BLE001
            log.warning("bus flush failed: %s", e)
        try:
            self.keep_rules()
        except Exception as e:  # noqa: BLE001
            log.warning("rule upkeep failed: %s", e)
        try:
            self.retry_transient()
        except Exception as e:  # noqa: BLE001
            log.warning("retry pass failed: %s", e)

    def keep_rules(self) -> int:
        """A rule has a TTL so a forgotten one cannot outlive its reason. While its incident is closed without
        a deployed fix the reason stands: renew it before it expires, and put it back if the gateway lost it."""
        with self.state.lock:
            open_rules = [(i["incident"], dict(i["rule"])) for i in self.state.data["incidents"].values()
                          if i.get("status") == "closed" and i.get("outcome") == "rule_only"
                          and isinstance(i.get("rule"), dict) and i.get("rule_posted")]
        if not open_rules:
            return 0
        active = {r.get("id"): r for r in self.gw.rules()}
        renewed = 0
        for iid, rule in open_rules:
            cur = active.get(rule.get("id"))
            ttl = float(rule.get("ttl_s") or self.cfg.rule_ttl_s)
            if cur is not None and float(cur.get("expires_in") or 0) > ttl / 4:
                continue
            for k in ("created", "expires_in"):
                rule.pop(k, None)
            self.gw.post_rule(rule)
            renewed += 1
            log.info("[%s] rule %s %s: the incident is still unpatched", iid, rule.get("id"),
                     "renewed" if cur is not None else "restored")
        return renewed

    def retry_transient(self) -> list:
        out = []
        now = time.time()
        with self.state.lock:
            d = self.state.data
            for iid, inc in d["incidents"].items():
                if inc.get("status") != "closed" or inc.get("outcome_detail") != TRANSIENT:
                    continue
                n = int(inc.get("retries") or 0)
                if n >= self.cfg.max_retries:
                    continue
                # 1, 4, 16 minutes, then hourly: quick for a blip, cheap during a long outage of the generator
                if now - float(inc.get("closed_at") or now) < min(3600.0, self.cfg.retry_cooldown_s * 4 ** n):
                    continue
                inc["retries"] = int(inc.get("retries") or 0) + 1
                inc["status"] = "queued"
                inc.setdefault("log", []).append("%.1f retry %d after a transient failure: %s"
                                                 % (now, inc["retries"], inc.get("reason")))
                if iid not in d["queue"]:
                    d["queue"].append(iid)
                out.append(iid)
            if out:
                self.state.save()
        for iid in out:
            log.info("[%s] queued again (retry %d of %d): last close was transient", iid,
                     self.state.incident(iid)["retries"], self.cfg.max_retries)
        return out

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
            pending = self.state.data.setdefault("audit_pending", [])
            aid = pending[0] if pending else None
        if aid is not None:
            try:
                self.run_audit(aid)
            except Exception as e:  # noqa: BLE001
                log.error("[%s] audit failed: %s\n%s", aid, e, traceback.format_exc())
            with self.state.lock:
                if aid in self.state.data["audit_pending"]:
                    self.state.data["audit_pending"].remove(aid)
                self.state.save()
            return aid
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
            self.close(inc, c.outcome, c.reason, c.detail)
        except Exception as e:  # noqa: BLE001
            log.error("[%s] failed: %s\n%s", iid, e, traceback.format_exc())
            why = "pipeline error: %s: %s" % (type(e).__name__, e)
            if inc.get("rule_posted"):
                self.close(inc, "rule_only", why + "; the rule stays active", TRANSIENT)
            else:       # nothing contains this incident: do not report it as contained
                self.close(inc, "error", why + "; no containment rule was posted", TRANSIENT)
        finally:
            for d in inc.pop("_tmp", []):
                shutil.rmtree(d, ignore_errors=True)
        self._schedule_audit(inc)
        return inc

    def close(self, inc, outcome: str, reason: str, detail: str | None = None):
        t0 = inc.get("first_seen") or inc["t"]["start"]
        rp = inc.get("first_rule_posted") or inc.get("rule_posted")
        str_ = round(rp - t0, 1) if rp else None
        stp = round(inc["t"]["verified"] - t0, 1) if outcome == "patched" and inc["t"].get("verified") else None
        inc.update(status="closed", outcome=outcome, reason=reason, closed_at=time.time(),
                   seconds_to_rule=str_, seconds_to_patch=stp, outcome_detail=detail)
        self.note(inc, "closed %s: %s" % (outcome, reason))
        data = {"incident": inc["incident"], "outcome": outcome, "seconds_to_rule": str_, "seconds_to_patch": stp}
        if detail:
            data["outcome_detail"] = detail
        self.publish(E.INCIDENT_CLOSED, data, inc)
        self.state.save()

    def _flow(self, inc):
        cfg = self.cfg
        iid = inc["incident"]
        self.publish(E.INCIDENT_OPENED, self.opened_data(inc), inc)
        app = cfg.reload_project() if hasattr(cfg, "reload_project") else None
        release = self.current_release()
        base_dir = cfg.release_dir(release)
        if not cfg.project.release_complete(base_dir):
            raise RuntimeError("release dir %s lacks %s" % (base_dir, ", ".join(cfg.project.app.release_paths)))
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
        cv = self._corpus_variants(inc, p)
        rep = self.v.reproduce(inc, p, base_dir, extra, corpus=cv) if cv else self.v.reproduce(inc, p, base_dir, extra)
        inc["repro"] = rep
        inc["t"]["poc_s"] = round(time.time() - t, 2)
        self.publish(E.POC_READY, {"incident": iid, "reproducible": rep["reproducible"], "runs": rep["runs"], "poc": p}, inc)
        self.state.save()
        if not rep["reproducible"]:
            where = "" if rep.get("sink_match", True) else " at the incident's sink %s" % p["expect"]["sink"].get("file")
            raise Closed("not_reproducible", "the PoC triggered the %s oracle%s in %d/3 runs on release %s"
                         % (p["expect"]["oracle"], where, rep["runs"], release))
        self.note(inc, "PoC reproduces 3/3; %d variants counted" % len(rep["counted"]))
        self._corpus_add(inc, p, rep)

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
        inc.setdefault("first_rule_posted", inc["rule_posted"])     # a retry must not move the containment time
        self.note(inc, "rule %s posted (%s)" % (rule["id"], rule["scope"]))
        self.state.save()

        # 3. fix loop
        autopatch, caps = app.effective_autopatch() if app is not None else ("merge", [])
        inc["autopatch"] = autopatch
        if autopatch == "off":
            raise Closed("rule_only", "autopatch is off; the rule stays active", "autopatch_off")
        if pm is None:
            raise Closed("rule_only", "patch generator unavailable (%s); the rule stays active" % self._patcher_err,
                         TRANSIENT)
        try:
            self.repo.ensure_base()
        except Exception as e:  # noqa: BLE001
            raise Closed("rule_only", "repository target unavailable: %s" % e, TRANSIENT)
        feedback, change, patched_dir, attempt_ok = [], None, None, False
        for attempt in range(1, cfg.max_attempts + 1):
            t = time.time()
            try:
                out = _call_with_timeout(pm.propose, cfg.patcher_timeout_s, base_dir, incmod.public(inc), list(feedback),
                                         attempt) or {}
            except Exception as e:  # noqa: BLE001
                out = {"diff": "", "notes": "patch generator failed: %s" % e, "_failed": True}
            if not isinstance(out, dict):
                out = {"notes": "patch generator returned %s, not a result object" % type(out).__name__, "_failed": True}
            src = patch_source(out)
            diff = out.get("diff") if isinstance(out.get("diff"), str) else ""
            rec = {"attempt": attempt, "source": src, "notes": str(out.get("notes") or "")[:2000],
                   "propose_s": round(time.time() - t, 1), "gates": []}
            if out.get("_failed") or not diff.strip():
                rec["no_proposal"] = True       # the generator gave nothing to judge (down, timed out, quota)
            inc["attempts"].append(rec)
            self.publish(E.PATCH_ATTEMPT, {"incident": iid, "attempt": attempt, "source": src}, inc)
            self.publish(E.PATCH_DIFF, {"incident": iid, "attempt": attempt, "diff": diff}, inc)
            holder = {"change": change, "pending": []}

            def on_result(gate, ok, detail, secs, attempt=attempt, rec=rec, holder=holder):
                rec["gates"].append({"gate": gate, "ok": ok, "detail": detail, "seconds": secs})
                data = {"incident": iid, "attempt": attempt, "gate": gate, "ok": ok, "detail": detail}
                if ok and str(detail).startswith("skipped:"):
                    data["skipped"] = True
                self.publish(E.GATE_RESULT, data, inc)
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
            # nothing was ever proposed: the generator is unavailable, not the fix impossible. Try again later.
            none = all(a.get("no_proposal") for a in inc["attempts"][-cfg.max_attempts:])
            raise Closed("rule_only", reason, TRANSIENT if none else None)
        if change is None:
            raise Closed("rule_only", "the pull request could not be opened; the rule stays active")
        caps = list(caps) + list(getattr(self.v, "caps", []) or [])
        if autopatch == "pr" or caps:
            why = "; ".join(caps) or "autopatch: pr"
            inc["caps"] = caps
            self._safe(self.repo.comment, change, "The validation gates passed. Not merged automatically (%s): "
                       "review and merge this pull request by hand. The containment rule stays active." % why)
            raise Closed("rule_only", "pull request open, not merged (%s); the rule stays active" % why, "pr_open")

        # 4. merge + release
        try:
            sha = self.repo.merge(change)
        except Exception as e:  # noqa: BLE001
            if not self._use_local("merge failed: %s" % e, inc):
                raise Closed("rule_only", "merge failed: %s" % e, TRANSIENT)
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
            res = {"ok": False, "rolled_back": False, "detail": "deploy call failed: %s" % e, "unreachable": True}
        inc["t"]["deploy_s"] = round(time.time() - t, 1)
        inc["deploy"] = res
        if not res.get("ok"):
            self._safe(self.repo.revert, change, sha, "deploy of %s failed: %s" % (new_rel, res.get("detail")))
            raise Closed("rule_only", "deploy of %s %s: %s; the rule stays active" % (
                new_rel, "rolled back" if res.get("rolled_back") else "failed", res.get("detail")),
                TRANSIENT if res.get("unreachable") else None)
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

    # ------------------------------------------------------------ corpus
    def _corpus_variants(self, inc, p) -> list:
        """Corpus values of the incident's class, set into its parameter: extra variants for the reproduction
        (counted only if they fire on the unpatched release, then judged by the poc gate and verification)."""
        param = inc.get("param")
        if not param or inc.get("vuln_class") not in auditmod.ORACLE_OF:
            return []
        base = p["requests"][-1]
        own = reqs.get_value(base, param, inc.get("route"))
        out = []
        for val in self.corpus.values(inc["vuln_class"], limit=auditmod.MAX_CORPUS_PER_PROBE):
            if val == str(own) or (inc["vuln_class"] == "idor" and not val.isdigit()):
                continue
            try:
                out.append((val, reqs.set_value(base, param, val, inc.get("route"))))
            except Exception:  # noqa: BLE001
                continue
        return out

    def _corpus_add(self, inc, p, rep) -> None:
        param = inc.get("param")
        if not param or inc.get("vuln_class") not in auditmod.ORACLE_OF:
            return
        vals = [reqs.get_value(p["requests"][-1], param, inc.get("route"))]
        vals += [reqs.get_value(v["request"], param, inc.get("route")) for v in rep.get("counted") or []]
        try:
            n = self.corpus.add(inc["vuln_class"], vals, inc["incident"], "%s %s" % (inc["method"], inc["route"]),
                                "%s:%s" % (param.get("in"), param.get("name")))
            if n:
                self.note(inc, "corpus %s: +%d confirmed value(s)" % (inc["vuln_class"], n))
        except Exception as e:  # noqa: BLE001
            self.note(inc, "corpus append failed: %s" % e)

    # ------------------------------------------------------------ class self-audit (pipeline/audit.py)
    def opened_data(self, inc) -> dict:
        data = {k: inc[k] for k in ("incident", "vuln_class", "method", "route", "param", "sink", "evidence_rid", "request")}
        data["origin"] = inc.get("origin") or "live"
        if inc.get("parent"):
            data["parent"] = inc["parent"]
        return data

    def audit_settings(self):
        proj = self.cfg.project
        a = getattr(proj, "audit", None)
        if a is None:
            return False, 40, 120
        return bool(a.enabled), int(a.max_jobs), float(a.max_seconds)

    def _schedule_audit(self, inc) -> None:
        if inc.get("outcome") not in ("patched", "rule_only") or inc.get("vuln_class") not in auditmod.ORACLE_OF:
            return
        if not self.audit_settings()[0]:
            return
        with self.state.lock:
            pend = self.state.data.setdefault("audit_pending", [])
            if inc["incident"] not in pend:
                pend.append(inc["incident"])
            self.state.save()

    def audit_candidates(self, inc, release: str, manifest: dict) -> tuple:
        """-> (candidates to judge, why-not text or ""). One audit per class per release; an audit incident's
        closure only re-audits the candidates no earlier audit of the class has judged; open and closed
        incidents (any origin) are never probed again."""
        cls = inc["vuln_class"]
        with self.state.lock:
            a = self.state.data.setdefault("audits", {}).setdefault(cls, {"releases": {}, "audited": []})
            if release in a["releases"]:
                return [], "class %s was already audited on release %s (by %s)" % (
                    cls, release, a["releases"][release].get("by"))
            audited = set(a["audited"])
            known = set(self.state.data["keys"])
        out = []
        for c in auditmod.candidates(self.spec, cls, manifest):
            k = c.key(cls)
            if k in known or k == inc.get("key"):
                continue
            if inc.get("origin") == "audit" and k in audited:
                continue
            out.append(c)
        return out, ""

    def run_audit(self, iid: str):
        inc = self.state.incident(iid)
        cls = inc.get("vuln_class")
        enabled, max_jobs, max_s = self.audit_settings()
        if not enabled or cls not in auditmod.ORACLE_OF:
            return None
        release = self.current_release()
        base_dir = self.cfg.release_dir(release)
        if not self.cfg.project.release_complete(base_dir):
            self.note(inc, "audit skipped: release dir %s incomplete" % base_dir)
            return None
        manifest = {}
        try:
            manifest = self.v.manifest(base_dir)
        except Exception as e:  # noqa: BLE001
            self.note(inc, "audit: manifest from the judge unavailable (%s); using the host copy" % e)
            manifest = self.manifest()
        cands, why = self.audit_candidates(inc, release, manifest)
        if why:
            self.note(inc, "audit skipped: " + why)
            return None
        if not cands:
            self.note(inc, "audit: no %s candidate left to judge on release %s" % (cls, release))
            with self.state.lock:
                self.state.data["audits"][cls]["releases"][release] = {"by": iid, "checked": [], "ts": time.time()}
                self.state.save()
            return None
        self.bus.publish(busmod.AUDIT_STARTED, {"incident": iid, "vuln_class": cls, "candidates": len(cands)},
                         incident=iid)
        self.note(inc, "audit %s on release %s: %d candidate(s)" % (cls, release, len(cands)))
        found = []

        def on_finding(f):
            new = self.enqueue_finding(f, inc, release, manifest)
            if new:
                found.append(new)
                self.bus.publish(busmod.AUDIT_FINDING, {"incident": new["incident"], "parent": iid,
                                                        "route": new["route"], "param": new["param"]},
                                 incident=new["incident"])
        res = auditmod.run(self.v, base_dir, cls, cands, manifest, self.corpus.values(cls, auditmod.MAX_CORPUS_PER_PROBE),
                           max_jobs=max_jobs, max_seconds=max_s, parallel=getattr(self.v, "audit_parallel", 3),
                           stop=self.paused, release=release, on_finding=on_finding)
        keys = [c.key(cls) for c in res.checked]
        with self.state.lock:
            a = self.state.data["audits"][cls]
            a["releases"][release] = {"by": iid, "checked": keys, "ts": time.time()}
            a["audited"] = sorted(set(a["audited"]) | set(keys))
            inc["audit"] = {"release": release, "candidates": len(cands), "checked": len(res.checked),
                            "skipped": [[c.label, w] for c, w in res.skipped], "findings": [x["incident"] for x in found],
                            "jobs": res.jobs, "seconds": res.seconds}
            self.state.save()
        self.bus.publish(busmod.AUDIT_DONE, {"incident": iid, "checked": len(res.checked), "findings": len(found),
                                             "seconds": res.seconds}, incident=iid)
        self.note(inc, "audit %s done: %d checked, %d skipped, %d finding(s) %s in %.1fs" % (
            cls, len(res.checked), len(res.skipped), len(found), [x["incident"] for x in found], res.seconds))
        return res

    def enqueue_finding(self, f, parent: dict, release: str, manifest: dict) -> dict | None:
        """A probe that fired: incident with origin audit, queued, unless its dedupe key is known."""
        ts = time.time()
        ev = dict(f.evidence)
        with self.state.lock:
            n = self.state.data.setdefault("audit_seq", 0) + 1
            self.state.data["audit_seq"] = n
        ev["rid"] = "audit-%s-%d" % (parent["incident"], n)
        ev.setdefault("release", release)
        sk = incmod.build({"type": E.ORACLE_FIRED, "ts": ts, "rid": ev["rid"], "data": ev}, self.spec, manifest)
        if sk["vuln_class"] != parent["vuln_class"]:
            log.info("audit probe %s fired %s, not %s: ignored", f.candidate.label, sk["vuln_class"], parent["vuln_class"])
            return None
        with self.state.lock:
            d = self.state.data
            if sk["key"] in d["keys"]:
                return None
            iid = self.state.new_id()
            sk.update(incident=iid, status="queued", hits=1, queued_at=ts, attempts=[], log=[], origin="audit",
                      parent=parent["incident"], audit_value=f.value[:200])
            d["incidents"][iid] = sk
            d["keys"][sk["key"]] = iid
            d["queue"].append(iid)
            self.state.save()
        log.info("audit finding %s (from %s): %s %s %s param=%s", iid, parent["incident"], sk["vuln_class"],
                 sk["method"], sk["route"], sk["param"])
        return sk

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
        src = next((a["source"] for a in inc.get("attempts") or [] if a.get("attempt") == attempt), "unknown")
        note = "Patch source: %s" % SOURCES.get(src, SOURCES["unknown"])     # in every attempt's commit message
        try:
            change = self.repo.open_change(inc["incident"], attempt, diff, patched_dir, title,
                                           self._pr_body(inc, attempt, src), note)
        except Exception as e:  # noqa: BLE001
            if not self._use_local("opening the pull request failed: %s" % e, inc):
                raise RuntimeError("could not open the pull request: %s" % e)
            previous = None
            change = self.repo.open_change(inc["incident"], attempt, diff, patched_dir, title,
                                           self._pr_body(inc, attempt, src), note)
        if previous is None or previous.url != change.url:
            self.publish(E.PR_OPENED, {"incident": inc["incident"], "url": change.url, "branch": change.branch}, inc)
        inc["pr"] = change.to_dict()
        return change

    def _pr_body(self, inc, attempt: int = 1, source: str = "unknown") -> str:
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
            "| patch source (attempt %d) | %s |" % (attempt, SOURCES.get(source, SOURCES["unknown"])),
            "", "**Captured request**", _fence(json.dumps(ev.get("request"), indent=1)[:4000]),
            "", "**Oracle detail**", _fence(json.dumps(prim.get("detail"), indent=1)[:3000]),
            "", "**Stack** (outermost first)", _fence("\n".join("%s:%s %s" % (f.get("file"), f.get("line"), f.get("func"))
                                                              for f in prim.get("stack") or [])),
            "", "**Regression case (PoC)**", _fence(json.dumps(poc_view, indent=1)[:6000]),
            "", "Each validation gate is reported as a commit status `immune/<gate>`: %s. Later attempts are "
                "further commits on this branch; each commit message states its own patch source." % ", ".join(GATES),
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
