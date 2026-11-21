"""The five validation gates (docs/plan-construccion.md §4), in order:

  policy      mechanical AST policy on the diff (host, no app code runs)
  properties  positive properties per class (runner)
  poc         PoC + variants: those firing the oracle on the unpatched code must not fire on the patched one (runner)
  tests       the app's test suite, `tests.command` (runner); reported as skipped when absent
  legit       legit scenarios give identical output before/after, and cover the patched endpoint (runner);
              without `scenarios`, the gateway recording (clean GETs to prod, most recent 200 per path)
              is replayed before/after instead

A gate that is skipped (tests) or fails only for lack of coverage (legit on recordings) does not
reject the patch: it caps autopatch at `pr` (contracts/product.md §3). `Validator.caps` lists why.

`Validator.validate()` stops at the first failing gate. Every result has a human-readable
`detail` that is published live and fed back to the patch generator.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time

from . import diffs, openapi, policy, poc as pocmod, properties
from .runner import Runner, RunnerError

log = logging.getLogger("pipeline.gates")
GATES = ("policy", "properties", "poc", "tests", "legit")
STANDIN = "pipeline.standin_scenarios"


class Validator:
    def __init__(self, cfg, runner: Runner | None = None):
        self.cfg = cfg
        self.runner = runner or Runner(cfg)
        self.cache = {}
        self._lock = threading.Lock()
        self.caps = []      # reasons the last validate() capped autopatch at pr

    # ------------------------------------------------------------ runner helpers (cached per base release)
    def run(self, release_dir, job, timeout=None):
        return self.runner.run(release_dir, job, timeout)

    def manifest(self, base_dir) -> dict:
        key = ("manifest", self.cfg.seed)
        if key not in self.cache:
            self.cache[key] = self.run(base_dir, {"kind": "harness", "sequences": []})["manifest"]
        return self.cache[key]

    def scenarios(self, release_dir) -> dict:
        return self.run(release_dir, {"kind": "scenarios", "module": self.cfg.scenarios_module, "fallback": STANDIN},
                        timeout=max(self.cfg.runner_timeout_s, 300))

    def base_scenarios(self, base_dir) -> dict:
        key = ("scenarios", os.path.realpath(base_dir))
        with self._lock:
            if key in self.cache:
                return self.cache[key]
        res = self.scenarios(base_dir)
        with self._lock:
            self.cache[key] = res
        return res

    # ------------------------------------------------------------ reproduction (before any patch)
    def reproduce(self, inc: dict, poc: dict, base_dir: str, extra_variants: list | None = None) -> dict:
        """PoC 3x + variants on the unpatched release. -> {runs, reproducible, counted, ignored, sink_match}"""
        manifest = None
        try:
            manifest = self.manifest(base_dir)
        except RunnerError:
            pass
        variants = pocmod.mutate(inc, poc, manifest)
        base = poc["requests"][-1]
        for i, v in enumerate(extra_variants or []):
            nv = pocmod.normalise_variant(v, base)
            if nv:
                variants.append(("p%d:%s" % (i, (nv.get("query") or nv["path"])[:40]), nv))
        seqs = [{"name": "poc", "requests": poc["requests"], "repeat": 3}]
        seqs += [{"name": "v:" + n, "requests": poc["requests"][:-1] + [r]} for n, r in variants]
        res = self.run(base_dir, {"kind": "harness", "state_b64": poc.get("state_b64"), "sequences": seqs})
        kind = poc["expect"]["oracle"]
        sink = poc["expect"].get("sink") or {}
        runs = res["sequences"][0]["runs"]
        hits = [any(e["oracle"] == kind for e in run[-1]["events"]) for run in runs]
        sink_match = any(any(fr.get("file") == sink.get("file") and fr.get("line") == sink.get("line")
                             for e in run[-1]["events"] for fr in e.get("stack") or []) for run in runs)
        counted, ignored = [], []
        for (n, r), s in zip(variants, res["sequences"][1:]):
            last = s["runs"][0][-1]
            (counted if any(e["oracle"] == kind for e in last["events"]) else ignored).append({"name": n, "request": r})
        return {"runs": sum(hits), "of": len(hits), "reproducible": all(hits) and len(hits) == 3,
                "counted": counted, "ignored": [x["name"] for x in ignored], "sink_match": sink_match,
                "statuses": [run[-1]["status"] for run in runs]}

    # ------------------------------------------------------------ gates
    def gate_policy(self, ctx):
        return policy.check(ctx["diff"], ctx["base_dir"], ctx["patched_dir"], self.cfg.policy_max_lines,
                            self.cfg.policy_max_files, dirs=self.cfg.project.app.source_dirs)[:2]

    def gate_properties(self, ctx):
        return properties.check(self, ctx["inc"], ctx["poc"], ctx["base_dir"], ctx["patched_dir"])

    def gate_poc(self, ctx):
        poc, rep = ctx["poc"], ctx["repro"]
        seqs = [{"name": "poc", "requests": poc["requests"], "repeat": 1}]
        seqs += [{"name": "v:" + v["name"], "requests": poc["requests"][:-1] + [v["request"]]} for v in rep["counted"]]
        res = self.run(ctx["patched_dir"], {"kind": "harness", "state_b64": poc.get("state_b64"), "sequences": seqs})
        fired = []
        for s in res["sequences"]:
            for run in s["runs"]:
                last = run[-1]
                if last["events"]:
                    e = last["events"][0]
                    fr = (e.get("stack") or [{}])[-1]
                    fired.append("%s still fires the %s oracle (status %d%s)" % (
                        "the PoC" if s["name"] == "poc" else "variant " + s["name"][2:], e["oracle"], last["status"],
                        ", at %s:%s" % (fr.get("file"), fr.get("line")) if fr else ""))
                    break
        n = len(rep["counted"])
        if fired:
            return False, "; ".join(fired[:4]) + (" (+%d more)" % (len(fired) - 4) if len(fired) > 4 else "")
        return True, ("the PoC and %d variant(s) that fire on the unpatched code fire no oracle on the patched code"
                      "%s" % (n, " (%d variant(s) did not fire before and were not counted)" % len(rep["ignored"])
                              if rep["ignored"] else ""))

    def gate_tests(self, ctx):
        if not self.cfg.project.tests_command:
            ctx.setdefault("caps", []).append("tests skipped (no tests.command)")
            return True, "skipped: no tests.command configured; autopatch capped at pr"
        res = self.run(ctx["patched_dir"], {"kind": "pytest", "timeout": 600}, timeout=700)
        if res.get("skipped"):
            ctx.setdefault("caps", []).append("tests skipped (no tests.command)")
            return True, "skipped: %s; autopatch capped at pr" % res.get("summary")
        if res.get("ok"):
            return True, "test suite: %s" % res.get("summary")
        failed = ", ".join(l.split(" ", 1)[1].split(" - ")[0].split("::")[-1] for l in res.get("failed") or [])
        return False, "test suite failed: %s%s" % (res.get("summary"), (" — failing: " + failed) if failed else "")

    def _targets(self, ctx) -> list:
        inc = ctx["inc"]
        targets = [(inc["method"], inc["route"])]
        for r in ctx.get("changed_routes") or []:
            m, _, p = r.partition(" ")
            if (m, p) not in targets:
                targets.append((m, p))
        return targets

    def recorded_requests(self, limit: int = 200) -> list:
        """Clean GET requests the gateway forwarded to prod with status 200: the most recent per path+query."""
        path = self.cfg.record_path
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                f.seek(max(0, f.tell() - 8 * 1024 * 1024))
                lines = f.read().decode("utf-8", "replace").splitlines()
        except OSError:
            return []
        recs = []
        for line in lines:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict):
                recs.append(r)
        # requests the gateway's after-check found to be attacks were recorded as clean first: never legitimate
        seen, out = {(r.get("path"), r.get("query") or "", r.get("uid")) for r in recs if r.get("aftercheck") == "oracle"}, []
        for r in reversed(recs):
            if "aftercheck" in r or r.get("method") != "GET" or r.get("class") != "clean" \
                    or r.get("route") != "prod" or r.get("status") != 200:
                continue
            key = (r.get("path"), r.get("query") or "", r.get("uid"))
            if key in seen or "<redacted>" in (r.get("query") or ""):
                continue
            seen.add(key)
            rq = {"name": "rec:%s?%s" % (r.get("path"), r.get("query") or ""), "method": "GET",
                  "path": r.get("path") or "/", "query": r.get("query") or "", "headers": {}}
            if r.get("uid") is not None:
                rq["uid"], rq["role"] = int(r["uid"]), "user"
            out.append(rq)
            if len(out) >= limit:
                break
        out.reverse()
        return out

    def gate_legit_replay(self, ctx):
        """No `scenarios`: replay recorded clean GETs before/after and compare status + body."""
        reqs_ = self.recorded_requests()
        if not reqs_:
            ctx.setdefault("caps", []).append("legit: no coverage (no recorded clean GET requests)")
            return False, "no coverage: the gateway recording holds no clean GET request to replay", True
        key = ("replay", os.path.realpath(ctx["base_dir"]), len(reqs_), reqs_[-1]["name"])
        before = self.cache.get(key) or self.run(ctx["base_dir"], {"kind": "replay", "requests": reqs_})
        self.cache[key] = before
        after = self.run(ctx["patched_dir"], {"kind": "replay", "requests": reqs_})
        diffs_ = []
        for x, y in zip(before["results"], after["results"]):
            if x.get("status") != 200:
                continue     # does not reproduce on the seed: not a usable baseline
            if (x["status"], x["body"]) != (y["status"], y["body"]):
                what = "status %s -> %s" % (x["status"], y["status"]) if x["status"] != y["status"] else "body differs"
                diffs_.append("%s: %s" % (x["name"][4:], what))
        if diffs_:
            return False, "legit behaviour changed on recorded requests: " + "; ".join(diffs_[:4])
        usable = [x for x in before["results"] if x.get("status") == 200]
        cover, uncovered = {}, []
        for m, tpl in self._targets(ctx):
            n = sum(1 for x in usable if openapi.route_matches(tpl, m, x.get("method"), x.get("path")))
            cover["%s %s" % (m, tpl)] = n
            if not n:
                uncovered.append("%s %s" % (m, tpl))
        if uncovered:
            ctx.setdefault("caps", []).append("legit: no coverage of %s" % ", ".join(uncovered))
            return False, ("no coverage: %d recorded request(s) identical before and after, none covers %s; "
                           "autopatch capped at pr" % (len(usable), ", ".join(uncovered))), True
        return True, ("%d recorded request(s) identical before and after; patched endpoint coverage: %s" % (
            len(usable), ", ".join("%s (%d)" % kv for kv in cover.items())))

    def gate_legit(self, ctx):
        if not self.cfg.scenarios_module:
            return self.gate_legit_replay(ctx)
        inc = ctx["inc"]
        before = self.base_scenarios(ctx["base_dir"])
        after = self.scenarios(ctx["patched_dir"])
        note = (" [%s]" % before["note"]) if before.get("note") else ""
        b = {s["name"]: s for s in before["scenarios"]}
        a = {s["name"]: s for s in after["scenarios"]}
        if not b:
            return False, "no legit scenarios available%s" % note
        broken = [n for n, s in b.items() if s.get("error")]
        if broken:
            return False, "legit scenario(s) %s fail on the unpatched release; cannot compare%s" % (", ".join(broken), note)
        diffs_ = []
        for name, s in b.items():
            t = a.get(name)
            if t is None or t.get("error"):
                diffs_.append("scenario %s %s on the patched release" % (name, "is missing" if t is None else "crashes: " + t["error"]))
                continue
            for i, (x, y) in enumerate(zip(s["steps"], t["steps"])):
                if x != y:
                    what = "status %s -> %s" % (x.get("status"), y.get("status")) if x.get("status") != y.get("status") else "response body differs"
                    diffs_.append("scenario %s step %d (%s %s %s): %s" % (name, i + 1, x.get("step"), x.get("method", ""),
                                                                       x.get("path", ""), what))
                    break
            else:
                if len(s["steps"]) != len(t["steps"]):
                    diffs_.append("scenario %s: %d steps before, %d after" % (name, len(s["steps"]), len(t["steps"])))
        if diffs_:
            return False, "legit behaviour changed: " + "; ".join(diffs_[:4]) + note
        targets = self._targets(ctx)
        steps = [st for s in b.values() for st in s["steps"]]
        uncovered = []
        cover = {}
        for m, tpl in targets:
            n = sum(1 for st in steps if st.get("method") and openapi.route_matches(tpl, m, st["method"], st.get("path")))
            cover["%s %s" % (m, tpl)] = n
            if not n:
                uncovered.append("%s %s" % (m, tpl))
        if uncovered and before.get("partial"):
            # generated journeys (GET routes only): missing coverage caps autopatch, it does not reject the patch
            ctx.setdefault("caps", []).append("legit: no coverage of %s" % ", ".join(uncovered))
            return False, ("no coverage: %d scenarios, %d steps identical before and after, none covers %s; "
                           "autopatch capped at pr%s" % (len(b), len(steps), ", ".join(uncovered), note)), True
        if uncovered:
            return False, "no legit scenario covers the patched endpoint(s) %s: not deployable%s" % (", ".join(uncovered), note)
        return True, ("%d scenarios, %d steps identical before and after; patched endpoint coverage: %s%s" % (
            len(b), len(steps), ", ".join("%s (%d steps)" % kv for kv in cover.items()), note))

    # ------------------------------------------------------------ driver
    def prepare(self, diff: str, base_dir: str, work_parent: str | None = None):
        """-> (patched_dir or None, error detail)"""
        patched = diffs.copy_release(base_dir, work_parent, paths=self.cfg.project.app.release_paths)
        try:
            diffs.apply(diff, patched)
        except diffs.DiffError as e:
            shutil.rmtree(patched, ignore_errors=True)
            return None, str(e)
        except Exception as e:  # noqa: BLE001
            shutil.rmtree(patched, ignore_errors=True)
            return None, "diff does not apply: %s" % e
        return patched, ""

    def validate(self, inc, poc, repro, base_dir, diff, on_result=None, after_policy=None, keep=False, gates=GATES):
        """Run the gates in order, stop at the first failure.
        on_result(gate, ok, detail, seconds); after_policy(patched_dir) runs once policy passed (e.g. open the PR).
        -> (ok, [(gate, ok, detail, seconds)], patched_dir or None)"""
        results = []
        self.caps = []

        def emit(g, ok, detail, secs):
            results.append((g, ok, detail, secs))
            if on_result:
                on_result(g, ok, detail, secs)

        t0 = time.time()
        if not isinstance(diff, str) or not diff.strip():
            emit("policy", False, "REJECTED: the patch generator returned an empty diff", 0.0)
            return False, results, None
        patched, err = self.prepare(diff, base_dir)
        if patched is None:
            emit("policy", False, "REJECTED: %s" % err, round(time.time() - t0, 2))
            return False, results, None
        ctx = {"inc": inc, "poc": poc, "repro": repro, "base_dir": base_dir, "patched_dir": patched, "diff": diff}
        try:
            files = [c.path for c in diffs.parse(diff) if c.path]
            ctx["changed_routes"] = policy.changed_routes(base_dir, patched, [f for f in files if f.endswith(".py")])
        except Exception:  # noqa: BLE001
            ctx["changed_routes"] = []
        ok_all = True
        for g in gates:
            t = time.time()
            soft = False
            try:
                out = getattr(self, "gate_" + g)(ctx)
                ok, detail = out[0], out[1]
                soft = len(out) > 2 and bool(out[2])
            except RunnerError as e:
                ok, detail = False, "gate could not run: %s" % e
            except Exception as e:  # noqa: BLE001
                log.exception("gate %s crashed", g)
                ok, detail = False, "gate crashed: %s: %s" % (type(e).__name__, e)
            emit(g, ok, detail, round(time.time() - t, 2))
            if not ok and soft:
                continue    # caps autopatch at pr (ctx["caps"]) instead of rejecting the patch
            if not ok:
                ok_all = False
                break
            if g == "policy" and after_policy:
                after_policy(patched)
        self.caps = list(ctx.get("caps") or []) if ok_all else []
        if not keep:
            shutil.rmtree(patched, ignore_errors=True)
            patched = None
        return ok_all, results, patched
