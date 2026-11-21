"""`immune init`: adapt immune to a project (contracts/product.md §5, steps 1-10).

    python -m immune.init [--project DIR] [--yes] [--no-llm] [--prod-db PATH] [--seed N]
    from immune.init import main; main(["--project", DIR, "--yes"])

Writes <project>/.immune/: config.yaml, openapi.yaml, profile.py, shadow/{columns,auth,marks,detect}.yaml,
runtime/data/{shadow/seed.db,manifest.json,markers.json}, deploy/, DEPLOY.md, report.md.
Prints one status line per step and ends with `READY: <command>` (exit 0) or `NEEDS ATTENTION:` + list (exit 1).
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import yaml

from immune import _cfg, deploycmd, doctor, shadowdata
from immune.initsteps import detect as det_mod
from immune.initsteps import drafts, llm, openapi as oa, report, validate
from immune.initsteps import scenarios as scen

COLS = ".immune/shadow/columns.yaml"
PROF = ".immune/profile.py"
AUTH = ".immune/shadow/auth.yaml"
MARKS = ".immune/shadow/marks.yaml"
MAX_ROUNDS = 3


class Init:
    def __init__(self, project, *, use_llm=True, prod_db=None, seed=1, out=None, runner=None):
        self.project = os.path.realpath(project)
        self.use_llm = use_llm
        self.prod_db_arg = prod_db
        self.seed = seed
        self.out = out or (lambda s: print(s, flush=True))
        self.runner = runner            # tests inject a fake CLI runner
        self.t0 = time.monotonic()
        self.llm_calls = []             # [{step, seconds, ok, changed, reason}]
        self.attention = []             # short human-readable items
        self.assumptions = []
        self.step_state = {}            # step -> {"source": "llm"|"heuristic"|"draft-fallback", "errors": [...]}
        self.det = {}
        self.doc = None
        self.schema = None
        self.cfg = None
        self.doctor_results = []
        self.shadow_report = {}
        self.deploy = {}
        self.scenarios_plan = None

    # ----------------------------------------------------------------------------------------- utils
    def say(self, n, text):
        self.out("[%2d/10] %s" % (n, text))

    def path(self, rel):
        return os.path.join(self.project, rel)

    def write(self, rel, text):
        p = self.path(rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)

    def read(self, rel):
        try:
            with open(self.path(rel), encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            return None

    # ----------------------------------------------------------------------------------------- steps
    def step1_detect(self):
        d = det_mod.detect(self.project)
        self.det = d
        self.assumptions += d.get("assumptions") or []
        if d.get("problems"):
            self.attention += d["problems"]
            self.say(1, "detect: %s" % "; ".join(d["problems"]))
            return False
        self.say(1, "detect: %s %s %s, port %d (%s), tests: %s, deploy: %s" % (
            d["runtime"], d["framework"], d["asgi"], d["port"], d["port_source"], d["tests_command"] or "none",
            d["deploy"]["style"]))
        return True

    def step2_openapi(self):
        doc, how = oa.dump(self.project, self.det)
        if doc is None:
            self.attention.append("no OpenAPI document: %s" % how)
            self.say(2, "openapi: FAILED (%s)" % how)
            return False
        self.doc = doc
        os.makedirs(self.path(".immune/shadow"), exist_ok=True)
        with open(self.path(".immune/shadow/openapi.base.json"), "w") as f:
            json.dump(doc, f, indent=1)
        oa.write(doc, self.path(".immune/openapi.yaml"))
        health = oa.health_route(doc)
        if not health:
            health = "/"
            self.assumptions.append("no health route in the OpenAPI; using /")
        self.det["health"] = health
        self.say(2, "openapi: %d operations (%s); health %s" % (len(oa.operations(doc)), how, health))
        return True

    def step3_database(self):
        prod = self.prod_db_arg or self.det.get("prod_db")
        if prod and not os.path.isabs(prod):
            prod = self.path(prod)
        if not prod or not os.path.isfile(prod):
            self.attention.append("no SQLite production database found (pass --prod-db PATH; env var %s)"
                                  % (self.det.get("db_env") or "?"))
            self.say(3, "database: NOT FOUND")
            return False
        if not self.det.get("db_env"):
            self.attention.append("could not tell which env var carries the database path; assumed APP_DB")
            self.det["db_env"] = "APP_DB"
        self.det["prod_db_abs"] = prod
        self.schema = shadowdata.dump_schema(prod)
        with open(self.path(".immune/shadow/schema.json"), "w") as f:
            json.dump(self.schema, f, indent=1)
        self.write(".immune/context/schema.md", report.schema_md(self.schema, prod))
        self.say(3, "database: %s via %s (%s); %d tables" % (os.path.relpath(prod, self.project), self.det["db_env"],
                                                             self.det.get("prod_db_source") or "--prod-db",
                                                             len(self.schema["tables"])))
        return True

    def config_dict(self, auth=None) -> dict:
        d = self.det
        env = {d["db_env"]: "{db}"}
        for s in d.get("secret_envs") or []:
            env[s] = "{secret}"
        rel_db = os.path.relpath(d["prod_db_abs"], self.project)
        cfg = {
            "version": 1, "name": d["name"], "runtime_dir": ".immune/runtime",
            "app": {"runtime": "python-asgi", "release_paths": d["release_paths"], "source_dirs": d["source_dirs"],
                    "asgi": d["asgi"], "port": d["port"], "health": d.get("health") or "/health", "env": env},
            "database": {"kind": "sqlite", "path_env": d["db_env"]},
            "data": {"prod_db": rel_db},
            "auth": auth or {"kind": "none"},
            "openapi": ".immune/openapi.yaml",
            "shadow": {"profile": _cfg.DEFAULT_PROFILE_MODULE, "columns": COLS},
            "repo": {"target": "local"},
            "autopatch": "pr", "mode": "enforce", "pool_size": 4,
        }
        if d.get("time_env"):
            cfg["app"]["frozen_time_env"] = d["time_env"]
        if d.get("tests_command"):
            cfg["tests"] = {"command": d["tests_command"]}
        return cfg

    def write_config(self, auth=None):
        text = ("# Generated by `immune init` - review, then commit (contracts/product.md section 2).\n"
                + yaml.safe_dump(self.config_dict(auth), sort_keys=False, width=120))
        self.write(".immune/config.yaml", text)
        self.cfg = _cfg.load(self.project)

    # ---------------------------------------------------------------------- LLM step machinery
    def facts(self) -> str:
        d = self.det
        lines = ["asgi app: %s (file %s)" % (d["asgi"], d.get("app_file")), "app package: %s" % d["package"],
                 "source dirs: %s" % d["source_dirs"], "DB_ENV (env var with the sqlite path): %s" % d["db_env"],
                 "secret env vars: %s" % (d.get("secret_envs") or "none"),
                 "frozen-time env var: %s" % (d.get("time_env") or "none"),
                 "file/static env vars: %s" % (d.get("file_envs") or "none"),
                 "static-looking dirs (relative to the repo root): %s" % (self.static_dirs() or "none"),
                 "health route: %s" % d.get("health")]
        return "\n".join(lines)

    def static_dirs(self) -> list[str]:
        out = []
        names = {"static", "files", "public", "assets", "media", "templates", "uploads", "downloads", "www"}
        for rel in self.det.get("release_paths") or []:
            root = self.path(rel)
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [x for x in dirnames if x not in det_mod.SKIP_DIRS]
                r = os.path.relpath(dirpath, self.project).replace(os.sep, "/")
                if os.path.basename(dirpath) in names and any(not f.endswith(".py") for f in filenames + dirnames) \
                        and not any(r.startswith(o + "/") for o in out) and "/tests" not in "/" + r:
                    out.append(r)
        return out

    def context(self, step) -> dict:
        ctx = {".immune/context/schema.md": self.read(".immune/context/schema.md") or "",
               ".immune/context/openapi.md": "# Operations (METHOD path, params, body properties)\n\n"
                                             + oa.summary(self.doc) + "\n",
               ".immune/context/facts.md": "# Detected facts\n\n" + self.facts() + "\n"}
        if step in ("profile", "marks"):
            ctx[COLS] = self.read(COLS) or ""
        return ctx

    def validate_step(self, step) -> list[str]:
        if step == "columns":
            return validate.columns(self.path(COLS), self.schema)
        if step == "marks":
            errs, _ = validate.marks(self.path(MARKS), self.doc)
            return errs
        errs, auth = validate.auth(self.path(AUTH), self.doc)
        if not errs:
            self.write_config(auth)
        perrs, _ = validate.profile(self.cfg)
        return errs + perrs

    def run_llm(self, step, drafts_now: dict, feedback: str | None) -> llm.StepResult:
        res = llm.run_step(step, self.project, self.context(step), drafts_now, self.facts(), feedback,
                           runner=self.runner)
        self.llm_calls.append({"step": step, "seconds": round(res.seconds, 1), "ok": res.ok, "changed": res.changed,
                               "reason": res.reason, "notes": res.notes, "denials": res.denials})
        return res

    def llm_step(self, step, draft_files: dict, feedback: str | None = None, attempts: int = MAX_ROUNDS) -> list[str]:
        """Write drafts, run the LLM (with mechanical validation feedback), keep the best valid result."""
        for rel, text in draft_files.items():
            if self.read(rel) is None or feedback is None:
                self.write(rel, text)
        if not self.use_llm:
            errs = self.validate_step(step)
            self.step_state[step] = {"source": "heuristic", "errors": errs}
            return errs
        current = {rel: self.read(rel) for rel in draft_files}
        errs = []
        for i in range(attempts):
            res = self.run_llm(step, current, feedback)
            if not res.ok:
                errs = ["LLM call failed: %s" % res.reason]
                feedback = None
                continue
            for rel, text in res.files.items():
                self.write(rel, text)
            errs = self.validate_step(step)
            if not errs:
                self.step_state[step] = {"source": "llm", "errors": [], "notes": res.notes, "attempts": i + 1}
                return []
            feedback = "Mechanical validation errors:\n- " + "\n- ".join(errs)
            current = {rel: self.read(rel) for rel in draft_files}
        # fall back to the heuristic draft if it validates
        backup = {rel: self.read(rel) for rel in draft_files}
        for rel, text in draft_files.items():
            self.write(rel, text)
        derrs = self.validate_step(step)
        if not derrs:
            self.step_state[step] = {"source": "draft-fallback", "errors": errs}
            return []
        for rel, text in backup.items():
            self.write(rel, text)
        self.validate_step(step)
        self.step_state[step] = {"source": "llm-invalid", "errors": errs}
        return errs

    # ----------------------------------------------------------------------------------------- 4-6
    def step4_columns(self, feedback=None):
        draft = drafts.dump_yaml(drafts.columns_draft(self.schema, self.doc),
                                 "# Column classification for the shadow data (contracts/product.md section 4).\n")
        errs = self.llm_step("columns", {COLS: draft}, feedback)
        self.say(4, "columns.yaml: %s" % self._state_line("columns", errs))
        return not errs

    def profile_drafts(self):
        cols = yaml.safe_load(self.read(COLS) or "{}") or {}
        auth = drafts.auth_draft(self.project, self.det, self.schema, cols, self.doc)
        prof = drafts.profile_draft(self.project, self.det, self.schema, cols, auth, self.doc, self.static_dirs())
        return {PROF: prof, AUTH: drafts.dump_yaml(auth, "# How the gateway identifies clients on prod.\n")}

    def step5_profile(self, feedback=None):
        errs = self.llm_step("profile", self.profile_drafts(), feedback)
        a = (yaml.safe_load(self.read(AUTH) or "{}") or {}).get("auth") or {}
        self.say(5, "profile.py + auth (%s): %s" % (a.get("kind"), self._state_line("profile", errs)))
        return not errs

    def step6_marks(self, feedback=None):
        cols = yaml.safe_load(self.read(COLS) or "{}") or {}
        draft = drafts.dump_yaml(drafts.marks_draft(self.doc, cols),
                                 "# x-owner-scoped / x-sensitive marks applied to .immune/openapi.yaml\n")
        errs = self.llm_step("marks", {MARKS: draft}, feedback)
        marks = yaml.safe_load(self.read(MARKS) or "{}") or {}
        if not oa.validate_marks(marks, self.doc):
            oa.write(oa.apply_marks(self.doc, marks), self.path(".immune/openapi.yaml"))
        self.say(6, "openapi marks: %d owner-scoped ops, %d sensitive fields: %s" % (
            len(marks.get("owner_scoped") or []), len(marks.get("sensitive") or []), self._state_line("marks", errs)))
        return not errs

    def _state_line(self, step, errs):
        st = self.step_state.get(step, {})
        src = st.get("source", "?")
        if errs:
            return "INVALID (%s): %s" % (src, "; ".join(errs[:3]))
        return "valid (%s%s)" % (src, ", %d attempt(s)" % st["attempts"] if st.get("attempts") else "")

    def step7_shadow(self):
        try:
            self.cfg = _cfg.load(self.project)
            rep = shadowdata.build(self.cfg, seed=self.seed)
        except Exception as e:  # noqa: BLE001
            self.say(7, "shadow data: FAILED: %s" % str(e).replace("\n", " ")[:400])
            return False, str(e)
        self.shadow_report = rep
        self.say(7, "shadow data: %d users, canaries %s, %d with known passwords; leak self-check clean" % (
            rep["users"], {k: v for k, v in (json.load(open(rep["manifest"]))["canaries"]).items()},
            rep["legit_with_password"]))
        self.write_scenarios()
        return True, ""

    def write_scenarios(self):
        """Deterministic legit journeys (.immune/scenarios.py) from the OpenAPI + columns + manifest; sets
        `scenarios:` in config.yaml so the legit gate has coverage of the GET routes (doctor check 8)."""
        cols = yaml.safe_load(self.read(COLS) or "{}") or {}
        doc = yaml.safe_load(self.read(".immune/openapi.yaml") or "{}") or self.doc or {}
        plan = scen.write(self.project, doc, cols, self.cfg.shadow.profile, self.det.get("name") or "app")
        self.scenarios_plan = plan
        raw = yaml.safe_load(self.read(".immune/config.yaml") or "{}") or {}
        if plan["ops"]:
            raw["scenarios"] = scen.MODULE
        else:
            raw.pop("scenarios", None)
        self.write(".immune/config.yaml", "# Generated by `immune init` - review, then commit (contracts/product.md "
                   "section 2).\n" + yaml.safe_dump(raw, sort_keys=False, width=120))
        self.cfg = _cfg.load(self.project)
        self.out("        scenarios: %d GET route(s) covered, %d not (%s)" % (
            len(plan["ops"]), len(plan["uncovered"]), "; ".join("%s: %s" % (u["op"], u["why"]) for u in plan["uncovered"][:3])
            or "-"))

    # ----------------------------------------------------------------------------------------- 8
    def step8_doctor(self):
        rounds = 0
        tests_check = None
        while True:
            only = [1, 2, 3, 4, 5, 6, 8] + ([7] if tests_check is None else [])
            results = doctor.run(self.project, only)
            if tests_check is None:
                tests_check = next((c for c in results if c["id"] == 7), None)
            results = [c for c in results if c["id"] != 7] + ([tests_check] if tests_check else [])
            results.sort(key=lambda c: c["id"])
            self.doctor_results = results
            failing = [c for c in results if not c["ok"]]
            self.say(8, "doctor round %d: %d/%d checks pass%s" % (
                rounds + 1, len(results) - len(failing), len(results),
                ("; failing: " + ", ".join("%d(%s)" % (c["id"], c["owner"]) for c in failing)) if failing else ""))
            for c in results:
                self.out("        " + doctor.format_line(c).strip())
            fixable = {}
            for c in failing:
                if c["owner"] in ("columns", "profile", "marks"):
                    fixable.setdefault(c["owner"], []).append(c)
            if not failing or not fixable or not self.use_llm or rounds >= MAX_ROUNDS:
                return
            rounds += 1
            for owner, checks in fixable.items():
                fb = feedback_text(checks)
                if owner == "columns":
                    self.step4_columns(feedback=fb)
                elif owner == "profile":
                    self.step5_profile(feedback=fb)
                else:
                    self.step6_marks(feedback=fb)
            ok, err = self.step7_shadow()
            if not ok:
                self.attention.append("shadow data could not be rebuilt: %s" % err[:200])
                return

    # ----------------------------------------------------------------------------------------- 9/10
    def step9_deploy(self):
        self.cfg = _cfg.load(self.project)
        with open(self.path(".immune/shadow/detect.yaml"), "w") as f:
            yaml.safe_dump({k: v for k, v in self.det.items() if k != "env"}, f, sort_keys=False)
        self.deploy = deploycmd.generate(self.cfg, self.det)
        report.write(self)
        self.say(9, "deploy (%s): %s; report: .immune/report.md" % (
            self.deploy["style"], ", ".join(os.path.relpath(p, self.project) for p in self.deploy["files"])))

    def run(self) -> int:
        ok = self.step1_detect() and self.step2_openapi() and self.step3_database()
        if ok:
            self.write_config()
            ok4 = self.step4_columns()
            if ok4:
                if self.use_llm:
                    with ThreadPoolExecutor(2) as ex:
                        f5 = ex.submit(self.step5_profile)
                        f6 = ex.submit(self.step6_marks)
                        ok5, ok6 = f5.result(), f6.result()
                else:
                    ok5, ok6 = self.step5_profile(), self.step6_marks()
                built, err = self.step7_shadow()
                if built:
                    self.step8_doctor()
                else:
                    self.attention.append("shadow data not built: %s" % err[:300])
            for step in ("columns", "profile", "marks"):
                st = self.step_state.get(step) or {}
                if st.get("errors") and st.get("source") != "draft-fallback":
                    self.attention.append("%s: %s" % (step, "; ".join(st["errors"][:3])))
            for c in self.doctor_results:
                if not c["ok"]:
                    self.attention.append("doctor check %d (%s): %s" % (c["id"], c["name"], c["reason"][:300]))
            try:
                self.step9_deploy()
            except Exception as e:  # noqa: BLE001
                self.attention.append("deploy artefacts: %s" % e)
        secs = time.monotonic() - self.t0
        self.out("init: %.0fs, %d LLM call(s) (%.0fs)" % (secs, len(self.llm_calls),
                                                        sum(c["seconds"] for c in self.llm_calls)))
        if self.attention or not ok:
            self.out("NEEDS ATTENTION:")
            for a in self.attention or ["init did not complete"]:
                self.out("  - %s" % a)
            return 1
        self.out("READY: %s" % self.deploy.get("ready_command"))
        return 0


def feedback_text(checks) -> str:
    out = []
    for c in checks:
        out.append("check %d (%s) FAILED: %s" % (c["id"], c["name"], c["reason"]))
        if c.get("detail"):
            out.append(json.dumps(c["detail"], default=str)[:3000])
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="immune init", description=__doc__.split("\n")[0])
    ap.add_argument("--project", default=".")
    ap.add_argument("--yes", action="store_true", help="non-interactive; overwrite an existing .immune/")
    ap.add_argument("--no-llm", action="store_true", help="heuristics only; TODOs are left in the report")
    ap.add_argument("--prod-db", default=None, help="production SQLite file (default: detected)")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args(argv)
    project = os.path.realpath(a.project)
    if not os.path.isdir(project):
        print("NEEDS ATTENTION:\n  - %s is not a directory" % project)
        return 1
    if os.path.exists(os.path.join(project, ".immune", "config.yaml")) and not a.yes:
        if not sys.stdin.isatty() or input("%s/.immune exists; overwrite? [y/N] " % project).strip().lower() != "y":
            print("NEEDS ATTENTION:\n  - %s/.immune/config.yaml exists (use --yes to regenerate)" % shlex.quote(project))
            return 1
    return Init(project, use_llm=not a.no_llm, prod_db=a.prod_db, seed=a.seed).run()


if __name__ == "__main__":
    sys.exit(main())
