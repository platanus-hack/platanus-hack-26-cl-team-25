from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

import yaml

from patcher import claude_cli

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RUNTIME = os.environ.get("RUNTIME_DIR") or os.path.join(ROOT, "runtime")
CACHE = os.path.join(RUNTIME, "anticipate", "cache")
CLASS_TEXT = {
    "traversal": "path traversal — an input that, after decoding and normalization, still refers to a parent "
                 "directory or otherwise escapes the directory it should stay in",
    "sqli": "SQL injection — input that changes the structure of a query",
    "injection": "command or code injection — input that reaches an interpreter as code",
}


# ---------------------------------------------------------------- target + source
def load_target(path_or_id: str) -> dict:
    p = path_or_id
    if not os.path.exists(p):
        p = os.path.join(HERE, "targets", path_or_id, "target.yaml")
    with open(p) as f:
        t = yaml.safe_load(f)
    t["_dir"] = os.path.dirname(os.path.abspath(p))
    return t


def _git(repo: str, *args: str, check=True) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    r = subprocess.run(["git", "-C", repo, "-c", "core.hooksPath=/dev/null", *args], capture_output=True,
                       text=True, env=env, timeout=600)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])}: {r.stderr.strip()[-300:]}")
    return r.stdout


def fetch(target: dict) -> str:
    """Shallow-fetch both refs into a cached repo. Returns the repo path."""
    repo = os.path.join(CACHE, target["id"])
    if not os.path.isdir(os.path.join(repo, ".git")):
        os.makedirs(repo, exist_ok=True)
        _git(repo, "init", "-q")
        _git(repo, "remote", "add", "origin", target["repo"])
    have = set(_git(repo, "tag").split())
    want = [r for r in (target["vulnerable_ref"], target["fixed_ref"]) if r not in have]
    if want:
        args = ["fetch", "-q", "--depth", "1", "origin"]
        for r in want:
            args += ["tag", r]
        _git(repo, *args)
    return repo


def show(repo: str, ref: str, path: str) -> str:
    return _git(repo, "show", f"{ref}:{path}")


def official_diff(repo: str, target: dict) -> str:
    return _git(repo, "diff", target["vulnerable_ref"], target["fixed_ref"], "--", *target["scope"])


# ---------------------------------------------------------------- LLM review in a confined copy
@dataclass
class Review:
    ok: bool
    diff: str = ""
    findings: list = field(default_factory=list)
    notes: str = ""
    seconds: float = 0.0
    model: str = ""
    denials: list = field(default_factory=list)


def _workspace(repo: str, target: dict) -> tuple[str, str]:
    tmp = tempfile.mkdtemp(prefix="anticipate-")
    work = os.path.join(tmp, "work")
    for rel in target["scope"] + target.get("context", []):
        dst = os.path.join(work, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w") as f:
            f.write(show(repo, target["vulnerable_ref"], rel))
    gitdir = os.path.join(tmp, "git")
    for args in (["init", "-q", "--template="], ["add", "-A"], ["commit", "-q", "-m", "baseline"]):
        _wgit(work, gitdir, *args)
    return tmp, work


def _wgit(work: str, gitdir: str, *args: str) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    r = subprocess.run(["git", "--git-dir", gitdir, "--work-tree", work, "-c", "user.name=a", "-c", "user.email=a@l",
                        "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                       cwd=work, capture_output=True, text=True, env=env, check=True)
    return r.stdout


def render_prompt(target: dict) -> str:
    with open(os.path.join(HERE, "prompts", "audit.md")) as f:
        tpl = f.read()
    bullets = lambda xs: "\n".join(f"- `{x}`" for x in xs) or "- (none)"
    return tpl.format(name=target["name"], area=target["area"].strip(), scope=bullets(target["scope"]),
                      context=bullets(target.get("context", [])),
                      vuln_class_text=CLASS_TEXT.get(target["vuln_class"], target["vuln_class"]))


def parse_findings(text: str) -> list:
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", text, flags=re.S)
    for b in reversed(blocks):
        try:
            data = json.loads(b)
            if isinstance(data.get("findings"), list):
                return data["findings"]
        except ValueError:
            continue
    return []


def review(repo: str, target: dict, model: str | None = None, timeout: float | None = None) -> Review:
    tmp, work = _workspace(repo, target)
    try:
        model = model or os.environ.get("ANTICIPATE_MODEL") or "opus"
        res = claude_cli.run(render_prompt(target), work, list(target["scope"]),
                             timeout=timeout or float(os.environ.get("ANTICIPATE_TIMEOUT_S", "900")), model_name=model)
        diff = _wgit(work, os.path.join(tmp, "git"), "diff", "--no-color")
        patched = {rel: open(os.path.join(work, rel)).read() for rel in target["scope"]}
        r = Review(ok=res.ok, diff=diff, findings=parse_findings(res.text), notes=res.text if res.ok else res.reason,
                   seconds=res.seconds, model=model, denials=res.denials)
        r.patched = patched  # type: ignore[attr-defined]
        return r
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- mechanical check (C function unit test)
def extract_function(source: str, signature: str) -> str | None:
    """Return the full definition that starts with `signature` (brace-matched, comments/strings skipped)."""
    i = source.find(signature + "\n{")
    if i < 0:
        m = re.search(re.escape(signature) + r"\s*\{", source)
        if not m:
            return None
        i = m.start()
    j = source.index("{", i)
    depth, k, n = 0, j, len(source)
    while k < n:
        c = source[k]
        if source.startswith("/*", k):
            k = source.find("*/", k + 2)
            if k < 0:
                return None
            k += 2
            continue
        if source.startswith("//", k):
            k = source.find("\n", k)
            continue
        if c in "\"'":
            k += 1
            while k < n and source[k] != c:
                k += 2 if source[k] == "\\" else 1
            k += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[i:k + 1]
        k += 1
    return None


HARNESS_MAIN = r'''
static void esc(const char *s) { putchar('"'); for (; *s; s++) { if (*s == '"' || *s == '\\') putchar('\\'); putchar(*s); } putchar('"'); }
int main(void) {
    static const char *in[] = { %(inputs)s };
    unsigned int flags = %(flags)s;
    char buf[1024];
    for (size_t i = 0; i < sizeof(in) / sizeof(in[0]); i++) {
        strncpy(buf, in[i], sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
        int ret = ap_normalize_path(buf, flags);
        printf("{\"i\":%%zu,\"ret\":%%d,\"out\":", i, ret); esc(buf); printf("}\n");
    }
    return 0;
}
'''


def _c_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def run_check(target: dict, file_text: str, label: str) -> dict:
    chk = target["check"]
    with open(os.path.join(target["_dir"], chk["vectors"])) as f:
        vec = yaml.safe_load(f)
    parts = []
    for sig in chk["functions"]:
        fn = extract_function(file_text, sig)
        if fn is None:
            return {"label": label, "compiled": False, "error": f"function not found: {sig}", "results": []}
        parts.append(fn)
    inputs = [v["in"] for v in vec["exact"]] + [v["in"] for v in vec["no_parent_segment"]]
    flags = " | ".join(f"AP_NORMALIZE_{x}" for x in vec["flags"]) or "0"
    with open(os.path.join(target["_dir"], chk["shim"])) as f:
        shim = f.read()
    src = shim + "\n\n" + "\n\n".join(parts) + HARNESS_MAIN % {"inputs": ", ".join(map(_c_str, inputs)), "flags": flags}
    job = tempfile.mkdtemp(prefix="anticipate-job-")
    try:
        with open(os.path.join(job, "t.c"), "w") as f:
            f.write(src)
        os.chmod(job, 0o755)
        cmd = ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp:exec", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--pids-limit", "64", "--memory", "256m", "--cpus", "1",
               "--label", "immune.component=anticipate", "-v", f"{job}:/job:ro", "immune-cbuild:1", "sh", "-c",
               "gcc -std=c11 -O1 -w -o /tmp/t /job/t.c 2>&1 && timeout 10 /tmp/t"]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    finally:
        shutil.rmtree(job, ignore_errors=True)
    rows = []
    for line in r.stdout.splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    if r.returncode != 0 or len(rows) != len(inputs):
        return {"label": label, "compiled": False, "error": (r.stdout + r.stderr)[-1500:], "results": []}
    results = []
    ne = len(vec["exact"])
    for row in rows:
        i = row["i"]
        if i < ne:
            want = vec["exact"][i]
            ok = row["ret"] == want["ret"] and row["out"] == want["out"]
            results.append({"kind": "legit", "in": want["in"], "ret": row["ret"], "out": row["out"],
                            "expect": f"ret={want['ret']} {want['out']}", "ok": ok})
        else:
            segs = re.sub(r"%2e", ".", row["out"], flags=re.I).split("/")
            v = vec["no_parent_segment"][i - ne]
            above = bool(v.get("above_root"))
            ok = ".." not in segs and (row["ret"] == 0 if above else True)
            results.append({"kind": "dot-segment", "in": v["in"], "ret": row["ret"], "out": row["out"],
                            "expect": "rejected (ret=0), no parent segment" if above else "no parent segment left",
                            "ok": ok})
    return {"label": label, "compiled": True, "results": results,
            "passed": sum(x["ok"] for x in results), "total": len(results)}


def equivalence(a: dict, b: dict) -> dict:
    if not (a.get("compiled") and b.get("compiled")):
        return {"comparable": False}
    same = [x["in"] for x, y in zip(a["results"], b["results"]) if (x["ret"], x["out"]) == (y["ret"], y["out"])]
    return {"comparable": True, "same": len(same), "total": len(a["results"]),
            "differ": [x["in"] for x, y in zip(a["results"], b["results"]) if (x["ret"], x["out"]) != (y["ret"], y["out"])]}


# ---------------------------------------------------------------- diff localisation
def _fn_name(line: str) -> str | None:
    names = [n for n in re.findall(r"(\w+)\s*\(", line or "") if not n.isupper()]
    return names[-1] if names else None


def hunks(diff: str) -> list[dict]:
    out, file = [], None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            file = line[6:] if line.startswith("+++ b/") else line[4:]
        m = re.match(r"@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@ ?(.*)", line)
        if m and file:
            start, n = int(m.group(1)), int(m.group(2) or 1)
            out.append({"file": file, "start": start, "end": start + max(n, 1) - 1, "context": (m.group(3) or "").strip(),
                        "function": _fn_name(m.group(3))})
    return out


def enclosing_functions(source: str, hs: list[dict]) -> set:
    """Map changed line ranges (in the vulnerable file) to the C function definitions that contain them."""
    lines = source.splitlines()
    starts = [(i + 1, _fn_name(l)) for i, l in enumerate(lines)
              if re.match(r"^[A-Za-z_][\w\s\*\(\),]*\b\w+\s*\([^;]*$", l) and _fn_name(l)]
    fns = set()
    for h in hs:
        best = None
        for ln, name in starts:
            if ln <= h["start"]:
                best = name
        if best:
            fns.add((h["file"], best))
    return fns


def compare(repo: str, target: dict, ours: str, official: str) -> dict:
    vuln_src = {rel: show(repo, target["vulnerable_ref"], rel) for rel in target["scope"]}
    ho, hf = hunks(ours), hunks(official)
    fo = set().union(*[enclosing_functions(vuln_src[f], [h for h in ho if h["file"] == f]) for f in vuln_src])
    ff = set().union(*[enclosing_functions(vuln_src[f], [h for h in hf if h["file"] == f]) for f in vuln_src])
    overlap = any(a["file"] == b["file"] and a["start"] <= b["end"] and b["start"] <= a["end"] for a in ho for b in hf)
    return {"our_functions": sorted(f"{a}:{b}" for a, b in fo), "official_functions": sorted(f"{a}:{b}" for a, b in ff),
            "same_function": bool(fo & ff), "overlapping_lines": overlap,
            "our_changed_lines": sum(1 for l in ours.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))),
            "official_changed_lines": sum(1 for l in official.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---")))}


def apply_to_vulnerable(repo: str, target: dict, diff: str) -> dict[str, str]:
    """Apply a stored diff to the vulnerable files in a temp dir; return {path: patched text}."""
    tmp = tempfile.mkdtemp(prefix="anticipate-apply-")
    try:
        for rel in target["scope"]:
            dst = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w") as f:
                f.write(show(repo, target["vulnerable_ref"], rel))
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        r = subprocess.run(["git", "apply", "--unsafe-paths", "--directory=", "-"], cwd=tmp, input=diff, text=True,
                           capture_output=True, env={**env, "GIT_CEILING_DIRECTORIES": tmp})
        if r.returncode != 0:
            r = subprocess.run(["patch", "-p1", "--batch", "--silent"], cwd=tmp, input=diff, text=True, capture_output=True)
            if r.returncode != 0:
                raise RuntimeError("stored diff does not apply: " + (r.stdout + r.stderr)[-300:])
        return {rel: open(os.path.join(tmp, rel)).read() for rel in target["scope"]}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def recheck(result_dir: str, log=print) -> dict:
    """Re-run the mechanical checks and the comparison on a stored result, without calling the model."""
    with open(os.path.join(result_dir, "result.json")) as fh:
        result = json.load(fh)
    t = load_target(result["target"]["id"])
    repo = fetch(t)
    f = t["check"]["file"]
    diff = result["diffs"]["suggested"]
    base = run_check(t, show(repo, t["vulnerable_ref"], f), "vulnerable")
    ours = run_check(t, apply_to_vulnerable(repo, t, diff)[f], "suggested") if diff else result["checks"]["suggested"]
    offc = run_check(t, show(repo, t["fixed_ref"], f), "official")
    result["checks"] = {"vulnerable": base, "suggested": ours, "official": offc}
    result["equivalence"] = equivalence(ours, offc)
    result["localisation"] = compare(repo, t, diff, result["diffs"]["official"]) if diff else {}
    result["target"] = {k: v for k, v in t.items() if not k.startswith("_")}
    with open(os.path.join(result_dir, "result.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    from . import report
    report.write(result, result_dir)
    log(f"suggested: {ours.get('passed')}/{ours.get('total')}  official: {offc.get('passed')}/{offc.get('total')}  "
        f"vulnerable: {base.get('passed')}/{base.get('total')}")
    return result


# ---------------------------------------------------------------- full run
def run(target_ref: str, model: str | None = None, out_dir: str | None = None, log=print) -> dict:
    t = load_target(target_ref)
    t0 = time.time()
    log(f"[1/5] fetching {t['name']} source ({t['vulnerable_ref']} and {t['fixed_ref']})")
    repo = fetch(t)
    off = official_diff(repo, t)
    f = t["check"]["file"]
    log("[2/5] baseline check of the released code")
    base = run_check(t, show(repo, t["vulnerable_ref"], f), "vulnerable")
    log(f"      {t['vulnerable_ref']}: {base.get('passed')}/{base.get('total')} properties hold")
    log(f"[3/5] confined review by the model (not told which advisory) — this can take a few minutes")
    rv = review(repo, t, model=model)
    log(f"      model {rv.model}: {len(rv.findings)} finding(s), diff {len(rv.diff.splitlines())} lines, {rv.seconds:.0f}s")
    log("[4/5] checking the suggested patch and the official one")
    ours = run_check(t, rv.patched[f], "suggested") if rv.diff else {"label": "suggested", "compiled": False,
                                                                      "error": "no change proposed", "results": []}
    offc = run_check(t, show(repo, t["fixed_ref"], f), "official")
    log(f"      suggested: {ours.get('passed')}/{ours.get('total')}   official {t['fixed_ref']}: {offc.get('passed')}/{offc.get('total')}")
    cmp_ = compare(repo, t, rv.diff, off) if rv.diff else {}
    result = {"target": {k: v for k, v in t.items() if not k.startswith("_")}, "started": t0, "seconds": time.time() - t0,
              "review": {"ok": rv.ok, "model": rv.model, "seconds": rv.seconds, "findings": rv.findings,
                         "notes": rv.notes[-4000:], "denials": rv.denials},
              "diffs": {"suggested": rv.diff, "official": off},
              "checks": {"vulnerable": base, "suggested": ours, "official": offc},
              "equivalence": equivalence(ours, offc), "localisation": cmp_}
    out_dir = out_dir or os.path.join(RUNTIME, "anticipate", "reports", t["id"], time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    from . import report
    with open(os.path.join(out_dir, "result.json"), "w") as fh:
        json.dump(result, fh, indent=2)
    report.write(result, out_dir)
    log(f"[5/5] report: {out_dir}/report.html  ({out_dir}/report.md)")
    return result
