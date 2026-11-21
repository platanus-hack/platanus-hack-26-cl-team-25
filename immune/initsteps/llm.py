"""The three LLM steps of `immune init`, run through the confined CLI of patcher/claude_cli.py.

Per call:
  1. the project is copied to /tmp/immune-init-XXXX/work (regular files only; no .git, virtualenvs, caches,
     databases, .env files, keys, or files > 512 KiB: the model never sees production data or secrets);
  2. context files (schema without values, OpenAPI summary, detection facts) go to work/.immune/context/,
     and the step's output files are pre-written there with the heuristic draft;
  3. `claude -p` runs with cwd=work, tools Read+Edit only, Read allowed under work, Edit allowed **only on the
     step's output files** (patcher.claude_cli: --restricted, dontAsk, no prompts, no MCP/hooks/skills);
  4. only the expected output files are read back; the caller validates them mechanically.
"""
from __future__ import annotations

import os
import secrets
import shutil
import tempfile
import time
from dataclasses import dataclass, field

from patcher import claude_cli

from .detect import SKIP_DIRS, SQLITE_MAGIC

PROMPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts")
MAX_FILE = 512 * 1024
SECRET_NAMES = (".env", ".pem", ".key", ".p12", ".pfx", ".crt", "id_rsa", "id_ed25519", ".netrc", ".pgpass")
DATA_EXT = (".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".db-journal", ".dump", ".bak")

STEPS = {
    "columns": {"prompt": "columns.md", "files": [".immune/shadow/columns.yaml"]},
    "profile": {"prompt": "profile.md", "files": [".immune/profile.py", ".immune/shadow/auth.yaml"]},
    "marks": {"prompt": "marks.md", "files": [".immune/shadow/marks.yaml"]},
}


@dataclass
class StepResult:
    step: str
    ok: bool
    files: dict = field(default_factory=dict)      # rel path -> text (only the expected files)
    changed: list = field(default_factory=list)
    reason: str = ""
    seconds: float = 0.0
    notes: str = ""
    denials: list = field(default_factory=list)


def model() -> str:
    return os.environ.get("IMMUNE_INIT_MODEL") or claude_cli.model()


def timeout_s() -> float:
    try:
        return float(os.environ.get("IMMUNE_INIT_TIMEOUT_S") or 420)
    except ValueError:
        return 420.0


def _skip_file(path: str, name: str) -> bool:
    low = name.lower()
    if low.startswith(".env") or low.endswith(SECRET_NAMES) or low.endswith(DATA_EXT) or low.endswith((".pyc", ".pyo")):
        return True
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > MAX_FILE:
            return True
        with open(path, "rb") as f:
            if f.read(16) == SQLITE_MAGIC:
                return True
    except OSError:
        return True
    return False


def copy_project(project: str, dst: str, exclude: tuple = ()) -> int:
    n = 0
    project = os.path.realpath(project)
    excl = {os.path.normpath(os.path.join(project, e)) for e in exclude}
    for dirpath, dirnames, filenames in os.walk(project):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")
                       and os.path.normpath(os.path.join(dirpath, d)) not in excl and not os.path.islink(os.path.join(dirpath, d))]
        rel = os.path.relpath(dirpath, project)
        for fn in filenames:
            src = os.path.join(dirpath, fn)
            if _skip_file(src, fn) or os.path.normpath(src) in excl:
                continue
            out = os.path.normpath(os.path.join(dst, rel, fn))
            os.makedirs(os.path.dirname(out), exist_ok=True)
            shutil.copyfile(src, out)
            n += 1
    return n


def prompt_text(name: str) -> str:
    with open(os.path.join(PROMPTS, name), encoding="utf-8") as f:
        return f.read()


def build_prompt(step: str, facts: str, feedback: str | None, nonce: str) -> str:
    parts = [prompt_text("common.md"), prompt_text(STEPS[step]["prompt"])]
    parts.append("## Facts detected mechanically\n\n<<<FACTS-%s\n%s\nFACTS-%s>>>\n" % (nonce, facts, nonce))
    if feedback:
        parts.append(prompt_text("feedback.md").replace("{nonce}", nonce).replace("{feedback}", feedback))
    parts.append("Output files you must leave complete and valid (edit them in place): %s\n"
                 % ", ".join(STEPS[step]["files"]))
    return "\n\n".join(parts)


def run_step(step: str, project: str, context: dict, drafts: dict, facts: str, feedback: str | None = None,
             runner=None) -> StepResult:
    """context/drafts: {rel path under the work dir: text}. ``runner`` replaces claude_cli.run in tests."""
    spec = STEPS[step]
    base = tempfile.mkdtemp(prefix="immune-init-")
    work = os.path.join(base, "work")
    os.makedirs(work)
    t0 = time.monotonic()
    try:
        copy_project(project, work, exclude=(".immune",))
        for rel, text in list(context.items()) + list(drafts.items()):
            p = os.path.join(work, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
        nonce = secrets.token_hex(6)
        prompt = build_prompt(step, facts, feedback, nonce)
        run = runner or (lambda pr, wd, ed: claude_cli.run(pr, wd, ed, timeout=timeout_s(), model_name=model()))
        res = run(prompt, work, list(spec["files"]))
        files, changed = {}, []
        for rel in spec["files"]:
            p = os.path.join(work, rel)
            if os.path.isfile(p) and not os.path.islink(p):
                with open(p, encoding="utf-8", errors="replace") as f:
                    files[rel] = f.read()
                if files[rel] != drafts.get(rel):
                    changed.append(rel)
        return StepResult(step, bool(res.ok), files, changed, "" if res.ok else res.reason,
                          time.monotonic() - t0, notes=(res.text or "")[:2000], denials=list(res.denials or []))
    finally:
        shutil.rmtree(base, ignore_errors=True)
