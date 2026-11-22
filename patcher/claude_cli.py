"""Headless Claude Code invocation, confined per call.

Confinement is passed on every invocation (nothing is written to ~/.claude):
  --tools Read,Edit          only the two file tools exist (no shell, web, agents, notebook)
  --strict-mcp-config        no MCP servers (none passed with --mcp-config)
  --disable-slash-commands   no skills / commands
  --restricted               file tools confined to the working directory; user/project/local
                             settings ignored (so no user allow-rules, hooks or plugins leak in)
  --permission-mode dontAsk  anything not pre-allowed is denied
  --permission-prompts none  nobody can approve anything at runtime
  --settings <json>          allow: Read(<work>/**), Edit(<each editable file>) only (none if the
                             list is empty); deny: Edit of tests dirs, Write; disableAllHooks
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass, field

DEFAULT_MODEL = "sonnet"
DEFAULT_TIMEOUT_S = 180.0


def claude_bin() -> str:
    explicit = os.environ.get("CLAUDE_BIN")
    if explicit:
        return explicit
    execpath = os.environ.get("CLAUDE_CODE_EXECPATH")
    if execpath and os.path.isfile(execpath) and os.access(execpath, os.X_OK):
        return execpath
    return shutil.which("claude") or "claude"


def model() -> str:
    return os.environ.get("PATCHER_MODEL") or DEFAULT_MODEL


def timeout_s() -> float:
    try:
        return float(os.environ.get("PATCHER_TIMEOUT_S") or DEFAULT_TIMEOUT_S)
    except ValueError:
        return DEFAULT_TIMEOUT_S


def _rule_path(p: str) -> str:
    # permission rules: "//abs/path" is an absolute filesystem path; forward
    # slashes keep the rules identical across hosts.
    return "/" + os.path.realpath(p).replace(os.sep, "/")


def settings_for(workdir: str, editable: list[str], deny_dirs: list[str] | None = None) -> dict:
    """Per-invocation settings. `editable` are paths relative to workdir; `deny_dirs` (relative dirs)
    are never editable (default: every `tests` dir at the top two levels of workdir)."""
    edit_allow = [f"Edit({_rule_path(os.path.join(workdir, e))})" for e in editable]
    if deny_dirs is None:
        deny_dirs = _test_dirs(workdir)
    return {
        "permissions": {
            "allow": [f"Read({_rule_path(workdir)}/**)", *edit_allow],
            "deny": [*(f"Edit({_rule_path(os.path.join(workdir, d))}/**)" for d in deny_dirs),
                     f"Write({_rule_path(workdir)}/**)"],
            "defaultMode": "dontAsk",
        },
        "disableAllHooks": True,
    }


def _test_dirs(workdir: str) -> list[str]:
    out = []
    try:
        for a in sorted(os.listdir(workdir)):
            pa = os.path.join(workdir, a)
            if a == "tests" and os.path.isdir(pa):
                out.append(a)
            elif os.path.isdir(pa) and not os.path.islink(pa):
                for b in sorted(os.listdir(pa)):
                    if b == "tests" and os.path.isdir(os.path.join(pa, b)):
                        out.append(a + "/" + b)
    except OSError:
        pass
    return out


def command(workdir: str, editable: list[str], model_name: str | None = None) -> list[str]:
    return [
        claude_bin(), "-p",
        "--model", model_name or model(),
        "--tools", "Read,Edit",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--restricted",
        "--permission-mode", "dontAsk",
        "--permission-prompts", "none",
        "--no-session-persistence",
        "--output-format", "json",
        "--settings", json.dumps(settings_for(workdir, editable), separators=(",", ":")),
    ]


@dataclass
class CliResult:
    ok: bool
    reason: str = ""
    text: str = ""
    seconds: float = 0.0
    returncode: int | None = None
    denials: list = field(default_factory=list)
    turns: int | None = None


def _redact(s: str) -> str:
    for var in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        v = os.environ.get(var)
        if v:
            s = s.replace(v, f"<{var}>")
    return s


def run(prompt: str, workdir: str, editable: list[str], timeout: float | None = None,
        model_name: str | None = None) -> CliResult:
    """Run the CLI with cwd=workdir, prompt on stdin. Never raises for CLI problems."""
    timeout = timeout_s() if timeout is None else timeout
    cmd = command(workdir, editable, model_name)
    env = dict(os.environ)  # ANTHROPIC_BASE_URL etc. pass through unchanged
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(cmd, cwd=workdir, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)
    except OSError as e:
        return CliResult(False, f"cannot start CLI: {e.__class__.__name__}: {e.strerror or e}")
    try:
        out, err = proc.communicate(prompt, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            # POSIX uses the process group; Windows has no killpg.
            if hasattr(os, "killpg"):
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass
        proc.communicate()
        return CliResult(False, f"timeout after {timeout:.0f}s", seconds=time.monotonic() - t0)
    secs = time.monotonic() - t0
    data = None
    for line in reversed((out or "").strip().splitlines()):
        try:
            data = json.loads(line)
            break
        except ValueError:
            continue
    if proc.returncode != 0 or not isinstance(data, dict):
        tail = _redact(((err or "") + (out or ""))[-400:].strip())
        return CliResult(False, f"CLI exit {proc.returncode}: {tail}", seconds=secs, returncode=proc.returncode)
    text = _redact(str(data.get("result") or ""))
    denials = [{"tool": d.get("tool_name"), "input": {k: str(v)[:200] for k, v in (d.get("tool_input") or {}).items()
                                                      if k in ("file_path", "path")}}
               for d in data.get("permission_denials") or []]
    if data.get("is_error"):
        return CliResult(False, f"CLI error ({data.get('subtype')}): {text[:300]}", text=text, seconds=secs,
                         returncode=proc.returncode, denials=denials, turns=data.get("num_turns"))
    return CliResult(True, "", text=text, seconds=secs, returncode=proc.returncode, denials=denials,
                     turns=data.get("num_turns"))
