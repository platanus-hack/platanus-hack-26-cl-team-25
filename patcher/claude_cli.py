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

Environment (`child_env`): the CLI does not inherit the caller's environment. It gets an allowlist (PATH, HOME,
locale, temp dir, proxy settings and the ANTHROPIC_* / CLAUDE_* provider settings), so the stack secrets the
pipeline holds (ADMIN_TOKEN, BUS_TOKEN, app secrets, GH_TOKEN, ...) never reach the model's process.

Identity: PATCHER_CLAUDE_CONFIG_DIR points the CLI at its own config/login directory (CLAUDE_CONFIG_DIR), and
PATCHER_ANTHROPIC_API_KEY gives it its own API key, so the patcher need not run on the operator's Claude session.
`identity()` says which one is in use; `immune doctor` reports it.
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
    # permission rules: "//abs/path" is an absolute filesystem path
    return "/" + os.path.realpath(p)


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


ENV_ALLOW = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TERM",
             "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
             "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
             "XDG_DATA_HOME", "XDG_RUNTIME_DIR"}
ENV_ALLOW_PREFIXES = ("ANTHROPIC_", "CLAUDE_", "AWS_", "GOOGLE_", "CLOUD_ML_", "VERTEX_")
# provider settings that are still stack-owned secrets, never forwarded
ENV_DENY = {"CLAUDE_BIN"}


def child_env(base: dict | None = None) -> dict:
    """Environment of the CLI process: an allowlist of `base` (default os.environ), plus the patcher identity."""
    base = dict(os.environ if base is None else base)
    env = {k: v for k, v in base.items()
           if k not in ENV_DENY and (k in ENV_ALLOW or k.startswith(ENV_ALLOW_PREFIXES))
           and not k.startswith("PATCHER_")}
    cfg_dir = base.get("PATCHER_CLAUDE_CONFIG_DIR")
    if cfg_dir:
        env["CLAUDE_CONFIG_DIR"] = cfg_dir
    key = base.get("PATCHER_ANTHROPIC_API_KEY")
    if key:
        env["ANTHROPIC_API_KEY"] = key
        env.pop("ANTHROPIC_AUTH_TOKEN", None)
    return env


def identity(base: dict | None = None) -> str:
    """Which credentials the patcher's CLI runs with (for `immune doctor`); never prints a secret."""
    base = dict(os.environ if base is None else base)
    if base.get("PATCHER_ANTHROPIC_API_KEY"):
        return "own API key (PATCHER_ANTHROPIC_API_KEY)"
    if base.get("PATCHER_CLAUDE_CONFIG_DIR"):
        return "own Claude login (PATCHER_CLAUDE_CONFIG_DIR=%s)" % base["PATCHER_CLAUDE_CONFIG_DIR"]
    if base.get("ANTHROPIC_API_KEY") or base.get("ANTHROPIC_AUTH_TOKEN"):
        return "operator's API credentials from the environment (set PATCHER_ANTHROPIC_API_KEY to separate them)"
    return ("operator's Claude Code login on this machine (set PATCHER_CLAUDE_CONFIG_DIR or "
            "PATCHER_ANTHROPIC_API_KEY to give the patcher its own)")


def _redact(s: str) -> str:
    for var in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "PATCHER_ANTHROPIC_API_KEY"):
        v = os.environ.get(var)
        if v:
            s = s.replace(v, f"<{var}>")
    return s


def run(prompt: str, workdir: str, editable: list[str], timeout: float | None = None,
        model_name: str | None = None) -> CliResult:
    """Run the CLI with cwd=workdir, prompt on stdin. Never raises for CLI problems."""
    timeout = timeout_s() if timeout is None else timeout
    cmd = command(workdir, editable, model_name)
    env = child_env()  # allowlist: ANTHROPIC_BASE_URL etc. pass, stack secrets do not
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
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
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
