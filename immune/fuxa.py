"""Passive monitoring and bounded authorization repairs for the FUXA demo."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

TAG = "v1.2.9"
COMMIT = "19c2471833e410eea235b81857ddcfde7b3851a0"
UPSTREAM = "https://github.com/frangoteam/FUXA.git"
ASSETS = Path(__file__).with_name("fuxa_runtime")
DEFAULT_RUNTIME = Path(__file__).resolve().parents[1] / "runtime" / "fuxa"
HTTP = re.compile(r"""(?:\b(?:\w*App|router))\.(get|post|put|patch|delete)\(\s*(['"])(/api/[^'"]*)\2""", re.I)
SOCKET = re.compile(r"""\bsocket\.on\(\s*(?:Events\.IoEventTypes\.(\w+)|['"]([\w:-]+)['"])""")
ACCESS = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "([A-Z]+) (\S+) HTTP/[\d.]+" (\d{3}) ')
DEV = re.compile(r"^([A-Z]+) (\S+) (\d{3})(?:\s|$)")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
OPERATIONS = {
    "settings.write": {
        "transport": "http", "method": "POST", "route": "/api/settings",
        "file": "server/api/index.js", "effect": "write-settings", "role": "admin",
        "anchor": "fs.writeFileSync(runtime.settings.userSettingsFile,",
    },
    "system-function.run": {
        "transport": "http", "method": "POST", "route": "/api/runSysFunction",
        "file": "server/api/scripts/index.js", "effect": "dispatch-system-function", "role": "admin",
        "anchor": "const result = await runtime.scriptsMgr.runSysFunction(",
    },
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True, encoding="utf-8", timeout=120).strip()


def write_json(path: Path, value) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def baseline(root: Path, repo: Path | None = None) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    if repo is None:
        repo = root / "upstream"
        if not repo.is_dir():
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", TAG, "--no-checkout", UPSTREAM, str(repo)],
                check=True, timeout=180,
            )
    if git(repo, "rev-parse", f"refs/tags/{TAG}^{{commit}}") != COMMIT:
        raise ValueError(f"La etiqueta {TAG} no coincide con el SHA fijado")
    source = root / "source"
    with tempfile.TemporaryDirectory(dir=root) as staging:
        archive = Path(staging) / "source.zip"
        extracted = Path(staging) / "source"
        git(repo, "archive", "--format=zip", f"--output={archive}", COMMIT, "server", "client/dist")
        with zipfile.ZipFile(archive) as package:
            package.extractall(extracted)
        profile = inventory(extracted)
        if not source.exists():
            extracted.replace(source)
        elif fingerprint(source) != fingerprint(extracted):
            raise ValueError("La copia local del código fijado fue modificada")
    write_json(root / "profile.json", profile)
    return profile


def inventory(source: Path) -> dict:
    version = json.loads((source / "server/package.json").read_text(encoding="utf-8"))["version"]
    if version != "1.2.9-2654":
        raise ValueError(f"Versión interna inesperada: {version}")
    operations = []
    for path in sorted((source / "server").rglob("*.js")):
        relative = path.relative_to(source)
        if relative.parts[1] in {"dist", "test"}:
            continue
        code = path.read_text(encoding="utf-8")
        for match in HTTP.finditer(code):
            method, route = match[1].upper(), match[3]
            operation = next((
                name for name, policy in OPERATIONS.items()
                if (policy["method"], policy["route"], policy["file"]) == (method, route, relative.as_posix())
            ), None)
            operations.append({
                "transport": "http", "method": method, "route": route, "file": relative.as_posix(),
                "line": code.count("\n", 0, match.start()) + 1, "coverage": operation or "pending",
            })
        for match in SOCKET.finditer(code):
            operations.append({
                "transport": "socket.io", "event": match[1] or match[2], "file": relative.as_posix(),
                "line": code.count("\n", 0, match.start()) + 1, "coverage": "pending",
            })
    policies = {}
    for name, policy in OPERATIONS.items():
        code = (source / policy["file"]).read_text(encoding="utf-8")
        if code.count(policy["anchor"]) != 1 or not any(row["coverage"] == name for row in operations):
            raise ValueError(f"No se encontró el punto de instrumentación de {name}")
        policies[name] = {
            **{key: value for key, value in policy.items() if key != "anchor"},
            "effect_line": code.count("\n", 0, code.index(policy["anchor"])) + 1,
            "expected": {"admin": "allow", "member": "deny", "anonymous": "deny", "unknown": "indeterminate"},
        }
    return {
        "schema": 1, "tag": TAG, "commit": COMMIT, "version": version, "operations": operations,
        "policies": policies, "smoke": ["/api/version", "/"], "source_digest": fingerprint(source),
        "inventory_limits": "Registros estáticos reconocibles. Socket.IO está inventariado, sin vigilancia activa.",
    }


def fingerprint(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest.update(path.relative_to(directory).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def instrument(source: Path, release: Path, enforced: set[str]) -> list[Path]:
    outputs = []
    for file in sorted({operation["file"] for operation in OPERATIONS.values()}):
        code = (source / file).read_text(encoding="utf-8")
        code = 'const immuneMonitor = require("/immune/observe.cjs");\n' + code
        for name, policy in OPERATIONS.items():
            if policy["file"] != file:
                continue
            route = re.compile(r'\.post\(\s*([\'"])' + re.escape(policy["route"]) + r'\1,')
            registration, = route.finditer(code)
            start = registration.end()
            code = code[:start] + f' immuneMonitor.http("{name}"),' + code[start:]
            anchor = re.compile(r"(?m)^([ \t]*)" + re.escape(policy["anchor"]))
            match, = anchor.finditer(code)
            mode = "enforce" if name in enforced else "observe"
            guard = (
                f'{match[1]}if (!immuneMonitor.authorize("{name}", "{mode}", req, runtime)) '
                'return res.status(403).end();\n'
            )
            code = code[:match.start()] + guard + code[match.start():]
        output = release / file
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(code, encoding="utf-8", newline="\n")
        outputs.append(output)
    return outputs


def assess(event: dict, revision: str) -> str | None:
    if revision is None or not isinstance(event, dict) or event.get("revision") != revision:
        return None
    operation = event.get("operation")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        return None
    correlation = event.get("id")
    if not isinstance(correlation, str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", correlation):
        return None
    role = event.get("role")
    if event.get("type") == "effect" and event.get("boundary") == OPERATIONS[operation]["effect"]:
        if event.get("decision") == "observed" and role in ("member", "anonymous"):
            return "incident"
        if role == "unknown":
            return "insufficient"
    if event.get("type") == "http" and event.get("status") in (401, 403):
        return "alert"
    return None


def access_report(path: Path, profile: dict) -> dict:
    routes = {(row["method"], row["route"]): name for name, row in profile["policies"].items()}
    counts = {"read": 0, "recognized": 0, "discarded": 0}
    alerts = []
    with path.open(encoding="utf-8", errors="replace") as records:
        for index, line in enumerate(records, 1):
            counts["read"] = index
            line = ANSI.sub("", line)
            match = ACCESS.match(line) or DEV.match(line)
            if not match:
                counts["discarded"] += 1
                continue
            counts["recognized"] += 1
            method, url, status = match.groups()
            route = url.partition("?")[0]
            operation = routes.get((method, route))
            if operation and status in ("401", "403"):
                alerts.append({"operation": operation, "method": method, "route": route,
                               "status": int(status), "line": index})
    return {**counts, "alerts": alerts, "coverage": "http-errors-only" if counts["recognized"] else "insufficient"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="immune fuxa")
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("baseline")
    prepare.add_argument("--repo", type=Path)
    up = commands.add_parser("up")
    up.add_argument("--port", type=int, default=1881)
    watch = commands.add_parser("watch")
    watch.add_argument("--input", type=Path, help="Analyze an exported Morgan log and exit")
    dashboard = commands.add_parser("dashboard")
    dashboard.add_argument("--port", type=int, default=8091)
    for name in ("status", "down", "demo"):
        commands.add_parser(name)
    args = parser.parse_args(argv)
    root = args.runtime.resolve()
    try:
        if args.command == "baseline":
            profile = baseline(root, args.repo)
            result = {"profile": str(root / "profile.json"), "commit": profile["commit"],
                      "covered": len(profile["policies"]),
                      "pending": sum(row["coverage"] == "pending" for row in profile["operations"])}
        elif args.command == "watch" and args.input:
            result = access_report(args.input, json.loads((root / "profile.json").read_text(encoding="utf-8")))
        elif args.command == "dashboard":
            from .fuxa_dashboard import serve
            serve(root, args.port)
            return 0
        else:
            from fleet.fuxa import FuxaFleet
            fleet = FuxaFleet(root)
            if args.command == "watch":
                last = None
                while True:
                    last = fleet.watch(last)
                    time.sleep(2)
            elif args.command == "up":
                result = fleet.up(args.port)
            else:
                result = getattr(fleet, args.command)()
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"immune fuxa: {error}", file=sys.stderr)
        return 1
