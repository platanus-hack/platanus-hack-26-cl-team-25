"""Passive monitoring and bounded authorization repairs for the FUXA demo."""
from __future__ import annotations

import argparse
import hashlib
import json
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
PROTECTED_FILES = {
    "server/runtime/index.js": {
        "    io.on('connection', async (socket) => {\n":
            "    io.on('connection', async (socket) => {\n"
            "        immunePolicy.protectSocket(socket, users, api.authJwt);\n",
        "io.emit(Events.IoEventTypes.DAQ_RESULT,": "socket.emit(Events.IoEventTypes.DAQ_RESULT,",
        "io.emit(Events.IoEventTypes.DAQ_ERROR,": "socket.emit(Events.IoEventTypes.DAQ_ERROR,",
    },
    "server/api/scheduler/index.js": {
        f'schedulerApp.{method}("/api/scheduler", secureFnc,':
            f'schedulerApp.{method}("/api/scheduler", '
            "(req, res, next) => immunePolicy.protectScheduler(req, res, next, runtime, authJwt), secureFnc,"
        for method in ("post", "delete")
    },
}
POLICY_REASONS = {
    "tag_write": "/socket.io",
    "device_control": "/socket.io",
    "historian_query": "/socket.io",
    "scheduler_authorization": "/api/scheduler",
}
# The effect boundary of each factory control. When a control starts in
# observation, reaching the effect with an unprivileged role is the evidence
# that turns it into an incident and, after validation, into enforcement.
PROTECTED_EFFECTS = {
    "tag_write": "tag-write",
    "device_control": "device-control",
    "historian_query": "historian-query",
    "scheduler_authorization": "scheduler-authorization",
}
SOCKET_COVERAGE = {
    "DEVICE_VALUES": "tag_write",
    "DEVICE_ENABLE": "device_control",
    "DAQ_QUERY": "historian_query",
}
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Routes every client needs before it holds an administrator session (login and
# token refresh). An admin-only guard there would lock everyone out once enforced.
SESSION_ROUTES = frozenset({"/api/signin", "/api/heartbeat"})
# One verdict per operation: the HTTP 200 only confirms delivery; the verdict
# says whether the effect was allowed.
VERDICTS = {
    "allow": "permitida", "authorized": "permitida",
    "deny": "bloqueada", "blocked": "bloqueada", "contained": "bloqueada",
    "unavailable": "evaluación no disponible",
    "restricted": "sesión restringida", "released": "restricción vencida",
    "incident": "incidente confirmado", "alert": "sospechosa",
}


def normalize_verdict(status: str | None) -> str:
    return VERDICTS.get(status, status or "sin cobertura")


def declare(row: dict) -> dict:
    """Who may execute the operation and which effect must be observed."""
    if row["transport"] == "socket.io":
        return {"role": "admin", "effect": "event"}
    if row["method"] in WRITE_METHODS:
        return {"role": "admin", "effect": "write"}
    return {"role": "member", "effect": "read"}


def route_anchor(method: str, route: str) -> re.Pattern:
    return re.compile(
        r"\." + re.escape(method.lower()) + r"\(\s*(['\"])" + re.escape(route) + r"\1,"
    )


def control_name(method: str, route: str) -> str:
    return "route." + method.lower() + "." + re.sub(r"[^a-z0-9]+", "-", route.lower()).strip("-")


def route_controls(profile: dict, source: Path | None = None) -> dict:
    """Declared pre-effect guards for every HTTP write route that lacks a control.

    A control is only declared when its anchor is verifiable in the revision
    source: exactly one registration of the route and a resolvable runtime in
    scope. Everything else stays pending instead of shipping a broken guard.
    """
    controls = {}
    for row in profile["operations"]:
        if row["transport"] != "http" or row.get("method") not in WRITE_METHODS:
            continue
        if row.get("coverage") in OPERATIONS or protected_operation(row) is not None:
            continue
        if row.get("route") in SESSION_ROUTES:
            continue
        method, route, file = row["method"], row["route"], row["file"]
        name = control_name(method, route)
        control = {
            "method": method, "route": route, "file": file,
            "role": row.get("role", "admin"), "effect": "write-route", "boundary": "write-route",
        }
        if source is not None:
            try:
                code = (source / file).read_text(encoding="utf-8")
            except OSError:
                continue
            if not re.search(r"\bruntime\b", code):
                continue
            if len(route_anchor(method, route).findall(code)) != 1:
                continue
        controls[name] = control
    return controls


def protected_operation(row: dict) -> str | None:
    if row["file"] == "server/runtime/index.js":
        return SOCKET_COVERAGE.get(row.get("event"))
    if (row["file"] == "server/api/scheduler/index.js" and row.get("route") == "/api/scheduler"
            and row.get("method") in {"POST", "DELETE"}):
        return "scheduler_authorization"
    return None


def coverage_counts(profile: dict, protected: list[str], controls: dict | None = None,
                    observed: list[str] | None = None) -> dict:
    controlled = {
        (control["method"], control["route"], control["file"])
        for control in (controls or {}).values()
    }
    observed = set(observed or ())
    pending = partial = 0
    for row in profile["operations"]:
        if row["coverage"] != "pending":
            continue
        if (row.get("method"), row.get("route"), row.get("file")) in controlled:
            continue
        operation = protected_operation(row)
        if operation in observed:
            continue  # wired control running in observation: covered, not pending
        if operation in protected:
            partial += operation == "tag_write"
        else:
            pending += 1
    return {"pending": pending, "partial": partial}


def audit_coverage(profile: dict, release: Path, metadata: dict) -> dict:
    protected = set(metadata.get("protected", []))
    enforced = set(metadata["enforced"])
    controls = metadata.get("controls", {})
    controlled = {}
    for name, control in controls.items():
        code = (release / control["file"]).read_text(encoding="utf-8")
        mode = "enforce" if name in enforced else "observe"
        guard = (
            f'(req, res, next) => immuneMonitor.routeGuard("{name}", "{mode}", req, res, next, '
            'typeof runtime === "undefined" ? null : runtime),'
        )
        wired = re.compile(
            r"\." + re.escape(control["method"].lower()) + r"\(\s*(['\"])"
            + re.escape(control["route"]) + r"\1,\s*" + re.escape(guard)
        )
        if len(wired.findall(code)) != 1:
            raise ValueError(f"El control previsto no se encontró en la revisión: {name}")
        controlled[(control["method"], control["route"], control["file"])] = name
    for name, policy in OPERATIONS.items():
        code = (release / policy["file"]).read_text(encoding="utf-8")
        mode = "enforce" if name in enforced else "observe"
        guard = f'immuneMonitor.authorize("{name}", "{mode}", req, runtime)'
        before_effect = re.compile(
            r"(?m)^([ \t]*)" + re.escape(f"if (!{guard}) return res.status(403).end();")
            + r"\n\1" + re.escape(policy["anchor"])
        )
        route_observer = re.compile(
            r'\.post\(\s*([\'"])' + re.escape(policy["route"]) + r'\1,\s*'
            + re.escape(f'immuneMonitor.http("{name}"),')
        )
        if len(before_effect.findall(code)) != 1 or len(route_observer.findall(code)) != 1:
            raise ValueError(f"El control previsto no se encontró en la revisión: {name}")
    if protected:
        if protected != POLICY_REASONS.keys():
            raise ValueError("La revisión declara un conjunto inesperado de controles")
        for file, changes in PROTECTED_FILES.items():
            code = (release / file).read_text(encoding="utf-8")
            if ('require("/immune/policy.cjs")' not in code
                    or any(code.count(replacement) != 1 for replacement in changes.values())):
                raise ValueError(f"No se pudo verificar la conexión de la política en {file}")

    counts = dict.fromkeys(("enforced", "observe", "partial", "write_review", "read_review", "event_review"), 0)
    findings = []
    protected_enforced = set(metadata.get("protected_enforced", metadata.get("protected", [])))
    for row in profile["operations"]:
        covered = row["coverage"]
        operation = protected_operation(row)
        control = controlled.get((row.get("method"), row.get("route"), row.get("file")))
        if covered in enforced:
            category = "enforced"
        elif covered in OPERATIONS:
            category = "observe"
        elif control is not None:
            category = "enforced" if control in enforced else "observe"
        elif operation in protected_enforced:
            category = "partial" if operation == "tag_write" else "enforced"
        elif operation in protected:
            # The control is wired but running in observation: the effect is
            # still reachable, so the entry is covered-in-observation.
            category = "observe"
        elif row.get("transport") == "socket.io":
            category = "event_review"
        elif row.get("method") in {"POST", "PUT", "PATCH", "DELETE"}:
            category = "write_review"
        else:
            category = "read_review"
        counts[category] += 1
        if category not in ("enforced", "observe"):
            findings.append({
                **{key: value for key, value in row.items()
                   if key in {"file", "line", "route", "method", "event", "role", "effect"}},
                "category": category,
            })
    return {"revision": metadata["revision"], "counts": counts, "findings": findings}


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
            declared = (
                {"role": OPERATIONS[operation]["role"], "effect": OPERATIONS[operation]["effect"]}
                if operation else declare({"transport": "http", "method": method})
            )
            operations.append({
                "transport": "http", "method": method, "route": route, "file": relative.as_posix(),
                "line": code.count("\n", 0, match.start()) + 1, "coverage": operation or "pending",
                **declared,
            })
        for match in SOCKET.finditer(code):
            operations.append({
                "transport": "socket.io", "event": match[1] or match[2], "file": relative.as_posix(),
                "line": code.count("\n", 0, match.start()) + 1, "coverage": "pending",
                **declare({"transport": "socket.io"}),
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
        "inventory_limits": "Registros estáticos reconocibles. Socket.IO está inventariado, sin vigilancia activa. "
                            "Cada entrada declara quién puede ejecutarla y qué efecto debe observarse.",
    }


def fingerprint(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest.update(path.relative_to(directory).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def instrument(source: Path, release: Path, enforced: set[str], controls: dict | None = None) -> list[Path]:
    outputs = []
    files: dict[str, list[tuple[str, dict]]] = {}
    for operation in sorted(OPERATIONS.values(), key=lambda item: item["file"]):
        files.setdefault(operation["file"], [])
    for name, control in sorted((controls or {}).items()):
        files.setdefault(control["file"], []).append((name, control))
    for file, route_specs in sorted(files.items()):
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
        for name, control in route_specs:
            route, = route_anchor(control["method"], control["route"]).finditer(code)
            mode = "enforce" if name in enforced else "observe"
            middleware = (
                f' (req, res, next) => immuneMonitor.routeGuard("{name}", "{mode}", req, res, next, '
                'typeof runtime === "undefined" ? null : runtime),'
            )
            code = code[:route.end()] + middleware + code[route.end():]
        output = release / file
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(code, encoding="utf-8", newline="\n")
        outputs.append(output)
    for file, changes in PROTECTED_FILES.items():
        code = (source / file).read_text(encoding="utf-8")
        for original, replacement in changes.items():
            if code.count(original) != 1:
                raise ValueError(f"No se encontró el punto de control de FUXA en {file}")
            code = code.replace(original, replacement)
        output = release / file
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text('const immunePolicy = require("/immune/policy.cjs");\n' + code,
                          encoding="utf-8", newline="\n")
        outputs.append(output)
    return outputs


def assess(event: dict, revision: str, operations: dict | None = None) -> str | None:
    declared = {**OPERATIONS, **(operations or {})}
    if revision is None or not isinstance(event, dict) or event.get("revision") != revision:
        return None
    operation = event.get("operation")
    if not isinstance(operation, str) or operation not in declared:
        return None
    correlation = event.get("id")
    if not isinstance(correlation, str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", correlation):
        return None
    role = event.get("role")
    if event.get("type") == "effect" and event.get("boundary") == declared[operation]["effect"]:
        if event.get("decision") == "observed" and role in ("member", "anonymous"):
            return "incident"
        if event.get("decision") == "blocked" and role in ("member", "anonymous"):
            return "blocked"
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


def live_runtime(default: Path) -> Path:
    from fleet.fuxa import FuxaFleet

    try:
        candidates = [
            FuxaFleet(path.resolve()) for path in default.parent.iterdir()
            if (path / "profile.json").is_file() and (path / "deployment.json").is_file()
        ]
        if not candidates:
            return default
        fleet = FuxaFleet(default)
        names = fleet.docker("ps", "--filter", "label=immune.fuxa", "--format", "{{.Names}}",
                             timeout=5, optional=True)
        running = set((names or "").splitlines())
        if fleet.gateway in running and fleet.active() is not None:
            return default
        active = {candidate.root for candidate in candidates if candidate.gateway in running
                  and candidate.active() is not None}
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return default
    if len(active) > 1:
        raise ValueError("Hay varias instancias de FUXA activas. Indica el directorio con --runtime.")
    return next(iter(active), default)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="immune fuxa")
    parser.add_argument("--runtime", type=Path, help="Directorio de la instancia de FUXA")
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
    commands.add_parser("reload-gateway", help="Actualiza el gateway y verifica la revisión activa")
    commands.add_parser("harden", help="Valida y activa los controles de autorización de FUXA")
    commands.add_parser("validate-active", help="Prueba la revisión activa de FUXA en un contenedor aislado")
    commands.add_parser("audit-coverage", help="Audita el inventario de cobertura sin enviar peticiones")
    patch_mode = commands.add_parser("patch-mode", help="Consulta o cambia el modo de parches de FUXA")
    patch_mode.add_argument("mode", choices=("auto", "review"), nargs="?")
    approve = commands.add_parser("approve", help="Autoriza el despliegue de un candidato validado")
    approve.add_argument("incident")
    args = parser.parse_args(argv)
    root = (args.runtime or DEFAULT_RUNTIME).resolve()
    try:
        live_commands = {"status", "dashboard", "demo", "reload-gateway", "harden", "validate-active",
                         "patch-mode", "approve", "audit-coverage"}
        if args.runtime is None and (args.command in live_commands or args.command == "watch" and args.input is None):
            root = live_runtime(root)
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
                last = fleet.watch(None)
                if last is None:
                    raise RuntimeError("No hay una revisión activa. Ejecuta fuxa up o indica --runtime.")
                while True:
                    time.sleep(2)
                    last = fleet.watch(last)
            elif args.command == "up":
                result = fleet.up(args.port)
            elif args.command == "reload-gateway":
                result = fleet.reload_gateway()
            elif args.command == "validate-active":
                result = fleet.validate_active()
            elif args.command == "audit-coverage":
                result = fleet.audit_coverage()
            elif args.command == "patch-mode":
                result = {"patch_mode": fleet.patch_mode(args.mode)}
            elif args.command == "approve":
                result = fleet.approve(args.incident)
            else:
                result = getattr(fleet, args.command)()
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"immune fuxa ({root}): {error}", file=sys.stderr)
        return 1
