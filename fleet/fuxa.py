"""Blue-green Fleet adapter for the isolated FUXA Node.js demo."""
from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from immune import fuxa

CONTROL = "/run/immune/active"
RULE_TTL = 900          # seconds a containment rule holds while a candidate validates
RULE_SET = "const fs=require('node:fs');fs.writeFileSync('/telemetry/rules.json',process.argv[1]);"
RULE_READ = ("const fs=require('node:fs');"
             "try{console.log(fs.readFileSync('/telemetry/rules.json','utf8'))}catch{}")
ACTIVATE = (
    "const fs=require('node:fs');"
    "const p='/run/immune/active';"
    "fs.writeFileSync(p+'.tmp',process.argv[1]);fs.renameSync(p+'.tmp',p);"
)
DIRECT_SMOKE = """
const http = require('node:http');
const {createHash} = require('node:crypto');
http.get({host: '127.0.0.1', port: 1881, path: process.argv[1], timeout: 2500}, res => {
    if (res.statusCode !== 200) process.exit(1);
    const hash = createHash('sha256');
    res.on('data', chunk => hash.update(chunk));
    res.on('end', () => console.log(hash.digest('hex')));
}).on('error', () => process.exit(1)).on('timeout', () => process.exit(1));
"""
SETTINGS_DIGEST = (
    "const f=require('node:fs');"
    "console.log(require('node:crypto').createHash('sha256')"
    ".update(f.readFileSync('/lab/_appdata/settings.js')).digest('hex'));"
)

LEGITIMATE_FLOWS = (
    ("project", "/api/project", 200, "application/json"),
    ("guest_access", "/api/users", 401, "application/json"),
    ("realtime", "/socket.io/?EIO=4&transport=polling", 200, "text/plain"),
)


class FuxaRollback(RuntimeError):
    """The prior release is serving again and its gateway smoke checks passed."""


class FuxaFleet:
    def __init__(self, root: Path):
        self.root = root
        self.source = root / "source"
        self.releases = root / "releases"
        self.prefix = "immune-fuxa-" + hashlib.sha256(os.fsencode(root)).hexdigest()[:12]
        self.gateway = self.prefix + "-gateway"
        self.internal = self.prefix + "-internal"
        self.testnet = self.prefix + "-tests"
        self.image = self.prefix + ":v1.2.9"
        self.label = "immune.fuxa=" + self.prefix

    @contextlib.contextmanager
    def lock(self):
        if not (self.root / "profile.json").is_file():
            raise ValueError("Ejecuta primero immune fuxa baseline")
        with (self.root / "fleet.lock").open("a+b") as lock:
            lock.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def docker(self, *args: str, timeout: int = 30, optional: bool = False) -> str | None:
        binary = shutil.which("docker")
        if binary is None:
            raise RuntimeError("Se necesita Docker para probar y redesplegar FUXA")
        result = subprocess.run([binary, *args], capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=timeout)
        if result.returncode:
            if optional:
                return None
            detail = (result.stderr or result.stdout).strip() if args[0] not in {"logs", "exec"} else ""
            raise RuntimeError(f"Docker {args[0]} falló" + (f": {detail[-1200:]}" if detail else ""))
        return result.stdout

    def active(self) -> str | None:
        name = self.docker("exec", self.gateway, "cat", CONTROL, optional=True)
        if not name:
            return None
        name = name.strip()
        if not re.fullmatch(re.escape(self.prefix) + r"-r-[a-f0-9]{12}", name):
            raise RuntimeError("El gateway devolvió una revisión inválida")
        return name.rsplit("-r-", 1)[1]

    def backend(self, revision: str) -> str:
        return self.prefix + "-r-" + revision

    def activate(self, revision: str) -> None:
        self.docker("exec", self.gateway, "node", "-e", ACTIVATE, self.backend(revision))

    def profile(self) -> dict:
        return json.loads((self.root / "profile.json").read_text(encoding="utf-8"))

    def meta(self, revision: str) -> dict:
        return json.loads((self.releases / revision / "release.json").read_text(encoding="utf-8"))

    def build(self) -> None:
        assets = fuxa.fingerprint(fuxa.ASSETS)
        if self.docker("image", "inspect", "--format", '{{index .Config.Labels "immune.fuxa.assets"}}',
                       self.image, optional=True) == assets + "\n":
            return
        with tempfile.TemporaryDirectory(dir=self.root) as staging:
            context = Path(staging)
            for path in fuxa.ASSETS.iterdir():
                shutil.copyfile(path, context / path.name)
            shutil.copytree(self.source, context / "source")
            if fuxa.fingerprint(context / "source") != self.profile()["source_digest"]:
                raise ValueError("La copia para Docker no coincide con el perfil")
            self.docker("build", "--label", f"immune.fuxa.assets={assets}", "-t", self.image,
                        str(context), timeout=1800)

    def make_release(self, enforced: set[str], controls: dict | None = None) -> str:
        digest = self.profile()["source_digest"]
        if fuxa.fingerprint(self.source) != digest:
            raise ValueError("El código fuente local no coincide con el perfil")
        # A patch only flips modes: it keeps the active revision's controls so the
        # candidate differs from it in exactly one control.
        if controls is None:
            controls = fuxa.route_controls(self.profile(), self.source)
        key = (digest, fuxa.fingerprint(fuxa.ASSETS), sorted(enforced), json.dumps(controls, sort_keys=True))
        revision = hashlib.sha256(json.dumps(key).encode()).hexdigest()[:12]
        dest = self.releases / revision
        dest.mkdir(parents=True, exist_ok=True)
        fuxa.instrument(self.source, dest, enforced, controls)
        fuxa.write_json(dest / "release.json", {
            "revision": revision, "enforced": sorted(enforced), "protected": list(fuxa.POLICY_REASONS),
            "protected_enforced": sorted(set(enforced) & set(fuxa.POLICY_REASONS)),
            "controls": controls,
        })
        return revision

    def sandbox(self) -> list[str]:
        return ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "256", "--memory", "1g", "--label", self.label]

    def mounts(self, revision: str) -> list[str]:
        result = []
        files = sorted(self.mount_files(revision) | fuxa.PROTECTED_FILES.keys())
        for file in files:
            host_path = self.releases / revision / file
            result += ["--mount", f"type=bind,src={host_path},dst=/app/{file},readonly"]
        return result

    def test(self, revision: str, *, image: str | None = None) -> None:
        image = image or self.image
        metadata = self.meta(revision)
        coverage_audit = fuxa.audit_coverage(self.profile(), self.releases / revision, metadata)
        enforced = ",".join(metadata["enforced"])
        observe = sorted(set(fuxa.POLICY_REASONS) - (set(metadata["enforced"]) & set(fuxa.POLICY_REASONS)))
        run = ["run", "--rm", *self.sandbox(), "--tmpfs", "/tmp:uid=1000,gid=1000,mode=0700",
               *self.mounts(revision),
               "-e", "IMMUNE_FUXA_PROTECTED_OBSERVE=" + ",".join(observe)]
        self.docker(*run, "--network", "none", image, "node", "/immune/check.cjs", enforced, timeout=60)
        checker = fuxa.ASSETS / "policy-check.cjs"
        output = self.docker(*run, "--network", "none", "--tmpfs", "/telemetry:uid=1000,gid=1000,mode=0700",
                             "--mount", f"type=bind,src={checker},dst=/immune/policy-check.cjs,readonly",
                             image, "node", "/immune/policy-check.cjs", timeout=60)
        report = json.loads(output)
        if (not isinstance(report, dict) or report.get("operations") != list(fuxa.POLICY_REASONS)
                or report.get("evaluator") != "metadata"
                or type(report.get("checks")) is not int or report["checks"] < 1
                or type(report.get("identities")) is not int or report["identities"] < 1):
            raise ValueError("El informe de la validación aislada de FUXA es inválido")
        # The upstream interface discovery test requires an interface besides loopback.
        self.ensure_network(self.testnet)
        self.docker(*run, "--network", self.testnet, image, "npm", "test", timeout=150)
        fuxa.write_json(self.releases / revision / "policy-validation.json", report)
        fuxa.write_json(self.releases / revision / "coverage-audit.json", coverage_audit)

    def ensure_network(self, network: str) -> None:
        status = self.docker("network", "inspect", "--format",
                             '{{.Internal}} {{index .Labels "immune.fuxa"}}', network, optional=True)
        if status is None:
            self.docker("network", "create", "--internal", "--label", self.label, network)
        elif status.strip() != f"true {self.prefix}":
            raise RuntimeError("La red no pertenece a la demo o permite salida")

    def state_volume(self) -> str:
        name = self.prefix + "-state-" + uuid.uuid4().hex[:12]
        self.docker("volume", "create", "--label", self.label, name)
        return name

    def state_mount(self, volume: str, *, readonly=False) -> str:
        label = self.docker("volume", "inspect", "--format", '{{index .Labels "immune.fuxa"}}', volume)
        if label.strip() != self.prefix or not re.fullmatch(re.escape(self.prefix) + r"-state-[0-9a-f]{12}", volume):
            raise RuntimeError("El volumen de estado no pertenece a esta demo")
        return f"type=volume,src={volume},dst=/lab" + (",readonly" if readonly else "")

    def state_signature(self, revision: str) -> tuple[str, str]:
        backend = self.backend(revision)
        settings = self.docker("exec", backend, "node", "-e", SETTINGS_DIGEST, timeout=5).strip()
        project = self.docker("exec", backend, "node", "-e", DIRECT_SMOKE, "/api/project", timeout=5).strip()
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in (settings, project)):
            raise RuntimeError("No se pudo verificar el estado de FUXA")
        return settings, project

    def copy_state(self, old: str, previous: str | None, target: str) -> None:
        run = ["run", "--rm", "--network", "none", *self.sandbox()]
        destination = self.state_mount(target)
        if previous:
            source = [*run, "--mount", self.state_mount(previous, readonly=True), self.image,
                      "tar", "-C", "/lab", "--exclude=./_logs", "-cf", "-", "."]
        else:
            exporter = (fuxa.ASSETS / "state-export.cjs").read_text(encoding="utf-8")
            source = ["exec", self.backend(old), "node", "-e", exporter]
        binary = shutil.which("docker")
        if binary is None:
            raise RuntimeError("No se encontró Docker para copiar el estado de FUXA")
        process = subprocess.Popen([binary, *source], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            with process.stdout:
                imported = subprocess.run(
                    [binary, *run, "-i", "--mount", destination, self.image,
                     "tar", "--no-same-owner", "-C", "/lab", "-xf", "-"],
                    stdin=process.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120,
                )
            if imported.returncode or process.wait(timeout=10):
                raise RuntimeError("No se pudo transferir el estado de FUXA")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    def start(self, revision: str, volume: str) -> None:
        self.remove(self.backend(revision))
        # Factory controls wired into the revision but left outside `enforced`
        # run in observation: the effect happens, gets recorded, and only an
        # incident puts them into enforcement.
        observe = sorted(set(fuxa.POLICY_REASONS) - (set(self.meta(revision)["enforced"]) & set(fuxa.POLICY_REASONS)))
        self.docker("run", "-d", "--name", self.backend(revision), *self.sandbox(),
                    "--network", self.internal, "--mount", self.state_mount(volume),
                    "--tmpfs", "/telemetry:uid=1000,gid=1000,mode=0700,size=32m",
                    "--tmpfs", "/tmp:uid=1000,gid=1000,mode=0700", *self.mounts(revision),
                    "-e", f"IMMUNE_FUXA_REVISION={revision}",
                    "-e", "IMMUNE_FUXA_PROTECTED_OBSERVE=" + ",".join(observe),
                    self.image, "node", "/immune/start.cjs")

    def remove(self, name: str) -> None:
        label = self.docker("inspect", "--format", '{{index .Config.Labels "immune.fuxa"}}', name, optional=True)
        if label is None:
            return
        if label.strip() != self.prefix:
            raise RuntimeError("El contenedor no pertenece a esta demo")
        self.docker("rm", "-f", name)

    def local_smoke(self, revision: str) -> dict:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            results = {}
            for path in self.profile()["smoke"]:
                digest = self.docker("exec", self.backend(revision), "node", "-e", DIRECT_SMOKE,
                                     path, timeout=5, optional=True)
                if not digest or not re.fullmatch(r"[a-f0-9]{64}", digest.strip()):
                    break
                results[path] = digest.strip()
            else:
                return results
            time.sleep(0.5)
        raise RuntimeError("El candidato FUXA no respondió a los flujos de humo")

    def gateway_smoke(self, revision: str, expected: dict, port: int) -> None:
        for path, digest in expected.items():
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
                if response.headers.get("x-immune-fuxa-revision") != revision or (
                    hashlib.sha256(response.read()).hexdigest() != digest
                ):
                    raise RuntimeError("El gateway no sirve la revisión o respuesta esperada")

    def verify_legitimate(self, revision: str, port: int) -> None:
        passed = []
        for flow, path, status, media_type in LEGITIMATE_FLOWS:
            try:
                response = urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                if (response.status != status or response.headers.get_content_type() != media_type
                        or response.headers.get("x-immune-fuxa-revision") != revision):
                    raise RuntimeError(f"No pasó la comprobación de FUXA: {flow}")
                if flow != "guest_access":
                    body = response.read(2_000_001)
                    if len(body) > 2_000_000:
                        raise RuntimeError(f"Respuesta demasiado grande en la comprobación de FUXA: {flow}")
                    try:
                        if flow == "realtime":
                            packet = json.loads(body[1:]) if body.startswith(b"0") else None
                            valid = (isinstance(packet, dict) and isinstance(packet.get("sid"), str)
                                     and bool(packet["sid"]) and type(packet.get("pingInterval")) is int
                                     and packet["pingInterval"] > 0 and type(packet.get("pingTimeout")) is int
                                     and packet["pingTimeout"] > 0)
                        else:
                            project = json.loads(body)
                            valid = (isinstance(project, dict) and isinstance(project.get("name"), str)
                                     and bool(project["name"]) and isinstance(project.get("hmi"), dict)
                                     and isinstance(project.get("devices"), dict)
                                     and isinstance(project.get("alarms"), list))
                    except ValueError as error:
                        raise RuntimeError(f"Respuesta inválida en la comprobación de FUXA: {flow}") from error
                    if not valid:
                        raise RuntimeError(f"Respuesta inválida en la comprobación de FUXA: {flow}")
            passed.append(flow)
        fuxa.write_json(self.releases / revision / "legitimate-validation.json", {"flows": passed})

    def start_gateway(self, port: int) -> None:
        routes = sorted({row["route"] for row in self.profile()["operations"] if row["transport"] == "http"})
        self.docker("run", "-d", "--name", self.gateway, *self.sandbox(),
                    "-p", f"127.0.0.1:{port}:1881", "--log-driver", "local",
                    "--log-opt", "max-size=5m", "--log-opt", "max-file=2",
                    "--tmpfs", "/run/immune:uid=1000,gid=1000,mode=0700",
                    "-e", "IMMUNE_FUXA_ROUTES=" + json.dumps(routes), self.image, "node", "/immune/gateway.cjs")
        self.docker("network", "connect", self.internal, self.gateway)

    def reload_gateway(self) -> dict:
        with self.lock():
            revision = self.active()
            if revision is None:
                raise RuntimeError("No hay una revisión activa")
            settings = json.loads((self.root / "deployment.json").read_text(encoding="utf-8"))
            self.build()
            backup = self.gateway + "-previous"
            self.docker("rename", self.gateway, backup)
            try:
                self.docker("stop", backup)
                self.start_gateway(settings["port"])
                self.activate(revision)
                self.gateway_smoke(revision, settings["smoke"], settings["port"])
                self.verify_legitimate(revision, settings["port"])
            except Exception:
                self.remove(self.gateway)
                self.docker("rename", backup, self.gateway)
                self.docker("start", self.gateway)
                self.activate(revision)
                self.gateway_smoke(revision, settings["smoke"], settings["port"])
                raise
            self.remove(backup)
            return self.status()

    def harden(self) -> dict:
        with self.lock():
            old = self.active()
            if old is None:
                raise RuntimeError("No hay una revisión activa")
            candidate = self.make_release(set(fuxa.OPERATIONS) | set(fuxa.POLICY_REASONS))
            if candidate != old:
                self.promote(old, candidate, retain_previous=True)
            return self.status()

    def validate_active(self) -> dict:
        with self.lock():
            revision = self.active()
            if revision is None:
                raise RuntimeError("No hay una revisión activa")
            image = self.docker("inspect", "--format", "{{.Image}}", self.backend(revision)).strip()
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
                raise RuntimeError("Docker devolvió una imagen de FUXA inválida")
            self.test(revision, image=image)
            settings = self.deployment()
            self.gateway_smoke(revision, settings["smoke"], settings["port"])
            self.verify_legitimate(revision, settings["port"])
            return self.status()

    def audit_coverage(self) -> dict:
        with self.lock():
            revision = self.active()
            if revision is None:
                raise RuntimeError("No hay una revisión activa")
            release = self.releases / revision
            audit = fuxa.audit_coverage(self.profile(), release, self.meta(revision))
            path = release / "coverage-audit.json"
            fuxa.write_json(path, audit)
            return {"revision": revision, "counts": audit["counts"], "report": str(path)}

    def deployment(self) -> dict:
        return json.loads((self.root / "deployment.json").read_text(encoding="utf-8"))

    def patch_mode(self, mode: str | None = None) -> str:
        path = self.root / "patch-mode.json"
        if mode is None:
            current = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else "auto"
            if current not in ("auto", "review"):
                raise ValueError("Modo de parches de FUXA inválido")
            return current
        if mode not in ("auto", "review"):
            raise ValueError("Modo de parches de FUXA inválido")
        with self.lock():
            fuxa.write_json(path, mode)
        return mode

    def up(self, port: int) -> dict:
        if not 1 <= port <= 65535:
            raise ValueError("Puerto inválido")
        with self.lock():
            if self.active():
                return self.status()
            settings = self.deployment() if (self.root / "deployment.json").is_file() else {}
            previous = settings.get("revision")
            enforced = set(self.meta(previous)["enforced"]) if previous else set(fuxa.OPERATIONS) | set(fuxa.POLICY_REASONS)
            revision = self.make_release(enforced)
            self.build()
            self.test(revision)
            self.ensure_network(self.internal)
            self.remove(self.gateway)
            volume = settings.get("state_volume") or self.state_volume()
            try:
                self.start(revision, volume)
                self.start_gateway(port)
                smoke = self.local_smoke(revision)
                self.activate(revision)
                self.gateway_smoke(revision, smoke, port)
                self.verify_legitimate(revision, port)
                fuxa.write_json(self.root / "deployment.json", {
                    "port": port, "smoke": smoke, "revision": revision, "state_volume": volume,
                })
            except Exception:
                self.remove(self.gateway)
                self.remove(self.backend(revision))
                raise
            return self.status()

    def promote(self, old: str, candidate: str, *, retain_previous=False, gates=None) -> str | None:
        def gate(name: str, detail: str) -> None:
            if gates is not None:
                gates[name] = {"ok": True, "detail": detail}

        settings = self.deployment()
        self.build()
        self.test(candidate)
        gate("tests", "Validación aislada y suite de FUXA superadas")
        gate("poc", "La identidad sin permiso no alcanza el efecto")
        if self.active() != old:
            raise RuntimeError("Cambió la revisión durante la validación")
        signature = self.state_signature(old)
        previous = settings.get("state_volume")
        volume = self.state_volume()
        backend = self.backend(old)
        isolated = False
        try:
            if previous:
                self.state_mount(previous, readonly=True)
                self.docker("stop", backend, timeout=30)
            else:
                self.docker("network", "disconnect", self.internal, backend)
            isolated = True
            self.copy_state(old, previous, volume)
            self.start(candidate, volume)
            smoke = self.local_smoke(candidate)
            if smoke != settings["smoke"]:
                raise RuntimeError("Cambió una respuesta legítima de FUXA")
            if self.state_signature(candidate) != signature:
                raise RuntimeError("El candidato no conservó el proyecto y la configuración de sesión")
            gate("properties", "Proyecto y sesiones intactos tras el cambio de revisión")
            self.activate(candidate)
            self.gateway_smoke(candidate, smoke, settings["port"])
            self.verify_legitimate(candidate, settings["port"])
            gate("legit", "Flujos legítimos verificados por el gateway")
            fuxa.write_json(self.root / "deployment.json", {
                **settings, "revision": candidate, "state_volume": volume,
            })
        except (Exception, KeyboardInterrupt) as error:
            switched = self.active() == candidate
            self.remove(self.backend(candidate))
            if isolated:
                if previous:
                    self.docker("start", backend)
                    self.local_smoke(old)
                else:
                    self.docker("network", "connect", self.internal, backend)
                if switched:
                    self.activate(old)
                self.gateway_smoke(old, settings["smoke"], settings["port"])
                if not isinstance(error, KeyboardInterrupt):
                    self.verify_legitimate(old, settings["port"])
                    raise FuxaRollback(str(error)) from error
            raise
        if retain_previous:
            return None
        try:
            self.remove(self.backend(old))
        except (OSError, RuntimeError, subprocess.SubprocessError):
            return "El gateway sirve el candidato. La limpieza del contenedor anterior quedó pendiente."
        return None

    def _rules(self, backend: str) -> list[dict]:
        out = self.docker("exec", backend, "node", "-e", RULE_READ, timeout=10, optional=True)
        try:
            parsed = json.loads(out or "[]")
        except ValueError:
            return []
        return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []

    def _set_rules(self, backend: str, rules: list[dict]) -> None:
        self.docker("exec", backend, "node", "-e", RULE_SET,
                    json.dumps(rules, separators=(",", ":")), timeout=10)

    def activate_rule(self, operation: str, event: dict | None = None,
                      ttl: int = RULE_TTL) -> dict | None:
        """Immediate containment while the candidate validates. The rule is
        proposed from the incident evidence (LLM when available, deterministic
        fallback otherwise) and validated before install: 'role' scope keeps
        administrators working; 'session' scope only holds the offender.
        Fault-tolerant: without a live backend the incident still proceeds."""
        try:
            from immune import fuxa_rules
            revision = self.active()
            if revision is None:
                return None
            backend = self.backend(revision)
            evidence = {
                "operation": operation,
                "transport": fuxa.POLICY_REASONS.get(operation, ""),
                "role": (event or {}).get("role"),
                "session": (event or {}).get("session"),
                "boundary": (event or {}).get("boundary"),
            }
            rule, learned = fuxa_rules.propose_rule(evidence, operation, evidence.get("session"), ttl)
            rule = {**rule, "id": uuid.uuid4().hex, "until": time.time() + rule["ttl_s"]}
            rules = [item for item in self._rules(backend) if item.get("until", 0) > time.time()]
            rules.append(rule)
            self._set_rules(backend, rules)
            return {"id": rule["id"], "operations": rule["operations"], "scope": rule["scope"],
                    "ttl_s": rule["ttl_s"], "until": rule["until"], "learned": learned}
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            return None

    def deactivate_rule(self, operation: str) -> dict | None:
        try:
            revision = self.active()
            if revision is None:
                return None
            backend = self.backend(revision)
            rules = [item for item in self._rules(backend) if item.get("until", 0) > time.time()
                     and operation not in (item.get("operations") or [])]
            self._set_rules(backend, rules)
            return {"operation": operation}
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            return None


    def incident(self, event: dict, *, synthetic: bool = False) -> dict:
        with self.lock():
            old = self.active()
            if old is None:
                return {"status": "ignored"}
            declared = {**fuxa.OPERATIONS, **self.meta(old).get("controls", {}),
                        **{name: {"effect": boundary} for name, boundary in fuxa.PROTECTED_EFFECTS.items()}}
            if fuxa.assess(event, old, declared) != "incident":
                return {"status": "ignored"}
            operation = event["operation"]
            enforced = set(self.meta(old)["enforced"])
            if operation in enforced:
                return {"status": "already-enforced"}
            directory = self.root / "incidents" / event["id"]
            directory.mkdir(parents=True, exist_ok=True)
            receipt = directory / "incident.json"
            if receipt.exists():
                previous = json.loads(receipt.read_text(encoding="utf-8"))
                if previous["status"] != "validating":
                    return previous
            candidate = self.make_release(enforced | {operation}, self.meta(old).get("controls", {}))
            if operation in fuxa.POLICY_REASONS:
                # A factory control moving from observation to enforcement is a
                # metadata change: no instrumented file may differ.
                before_meta = self.meta(old)
                after_meta = self.meta(candidate)
                for file in self.mount_files(old) | set(fuxa.PROTECTED_FILES):
                    if (self.releases / old / file).read_bytes() != (self.releases / candidate / file).read_bytes():
                        raise RuntimeError("El parche modifica otro archivo instrumentado")
                if (set(after_meta["enforced"]) - set(before_meta["enforced"]) != {operation}
                        or after_meta["controls"] != before_meta["controls"]):
                    raise RuntimeError("El parche no pasó la política de cambios")
                patch = difflib.unified_diff(
                    ["enforced: " + " ".join(before_meta["enforced"])],
                    ["enforced: " + " ".join(after_meta["enforced"])],
                    "a/release.json", "b/release.json")
                (directory / "candidate.diff").write_text("".join(patch) + "\n", encoding="utf-8", newline="\n")
                result = {key: event[key] for key in ("id", "operation", "role", "boundary")}
                if isinstance(event.get("session"), str):
                    result["session"] = event["session"]
                result.update(status="validating", previous=old, candidate=candidate,
                              synthetic=synthetic, started=time.time(),
                              gates={"policy": {"ok": True,
                                                "detail": "El cambio es exactamente pasar el control a enforce"}})
                result["rule"] = self.activate_rule(operation, event)
                fuxa.write_json(receipt, result)
                return self.finish_incident(receipt, result, review=self.patch_mode() == "review")
            if operation in fuxa.OPERATIONS:
                file = fuxa.OPERATIONS[operation]["file"]
                guard = f'immuneMonitor.authorize("{operation}", '
            else:
                control = self.meta(candidate)["controls"][operation]
                file = control["file"]
                guard = f'immuneMonitor.routeGuard("{operation}", '
            before = (self.releases / old / file).read_text(encoding="utf-8")
            after = (self.releases / candidate / file).read_text(encoding="utf-8")
            if before.count(guard + '"observe"') != 1 or after != before.replace(
                guard + '"observe"', guard + '"enforce"'
            ):
                raise RuntimeError("El parche no pasó la política de cambios")
            for other in self.mount_files(old) - {file}:
                if (self.releases / old / other).read_bytes() != (self.releases / candidate / other).read_bytes():
                    raise RuntimeError("El parche modifica otro archivo instrumentado")
            patch = difflib.unified_diff(before.splitlines(True), after.splitlines(True), "a/" + file, "b/" + file)
            (directory / "candidate.diff").write_text("".join(patch), encoding="utf-8", newline="\n")
            result = {key: event[key] for key in ("id", "operation", "role", "boundary")}
            if isinstance(event.get("session"), str):
                result["session"] = event["session"]
            result.update(status="validating", previous=old, candidate=candidate,
                          synthetic=synthetic, started=time.time(),
                          gates={"policy": {"ok": True,
                                            "detail": "El diff es exactamente el cambio de modo del control"}})
            result["rule"] = self.activate_rule(operation, event)
            fuxa.write_json(receipt, result)
            return self.finish_incident(receipt, result, review=self.patch_mode() == "review")

    def finish_incident(self, receipt: Path, record: dict, *, review=False) -> dict:
        gates = record.setdefault("gates", {})

        def gate(name: str, ok: bool, detail: str) -> None:
            gates[name] = {"ok": bool(ok), "detail": str(detail)[:300]}

        def missing_gate(detail: str) -> None:
            for name in ("tests", "poc", "properties", "legit"):
                if name not in gates:
                    gate(name, False, detail)
                    return

        try:
            if review:
                self.build()
                self.test(record["candidate"])
                gate("tests", True, "Validación aislada superada")
                gate("poc", True, "La identidad sin permiso no alcanza el efecto")
                record.update(status="review", reviewed_at=time.time())
            else:
                cleanup = self.promote(record["previous"], record["candidate"], gates=gates)
                record["status"] = "deployed"
                if cleanup:
                    record["detail"] = cleanup
                # The permanent control is live: the containment rule retires.
                record["rule_off"] = self.deactivate_rule(record["operation"]) is not None
        except FuxaRollback as error:
            record.update(status="failed", rolled_back=True, detail=str(error))
            missing_gate(str(error))
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            record.update(status="failed", detail=str(error))
            missing_gate(str(error))
        if record["status"] != "review":
            record["finished"] = time.time()
        fuxa.write_json(receipt, record)
        return record

    def approve(self, ident: str) -> dict:
        if str(uuid.UUID(ident)) != ident:
            raise ValueError("Identificador de incidente inválido")
        with self.lock():
            path = self.root / "incidents" / ident / "incident.json"
            record = json.loads(path.read_text(encoding="utf-8"))
            if record["id"] != ident or record["status"] != "review":
                raise ValueError("El incidente no tiene un candidato pendiente de aprobación")
            previous = self.active()
            if record["previous"] != previous:
                raise RuntimeError("La revisión activa cambió desde que se validó el candidato")
            enforced = set(self.meta(previous)["enforced"])
            operation = record["operation"]
            if (operation not in fuxa.OPERATIONS and operation not in self.meta(previous).get("controls", {})
                    and operation not in fuxa.POLICY_REASONS):
                raise ValueError("La operación del parche no coincide con la revisión activa")
            if operation in enforced:
                raise ValueError("La operación del parche no coincide con la revisión activa")
            if self.make_release(enforced | {operation}, self.meta(previous).get("controls", {})) != record["candidate"]:
                raise RuntimeError("El candidato cambió desde que se validó")
            return self.finish_incident(path, record)

    def mount_files(self, revision: str | None = None) -> set[str]:
        files = {policy["file"] for policy in fuxa.OPERATIONS.values()}
        for control in self.meta(revision).get("controls", {}).values() if revision else {}:
            files.add(control["file"])
        return files

    def watch(self, last: tuple | None) -> tuple | None:
        revision = self.active()
        if revision is None:
            return last
        cursor = self.root / "watch-cursor.json"
        if last is None and cursor.exists():
            last = tuple(json.loads(cursor.read_text(encoding="utf-8")))
        backend = self.backend(revision)
        container = self.docker("inspect", "--format", "{{.Id}}", backend, optional=True)
        if container is None:
            if self.active() != revision:
                return last
            raise RuntimeError("El contenedor activo de FUXA no está disponible")
        container = container.strip()
        offset = last[1] if last and last[0] == container else 0
        data = self.docker("exec", backend, "node", "/immune/read-events.cjs", str(offset), optional=True)
        if data is None:
            if self.active() != revision:
                return last
            running = self.docker("inspect", "--format", "{{.State.Running}}", backend, optional=True)
            if running and running.strip() == "false":
                return last
            raise RuntimeError("No se pudo leer la telemetría del contenedor activo")
        batch = json.loads(data)
        controls = self.meta(revision).get("controls", {})
        declared = {**fuxa.OPERATIONS, **controls,
                    **{name: {"effect": boundary} for name, boundary in fuxa.PROTECTED_EFFECTS.items()}}
        for message in batch["entries"]:
            try:
                event = json.loads(message)
            except ValueError:
                continue
            if not isinstance(event, dict) or event.get("revision") != revision:
                continue
            if event.get("type") in ("policy_denied", "policy_decision"):
                reason = event.get("reason")
                if (not isinstance(reason, str) or reason not in fuxa.POLICY_REASONS
                        or not isinstance(event.get("id"), str)):
                    continue
                decision = "deny" if event["type"] == "policy_denied" else event.get("decision")
                if decision == "observed":
                    # A factory control in observation let an unprivileged role
                    # reach the effect: that is the incident evidence.
                    boundary = fuxa.PROTECTED_EFFECTS.get(reason)
                    if not boundary:
                        continue
                    reshaped = {"id": event["id"], "revision": revision, "type": "effect",
                                "operation": reason, "boundary": boundary, "decision": "observed",
                                "role": "admin" if event.get("role") == "administrator" else "member"}
                    if isinstance(event.get("session"), str):
                        reshaped["session"] = event["session"]
                    verdict = fuxa.assess(reshaped, revision, declared)
                    if verdict == "incident":
                        result = self.incident(reshaped)
                        print(json.dumps(result, ensure_ascii=False), flush=True)
                        if result["status"] == "deployed":
                            break
                    continue
                outcomes = {"deny": ("blocked", 403), "contained": ("blocked", 403),
                            "allow": ("authorized", None), "unavailable": ("unavailable", 503)}
                if isinstance(decision, str) and decision in outcomes:
                    verdict, status = outcomes[decision]
                    signal = {"status": verdict, "id": event["id"], "reason": reason,
                              "verdict": fuxa.normalize_verdict(verdict)}
                    if isinstance(event.get("session"), str):
                        signal["session"] = event["session"]
                    self.append_signal(signal,
                                       status if reason == "scheduler_authorization" else None)
                continue
            if event.get("type") in ("session_restricted", "session_released"):
                restricted = event["type"] == "session_restricted"
                if not isinstance(event.get("session"), str) or not isinstance(event.get("id"), str):
                    continue
                signal = {"status": "restricted" if restricted else "released",
                          "id": event["id"], "session": event["session"],
                          "reason": event.get("reason"),
                          "verdict": fuxa.normalize_verdict("restricted" if restricted else "released")}
                if restricted and isinstance(event.get("operations"), list):
                    signal["operations"] = [item for item in event["operations"] if isinstance(item, str)]
                    signal["expires"] = event.get("expires")
                self.append_signal(signal, 403 if restricted else None)
                print(json.dumps({"status": signal["status"], "session": signal["session"]},
                                 ensure_ascii=False), flush=True)
                continue
            verdict = fuxa.assess(event, revision, declared)
            if verdict is None:
                continue
            if verdict == "incident":
                result = self.incident(event)
            else:
                result = {"status": verdict, "operation": event["operation"], "id": event["id"]}
                if verdict in ("alert", "blocked"):
                    status = 403 if verdict == "blocked" else event["status"]
                    self.append_signal({**result, "verdict": fuxa.normalize_verdict(verdict)}, status)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            if result["status"] == "deployed":
                break
        current = (container, batch["offset"])
        fuxa.write_json(cursor, current)
        return current

    def append_signal(self, signal: dict, status: int | None) -> None:
        with (self.root / "signals.jsonl").open("a", encoding="utf-8") as signals:
            signals.write(json.dumps({**signal, "http_status": status, "ts": time.time()}) + "\n")

    def status(self) -> dict:
        revision = self.active()
        profile = self.profile()
        result = {"runtime": str(self.root), "tag": profile["tag"], "commit": profile["commit"], "active": revision,
                  "coverage": list(profile["policies"]), "patch_mode": self.patch_mode()}
        if revision:
            result.update(self.meta(revision))
            # Older releases ship every factory control enforced.
            enforced_protected = self.meta(revision).get("protected_enforced")
            result["protected"] = list(fuxa.POLICY_REASONS) if enforced_protected is None else enforced_protected
            result["protected_observed"] = [op for op in fuxa.POLICY_REASONS if op not in result["protected"]]
            validation = self.releases / revision / "policy-validation.json"
            if validation.is_file():
                result["validation"] = json.loads(validation.read_text(encoding="utf-8"))
            legitimate = self.releases / revision / "legitimate-validation.json"
            if legitimate.is_file():
                result["legitimate"] = json.loads(legitimate.read_text(encoding="utf-8"))
            audit = self.releases / revision / "coverage-audit.json"
            if audit.is_file():
                result["coverage_audit"] = json.loads(audit.read_text(encoding="utf-8"))["counts"]
            deployment = self.root / "deployment.json"
            if deployment.exists():
                settings = self.deployment()
                result["url"] = f"http://127.0.0.1:{settings['port']}"
                result["persistent"] = settings.get("revision") == revision and bool(settings.get("state_volume"))
        return {**result, **fuxa.coverage_counts(profile, result.get("protected", []), result.get("controls"),
                                                 result.get("protected_observed"))}

    def demo(self) -> dict:
        revision = self.active()
        if revision is None:
            raise RuntimeError("Ejecuta primero immune fuxa up")
        enforced = set(self.meta(revision)["enforced"])
        candidates = {**fuxa.OPERATIONS,
                      **{name: {"effect": boundary} for name, boundary in fuxa.PROTECTED_EFFECTS.items()}}
        operation = next((name for name in candidates if name not in enforced), None)
        if operation is None:
            return {"status": "already-enforced", "active": revision}
        return self.incident({
            "id": str(uuid.uuid4()), "revision": revision, "type": "effect", "decision": "observed",
            "boundary": candidates[operation]["effect"], "operation": operation, "role": "member",
        }, synthetic=True)

    def down(self) -> dict:
        with self.lock():
            containers = self.docker("ps", "-a", "--filter", f"label={self.label}", "--format", "{{.Names}}")
            for name in containers.splitlines():
                self.remove(name)
            for network in (self.internal, self.testnet):
                status = self.docker("network", "inspect", "--format",
                                     '{{index .Labels "immune.fuxa"}}', network, optional=True)
                if status and status.strip() == self.prefix:
                    self.docker("network", "rm", network)
        return {"status": "stopped"}
