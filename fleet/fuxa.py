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
import urllib.request
import uuid
from pathlib import Path

from immune import fuxa

CONTROL = "/run/immune/active"
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

    def make_release(self, enforced: set[str]) -> str:
        digest = self.profile()["source_digest"]
        if fuxa.fingerprint(self.source) != digest:
            raise ValueError("El código fuente local no coincide con el perfil")
        key = (digest, fuxa.fingerprint(fuxa.ASSETS), sorted(enforced))
        revision = hashlib.sha256(json.dumps(key).encode()).hexdigest()[:12]
        dest = self.releases / revision
        dest.mkdir(parents=True, exist_ok=True)
        fuxa.instrument(self.source, dest, enforced)
        fuxa.write_json(dest / "release.json", {"revision": revision, "enforced": sorted(enforced)})
        return revision

    def sandbox(self) -> list[str]:
        return ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "256", "--memory", "1g", "--label", self.label]

    def mounts(self, revision: str) -> list[str]:
        result = []
        files = sorted({policy["file"] for policy in fuxa.OPERATIONS.values()})
        for file in files:
            host_path = self.releases / revision / file
            result += ["--mount", f"type=bind,src={host_path},dst=/app/{file},readonly"]
        return result

    def test(self, revision: str) -> None:
        enforced = ",".join(self.meta(revision)["enforced"])
        run = ["run", "--rm", *self.sandbox(), "--tmpfs", "/tmp:uid=1000,gid=1000,mode=0700",
               *self.mounts(revision)]
        self.docker(*run, "--network", "none", self.image, "node", "/immune/check.cjs", enforced, timeout=60)
        # The upstream interface discovery test requires an interface besides loopback.
        self.ensure_network(self.testnet)
        self.docker(*run, "--network", self.testnet, self.image, "npm", "test", timeout=150)

    def ensure_network(self, network: str) -> None:
        status = self.docker("network", "inspect", "--format",
                             '{{.Internal}} {{index .Labels "immune.fuxa"}}', network, optional=True)
        if status is None:
            self.docker("network", "create", "--internal", "--label", self.label, network)
        elif status.strip() != f"true {self.prefix}":
            raise RuntimeError("La red no pertenece a la demo o permite salida")

    def start(self, revision: str) -> None:
        self.remove(self.backend(revision))
        self.docker("run", "-d", "--name", self.backend(revision), *self.sandbox(),
                    "--network", self.internal, "--tmpfs", "/lab:uid=1000,gid=1000,mode=0700",
                    "--tmpfs", "/telemetry:uid=1000,gid=1000,mode=0700,size=32m",
                    "--tmpfs", "/tmp:uid=1000,gid=1000,mode=0700", *self.mounts(revision),
                    "-e", f"IMMUNE_FUXA_REVISION={revision}", self.image, "node", "/immune/start.cjs")

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

    def up(self, port: int) -> dict:
        if not 1 <= port <= 65535:
            raise ValueError("Puerto inválido")
        with self.lock():
            if self.active():
                return self.status()
            revision = self.make_release(set())
            self.build()
            self.test(revision)
            self.ensure_network(self.internal)
            self.remove(self.gateway)
            try:
                self.start(revision)
                self.docker("run", "-d", "--name", self.gateway, *self.sandbox(),
                            "-p", f"127.0.0.1:{port}:1881",
                            "--tmpfs", "/run/immune:uid=1000,gid=1000,mode=0700",
                            self.image, "node", "/immune/gateway.cjs")
                self.docker("network", "connect", self.internal, self.gateway)
                smoke = self.local_smoke(revision)
                self.activate(revision)
                self.gateway_smoke(revision, smoke, port)
                fuxa.write_json(self.root / "deployment.json", {"port": port, "smoke": smoke})
            except Exception:
                self.remove(self.gateway)
                self.remove(self.backend(revision))
                raise
            return self.status()

    def promote(self, old: str, candidate: str) -> str | None:
        settings = json.loads((self.root / "deployment.json").read_text(encoding="utf-8"))
        self.test(candidate)
        if self.active() != old:
            raise RuntimeError("Cambió la revisión durante la validación")
        try:
            self.start(candidate)
            smoke = self.local_smoke(candidate)
            if smoke != settings["smoke"]:
                raise RuntimeError("Cambió una respuesta legítima de FUXA")
            self.activate(candidate)
            self.gateway_smoke(candidate, smoke, settings["port"])
        except Exception:
            if self.active() == candidate:
                self.activate(old)
            if self.active() == old:
                self.remove(self.backend(candidate))
                self.gateway_smoke(old, settings["smoke"], settings["port"])
            raise
        try:
            self.remove(self.backend(old))
        except (OSError, RuntimeError, subprocess.SubprocessError):
            return "El gateway sirve el candidato. La limpieza del contenedor anterior quedó pendiente."
        return None

    def incident(self, event: dict, *, synthetic: bool = False) -> dict:
        with self.lock():
            old = self.active()
            if fuxa.assess(event, old) != "incident":
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
            candidate = self.make_release(enforced | {operation})
            file = fuxa.OPERATIONS[operation]["file"]
            before = (self.releases / old / file).read_text(encoding="utf-8")
            after = (self.releases / candidate / file).read_text(encoding="utf-8")
            guard = f'immuneMonitor.authorize("{operation}", '
            if before.count(guard + '"observe"') != 1 or after != before.replace(
                guard + '"observe"', guard + '"enforce"'
            ):
                raise RuntimeError("El parche no pasó la política de cambios")
            for other in self.mount_files() - {file}:
                if (self.releases / old / other).read_bytes() != (self.releases / candidate / other).read_bytes():
                    raise RuntimeError("El parche modifica otro archivo instrumentado")
            patch = difflib.unified_diff(before.splitlines(True), after.splitlines(True), "a/" + file, "b/" + file)
            (directory / "candidate.diff").write_text("".join(patch), encoding="utf-8", newline="\n")
            result = {key: event[key] for key in ("id", "operation", "role", "boundary")}
            result.update(status="validating", previous=old, candidate=candidate,
                          synthetic=synthetic, started=time.time())
            fuxa.write_json(receipt, result)
            try:
                cleanup = self.promote(old, candidate)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                result.update(status="failed", detail=str(error))
            else:
                result["status"] = "deployed"
                if cleanup:
                    result["detail"] = cleanup
            result["finished"] = time.time()
            fuxa.write_json(receipt, result)
            return result

    @staticmethod
    def mount_files() -> set[str]:
        return {policy["file"] for policy in fuxa.OPERATIONS.values()}

    def watch(self, last: tuple | None) -> tuple | None:
        revision = self.active()
        if revision is None:
            raise RuntimeError("No hay una revisión activa")
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
            raise RuntimeError("No se pudo leer la telemetría del contenedor activo")
        batch = json.loads(data)
        for message in batch["entries"]:
            try:
                event = json.loads(message)
            except ValueError:
                continue
            verdict = fuxa.assess(event, revision)
            if verdict is None:
                continue
            if verdict == "incident":
                result = self.incident(event)
            else:
                result = {"status": verdict, "operation": event["operation"], "id": event["id"]}
                if verdict == "alert":
                    with (self.root / "signals.jsonl").open("a", encoding="utf-8") as signals:
                        signals.write(json.dumps({**result, "http_status": event["status"], "ts": time.time()}) + "\n")
            print(json.dumps(result, ensure_ascii=False), flush=True)
            if result["status"] == "deployed":
                break
        current = (container, batch["offset"])
        fuxa.write_json(cursor, current)
        return current

    def status(self) -> dict:
        revision = self.active()
        profile = self.profile()
        result = {"tag": profile["tag"], "commit": profile["commit"], "active": revision,
                  "coverage": list(profile["policies"]),
                  "pending": sum(row["coverage"] == "pending" for row in profile["operations"])}
        if revision:
            result.update(self.meta(revision))
            deployment = self.root / "deployment.json"
            if deployment.exists():
                port = json.loads(deployment.read_text(encoding="utf-8"))["port"]
                result["url"] = f"http://127.0.0.1:{port}"
        return result

    def demo(self) -> dict:
        revision = self.active()
        if revision is None:
            raise RuntimeError("Ejecuta primero immune fuxa up")
        enforced = set(self.meta(revision)["enforced"])
        operation = next((name for name in fuxa.OPERATIONS if name not in enforced), None)
        if operation is None:
            return {"status": "already-enforced", "active": revision}
        return self.incident({
            "id": str(uuid.uuid4()), "revision": revision, "type": "effect", "decision": "observed",
            "boundary": fuxa.OPERATIONS[operation]["effect"], "operation": operation, "role": "member",
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
