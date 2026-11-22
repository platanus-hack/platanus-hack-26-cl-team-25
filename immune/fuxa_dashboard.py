"""Expose FUXA Fleet records through the existing Immune dashboard."""
from __future__ import annotations

import asyncio
import contextlib
import json
import subprocess
import time
from pathlib import Path

import uvicorn
from starlette.responses import JSONResponse
from starlette.routing import Route

from dashboard.server import create_app
from fleet.fuxa import FuxaFleet
from immune.fuxa import POLICY_REASONS, coverage_counts, protected_operation
from immune_contracts import events


REQUEST_FIELDS = ("ts", "method", "path", "status", "transport", "ms")
ROLE_LABEL = {"member": "usuario sin privilegios", "anonymous": "anónimo", "admin": "administrador",
              "unknown": "desconocido"}
OPERATION_LABEL = {
    "tag_write": "Escritura de tag (Socket.IO device-values)",
    "device_control": "Control de dispositivo (Socket.IO device-enable)",
    "historian_query": "Consulta del histórico (Socket.IO daq-query)",
    "scheduler_authorization": "Cambio de programación (/api/scheduler)",
    "settings.write": "Escritura de configuración (/api/settings)",
    "system-function.run": "Función del sistema (/api/runSysFunction)",
}
GATEWAY_REASONS = {"device_control", "tag_write", "historian_query", "scheduler_without_token"}


def event(kind: str, data: dict, stamp: float, incident: str | None = None, rid: str | None = None) -> dict:
    return {**events.make(kind, "fuxa", data, run="fuxa-v1.2.9", incident=incident, rid=rid), "ts": stamp}


class Feed:
    def __init__(self, root: Path):
        self.fleet = FuxaFleet(root)
        self.root = root
        self.profile = self.fleet.profile()
        self.active = None
        self.receipts = {}
        self.gateway_signals = {}
        # Correlation between the gateway request and the server-side verdict.
        # HTTP operations share the op id; Socket.IO operations join by (sid, operation).
        self.socket_index = {}
        self.outcomes = {}
        self.restrictions = {}
        self.gate_seen = {}
        self.rule_seen = set()
        self.rule_off = set()
        self.signal_offset = 0

    def requests(self, tail=40) -> dict:
        try:
            lines = self.fleet.docker("logs", "--tail", str(tail), self.fleet.gateway, timeout=5, optional=True)
        except (OSError, RuntimeError, subprocess.SubprocessError):
            lines = None
        rows = []
        for line in (lines or "").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict) or row.get("type") != "fuxa.request" or not all(
                key in row for key in REQUEST_FIELDS
            ):
                continue
            request = {key: row[key] for key in REQUEST_FIELDS}
            ident = row.get("id")
            if isinstance(ident, str):
                request["id"] = ident
            sid = row.get("sid")
            if isinstance(sid, str):
                request["sid"] = sid
            reason = row.get("reason")
            if isinstance(reason, str) and reason in GATEWAY_REASONS:
                request.update({"class": "blocked" if row.get("blocked") is True else "suspect",
                                "reason": reason, "id": row.get("id")})
            elif request["transport"] == "http" and request["status"] in (401, 403):
                request["class"] = "suspect"
            else:
                request["class"] = "uninspected" if reason == "not_inspected" else "clean"
            outcome = self.outcome_of(request, reason)
            if outcome:
                request["verdict"] = outcome
            rows.append(request)
        return {"available": lines is not None, "requests": rows[::-1]}

    def outcome_of(self, request: dict, reason) -> str | None:
        ident = request.get("id")
        if isinstance(ident, str) and ident in self.outcomes:
            return self.outcomes[ident]["class"]
        sid = request.get("sid")
        if isinstance(sid, str) and isinstance(reason, str):
            ident = self.socket_index.get(("socket", sid, reason))
            if ident and ident in self.outcomes:
                return self.outcomes[ident]["class"]
        return None

    def remember_outcome(self, rid: str, classification: str, stamp: float) -> None:
        self.outcomes[rid] = {"class": classification, "ts": stamp}
        if len(self.outcomes) > 600:
            for key in list(self.outcomes)[: len(self.outcomes) - 600]:
                del self.outcomes[key]

    def operation_row(self, record: dict) -> dict:
        operation = record.get("operation")
        policy = self.profile["policies"].get(operation)
        if policy:
            return policy
        try:
            control = self.fleet.meta(record["candidate"]).get("controls", {}).get(operation)
        except (OSError, ValueError, RuntimeError):
            control = None
        if control:
            row = next((item for item in self.profile["operations"]
                        if (item.get("method"), item.get("route"), item.get("file"))
                        == (control["method"], control["route"], control["file"])), {})
            return {**control, "effect_line": row.get("line")}
        if operation in POLICY_REASONS:
            row = next((item for item in self.profile["operations"] if protected_operation(item) == operation), {})
            if row.get("transport") == "socket.io":
                return {"method": "Socket.IO", "route": "/socket.io " + str(row.get("event", "")).lower(),
                        "file": row.get("file", "server/runtime/index.js"), "effect_line": row.get("line")}
            return {"method": row.get("method", "HTTP"), "route": POLICY_REASONS[operation],
                    "file": row.get("file", "server/api/scheduler/index.js"), "effect_line": row.get("line")}
        return {"method": None, "route": None, "file": None, "effect_line": None}

    def analysis(self, record: dict, operation: dict, stamp: float) -> dict:
        """The incident's evidence, shaped like the store's oracle report."""
        name = record.get("operation")
        role = record.get("role")
        detail = {
            "operation": OPERATION_LABEL.get(name, name),
            "role": ROLE_LABEL.get(role, role),
            "boundary": record.get("boundary"),
            "decision": "El control estaba en observación y el efecto se ejecutó con un rol sin permiso",
            "expected": "Sólo un administrador puede ejecutar esta operación",
        }
        if isinstance(record.get("session"), str):
            detail["session"] = record["session"]
        socket = operation.get("method") == "Socket.IO"
        return event(events.ORACLE_FIRED, {
            "mode": "producción" if not record.get("synthetic") else "simulación",
            "status": None if socket else 200,
            "role": role,
            "request": {"method": operation.get("method"), "path": operation.get("route"), "query": ""},
            "events": [{
                "oracle": "autorización",
                "detail": detail,
                "stack": [{"file": operation.get("file"), "line": operation.get("effect_line")}]
                if operation.get("file") else [],
            }],
        }, stamp, record["id"], rid=record["id"])

    def pending_gates(self, ident: str, record: dict, stamp: float) -> list[dict]:
        seen = self.gate_seen.setdefault(ident, set())
        batch = []
        for name, gate in (record.get("gates") or {}).items():
            if name in seen:
                continue
            seen.add(name)
            batch.append(event(events.GATE_RESULT, {
                "attempt": 1, "gate": name, "ok": bool(gate.get("ok")),
                "detail": gate.get("detail"),
            }, stamp, ident))
        return batch

    def collect(self) -> list[dict]:
        now = time.time()
        try:
            live = self.fleet.status()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            live = {}
        cursor = self.root / "watch-cursor.json"
        status = {
            "active": live.get("active"),
            "enforced": live.get("enforced", []),
            "protected": live.get("protected", []),
            "persistent": live.get("persistent", False),
            "validation": live.get("validation"),
            "legitimate": live.get("legitimate"),
            "patch_mode": live.get("patch_mode"),
            "coverage": list(self.profile["policies"]),
            "coverage_audit": live.get("coverage_audit"),
            **coverage_counts(self.profile, live.get("protected", []), live.get("controls"),
                              live.get("protected_observed")),
            "monitor": cursor.exists() and now - cursor.stat().st_mtime < 12,
        }
        batch = []
        if status != self.active:
            self.active = status
            batch.append(event(events.FUXA_STATUS, status, now))
        if status["active"]:
            for request in reversed(self.requests(tail=120)["requests"]):
                ident = request.get("id")
                if not isinstance(ident, str) or ident in self.gateway_signals:
                    continue
                self.gateway_signals[ident] = None
                if len(self.gateway_signals) > 400:
                    del self.gateway_signals[next(iter(self.gateway_signals))]
                sid = request.get("sid")
                if isinstance(sid, str) and isinstance(request.get("reason"), str):
                    self.socket_index.setdefault(("socket", sid, request["reason"]), ident)
                batch.append(event(events.REQ_CLASSIFIED, {
                    "class": request["class"], "method": request["method"], "path": request["path"],
                    "status": request["status"], "reason": request.get("reason"),
                    **({"verdict": request["verdict"]} if "verdict" in request else {}),
                }, request["ts"], rid=ident))
        records = []
        for receipt in (self.root / "incidents").glob("*/incident.json"):
            try:
                records.append((receipt.stat().st_mtime, receipt, json.loads(receipt.read_text(encoding="utf-8"))))
            except (OSError, ValueError):
                continue
        for modified, receipt, record in sorted(records):
            ident = record["id"]
            if record["status"] == self.receipts.get(ident):
                continue
            operation = self.operation_row(record)
            started = record.get("started", modified)
            if ident not in self.receipts:
                batch.append(event(events.REQ_CLASSIFIED, {
                    "class": "simulation" if record.get("synthetic") else "evidence",
                    "method": operation["method"], "path": operation["route"],
                }, started, ident, rid=ident))
                batch.append(event(events.INCIDENT_OPENED, {
                    "vuln_class": "Autorización", "route": operation["route"],
                    "method": operation.get("method"), "evidence_rid": ident,
                    "sink": {"file": operation["file"], "line": operation["effect_line"]},
                    "fuxa": {"synthetic": record.get("synthetic", False), "role": record["role"],
                             "timed": "started" in record},
                }, started, ident))
                batch.append(self.analysis(record, operation, started))
                batch.append(event(events.PATCH_ATTEMPT, {"attempt": 1, "source": "control de autorización"},
                                   started, ident))
                diff = receipt.with_name("candidate.diff")
                if diff.exists():
                    batch.append(event(events.PATCH_DIFF, {"attempt": 1, "diff": diff.read_text(encoding="utf-8")},
                                       started, ident))
            batch.extend(self.pending_gates(ident, record, started))
            rule = record.get("rule") or {}
            if rule.get("id") and ident not in self.rule_seen:
                self.rule_seen.add(ident)
                batch.append(event(events.RULE_ACTIVE, {
                    "id": rule["id"], "method": operation.get("method") or "operación",
                    "route": operation.get("route") or operation.get("operation"),
                    "scope": rule.get("scope", "operación"), "ttl_s": rule.get("ttl_s"),
                    "operations": rule.get("operations") or [record.get("operation")],
                    "learned": bool(rule.get("learned")),
                }, started, ident))
            if record["status"] == "deployed" and rule.get("id") and ident not in self.rule_off:
                self.rule_off.add(ident)
                batch.append(event(events.RULE_EXPIRED, {"id": rule["id"], "reason": "patched"},
                                   record.get("finished", modified), ident))
            if record["status"] == "review":
                batch.append(event(events.FUXA_REVIEW, {}, record.get("reviewed_at", modified), ident))
            elif record["status"] != "validating":
                deployed = record["status"] == "deployed"
                legacy_rollback = record["status"] == "failed" and record.get("synthetic") and (
                    record.get("detail") == "synthetic post-switch verification failure"
                )
                rolled_back = record.get("rolled_back") is True or legacy_rollback
                finished = record.get("finished", modified)
                if deployed:
                    detail = "Validaciones superadas y revisión verificada en el gateway."
                elif rolled_back:
                    detail = f"Inmune restauró y verificó la revisión {record['previous']} después de un fallo."
                else:
                    detail = "Candidato rechazado. Consulta el registro del incidente para ver el motivo."
                batch.append(event(events.DEPLOY_DONE, {
                    "release": record["candidate"], "ok": deployed, "rolled_back": bool(rolled_back),
                    "detail": detail,
                }, finished, ident))
                outcome = "patched" if deployed else "rolled_back" if rolled_back else "rejected"
                batch.append(event(events.INCIDENT_CLOSED, {"outcome": outcome}, finished, ident))
            self.receipts[ident] = record["status"]
        signal_file = self.root / "signals.jsonl"
        if signal_file.is_file():
            with signal_file.open("rb") as signals:
                signals.seek(self.signal_offset)
                while line := signals.readline():
                    if not line.endswith(b"\n"):
                        break
                    self.signal_offset = signals.tell()
                    try:
                        signal = json.loads(line)
                    except ValueError:
                        continue
                    verdict = signal.get("verdict")
                    status = signal.get("status")
                    if status in ("restricted", "released"):
                        session = signal.get("session")
                        if not isinstance(session, str):
                            continue
                        ident = signal.get("id")
                        rid = ident if isinstance(ident, str) else None
                        if status == "restricted":
                            self.restrictions[session] = signal
                            batch.append(event(events.SESSION_RESTRICTED, {
                                "session": session, "operations": signal.get("operations", []),
                                "reason": signal.get("reason"), "expires": signal.get("expires"),
                            }, signal["ts"], rid=rid))
                        else:
                            self.restrictions.pop(session, None)
                            batch.append(event(events.SESSION_RELEASED, {
                                "session": session, "reason": signal.get("reason"),
                            }, signal["ts"], rid=rid))
                        continue
                    reason = signal.get("reason")
                    if isinstance(reason, str) and reason in POLICY_REASONS:
                        method = "Socket.IO" if POLICY_REASONS[reason] == "/socket.io" else "HTTP"
                        path = POLICY_REASONS[reason]
                        session = signal.get("session")
                        ident = signal.get("id")
                        rid = ident if isinstance(ident, str) else None
                        if POLICY_REASONS[reason] == "/socket.io" and isinstance(session, str):
                            # One operation, one row: join the verdict with the
                            # gateway request that delivered the Socket.IO event.
                            rid = self.socket_index.get(("socket", session, reason), rid)
                    else:
                        operation = self.profile["policies"].get(signal.get("operation"))
                        if not operation:
                            continue
                        method, path = operation["method"], operation["route"]
                        ident = signal.get("id")
                        rid = ident if isinstance(ident, str) else None
                    classification = status if status in ("blocked", "authorized", "unavailable") else "suspect"
                    if isinstance(rid, str):
                        self.remember_outcome(rid, classification, signal["ts"])
                    batch.append(event(events.REQ_CLASSIFIED, {
                        "class": classification, "method": method,
                        "path": path, "status": signal["http_status"], "reason": reason,
                        **({"verdict": verdict} if isinstance(verdict, str) else {}),
                    }, signal["ts"], rid=rid))
        return batch


    def restrictions_snapshot(self) -> list[dict]:
        path = self.root / "signals.jsonl"
        active: dict[str, dict] = {}
        if path.is_file():
            with path.open(encoding="utf-8", errors="replace") as records:
                for line in records:
                    try:
                        signal = json.loads(line)
                    except ValueError:
                        continue
                    session = signal.get("session")
                    status = signal.get("status")
                    if not isinstance(session, str):
                        continue
                    if status == "restricted":
                        active[session] = {
                            "session": session, "operations": signal.get("operations", []),
                            "reason": signal.get("reason"), "expires": signal.get("expires"),
                            "ts": signal.get("ts"),
                        }
                    elif status == "released":
                        active.pop(session, None)
        return sorted(active.values(), key=lambda item: (item.get("expires") or 0, item["session"]))


def serve(root: Path, port: int) -> None:
    if not 1 <= port <= 65535:
        raise ValueError("Puerto inválido")
    feed = Feed(root)

    @contextlib.asynccontextmanager
    async def lifespan(app):
        bus = app.state.bus

        async def refresh():
            while True:
                batch = await asyncio.to_thread(feed.collect)
                if batch:
                    await bus.publish(batch)
                await asyncio.sleep(2)

        task = asyncio.create_task(refresh())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def live_requests(_request):
        snapshot = await asyncio.to_thread(feed.requests)
        return JSONResponse(snapshot, headers={"Cache-Control": "no-store"})

    async def live_restrictions(_request):
        snapshot = await asyncio.to_thread(feed.restrictions_snapshot)
        return JSONResponse({"restrictions": snapshot}, headers={"Cache-Control": "no-store"})

    app = create_app(store="", token="", lifespan=lifespan)
    app.router.routes.append(Route("/fuxa/requests", live_requests, methods=["GET"]))
    app.router.routes.append(Route("/fuxa/restrictions", live_restrictions, methods=["GET"]))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
