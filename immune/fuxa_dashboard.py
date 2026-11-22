"""Expose FUXA Fleet records through the existing Inmune dashboard."""
from __future__ import annotations

import asyncio
import contextlib
import json
import subprocess
import time
from pathlib import Path

import uvicorn

from dashboard.server import create_app
from fleet.fuxa import FuxaFleet
from immune_contracts import events


def event(kind: str, data: dict, stamp: float, incident: str | None = None, rid: str | None = None) -> dict:
    return {**events.make(kind, "fuxa", data, run="fuxa-v1.2.9", incident=incident, rid=rid), "ts": stamp}


class Feed:
    def __init__(self, root: Path):
        self.fleet = FuxaFleet(root)
        self.root = root
        self.profile = self.fleet.profile()
        self.active = None
        self.receipts = {}
        self.signal_offset = 0

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
            "coverage": list(self.profile["policies"]),
            "pending": sum(row["coverage"] == "pending" for row in self.profile["operations"]),
            "monitor": cursor.exists() and now - cursor.stat().st_mtime < 12,
        }
        batch = []
        if status != self.active:
            self.active = status
            batch.append(event(events.FUXA_STATUS, status, now))
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
            operation = self.profile["policies"][record["operation"]]
            started = record.get("started", modified)
            if ident not in self.receipts:
                batch.append(event(events.INCIDENT_OPENED, {
                    "vuln_class": "Autorización", "route": operation["route"],
                    "sink": {"file": operation["file"], "line": operation["effect_line"]},
                    "fuxa": {"synthetic": record.get("synthetic", False), "role": record["role"],
                             "timed": "started" in record},
                }, started, ident))
                batch.append(event(events.PATCH_ATTEMPT, {"attempt": 1, "source": "control de autorización"},
                                   started, ident))
                diff = receipt.with_name("candidate.diff")
                if diff.exists():
                    batch.append(event(events.PATCH_DIFF, {"attempt": 1, "diff": diff.read_text(encoding="utf-8")},
                                       started, ident))
            if record["status"] != "validating":
                deployed = record["status"] == "deployed"
                finished = record.get("finished", modified)
                batch.append(event(events.DEPLOY_DONE, {
                    "release": record["candidate"], "ok": deployed,
                    "detail": "Validaciones superadas y revisión verificada en el gateway" if deployed
                    else "Candidato rechazado. Consulta el registro del incidente para ver el motivo.",
                }, finished, ident))
                batch.append(event(events.INCIDENT_CLOSED, {"outcome": "patched" if deployed else "rejected"},
                                   finished, ident))
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
                    operation = self.profile["policies"][signal["operation"]]
                    batch.append(event(events.REQ_CLASSIFIED, {
                        "class": "suspect", "method": operation["method"], "path": operation["route"],
                    }, signal["ts"], rid=signal["id"]))
                    batch.append(event(events.REQ_ROUTED, {
                        "status": signal["http_status"],
                    }, signal["ts"], rid=signal["id"]))
        return batch


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

    uvicorn.run(create_app(store="", token="", lifespan=lifespan), host="127.0.0.1", port=port, log_level="warning")
