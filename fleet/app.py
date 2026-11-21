from __future__ import annotations

import logging
import threading

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .config import Config
from .manager import Fleet, FleetError


class ResetBody(BaseModel):
    release: str
    pool_size: int = 4


class DeployBody(BaseModel):
    release: str


def create_app(cfg: Config | None = None, fleet: Fleet | None = None) -> FastAPI:
    logging.basicConfig(level=logging.INFO)
    cfg = cfg or Config.from_env()
    if fleet is None:
        from .generic import make_fleet   # app.runtime generic -> GenericFleet (fleet/generic.py)
        fleet = make_fleet(cfg)
    app = FastAPI(title="fleet")
    app.state.fleet = fleet

    def auth(x_admin_token: str = Header(None)):
        if not cfg.admin_token or x_admin_token != cfg.admin_token:
            raise HTTPException(401, "unauthorized")

    def run(fn, *a):
        try:
            return fn(*a)
        except FleetError as e:
            raise HTTPException(e.status, str(e))

    @app.on_event("startup")
    def _start():
        threading.Thread(target=fleet.loop, daemon=True, name="reconcile").start()

    @app.on_event("shutdown")
    def _stop():
        fleet.stop()

    @app.post("/reset", dependencies=[Depends(auth)])
    def reset(b: ResetBody):
        return run(fleet.reset, b.release, b.pool_size)

    @app.post("/deploy", dependencies=[Depends(auth)])
    def deploy(b: DeployBody):
        return run(fleet.deploy, b.release)

    @app.get("/state", dependencies=[Depends(auth)])
    def state():
        return fleet.state()

    return app
