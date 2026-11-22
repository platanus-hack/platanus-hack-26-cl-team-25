"""python -m sidecar.httpds --port 3922 : authz oracle sidecar in front of one shadow ScadaBR.

Env (see sidecar/httpds/core.py Config): SHADOW_UPSTREAM, HTTPDS_MANIFEST, CLONE_ID, CLONE_KEY,
COLLECTOR_URL, RELEASE, SIDECAR_TIMEOUT_S.
"""
from __future__ import annotations

import argparse
import logging

import uvicorn

from .core import Config, Sidecar


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m sidecar.httpds")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    uvicorn.run(Sidecar(Config.from_env()), host=a.host, port=a.port, log_level="warning", access_log=False,
                lifespan="on", server_header=False, date_header=False)


if __name__ == "__main__":
    main()
