"""python -m gateway : one asyncio process, three listeners (data, admin, clone ingest)."""
from __future__ import annotations

import asyncio
import contextlib
import logging
import signal

import uvicorn

from .core import Config, Gateway


class _Server(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self):  # signals are handled once for all three servers
        yield


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    cfg = Config.from_env()
    gw = Gateway(cfg)
    await gw.start()
    servers = [
        _Server(uvicorn.Config(app, host=cfg.host, port=port, log_level="warning", access_log=False,
                               lifespan="off", server_header=False, date_header=False,
                               interface="asgi3", proxy_headers=False))
        for app, port in ((gw.data_app, cfg.data_port), (gw.admin_app(), cfg.admin_port),
                          (gw.ingest_app(), cfg.ingest_port))
    ]

    def stop(*_):
        for s in servers:
            s.should_exit = True

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop)
    logging.getLogger("gateway").info("gateway up: data=%s admin=%s ingest=%s upstream=%s",
                                      cfg.data_port, cfg.admin_port, cfg.ingest_port, cfg.prod_addr)
    try:
        await asyncio.gather(*(s.serve() for s in servers))
    finally:
        await gw.stop()


if __name__ == "__main__":
    asyncio.run(main())
