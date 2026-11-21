"""Shadow clone server: ``python -m shadow.run --profile <module> [--host H] --port P``.

Installs the instrumentation, then imports the profile/app, restores APP_DB from
SHADOW_SEED_DB, warms up, and serves the wrapped ASGI app with uvicorn. One
request at a time (asyncio lock); see contracts/README.md §5.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from . import instrument

instrument.install()  # before the app (or anything that imports sqlite3 users) is imported


class ShadowApp:
    def __init__(self, engine):
        self.engine = engine
        self.lock = asyncio.Lock()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self._lifespan(receive, send)
        if scope["type"] != "http":
            return  # websockets are not part of the victim contract
        body = bytearray()
        while True:
            msg = await receive()
            if msg["type"] == "http.request":
                body += msg.get("body", b"")
                if not msg.get("more_body", False):
                    break
            elif msg["type"] == "http.disconnect":
                return
        extra = {k: scope[k] for k in ("client", "server", "scheme", "http_version", "root_path", "raw_path") if k in scope}
        async with self.lock:
            res = await self.engine.handle(scope["method"], scope["path"], scope.get("query_string", b""),
                                           list(scope.get("headers", [])), bytes(body), extra)
            try:
                await send({"type": "http.response.start", "status": res.status, "headers": res.raw_headers})
                await send({"type": "http.response.body", "body": res.body, "more_body": False})
            finally:
                self.engine.finish(res)

    async def _lifespan(self, receive, send):
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                try:
                    await self.engine.start()
                except Exception as e:
                    logging.getLogger("shadow").exception("startup failed")
                    await send({"type": "lifespan.startup.failed", "message": repr(e)})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await self.engine.stop()
                await send({"type": "lifespan.shutdown.complete"})
                return


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m shadow.run")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--log-level", default=os.environ.get("SHADOW_LOG_LEVEL", "info"))
    a = ap.parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=a.log_level.upper(),
                        format="%(asctime)s shadow[%(process)d] %(levelname)s %(message)s")
    from .core import Engine
    engine = Engine(a.profile, os.environ.get("SHADOW_SEED_DB"), collector=os.environ.get("COLLECTOR_URL"),
                    clone_id=os.environ.get("CLONE_ID", ""), clone_key=os.environ.get("CLONE_KEY", ""),
                    release=os.environ.get("RELEASE", ""))
    import uvicorn
    uvicorn.run(ShadowApp(engine), host=a.host, port=a.port, log_level="warning", lifespan="on",
                access_log=False)


if __name__ == "__main__":
    main()
