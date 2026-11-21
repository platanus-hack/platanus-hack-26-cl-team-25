import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import uvicorn  # noqa: E402

from dashboard.server import create_app  # noqa: E402


def main() -> None:
    host = os.environ.get("DASH_HOST", "0.0.0.0")
    port = int(os.environ.get("DASH_PORT", "8090"))
    app = create_app()
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    on_signal = server.handle_exit

    def handle_exit(sig, frame):
        # An open event stream never ends by itself, and uvicorn waits for open connections before it exits:
        # without this a restart leaves the old process alive and the pages attached to it, receiving nothing.
        app.state.bus.closing = True
        on_signal(sig, frame)

    server.handle_exit = handle_exit
    server.run()


if __name__ == "__main__":
    main()
