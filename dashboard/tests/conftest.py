import os
import socket
import sys
import threading
import time

import pytest
import uvicorn

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from dashboard.server import create_app  # noqa: E402

TOKEN = "tok-test"


class Live:
    def __init__(self, store):
        self.store = str(store)
        self.app = create_app(self.store, TOKEN)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        self.port = s.getsockname()[1]
        s.close()
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                break
            time.sleep(0.05)
        self.url = f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.server.should_exit = True
        self.thread.join(5)


@pytest.fixture
def live(tmp_path):
    s = Live(tmp_path / "events.jsonl")
    yield s
    s.stop()


def ev(type_="attack.attempt", **data):
    return {"type": type_, "ts": time.time(), "run": "t", "src": "test", "rid": None, "incident": None,
            "data": data or {"vuln": "v", "ok": True, "saw_real_data": False}}
