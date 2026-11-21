"""Stdlib-only demo app for the sidecar's *launch* mode test (runs inside the sidecar image, started by
the sidecar as a traced child). /download joins without containment; /safe-download checks it."""
import json
import os
import subprocess  # noqa: F401  (imported at startup so that lazy imports do not show up as file opens)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

STATIC = os.environ.get("APP_STATIC", os.path.join(os.path.dirname(os.path.abspath(__file__)), "static"))


class H(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="application/json"):
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/health":
            return self._send(200, {"ok": True})
        if u.path in ("/download", "/safe-download"):
            path = os.path.join(STATIC, q.get("name", ""))
            if u.path == "/safe-download" and not os.path.realpath(path).startswith(os.path.realpath(STATIC) + os.sep):
                return self._send(404, {"detail": "not found"})
            try:
                with open(path, "rb") as f:
                    return self._send(200, f.read(), "application/octet-stream")
            except OSError:
                return self._send(404, {"detail": "not found"})
        if u.path == "/lookup":
            out = subprocess.run(["/bin/sh", "-c", "echo " + q.get("host", "")], capture_output=True).stdout
            return self._send(200, {"out": out.decode()})
        return self._send(404, {"detail": "Not Found"})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("PORT", "3000"))), H).serve_forever()
