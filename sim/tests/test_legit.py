import asyncio
import json
import socket
import threading
import time

import pytest
import uvicorn

from conftest import fresh_db, load_app
from sim import legit


def serve(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    t = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    assert server.started
    return server, t, "http://127.0.0.1:%d" % port


def stop(server, t):
    server.should_exit = True
    t.join(5)


def test_generator_clean_app_has_no_violations(seeded, tmp_path, monkeypatch, manifest):
    app = load_app(fresh_db(seeded, tmp_path / "live.db"), monkeypatch, frozen=False)
    server, t, base = serve(app)
    try:
        out = tmp_path / "sum.json"
        mf = tmp_path / "m.json"
        mf.write_text(json.dumps(manifest))
        rc = legit.main(["--base", base, "--users", "3", "--anon", "2", "--rate", "60", "--duration", "3",
                         "--manifest", str(mf), "--json", str(out), "--seed", "7"])
        s = json.loads(out.read_text())
        assert s["requests"] > 50
        assert s["violations"] == {} and s["server_errors"] == 0 and s["conn_errors"] == 0, s["problems"]
        assert rc == 0
    finally:
        stop(server, t)


def test_generator_flags_imm_header_and_marker(seeded, tmp_path, monkeypatch, manifest):
    inner = load_app(fresh_db(seeded, tmp_path / "bad.db"), monkeypatch, frozen=False)

    async def app(scope, receive, send):
        async def snd(msg):
            if msg["type"] == "http.response.start":
                msg = dict(msg, headers=list(msg["headers"]) + [(b"x-imm-verdict", b"clean")])
            await send(msg)
        await inner(scope, receive, snd)

    server, t, base = serve(app)
    try:
        stats = asyncio.run(legit.run(base, 1, 1, 60, 2, manifest, 3, quiet=True))
        assert stats.violations["x-imm-header"] > 0
        assert stats.bad > 0
    finally:
        stop(server, t)


def test_generator_connection_failure_is_failure(manifest):
    stats = asyncio.run(legit.run("http://127.0.0.1:1", 1, 0, 20, 1, manifest, 1, quiet=True))
    assert stats.conn_errors > 0 and stats.bad > 0
