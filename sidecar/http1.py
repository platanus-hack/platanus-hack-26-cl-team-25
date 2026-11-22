"""Minimal HTTP/1.1 client to the app (one connection per request, ``Connection: close``).

We need the raw response (status, header list, body bytes exactly as sent, no decompression), so
we speak HTTP ourselves rather than through a client library that adds or rewrites headers.
"""
from __future__ import annotations

import asyncio

HOP = {b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"upgrade", b"te", b"trailer",
       b"content-length"}


class AppError(Exception):
    pass


async def request(host, port, method, target, headers, body: bytes, timeout: float):
    """headers: list[(bytes, bytes)] lowercase names. Returns (status, [(name, value)], body)."""
    return await asyncio.wait_for(_request(host, port, method, target, headers, body), timeout)


async def _request(host, port, method, target, headers, body):
    try:
        r, w = await asyncio.open_connection(host, port)
    except OSError as e:
        raise AppError(f"connect: {e!r}")
    try:
        lines = [f"{method} {target} HTTP/1.1".encode()]
        has_host = False
        for k, v in headers:
            if k in HOP:
                continue
            has_host |= k == b"host"
            lines.append(k + b": " + v)
        if not has_host:
            lines.append(f"host: {host}:{port}".encode())
        lines.append(b"connection: close")
        if body or method.upper() in ("POST", "PUT", "PATCH"):
            lines.append(b"content-length: " + str(len(body)).encode())
        w.write(b"\r\n".join(lines) + b"\r\n\r\n" + body)
        await w.drain()
        while True:
            status_line = await r.readline()
            if not status_line:
                raise AppError("empty response")
            parts = status_line.split(None, 2)
            status = int(parts[1])
            hdrs = []
            while True:
                line = await r.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                k, _, v = line.partition(b":")
                hdrs.append((k.strip().lower(), v.strip()))
            if 100 <= status < 200:
                continue  # 100 Continue / 103 Early Hints
            break
        hd = {}
        for k, v in hdrs:
            hd.setdefault(k, v)
        if method.upper() == "HEAD" or status in (204, 304):
            data = b""
        elif b"chunked" in hd.get(b"transfer-encoding", b"").lower():
            data = bytearray()
            while True:
                size_line = await r.readline()
                size = int(size_line.split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while (await r.readline()) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                data += await r.readexactly(size)
                await r.readexactly(2)
            data = bytes(data)
        elif b"content-length" in hd:
            data = await r.readexactly(int(hd[b"content-length"]))
        else:
            data = await r.read()
        return status, [(k, v) for k, v in hdrs if k not in HOP], data
    except (asyncio.IncompleteReadError, ConnectionError, ValueError, IndexError) as e:
        raise AppError(repr(e))
    finally:
        w.close()
