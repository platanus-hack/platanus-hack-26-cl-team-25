"""Client for the Coraza / OWASP-CRS detection sidecar (waf/).

Best-effort and fail-open by design: any error, timeout or non-200 means "not anomalous", so a WAF
outage never blocks traffic or changes the gateway's decision. The gateway consults it only for requests
positive security already called clean, and on an anomaly it DETONATES in a clone (never blocks).
"""
from __future__ import annotations

import base64
import logging

import httpx

log = logging.getLogger("gateway.waf")


class WafClient:
    def __init__(self, url: str, timeout_s: float = 1.5):
        self.url = url.rstrip("/")
        self.client = httpx.AsyncClient(timeout=timeout_s)

    async def aclose(self) -> None:
        await self.client.aclose()

    async def check(self, method: str, path: str, query: str, headers: dict, body: bytes) -> dict | None:
        """Return the sidecar's verdict dict ({anomalous, rule_id, ...}) or None (fail-open)."""
        if not self.url:
            return None
        payload = {"method": method, "path": path, "query": query or "",
                   "headers": {str(k): str(v) for k, v in (headers or {}).items()},
                   "body_b64": base64.b64encode(body or b"").decode()}
        try:
            r = await self.client.post(self.url + "/eval", json=payload)
            if r.status_code == 200:
                return r.json()
        except (httpx.HTTPError, ValueError) as e:
            log.debug("waf eval failed (fail-open): %s", e)
        return None
