"""HTTP clients for the gateway admin API and fleet (timeouts on every call)."""
from __future__ import annotations

import httpx


class ServiceError(Exception):
    pass


class _Base:
    def __init__(self, url: str, token: str, timeout: float = 5.0):
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout

    def _req(self, method, path, timeout=None, **kw):
        try:
            r = httpx.request(method, self.url + path, headers={"x-admin-token": self.token},
                              timeout=timeout or self.timeout, **kw)
        except httpx.HTTPError as e:
            raise ServiceError("%s %s: %s" % (method, path, e)) from e
        return r


class GatewayAdmin(_Base):
    def post_rule(self, rule: dict) -> dict:
        r = self._req("POST", "/_admin/rules", json=rule)
        if r.status_code not in (200, 201):
            raise ServiceError("POST /_admin/rules -> %d %s" % (r.status_code, r.text[:200]))
        return r.json()

    def delete_rule(self, rule_id: str) -> bool:
        r = self._req("DELETE", "/_admin/rules/" + rule_id)
        if r.status_code == 404:
            return False
        if r.status_code >= 300:
            raise ServiceError("DELETE rule -> %d" % r.status_code)
        return True

    def prodlog(self, rid: str) -> dict:
        r = self._req("GET", "/_admin/prodlog", params={"rid": rid})
        if r.status_code != 200:
            raise ServiceError("GET prodlog -> %d" % r.status_code)
        return r.json()


class Fleet(_Base):
    def deploy(self, release: str, timeout: float = 300.0) -> dict:
        r = self._req("POST", "/deploy", json={"release": release}, timeout=timeout)
        if r.status_code != 200:
            return {"ok": False, "rolled_back": False, "detail": "fleet /deploy -> %d %s" % (r.status_code, r.text[:300])}
        return r.json()

    def state(self) -> dict:
        r = self._req("GET", "/state")
        if r.status_code != 200:
            raise ServiceError("GET /state -> %d" % r.status_code)
        return r.json()
