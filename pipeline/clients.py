"""HTTP clients for the gateway admin API and fleet (timeouts on every call)."""
from __future__ import annotations

import time

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

    def rules(self) -> list:
        r = self._req("GET", "/_admin/rules")
        if r.status_code != 200:
            raise ServiceError("GET /_admin/rules -> %d" % r.status_code)
        return r.json().get("rules") or []

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
    DEPLOY_ATTEMPTS = 3
    RESTART_WAIT_S = 90.0

    def deploy(self, release: str, timeout: float = 300.0) -> dict:
        """Blue/green deploy. The fleet process can die and be restarted in the middle of it: a lost connection
        is not a failed deploy. Wait for the fleet to come back, see what is in production, and ask again."""
        last = ""
        for attempt in range(1, self.DEPLOY_ATTEMPTS + 1):
            try:
                r = self._req("POST", "/deploy", json={"release": release}, timeout=timeout)
            except ServiceError as e:
                last = str(e)
                st = self._wait_ready()
                if st is None:
                    continue
                if (st.get("prod") or {}).get("release") == release:
                    return {"ok": True, "rolled_back": False, "release": release, "attempts": attempt,
                            "active": (st.get("prod") or {}).get("active"),
                            "detail": "deployed (confirmed after the fleet restarted)"}
                continue
            if r.status_code == 409 and attempt < self.DEPLOY_ATTEMPTS:      # restarted, still taking over the run
                last = "fleet /deploy -> 409 %s" % r.text[:200]
                self._wait_ready()
                continue
            if r.status_code != 200:
                return {"ok": False, "rolled_back": False,
                        "detail": "fleet /deploy -> %d %s" % (r.status_code, r.text[:300])}
            res = r.json()
            if attempt > 1:
                res["attempts"] = attempt
            return res
        raise ServiceError("deploy of %s: no answer from the fleet after %d attempts (%s)"
                           % (release, self.DEPLOY_ATTEMPTS, last))

    def _wait_ready(self) -> dict | None:
        end = time.time() + self.RESTART_WAIT_S
        while time.time() < end:
            try:
                st = self.state()
                if st.get("ready", True) and (st.get("prod") or {}).get("active"):
                    return st
            except ServiceError:
                pass
            time.sleep(0.5)
        return None

    def state(self) -> dict:
        r = self._req("GET", "/state")
        if r.status_code != 200:
            raise ServiceError("GET /state -> %d" % r.status_code)
        return r.json()
