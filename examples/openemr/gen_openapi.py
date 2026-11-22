"""Write overlay/.immune/openapi.yaml for OpenEMR 8.2.0 from the tag's own sources.

    python examples/openemr/gen_openapi.py [--app examples/openemr/app]

- the REST / FHIR API: swagger/openemr-api.yaml of v8_2_0 (OpenEMR's own spec), paths under /apis/default;
- the web UI: every PHP script reachable over HTTP under interface/, portal/ and the docroot entry points,
  as GET + POST operations. Their parameters are not declared, so the gateway applies its default grammar
  to every value (anything unusual is detonated in a shadow clone first);
- the login form with clearPass marked x-sensitive (never judged or recorded), the health and session
  introspection endpoints.
"""
from __future__ import annotations

import argparse
import os

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIRS = ["interface", "portal"]
ENTRY = ["index.php", "controller.php"]
SKIP_PARTS = {"vendor", "node_modules", "tests", "test"}


def php_paths(app: str) -> list[str]:
    out = [p for p in ENTRY if os.path.isfile(os.path.join(app, p))]
    for d in WEB_DIRS:
        for root, dirs, files in os.walk(os.path.join(app, d)):
            dirs[:] = sorted(x for x in dirs if x not in SKIP_PARTS)
            for f in sorted(files):
                if f.endswith(".php"):
                    out.append(os.path.relpath(os.path.join(root, f), app).replace(os.sep, "/"))
    return sorted(set(out))


def ui_operation(path: str) -> dict:
    tag = path.split("/")[0]
    return {"get": {"tags": [tag], "summary": "OpenEMR UI script", "responses": {"200": {"description": "page"}}},
            "post": {"tags": [tag], "summary": "OpenEMR UI script (form)",
                     "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "object"}},
                                                 "multipart/form-data": {"schema": {"type": "object"}}}},
                     "responses": {"200": {"description": "page"}}}}


def oauth2_paths() -> dict:
    """The OAuth2 endpoints of oauth2/ (served by ApiApplication; they are outside the REST/FHIR spec of the
    tag, so until now the gateway classified them without grammar). Declaring them gives the classifier its
    parameter grammar and the observer its input extraction (CVE-2026-67610 / 67611 live here)."""
    O = "/oauth2/default"
    return {
        O + "/registration": {"post": {
            "tags": ["oauth2"], "summary": "Dynamic client registration (unauthenticated in 8.2.0, CWE-306)",
            "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
                "client_name": {"type": "string", "maxLength": 255},
                "redirect_uris": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 512}},
                "grant_types": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 32}},
                "scope": {"type": "string", "maxLength": 1024},
                "token_endpoint_auth_method": {"type": "string", "maxLength": 32},
                "jwks": {"type": "object"},
                "contacts": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 255}},
                "post_logout_redirect_uris": {"type": "array", "maxItems": 8,
                                              "items": {"type": "string", "maxLength": 512}},
                "initiate_login_uri": {"type": "string", "maxLength": 512}}}}}},
            "responses": {"200": {"description": "client registered"}, "400": {"description": "rejected"}}}},
        O + "/token": {"post": {
            "tags": ["oauth2"], "summary": "Token endpoint (authorization_code, password, client_credentials)",
            "x-owner-scoped": True,   # uid-less requests here (password/client_credentials grants) get
                                      # detonated: the profile's `mfa` oracle probes the second-factor
            "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "object",
                "properties": {
                    "grant_type": {"type": "string", "maxLength": 40},
                    "client_id": {"type": "string", "maxLength": 80},
                    "client_secret": {"type": "string", "x-sensitive": True},
                    "client_assertion": {"type": "string", "x-sensitive": True},
                    "client_assertion_type": {"type": "string", "maxLength": 128},
                    "username": {"type": "string", "maxLength": 255},
                    "password": {"type": "string", "x-sensitive": True},
                    "mfa_token": {"type": "string", "maxLength": 8},
                    "scope": {"type": "string", "maxLength": 1024},
                    "code": {"type": "string", "maxLength": 128},
                    "redirect_uri": {"type": "string", "maxLength": 512},
                    "code_verifier": {"type": "string", "maxLength": 128},
                    "refresh_token": {"type": "string", "x-sensitive": True}}}}}},
            "responses": {"200": {"description": "token"}, "400": {"description": "oauth error"}}}},
        O + "/authorize": {"get": {
            "tags": ["oauth2"], "summary": "Authorization endpoint",
            "parameters": [
                {"name": "client_id", "in": "query", "schema": {"type": "string", "maxLength": 80}},
                {"name": "redirect_uri", "in": "query", "schema": {"type": "string", "maxLength": 512}},
                {"name": "response_type", "in": "query", "schema": {"type": "string", "maxLength": 32}},
                {"name": "scope", "in": "query", "schema": {"type": "string", "maxLength": 1024}},
                {"name": "state", "in": "query", "schema": {"type": "string", "maxLength": 256}},
                {"name": "code_challenge", "in": "query", "schema": {"type": "string", "maxLength": 128}},
                {"name": "code_challenge_method", "in": "query", "schema": {"type": "string", "maxLength": 16}}],
            "responses": {"200": {"description": "login/consent page"}, "302": {"description": "redirect"}}}},
        O + "/introspect": {"post": {
            "tags": ["oauth2"], "summary": "Token introspection (RFC 7662)",
            "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "object",
                "properties": {"token": {"type": "string", "x-sensitive": True},
                               "client_id": {"type": "string", "maxLength": 80},
                               "client_secret": {"type": "string", "x-sensitive": True}}}}}},
            "responses": {"200": {"description": "introspection"}}}},
        O + "/userinfo": {"get": {"tags": ["oauth2"], "responses": {"200": {"description": "userinfo"}}}},
        O + "/jwk": {"get": {"tags": ["oauth2"], "responses": {"200": {"description": "JSON Web Keys"}}}},
        O + "/logout": {"get": {"tags": ["oauth2"], "responses": {"302": {"description": "logged out"}}}},
    }


def billing_paths() -> dict:
    """sl_eob_invoice.php with its encounter `id` declared (CVE-2026-124471: the page performs no ACL
    check). owner-scoped so any non-admin read is detonated in a shadow clone and the profile's `acl`
    oracle replays the missing authorization; `x-owner-id` feeds the enumeration heuristic for the
    id-iteration shape."""
    return {"/interface/billing/sl_eob_invoice.php": {
        "get": {"tags": ["billing"], "summary": "EOB posting - invoice editor (no ACL check in 8.2.0)",
                "x-owner-scoped": True,
                "parameters": [{"name": "id", "in": "query", "schema": {"type": "integer", "minimum": 0},
                                "x-owner-id": True}],
                "responses": {"200": {"description": "invoice page"}}},
        "post": {"tags": ["billing"], "summary": "Post payment, adjustment or billing note (no ACL check in 8.2.0)",
                 "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "object",
                     "properties": {"id": {"type": "integer", "minimum": 0},
                                    "form_save": {"type": "string", "maxLength": 4},
                                    "form_pid": {"type": "string", "maxLength": 12},
                                    "form_encounter": {"type": "string", "maxLength": 12},
                                    "form_method": {"type": "string", "maxLength": 32},
                                    "form_amount": {"type": "string", "maxLength": 16}}}}}},
                 "responses": {"200": {"description": "posted"}}}}}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", default=os.path.join(HERE, "app"))
    ap.add_argument("--out", default=os.path.join(HERE, "overlay", ".immune", "openapi.yaml"))
    a = ap.parse_args(argv)
    with open(os.path.join(a.app, "swagger", "openemr-api.yaml"), encoding="utf-8") as fh:
        api = yaml.safe_load(fh)
    base = "/" + (api.get("servers") or [{"url": "/apis/default/"}])[0]["url"].strip("/")
    paths = {}
    for p, ops in (api.get("paths") or {}).items():
        paths[base + "/" + p.lstrip("/")] = ops
    for p in php_paths(a.app):
        paths.setdefault("/" + p, ui_operation(p))
    paths["/interface/main/main_screen.php"] = {
        "get": ui_operation("interface/main/main_screen.php")["get"],
        "post": {"tags": ["interface"], "summary": "Login (auth=login) and session screens",
                 "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": {
                     "type": "object", "properties": {
                         "authUser": {"type": "string", "maxLength": 255},
                         "clearPass": {"type": "string", "x-sensitive": True},
                         "new_login_session_management": {"type": "string", "maxLength": 4},
                         "languageChoice": {"type": "string", "maxLength": 8}}}}}},
                 "responses": {"302": {"description": "logged in"}, "200": {"description": "login page"}}}}
    paths["/meta/health/readyz"] = {"get": {"tags": ["meta"], "responses": {"200": {"description": "ready"}}}}
    paths["/meta/health/livez"] = {"get": {"tags": ["meta"], "responses": {"200": {"description": "alive"}}}}
    paths["/_immune/whoami"] = {"get": {"tags": ["immune"], "summary": "Session introspection (Immune)",
                                        "responses": {"200": {"description": "{id, role}"}}}}
    paths.update(oauth2_paths())
    paths.update(billing_paths())
    spec = {"openapi": "3.0.0",
            "info": {"title": "OpenEMR 8.2.0 (tag v8_2_0) as seen by Immune's gateway", "version": "8.2.0"},
            "paths": dict(sorted(paths.items())), "components": api.get("components") or {}}
    with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# Generated by examples/openemr/gen_openapi.py from OpenEMR v8_2_0 (swagger/openemr-api.yaml and the\n"
                 "# PHP scripts under interface/ and portal/). Do not edit by hand: re-run the script.\n")
        yaml.safe_dump(spec, fh, sort_keys=False, allow_unicode=True, width=120)
    print("%d paths -> %s" % (len(paths), a.out))


if __name__ == "__main__":
    main()
