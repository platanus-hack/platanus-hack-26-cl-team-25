"""Sidecar configuration: a YAML/JSON file (``--config``), overridable by env and CLI.

Flat keys (all optional except ``app_port``)::

    listen_host: 0.0.0.0          # where the sidecar serves the wire protocol
    listen_port: 8000
    app_host: 127.0.0.1           # the app, on the shared loopback
    app_port: 3000
    health: /health
    mode: attach                  # attach (--pid container:<app>) | launch (sidecar starts `command` traced)
    command: [node, server.js]    # launch mode only
    target_pid: null              # attach: anchor pid of the app (default: PID 1 of the shared namespace)
    allowed_file_roots: [/app/static]   # paths as seen by the app
    source_dirs: [/app]           # app source, scanned for string literals (sql taint rule 3)
    scan_executable_max_mb: 32    # also take printable strings of the app's executables up to this size
    warmup_paths: [/]             # benign GETs at startup (health and a 404 are always added)
    warmup_rounds: 2
    grace_ms: 30                  # how long events still count after the response (see README)
    request_timeout_s: 30
    profile: /path/profile.py     # or a module name: mint_token / identity_headers / ensure_user / identify / load_markers / public_paths
    identity_command: null        # shell; env IMM_UID/IMM_ROLE; stdout "Header: value" lines or a bare bearer token
    public_paths: []
    markers_path: null            # default env MARKERS_PATH
    postgres:                     # optional
      listen: 127.0.0.1:5432      # the app's DATABASE_URL points here
      upstream: pg:5432
      admin_url: postgres://postgres:pw@pg:5432/postgres
      database: clone
      template: seed

A product config (contracts/product.md §2/§6, with ``app:``/``database:`` sections) is also accepted:
``app.port``, ``app.health``, ``app.allowed_file_roots``, ``app.command``, ``app.source_dirs`` map to the
keys above and a ``sidecar:`` section supplies the rest.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class PgConfig:
    listen_host: str = "127.0.0.1"
    listen_port: int = 5432
    up_host: str = ""
    up_port: int = 5432
    admin_url: str = ""
    database: str = "clone"
    template: str = "seed"


@dataclass
class Config:
    listen_host: str = "0.0.0.0"
    listen_port: int = 8000
    app_host: str = "127.0.0.1"
    app_port: int = 3000
    health: str = "/health"
    mode: str = "attach"
    command: list = field(default_factory=list)
    target_pid: int | None = None
    allowed_file_roots: list = field(default_factory=list)
    source_dirs: list = field(default_factory=list)
    scan_executable_max_mb: int = 32
    warmup_paths: list = field(default_factory=list)
    warmup_rounds: int = 2
    grace_ms: int = 30
    request_timeout_s: float = 30.0
    profile: str | None = None
    identity_command: str | None = None
    public_paths: list = field(default_factory=list)
    markers_path: str | None = None
    postgres: PgConfig | None = None
    trace: bool = True
    clone_id: str = ""
    clone_key: str = ""
    collector_url: str | None = None
    release: str = ""


def _hostport(s: str, default_port: int):
    host, _, port = str(s).rpartition(":")
    return (host or "127.0.0.1"), int(port or default_port)


def _read(path: str) -> dict:
    with open(path) as f:
        text = f.read()
    try:
        return json.loads(text)
    except ValueError:
        import yaml
        return yaml.safe_load(text) or {}


def from_dict(d: dict) -> Config:
    d = dict(d or {})
    if isinstance(d.get("app"), dict):  # product config
        app = d["app"]
        flat = {"app_port": app.get("port"), "health": app.get("health"),
                "allowed_file_roots": app.get("allowed_file_roots"), "command": app.get("command"),
                "source_dirs": app.get("source_dirs")}
        if isinstance(d.get("shadow"), dict) and d["shadow"].get("profile"):
            flat["profile"] = d["shadow"]["profile"]
        flat.update(d.get("sidecar") or {})
        d = {k: v for k, v in flat.items() if v is not None}
    c = Config()
    pg = d.pop("postgres", None)
    for k, v in d.items():
        if hasattr(c, k) and v is not None:
            setattr(c, k, v)
    if pg:
        p = PgConfig()
        p.listen_host, p.listen_port = _hostport(pg.get("listen", "127.0.0.1:5432"), 5432)
        p.up_host, p.up_port = _hostport(pg["upstream"], 5432)
        p.admin_url = pg.get("admin_url", "")
        p.database = pg.get("database", p.database)
        p.template = pg.get("template", p.template)
        c.postgres = p
    c.app_port, c.listen_port, c.grace_ms = int(c.app_port), int(c.listen_port), int(c.grace_ms)
    return c


def load(path: str | None, env=None) -> Config:
    env = os.environ if env is None else env
    c = from_dict(_read(path)) if path else Config()
    c.clone_id = env.get("CLONE_ID", c.clone_id)
    c.clone_key = env.get("CLONE_KEY", c.clone_key)
    c.collector_url = env.get("COLLECTOR_URL", c.collector_url)
    c.release = env.get("RELEASE", c.release)
    c.markers_path = c.markers_path or env.get("MARKERS_PATH")
    if env.get("SIDECAR_GRACE_MS"):
        c.grace_ms = int(env["SIDECAR_GRACE_MS"])
    return c
