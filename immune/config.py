"""`<project>/.immune/config.yaml` loader (contracts/product.md §2).

    from immune.config import load
    cfg = load("/path/to/project")          # -> Config (validated, absolute paths)

Every component takes its app-specific facts from this object. `current()` is the
process-wide instance: the project named by env `IMMUNE_PROJECT` (or `PROJECT_DIR`),
else IMMUNE_HOME (this repository, whose root `.immune/config.yaml` describes the
built-in demo app `victim`).

Placeholders
  app.env values         {db} {static} {secret}
  data.seed_command      {prod_db} {shadow_db} {manifest} {markers} {seed}
`{static}` is `<release root>/<app.static>` (`app.static` is a release-relative directory;
using `{static}` without it is a validation error).
"""
from __future__ import annotations

import copy
import json
import os
import posixpath
import re
from dataclasses import dataclass, field, asdict

IMMUNE_HOME = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_REL = os.path.join(".immune", "config.yaml")
CONTAINER_HOME = "/opt/immune"      # IMMUNE_HOME inside every container
CONTAINER_APP = "/app"              # the release inside prod / clone / runner containers

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
ASGI_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_.]*$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TOKEN_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

RUNTIMES = ("python-asgi", "generic")
AUTH_KINDS = ("immune-token", "jwt-hs256", "introspect", "none")
AUTOPATCH = ("off", "pr", "merge")
MODES = ("observe", "enforce")
REPO_TARGETS = ("local", "github")
DB_KINDS = ("sqlite", "postgres", "mysql")
DB_ENV_TOKENS = {"host", "port", "user", "password", "database", "url"}
TRACER_KINDS = ("php-xdebug",)
ENV_TOKENS = {"db", "static", "secret"}
SEED_TOKENS = {"prod_db", "shadow_db", "manifest", "markers", "seed"}
DEFAULT_PORTS = {"gateway": 8080, "admin": 8081, "dashboard": 8090, "fleet": 8070}
_AUTOPATCH_RANK = {"off": 0, "pr": 1, "merge": 2}


class ConfigError(ValueError):
    """Invalid or missing config. The message names the file and the offending key."""


# ---------------------------------------------------------------------------- dataclasses
@dataclass
class AppConfig:
    runtime: str = "python-asgi"
    release_paths: list = field(default_factory=list)
    source_dirs: list = field(default_factory=list)
    asgi: str = ""
    port: int = 8000
    health: str = "/health"
    env: dict = field(default_factory=dict)
    frozen_time_env: str = ""
    static: str = ""                       # release-relative dir for {static}
    image: str = ""                        # generic runtime
    build: dict = field(default_factory=dict)
    command: list = field(default_factory=list)
    allowed_file_roots: list = field(default_factory=list)

    @property
    def package(self) -> str:
        """Top-level python package of the ASGI app ('' for the generic runtime)."""
        return self.asgi.split(":", 1)[0].split(".", 1)[0] if self.asgi else ""


@dataclass
class DatabaseConfig:
    kind: str = "sqlite"
    path_env: str = "APP_DB"
    url_env: str = ""
    env: dict = field(default_factory=dict)   # generic: NAME -> template of {host} {port} {user} {password} {database} {url}


@dataclass
class DataConfig:
    prod_db: str = ""                      # absolute
    seed_command: str = ""
    insert_canaries: bool = False


@dataclass
class AuthConfig:
    kind: str = "immune-token"
    secret_env: str = ""
    uid_claim: str = "sub"
    role_claim: str = ""
    admin_values: list = field(default_factory=lambda: ["admin"])
    path: str = "/api/me"
    uid_field: str = "id"
    role_field: str = "role"
    cache_s: float = 30.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ShadowConfig:
    profile: str = ""
    columns: str = ""                      # absolute, or ''
    tracer: dict = field(default_factory=dict)   # generic: {kind: php-xdebug, dir, exclude} (shadow-only image)


@dataclass
class AuditConfig:
    """Class self-audit after a closed incident (pipeline/audit.py): budget per audit."""
    enabled: bool = True                   # default: true for python-asgi, false for generic (judge triples are slow)
    max_jobs: int = 40                     # judge jobs (one per candidate operation x parameter)
    max_seconds: int = 120


@dataclass
class RepoConfig:
    target: str = "local"
    github: str = ""
    t0_tag: str = "immune-t0"              # tag of the t0 tree in the repo target (extension of §2)


@dataclass
class Config:
    project_dir: str
    config_path: str
    name: str
    runtime_dir: str
    app: AppConfig
    database: DatabaseConfig
    data: DataConfig
    auth: AuthConfig
    openapi: str                           # absolute path
    shadow: ShadowConfig
    tests_command: str = ""
    scenarios: str = ""
    repo: RepoConfig = field(default_factory=RepoConfig)
    autopatch: str = "merge"
    mode: str = "enforce"
    pool_size: int = 4
    aftercheck: bool = False               # gateway: replay clean requests in a clone after prod answered
    audit: AuditConfig = field(default_factory=AuditConfig)
    ports: dict = field(default_factory=lambda: dict(DEFAULT_PORTS))
    raw: dict = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------ names
    @property
    def prefix(self) -> str:
        """Container / runner name prefix: immune-<name>."""
        return "immune-%s" % self.name

    @property
    def compose_project(self) -> str:
        return "immune-%s" % self.name

    def network(self, short: str) -> str:
        """Docker network created by the stack's compose file (prodnet, clonenet, ctrlnet, edge)."""
        return "%s_%s" % (self.compose_project, short)

    # ------------------------------------------------------------------ runtime layout
    def rt(self, *parts) -> str:
        return os.path.join(self.runtime_dir, *parts)

    def release_dir(self, release: str) -> str:
        return self.rt("releases", release)

    @property
    def prod_data_dir(self) -> str:
        return os.path.dirname(self.data.prod_db)

    @property
    def prod_db_name(self) -> str:
        return os.path.basename(self.data.prod_db)

    @property
    def shadow_dir(self) -> str:
        return self.rt("data", "shadow")

    @property
    def shadow_seed(self) -> str:
        return self.rt("data", "shadow", "seed.db")

    @property
    def manifest_path(self) -> str:
        return self.rt("data", "manifest.json")

    @property
    def markers_path(self) -> str:
        return self.rt("data", "markers.json")

    @property
    def record_path(self) -> str:
        return self.rt("recordings", "requests.jsonl")

    @property
    def dot_immune(self) -> str:
        return os.path.join(self.project_dir, ".immune")

    # ------------------------------------------------------------------ release helpers
    def release_complete(self, release_dir: str) -> bool:
        """True when every app.release_paths entry exists under release_dir."""
        return bool(self.app.release_paths) and all(
            os.path.exists(os.path.join(release_dir, p)) for p in self.app.release_paths)

    def in_source_dirs(self, relpath: str) -> bool:
        p = _norm_rel(relpath)
        return p is not None and any(p == d or p.startswith(d + "/") for d in self.app.source_dirs)

    # ------------------------------------------------------------------ substitution
    def app_env(self, *, db: str, secret: str, root: str = CONTAINER_APP) -> dict:
        """app.env with {db} {static} {secret} substituted; the db path env var is always set.

        The env values are container paths (POSIX), so the join keeps forward slashes
        regardless of the host platform."""
        vals = {"db": db, "secret": secret,
                "static": posixpath.join(root, self.app.static) if self.app.static else ""}
        out = {k: substitute(str(v), vals) for k, v in self.app.env.items()}
        if self.database.kind == "sqlite" and self.database.path_env:
            out.setdefault(self.database.path_env, db)
        return out

    def seed_command_for(self, *, prod_db: str, shadow_db: str, manifest: str, markers: str, seed: int = 1) -> str:
        if not self.data.seed_command:
            return ""
        return substitute(self.data.seed_command, {"prod_db": prod_db, "shadow_db": shadow_db, "manifest": manifest,
                                                   "markers": markers, "seed": str(seed)}, quote=True)

    # ------------------------------------------------------------------ policy
    def effective_autopatch(self) -> tuple[str, list]:
        """(autopatch after the §3 caps, [reasons])."""
        value, why = self.autopatch, []
        if not self.tests_command:
            why.append("no tests.command: autopatch capped at pr")
        if why and _AUTOPATCH_RANK[value] > _AUTOPATCH_RANK["pr"]:
            value = "pr"
        return value, why

    def facts(self) -> dict:
        """JSON-safe app facts handed to sandboxed runner jobs (no secrets)."""
        return {"asgi": self.app.asgi, "package": self.app.package, "release_paths": list(self.app.release_paths),
                "source_dirs": list(self.app.source_dirs), "profile": self.shadow.profile,
                "db_env": self.database.path_env, "env": dict(self.app.env), "static": self.app.static,
                "frozen_time_env": self.app.frozen_time_env, "seed_command": self.data.seed_command,
                "tests_command": self.tests_command, "health": self.app.health}

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw", None)
        return d


# ---------------------------------------------------------------------------- helpers
def _norm_rel(p) -> str | None:
    if not isinstance(p, str) or not p.strip():
        return None
    p = p.strip().replace("\\", "/")
    if p.startswith("/"):
        return None
    norm = os.path.normpath(p).replace(os.sep, "/")
    if norm == "." or norm.startswith("../") or norm == "..":
        return None
    return norm


def substitute(text: str, values: dict, quote: bool = False) -> str:
    """Replace {token} for known tokens; unknown tokens are left alone (validation rejects them)."""
    import shlex

    def rep(m):
        k = m.group(1)
        if k not in values:
            return m.group(0)
        v = str(values[k])
        return shlex.quote(v) if quote else v
    return TOKEN_RE.sub(rep, text)


def tokens(text: str) -> set:
    return set(TOKEN_RE.findall(text or ""))


class _V:
    """Collects validation errors with the key path."""

    def __init__(self, path: str):
        self.path, self.errors = path, []

    def err(self, key: str, msg: str):
        self.errors.append("%s: %s" % (key, msg))

    def section(self, raw: dict, key: str) -> dict:
        v = raw.get(key)
        if v is None:
            return {}
        if not isinstance(v, dict):
            self.err(key, "must be a mapping")
            return {}
        return v

    def str_(self, d: dict, key: str, full: str, default: str = "", required: bool = False) -> str:
        v = d.get(key, None)
        if v is None or v == "":
            if required:
                self.err(full, "is required")
            return default
        if not isinstance(v, (str, int, float)) or isinstance(v, bool):
            self.err(full, "must be a string")
            return default
        return str(v)

    def int_(self, d: dict, key: str, full: str, default: int, lo: int, hi: int) -> int:
        v = d.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int):
            try:
                v = int(str(v))
            except (TypeError, ValueError):
                self.err(full, "must be an integer")
                return default
        if not lo <= v <= hi:
            self.err(full, "must be between %d and %d (got %d)" % (lo, hi, v))
            return default
        return v

    def enum(self, d: dict, key: str, full: str, allowed, default: str) -> str:
        v = d.get(key, default)
        if v is None:
            v = default
        if v is False and "off" in allowed:   # YAML 1.1: `off` parses as False
            v = "off"
        if v not in allowed:
            self.err(full, "must be one of %s (got %r)" % ("|".join(allowed), v))
            return default
        return v

    def list_(self, d: dict, key: str, full: str, required: bool = False) -> list:
        v = d.get(key)
        if v is None:
            if required:
                self.err(full, "is required (a list)")
            return []
        if isinstance(v, str):
            v = [v]
        if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
            self.err(full, "must be a list of strings")
            return []
        return list(v)


def find_project(start: str | None = None) -> str:
    """Nearest directory (start, then parents) holding .immune/config.yaml; else IMMUNE_HOME."""
    d = os.path.abspath(start or os.getcwd())
    while True:
        if os.path.isfile(os.path.join(d, CONFIG_REL)):
            return d
        up = os.path.dirname(d)
        if up == d:
            return IMMUNE_HOME
        d = up


def load(project_dir: str | None = None, *, check_paths: bool = True) -> Config:
    """Read and validate `<project_dir>/.immune/config.yaml`. Raises ConfigError."""
    import yaml

    project = os.path.realpath(os.path.abspath(project_dir or IMMUNE_HOME))
    path = os.path.join(project, CONFIG_REL)
    if not os.path.isdir(project):
        raise ConfigError("project directory %s does not exist" % project)
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        raise ConfigError("%s not found (run `immune init --project %s`)" % (path, project)) from None
    except OSError as e:
        raise ConfigError("%s: cannot read: %s" % (path, e)) from None
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError("%s: invalid YAML: %s" % (path, e)) from None
    return from_dict(raw, project, path, check_paths=check_paths)


def from_dict(raw, project: str, path: str = "<config>", *, check_paths: bool = True) -> Config:
    if not isinstance(raw, dict):
        raise ConfigError("%s: the top level must be a mapping" % path)
    raw = copy.deepcopy(raw)
    v = _V(path)
    project = os.path.realpath(os.path.abspath(project))

    def abspath(p):
        return os.path.normpath(p if os.path.isabs(p) else os.path.join(project, p))

    if raw.get("version", 1) != 1:
        v.err("version", "only version 1 is supported (got %r)" % raw.get("version"))
    name = v.str_(raw, "name", "name", required=True)
    if name and not NAME_RE.match(name):
        v.err("name", "must be a lower-case slug [a-z0-9-], at most 31 characters (got %r)" % name)
    runtime_dir = abspath(v.str_(raw, "runtime_dir", "runtime_dir", default=os.path.join(".immune", "runtime")))

    # app
    a = v.section(raw, "app")
    app = AppConfig()
    app.runtime = v.enum(a, "runtime", "app.runtime", RUNTIMES, "python-asgi")
    app.release_paths = []
    for p in v.list_(a, "release_paths", "app.release_paths", required=True):
        n = _norm_rel(p)
        if n is None:
            v.err("app.release_paths", "%r must be a relative path inside the project" % p)
        elif check_paths and not os.path.exists(os.path.join(project, n)):
            v.err("app.release_paths", "%r does not exist in %s" % (p, project))
        elif n in (".immune",) or n.startswith(".immune/") or n == ".git" or n.startswith(".git/"):
            v.err("app.release_paths", "%r may not be part of a release" % p)
        else:
            app.release_paths.append(n)
    if not app.release_paths and "app.release_paths" not in " ".join(v.errors):
        v.err("app.release_paths", "must name at least one file or directory")
    rt_rel = os.path.relpath(runtime_dir, project).replace(os.sep, "/")
    for rp in app.release_paths:
        if rt_rel == rp or rt_rel.startswith(rp + "/") or rp == "." or rp.startswith(rt_rel + "/"):
            v.err("app.release_paths", "%r overlaps runtime_dir %r" % (rp, rt_rel))
    app.source_dirs = []
    for p in v.list_(a, "source_dirs", "app.source_dirs", required=True):
        n = _norm_rel(p)
        if n is None:
            v.err("app.source_dirs", "%r must be a relative path inside the project" % p)
        elif not any(n == r or n.startswith(r + "/") for r in app.release_paths):
            v.err("app.source_dirs", "%r is not inside app.release_paths %s" % (p, app.release_paths))
        else:
            app.source_dirs.append(n)
    app.asgi = v.str_(a, "asgi", "app.asgi")
    if app.runtime == "python-asgi":
        if not app.asgi:
            v.err("app.asgi", "is required for runtime python-asgi (module:attribute)")
        elif not ASGI_RE.match(app.asgi):
            v.err("app.asgi", "must look like package.module:app (got %r)" % app.asgi)
    app.port = v.int_(a, "port", "app.port", 8000, 1, 65535)
    app.health = v.str_(a, "health", "app.health", default="/health")
    if not app.health.startswith("/"):
        v.err("app.health", "must be a path starting with / (got %r)" % app.health)
    env = a.get("env") or {}
    if not isinstance(env, dict):
        v.err("app.env", "must be a mapping of NAME: value")
        env = {}
    for k, val in env.items():
        if not isinstance(k, str) or not ENV_NAME_RE.match(k):
            v.err("app.env", "invalid variable name %r" % (k,))
            continue
        if isinstance(val, (dict, list)) or val is None:
            v.err("app.env.%s" % k, "must be a scalar")
            continue
        bad = tokens(str(val)) - ENV_TOKENS
        if bad:
            v.err("app.env.%s" % k, "unknown placeholder(s) %s (allowed: {db} {static} {secret})"
                  % ", ".join("{%s}" % b for b in sorted(bad)))
        app.env[k] = str(val)
    app.frozen_time_env = v.str_(a, "frozen_time_env", "app.frozen_time_env")
    if app.frozen_time_env and not ENV_NAME_RE.match(app.frozen_time_env):
        v.err("app.frozen_time_env", "invalid variable name %r" % app.frozen_time_env)
    app.static = v.str_(a, "static", "app.static")
    if app.static and _norm_rel(app.static) is None:
        v.err("app.static", "must be a relative path inside the release (got %r)" % app.static)
    if any("{static}" in x for x in app.env.values()) and not app.static:
        v.err("app.env", "{static} is used but app.static (release-relative static dir) is not set")
    app.image = v.str_(a, "image", "app.image")
    app.build = a.get("build") if isinstance(a.get("build"), dict) else {}
    cmd = a.get("command")
    if isinstance(cmd, str):
        import shlex
        cmd = shlex.split(cmd)
    app.command = [str(x) for x in cmd] if isinstance(cmd, list) else []
    app.allowed_file_roots = v.list_(a, "allowed_file_roots", "app.allowed_file_roots")
    if app.runtime == "generic":
        if not app.build:
            v.err("app.build", "runtime generic needs app.build (the fleet builds one image per release; "
                               "app.image alone is not supported)")
        if not app.command:
            v.err("app.command", "runtime generic needs app.command")

    # database
    d = v.section(raw, "database")
    database = DatabaseConfig(kind=v.enum(d, "kind", "database.kind", DB_KINDS, "sqlite"),
                              path_env=v.str_(d, "path_env", "database.path_env", default="APP_DB"),
                              url_env=v.str_(d, "url_env", "database.url_env"))
    if database.path_env and not ENV_NAME_RE.match(database.path_env):
        v.err("database.path_env", "invalid variable name %r" % database.path_env)
    if database.kind in ("postgres", "mysql") and app.runtime != "generic":
        v.err("database.kind", "%s is only supported with app.runtime generic" % database.kind)
    denv = d.get("env") or {}
    if not isinstance(denv, dict):
        v.err("database.env", "must be a mapping of NAME: template")
        denv = {}
    for k, val in denv.items():
        if not isinstance(k, str) or not ENV_NAME_RE.match(k):
            v.err("database.env", "invalid variable name %r" % (k,))
            continue
        if isinstance(val, (dict, list)) or val is None:
            v.err("database.env.%s" % k, "must be a scalar")
            continue
        bad = tokens(str(val)) - DB_ENV_TOKENS
        if bad:
            v.err("database.env.%s" % k, "unknown placeholder(s) %s (allowed: %s)" % (
                ", ".join("{%s}" % b for b in sorted(bad)), " ".join("{%s}" % t for t in sorted(DB_ENV_TOKENS))))
        database.env[k] = str(val)
    if database.kind == "mysql" and not (database.env or database.url_env):
        v.err("database.env", "database.kind mysql needs database.env (or database.url_env) to hand the app its database")

    # data
    dd = v.section(raw, "data")
    data = DataConfig()
    prod = v.str_(dd, "prod_db", "data.prod_db", required=database.kind == "sqlite")
    data.prod_db = abspath(prod) if prod else ""
    if data.prod_db and os.path.isdir(data.prod_db):
        v.err("data.prod_db", "must be a database file path, not a directory (%s)" % data.prod_db)
    data.seed_command = v.str_(dd, "seed_command", "data.seed_command")
    bad = tokens(data.seed_command) - SEED_TOKENS
    if bad:
        v.err("data.seed_command", "unknown placeholder(s) %s (allowed: %s)" % (
            ", ".join("{%s}" % b for b in sorted(bad)), " ".join("{%s}" % t for t in sorted(SEED_TOKENS))))
    data.insert_canaries = bool(dd.get("insert_canaries", False))

    # auth
    au = v.section(raw, "auth")
    auth = AuthConfig(kind=v.enum(au, "kind", "auth.kind", AUTH_KINDS, "immune-token"))
    auth.secret_env = v.str_(au, "secret_env", "auth.secret_env")
    auth.uid_claim = v.str_(au, "uid_claim", "auth.uid_claim", default="sub")
    auth.role_claim = v.str_(au, "role_claim", "auth.role_claim")
    if "admin_values" in au:
        auth.admin_values = [str(x) for x in v.list_(au, "admin_values", "auth.admin_values")]
    auth.path = v.str_(au, "path", "auth.path", default="/api/me")
    auth.uid_field = v.str_(au, "uid_field", "auth.uid_field", default="id")
    auth.role_field = v.str_(au, "role_field", "auth.role_field", default="role")
    try:
        auth.cache_s = float(au.get("cache_s", 30))
        if auth.cache_s < 0:
            raise ValueError
    except (TypeError, ValueError):
        v.err("auth.cache_s", "must be a non-negative number")
    if auth.kind == "jwt-hs256":
        if not auth.secret_env:
            v.err("auth.secret_env", "is required for auth.kind jwt-hs256 (env var holding the HS256 secret)")
        elif not ENV_NAME_RE.match(auth.secret_env):
            v.err("auth.secret_env", "invalid variable name %r" % auth.secret_env)
    if auth.kind == "introspect" and not auth.path.startswith("/"):
        v.err("auth.path", "must be a path starting with / (got %r)" % auth.path)

    # openapi / shadow
    oa = v.str_(raw, "openapi", "openapi", required=True)
    openapi = abspath(oa) if oa else ""
    if openapi and check_paths and not os.path.isfile(openapi):
        v.err("openapi", "%s does not exist" % openapi)
    s = v.section(raw, "shadow")
    shadow = ShadowConfig(profile=v.str_(s, "profile", "shadow.profile", required=app.runtime == "python-asgi"))
    if shadow.profile and not MODULE_RE.match(shadow.profile):
        v.err("shadow.profile", "must be a python module name (got %r)" % shadow.profile)
    cols = v.str_(s, "columns", "shadow.columns")
    shadow.columns = abspath(cols) if cols else ""
    tr = s.get("tracer") or {}
    if not isinstance(tr, dict):
        v.err("shadow.tracer", "must be a mapping {kind, dir, exclude}")
        tr = {}
    if tr:
        if app.runtime != "generic":
            v.err("shadow.tracer", "is only supported with app.runtime generic")
        if tr.get("kind", "php-xdebug") not in TRACER_KINDS:
            v.err("shadow.tracer.kind", "must be one of %s" % ", ".join(TRACER_KINDS))
        if tr.get("dir") is not None and not str(tr["dir"]).startswith("/tmp/"):
            v.err("shadow.tracer.dir", "must be under /tmp/ (the only writable path of a clone)")
        if tr.get("exclude") is not None and not (isinstance(tr["exclude"], list)
                                                  and all(isinstance(x, str) for x in tr["exclude"])):
            v.err("shadow.tracer.exclude", "must be a list of path fragments")
        shadow.tracer = {"kind": str(tr.get("kind", "php-xdebug")), "dir": str(tr.get("dir") or "/tmp/immune-trace"),
                         "exclude": list(tr.get("exclude") or ["/vendor/"])}

    # tests / scenarios / repo / policy
    t = v.section(raw, "tests")
    tests_command = v.str_(t, "command", "tests.command")
    scenarios = v.str_(raw, "scenarios", "scenarios")
    if scenarios and not MODULE_RE.match(scenarios):
        v.err("scenarios", "must be a python module name (got %r)" % scenarios)
    r = v.section(raw, "repo")
    repo = RepoConfig(target=v.enum(r, "target", "repo.target", REPO_TARGETS, "local"),
                      github=v.str_(r, "github", "repo.github"),
                      t0_tag=v.str_(r, "t0_tag", "repo.t0_tag", default="immune-t0"))
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$", repo.t0_tag):
        v.err("repo.t0_tag", "invalid tag name %r" % repo.t0_tag)
    if repo.target == "github" and not re.match(r"^[\w.-]+/[\w.-]+$", repo.github or ""):
        v.err("repo.github", "repo.target github needs repo.github: owner/name")
    autopatch = v.enum(raw, "autopatch", "autopatch", AUTOPATCH, "merge")
    mode = v.enum(raw, "mode", "mode", MODES, "enforce")
    pool_size = v.int_(raw, "pool_size", "pool_size", 4, 0, 32)
    aftercheck = raw.get("aftercheck", False)
    if not isinstance(aftercheck, bool):
        v.err("aftercheck", "must be true or false")
        aftercheck = False
    au = v.section(raw, "audit")
    audit = AuditConfig(enabled=app.runtime == "python-asgi",
                        max_jobs=v.int_(au, "max_jobs", "audit.max_jobs", 40, 0, 1000),
                        max_seconds=v.int_(au, "max_seconds", "audit.max_seconds", 120, 0, 3600))
    if "enabled" in au:
        if isinstance(au["enabled"], bool):
            audit.enabled = au["enabled"]
        else:
            v.err("audit.enabled", "must be true or false")
    ports = dict(DEFAULT_PORTS)
    pr = v.section(raw, "ports")
    for k, val in pr.items():
        if k not in DEFAULT_PORTS:
            v.err("ports.%s" % k, "unknown port (known: %s)" % ", ".join(DEFAULT_PORTS))
            continue
        ports[k] = v.int_(pr, k, "ports.%s" % k, DEFAULT_PORTS[k], 1, 65535)
    if len(set(ports.values())) != len(ports):
        v.err("ports", "host ports must be distinct (%s)" % ports)

    if v.errors:
        raise ConfigError("%s is invalid:\n  - %s" % (path, "\n  - ".join(v.errors)))
    return Config(project_dir=project, config_path=path, name=name, runtime_dir=runtime_dir, app=app,
                  database=database, data=data, auth=auth, openapi=openapi, shadow=shadow,
                  tests_command=tests_command, scenarios=scenarios, repo=repo, autopatch=autopatch, mode=mode,
                  pool_size=pool_size, aftercheck=aftercheck, audit=audit, ports=ports, raw=raw)


# ---------------------------------------------------------------------------- process-wide instance
_CURRENT: dict = {}


def project_from_env(env=None) -> str:
    env = os.environ if env is None else env
    return env.get("IMMUNE_PROJECT") or env.get("PROJECT_DIR") or IMMUNE_HOME


def current(env=None) -> Config:
    """The config of the project this process serves (cached per project dir)."""
    proj = os.path.realpath(project_from_env(env))
    if proj not in _CURRENT:
        _CURRENT[proj] = load(proj)
    return _CURRENT[proj]


def reset_cache() -> None:
    _CURRENT.clear()


def set_key(project_dir: str, key: str, value) -> str:
    """Rewrite one top-level scalar key of config.yaml in place (keeps comments). -> path."""
    import yaml

    path = os.path.join(os.path.realpath(project_dir), CONFIG_REL)
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines(keepends=True)
    pat = re.compile(r"^%s\s*:(\s*)([^#\n]*?)(\s*#.*)?$" % re.escape(key))
    rendered = json.dumps(value) if not isinstance(value, str) or not re.match(r"^[A-Za-z0-9_.-]+$", value) else value
    for i, line in enumerate(lines):
        m = pat.match(line.rstrip("\n"))
        if m:
            lines[i] = "%s: %s%s\n" % (key, rendered, m.group(3) or "")
            break
    else:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append("%s: %s\n" % (key, rendered))
    from_dict(yaml.safe_load("".join(lines)), project_dir, path, check_paths=False)  # raises before writing
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(lines)
    os.replace(tmp, path)
    reset_cache()
    return path
