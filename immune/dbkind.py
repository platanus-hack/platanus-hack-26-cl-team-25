"""Database kinds of the generic runtime: Postgres (the original) and MySQL / MariaDB.

One place for what differs between them, so `immune up` (immune/generic.py), fleet (fleet/generic.py)
and the pipeline's judge triples (pipeline/generic.py) stay the same code for both:

  image, uid, tmpfs     the per-clone / demo database container (throw-away, tmpfs data, --cap-drop ALL)
  args / env            server flags and the init environment (superuser and `app` passwords)
  init_dir              <runtime>/data/shadow/<init_dir>: the docker-entrypoint-initdb.d of every clone db
                        (role/user `app`, template database `seed`, and for MySQL the database `clone`)
  ready()               TCP readiness (the entrypoints' init phase never listens on TCP)
  url() / parse()       the app's connection URL
  app_env()             env the app gets: database.url_env and/or database.env templates
  sidecar()             the sidecar's proxy section (`postgres:` / `mysql:`)
"""
from __future__ import annotations

import subprocess
import time
from urllib.parse import quote, unquote, urlparse

PG_IMAGE = "postgres:16-alpine"
MARIADB_IMAGE = "mariadb:11.8.8@sha256:be1ef4fe5f14589325c08a41c76334097ce66c86264b75e1d28342c742782a61"


def _docker(*args, timeout=30) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


class DbKind:
    name = ""
    image = ""
    port = 0
    user = ""
    init_dir = ""
    scheme = ""
    clone_memory = "256m"

    def url(self, user: str, password: str, host: str, database: str, port: int | None = None) -> str:
        return "%s://%s:%s@%s:%d/%s" % (self.scheme, quote(user, safe=""), quote(password, safe=""), host,
                                        port or self.port, database)

    def parse(self, url: str) -> dict:
        u = urlparse(url)
        return {"host": u.hostname or "127.0.0.1", "port": u.port or self.port, "user": unquote(u.username or ""),
                "password": unquote(u.password or ""), "database": (u.path or "/").lstrip("/")}

    def app_env(self, url: str, url_env: str, templates: dict) -> dict:
        """The env through which the app reaches its database: url_env=<url> and/or the database.env templates."""
        p = self.parse(url)
        vals = {"host": p["host"], "port": str(p["port"]), "user": p["user"], "password": p["password"],
                "database": p["database"], "url": url}
        out = {}
        if url_env:
            out[url_env] = url
        for k, tmpl in (templates or {}).items():
            s = str(tmpl)
            for tok, val in vals.items():
                s = s.replace("{%s}" % tok, val)
            out[k] = s
        return out

    def ready(self, container: str, superuser_password: str = "", timeout: float = 60.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if self._ping(container, superuser_password):
                return True
            st = _docker("inspect", "-f", "{{.State.Running}}", container).stdout.strip()
            if st != "true":
                return False
            time.sleep(0.2)
        return False

    def _ping(self, container: str, pw: str) -> bool:
        raise NotImplementedError


class PgKind(DbKind):
    name, image, port, user, init_dir, scheme = "postgres", PG_IMAGE, 5432, "70:70", "pginit", "postgres"
    args = ["-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"]

    def tmpfs(self) -> dict:
        return {"/var/lib/postgresql/data": "uid=70,gid=70,mode=0700", "/var/run/postgresql": "uid=70,gid=70",
                "/tmp": "size=32m,mode=1777"}

    def env(self, su_pw: str, app_pw: str) -> dict:
        return {"POSTGRES_PASSWORD": su_pw, "APP_DB_PASSWORD": app_pw}

    def demo_env(self, user: str, password: str, database: str, su_pw: str) -> dict:
        return {"POSTGRES_USER": user, "POSTGRES_PASSWORD": password, "POSTGRES_DB": database}

    def _ping(self, container, pw):
        return _docker("exec", container, "pg_isready", "-q", "-h", "127.0.0.1", "-p", "5432").returncode == 0

    def admin_url(self, su_pw: str, host: str) -> str:
        return "postgres://postgres:%s@%s:5432/postgres" % (su_pw, host)

    def sidecar(self, db_host: str, su_pw: str) -> dict:
        return {"postgres": {"listen": "127.0.0.1:5432", "upstream": "%s:5432" % db_host,
                             "admin_url": self.admin_url(su_pw, db_host), "database": "clone", "template": "seed"}}


class MysqlKind(DbKind):
    name, image, port, user, init_dir, scheme = "mysql", MARIADB_IMAGE, 3306, "999:999", "myinit", "mysql"
    # The template and live database share a tmpfs. Both count against the limit during a full reset.
    clone_memory = "1g"
    # throw-away data: durability off, small buffers, no binary log, the charset OpenEMR-style apps expect
    args = ["--innodb-flush-log-at-trx-commit=0", "--innodb-doublewrite=0", "--skip-log-bin",
            "--innodb-buffer-pool-size=96M", "--character-set-server=utf8mb4",
            "--collation-server=utf8mb4_general_ci", "--max-connections=200", "--skip-name-resolve"]

    def tmpfs(self) -> dict:
        return {"/var/lib/mysql": "uid=999,gid=999,mode=0700", "/run/mysqld": "uid=999,gid=999,mode=0755",
                "/tmp": "size=64m,mode=1777"}

    def env(self, su_pw: str, app_pw: str) -> dict:
        return {"MARIADB_ROOT_PASSWORD": su_pw, "APP_DB_PASSWORD": app_pw, "MARIADB_ROOT_HOST": "%"}

    def demo_env(self, user: str, password: str, database: str, su_pw: str) -> dict:
        return {"MARIADB_ROOT_PASSWORD": su_pw, "MARIADB_ROOT_HOST": "%", "MARIADB_DATABASE": database,
                "MARIADB_USER": user, "MARIADB_PASSWORD": password}

    def _ping(self, container, pw):
        probe = _docker("exec", "-e", "MYSQL_PWD=" + pw, container, "mariadb", "--protocol=tcp",
                        "-h", "127.0.0.1", "-uroot", "--connect-timeout=2", "--skip-ssl", "--batch", "--skip-column-names",
                        "-e", "SELECT 1")
        return probe.returncode == 0 and probe.stdout.strip() == "1"

    def admin_url(self, su_pw: str, host: str) -> str:
        return "mysql://root:%s@%s:3306/" % (quote(su_pw, safe=""), host)

    def sidecar(self, db_host: str, su_pw: str) -> dict:
        return {"mysql": {"listen": "127.0.0.1:3306", "upstream": "%s:3306" % db_host,
                          "admin_url": self.admin_url(su_pw, db_host), "database": "clone", "template": "seed"}}


KINDS = {"postgres": PgKind(), "mysql": MysqlKind()}


def of(kind: str) -> DbKind:
    try:
        return KINDS[kind]
    except KeyError:
        raise ValueError("database.kind %r has no proxy for the generic runtime (supported: %s)"
                         % (kind, ", ".join(KINDS))) from None
