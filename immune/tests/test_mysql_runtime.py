"""The generic runtime on MySQL / MariaDB (OpenEMR): config, database kinds, request inputs, constants and the
OpenEMR onboarding files."""
import os
from subprocess import CompletedProcess

import pytest
import yaml

from immune import config as icfg
from immune import dbkind
from shadow import sqltaint
from sidecar import constants, observer

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OVERLAY = os.path.join(ROOT, "examples", "openemr", "overlay")


def raw_config():
    with open(os.path.join(OVERLAY, ".immune", "config.yaml"), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_openemr_config_validates_and_hands_mysql_through_env():
    cfg = icfg.from_dict(raw_config(), OVERLAY, "config.yaml", check_paths=False)
    assert cfg.database.kind == "mysql" and cfg.app.port == 8080
    assert cfg.shadow.tracer == {"kind": "php-xdebug", "dir": "/tmp/immune-trace", "exclude": ["/vendor/"]}
    kind = dbkind.of("mysql")
    env = kind.app_env(kind.url("app", "p@ss", "127.0.0.1", "clone"), "", cfg.database.env)
    assert env == {"MYSQL_HOST": "127.0.0.1", "MYSQL_PORT": "3306", "MYSQL_USER": "app", "MYSQL_PASS": "p@ss",
                   "MYSQL_DATABASE": "clone"}


@pytest.mark.parametrize("change,error", [
    ({"database": {"kind": "mysql"}}, "database.env"),
    ({"database": {"kind": "mysql", "env": {"X": "{nope}"}}}, "unknown placeholder"),
    ({"shadow": {"profile": "p", "tracer": {"kind": "gdb"}}}, "shadow.tracer.kind"),
    ({"shadow": {"profile": "p", "tracer": {"dir": "/var/x"}}}, "/tmp/"),
])
def test_mysql_and_tracer_validation(change, error):
    raw = raw_config()
    raw.update(change)
    with pytest.raises(icfg.ConfigError, match=error.replace("/", ".")):
        icfg.from_dict(raw, OVERLAY, "config.yaml", check_paths=False)


def test_db_kinds_keep_postgres_unchanged():
    pg, my = dbkind.of("postgres"), dbkind.of("mysql")
    assert pg.sidecar("db", "pw")["postgres"]["admin_url"] == "postgres://postgres:pw@db:5432/postgres"
    assert my.sidecar("db", "pw")["mysql"] == {"listen": "127.0.0.1:3306", "upstream": "db:3306",
                                               "admin_url": "mysql://root:pw@db:3306/", "database": "clone",
                                               "template": "seed"}
    assert pg.parse("postgres://u:p@h:5432/d")["database"] == "d"
    with pytest.raises(ValueError):
        dbkind.of("oracle")


@pytest.mark.parametrize("returncode,out,ready", [(1, "", False), (0, "", False), (0, "1\n", True)])
def test_mysql_readiness_requires_a_successful_tcp_query(monkeypatch, returncode, out, ready):
    def docker(*args):
        assert "--protocol=tcp" in args
        assert args[-2:] == ("-e", "SELECT 1")
        return CompletedProcess(args, returncode, stdout=out)

    monkeypatch.setattr(dbkind, "_docker", docker)
    assert dbkind.of("mysql")._ping("clone-db", "demo-password") is ready


def test_literal_route_segments_are_not_inputs():
    from gateway.spec import Spec
    spec = Spec({"openapi": "3.0.0", "paths": {"/apis/default/fhir/Patient": {"get": {}},
                                                "/apis/default/api/patient/{puuid}": {"get": {}}}})
    assert observer.extract_inputs("/apis/default/fhir/Patient", "", {}, b"", spec) == []
    assert observer.extract_inputs("/apis/default/api/patient/ab-1", "", {}, b"", spec) == [("path", "puuid", "ab-1")]
    assert ("path", "path[0]", "other") in observer.extract_inputs("/other/route", "", {}, b"", spec)


def test_php_constants_split_at_placeholders_and_interpolation():
    lits = constants.literals('$s = "SELECT a, is_default FROM t WHERE id=? AND x={$y} AND z=$w->q";')
    assert "SELECT a, is_default FROM t WHERE id=" in lits
    stmt = "SELECT a, is_default FROM t WHERE id='5' AND x=1 AND z=2"
    i = stmt.index("default")
    assert sqltaint.explained_by_constant(stmt, i, i + 7, sqltaint.Constants(lits))


def test_overlay_never_overrides_openemr_files():
    allowed = (".immune/", "immune-runtime/")
    for root, _dirs, files in os.walk(OVERLAY):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), OVERLAY).replace(os.sep, "/")
            assert rel.startswith(allowed) or rel == "Dockerfile.immune", rel


def test_columns_classify_patient_phi_and_owned_secrets():
    with open(os.path.join(OVERLAY, ".immune", "shadow", "columns.yaml"), encoding="utf-8") as fh:
        cols = yaml.safe_load(fh)
    t = cols["tables"]
    assert len(t) == 283
    assert "fname" in t["patient_data"]["private"] and "owner" not in t["patient_data"]
    assert t["users_secure"]["owner"] == "id" and "password" in t["users_secure"]["secret"]
    assert "response" in t["api_log"]["secret"]
