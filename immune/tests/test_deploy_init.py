import os
import shutil
import sqlite3
import subprocess
import sys

import pytest
import yaml

from immune import config as icfg
from immune import deploycmd, doctor, init
from immune.initsteps import detect, docker

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_init_detects_php_mysql_without_writing_sqlite_configuration(tmp_path, capsys):
    (tmp_path / "index.php").write_text("<?php $db = new mysqli($host, $user, $password);")
    detected = detect.detect(str(tmp_path))
    assert (detected["runtime"], detected["framework"], detected["database_kind"]) == ("generic", "php", "mysql")
    assert init.main(["--project", str(tmp_path), "--yes"]) == 1
    assert "PHP + MySQL" in capsys.readouterr().out
    assert not (tmp_path / ".immune").exists()


def test_pinned_dockerfile_bases_ignore_stage_and_unpinned_images(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    image = "example/php:1@sha256:" + "a" * 64
    dockerfile.write_text(f"FROM --platform=linux/amd64 {image} AS base\nFROM base\nFROM php:latest\nFROM {image}\n")
    assert doctor._pinned_bases(str(dockerfile)) == [image]


def _cfg(tmp_path, compose=True):
    p = tmp_path / "proj"
    (p / "app").mkdir(parents=True)
    (p / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    (p / ".immune").mkdir()
    (p / ".immune" / "openapi.yaml").write_text("openapi: 3.0.3\npaths: {}\n")
    if compose:
        (p / "docker-compose.yml").write_text(
            "services:\n  web:\n    build: .\n    ports: ['8000:8000']\n    volumes: ['webdata:/data']\n"
            "volumes:\n  webdata: {}\n")
        (p / "Dockerfile").write_text("FROM python:3.12\n")
    raw = {"version": 1, "name": "demoapp", "app": {"release_paths": ["app"], "source_dirs": ["app"],
                                                    "asgi": "app.main:app", "port": 8000},
           "data": {"prod_db": "data/app.db"}, "auth": {"kind": "none"}, "openapi": ".immune/openapi.yaml",
           "shadow": {"profile": "profile"}, "autopatch": "pr"}
    with open(p / ".immune" / "config.yaml", "w") as f:
        yaml.safe_dump(raw, f)
    return icfg.load(str(p))


def _det(style="compose"):
    if style == "compose":
        return {"deploy": {"style": "compose", "compose_file": "docker-compose.yml", "service": "web",
                           "ports": [{"host": 8000, "container": 8000}], "files": ["docker-compose.yml", "Dockerfile"],
                           "volumes": ["webdata:/data"], "dockerfile": "Dockerfile"}}
    return {"deploy": {"style": style, "files": []}}


def test_compose_override_puts_gateway_in_front(tmp_path):
    cfg = _cfg(tmp_path)
    res = deploycmd.generate(cfg, _det())
    path = os.path.join(cfg.project_dir, ".immune", "deploy", "compose.immune.yaml")
    text = open(path).read()
    assert "ports: !reset []" in text                                  # the app is no longer published
    yaml.add_constructor("!reset", lambda loader, node: [], Loader=yaml.SafeLoader)
    doc = yaml.safe_load(text)
    gw = doc["services"]["immune-gateway"]
    assert gw["ports"][0] == "8000:8080"                               # gateway publishes the app's port
    assert gw["environment"]["PROD_ADDR"] == "web:8000"
    assert gw["container_name"] == "immune-demoapp-front"
    assert doc["networks"]["immune_prodnet"] == {"name": "immune-demoapp-front_prodnet", "internal": True}
    assert "immune_prodnet" in doc["services"]["web"]["networks"]
    assert res["command"][-2:] == ["up", "-d"] and res["ready_command"].startswith("immune deploy --project")
    md = open(os.path.join(cfg.project_dir, ".immune", "DEPLOY.md")).read()
    assert "immune deploy --project" in md and "no longer published" in md and "webdata:/data" in md
    assert oct(os.stat(os.path.join(cfg.project_dir, ".immune", "deploy", "immune.env")).st_mode)[-3:] == "600"


@pytest.mark.docker
def test_compose_override_is_valid_for_docker_compose(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("no docker")
    cfg = _cfg(tmp_path)
    deploycmd.generate(cfg, _det())
    p = subprocess.run(["docker", "compose", "--project-directory", cfg.project_dir, "-f",
                        os.path.join(cfg.project_dir, "docker-compose.yml"), "-f",
                        os.path.join(cfg.project_dir, ".immune", "deploy", "compose.immune.yaml"), "config", "--format",
                        "json"], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    import json
    merged = json.loads(p.stdout)
    assert not merged["services"]["web"].get("ports")
    assert merged["services"]["immune-gateway"]["ports"][0]["published"] == "8000"


def test_dockerfile_only_and_manual(tmp_path):
    cfg = _cfg(tmp_path, compose=False)
    res = deploycmd.generate(cfg, {"deploy": {"style": "dockerfile", "dockerfile": "Dockerfile", "files": ["Dockerfile"]}})
    doc = yaml.safe_load(open(res["files"][0]).read().replace("!reset", ""))
    assert doc["services"]["demoapp"]["build"]["dockerfile"] == "Dockerfile"
    shutil.rmtree(os.path.join(cfg.project_dir, ".immune", "deploy"))
    res = deploycmd.generate(cfg, _det("systemd"))
    assert res["command"] is None and res["ready_command"].startswith("immune up --project")
    md = open(os.path.join(cfg.project_dir, ".immune", "DEPLOY.md")).read()
    assert "(manual)" in md and "PROD_ADDR" in md
    assert not os.path.exists(os.path.join(cfg.project_dir, ".immune", "deploy", "compose.immune.yaml"))
    assert deploycmd.main(["--project", cfg.project_dir]) == 0


def _victim_project(tmp_path):
    p = tmp_path / "shop"
    p.mkdir()
    shutil.copytree(os.path.join(ROOT, "victim"), str(p / "victim"), ignore=shutil.ignore_patterns("__pycache__"))
    (p / "data").mkdir()
    s = tmp_path / "s"
    s.mkdir()
    subprocess.run([sys.executable, "-m", "victim.seed", "--out-prod", str(p / "data" / "app.db"), "--out-shadow",
                    str(s / "x.db"), "--manifest", str(s / "m.json"), "--markers", str(s / "k.json")], cwd=ROOT, check=True)
    return str(p)


@pytest.mark.docker
def test_init_no_llm_on_builtin_app(tmp_path):
    ok, why = docker.available()
    if not ok:
        pytest.skip(why)
    from immune.init import Init
    proj = _victim_project(tmp_path)
    lines = []
    rc = Init(proj, use_llm=False, out=lines.append).run()
    text = "\n".join(lines)
    assert rc == 0, text
    assert lines[-1].startswith("READY: immune up --project ")
    for rel in ("config.yaml", "openapi.yaml", "profile.py", "shadow/columns.yaml", "shadow/marks.yaml",
                "runtime/data/shadow/seed.db", "runtime/data/manifest.json", "runtime/data/markers.json",
                "DEPLOY.md", "report.md"):
        assert os.path.exists(os.path.join(proj, ".immune", rel)), rel
    oa = yaml.safe_load(open(os.path.join(proj, ".immune", "openapi.yaml")))
    assert oa["paths"]["/api/orders/{order_id}"]["get"]["x-owner-scoped"] is True
    assert "8/8 checks pass" in text
    c = sqlite3.connect(os.path.join(proj, "data", "app.db"))
    assert c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 60     # prod untouched
    c.close()
