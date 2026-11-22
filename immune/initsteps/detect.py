"""Step 1 of `immune init`: heuristic detection (no LLM, no import of the target code).

detect(project) -> dict with runtime, framework, asgi entry, source/release paths, port, env vars
(and which one carries the database path / secret / frozen time), tests command, deploy style,
SQLite files, and the list of assumptions made.
"""
from __future__ import annotations

import ast
import os
import re
import unicodedata

import yaml

SKIP_DIRS = {".git", ".immune", ".venv", "venv", "env", ".env", "node_modules", "__pycache__", ".pytest_cache",
             ".mypy_cache", ".ruff_cache", ".tox", "dist", "build", "site-packages", ".idea", ".vscode", "runtime"}
ROOT_FILES = ("pytest.ini", "pyproject.toml", "setup.cfg", "setup.py", "tox.ini", "conftest.py", "requirements.txt",
              "requirements-dev.txt", "requirements.in")
SQLITE_MAGIC = b"SQLite format 3\x00"
APP_RE = re.compile(r"^([A-Za-z_]\w*)\s*(?::\s*[\w\[\]., ]+)?=\s*(FastAPI|Starlette)\s*\(", re.M)
TITLE_RE = re.compile(r"(?:FastAPI|Starlette)\s*\([^)]*?title\s*=\s*[\"']([^\"']+)[\"']", re.S)
ENV_RES = (
    re.compile(r"""os\.environ\.get\(\s*["']([A-Za-z_]\w*)["']\s*(?:,\s*([^)]*))?\)"""),
    re.compile(r"""os\.getenv\(\s*["']([A-Za-z_]\w*)["']\s*(?:,\s*([^)]*))?\)"""),
    re.compile(r"""os\.environ\[\s*["']([A-Za-z_]\w*)["']\s*\]"""),
    re.compile(r"""environ\.get\(\s*["']([A-Za-z_]\w*)["']\s*(?:,\s*([^)]*))?\)"""),
)


def walk(project: str, exts=(".py",), max_files: int = 5000):
    n = 0
    for dirpath, dirnames, filenames in os.walk(project):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for fn in sorted(filenames):
            if exts is None or fn.endswith(exts):
                n += 1
                if n > max_files:
                    return
                yield os.path.join(dirpath, fn)


def _rel(project, path):
    return os.path.relpath(path, project).replace(os.sep, "/")


def _read(path, limit=400_000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def slug(text: str) -> str:
    t = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode().lower()
    t = re.sub(r"[^a-z0-9]+", "-", t).strip("-")
    t = re.sub(r"-(app|api|service)$", "", t) or t
    return (t or "app")[:31].strip("-") or "app"


def is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in ("tests", "test") for p in parts[:-1]) or parts[-1].startswith("test_") or parts[-1] == "conftest.py"


def find_asgi(project: str) -> list[dict]:
    out = []
    for path in walk(project):
        rel = _rel(project, path)
        if is_test_path(rel):
            continue
        text = _read(path)
        for m in APP_RE.finditer(text):
            mod = rel[:-3].replace("/", ".")
            if mod.endswith(".__init__"):
                mod = mod[: -len(".__init__")]
            t = TITLE_RE.search(text)
            out.append({"asgi": "%s:%s" % (mod, m.group(1)), "file": rel, "framework": m.group(2).lower(),
                        "title": t.group(1) if t else None, "depth": rel.count("/")})
    base = {"main.py": 0, "app.py": 1, "asgi.py": 2, "server.py": 3}
    out.sort(key=lambda c: (base.get(os.path.basename(c["file"]), 9), c["depth"], c["file"]))
    return out


def find_env(project: str, dirs: list[str]) -> dict:
    env = {}
    for d in dirs:
        root = os.path.join(project, d)
        files = [root] if os.path.isfile(root) else walk(root)
        for path in files:
            rel = _rel(project, path)
            if is_test_path(rel):
                continue
            text = _read(path)
            for rx in ENV_RES:
                for m in rx.finditer(text):
                    name = m.group(1)
                    default = None
                    if m.lastindex and m.lastindex >= 2 and m.group(2):
                        raw = m.group(2).strip()
                        try:
                            default = ast.literal_eval(raw)
                        except Exception:
                            default = "<expr: %s>" % raw[:60]
                    e = env.setdefault(name, {"default": None, "files": [], "required": False})
                    if default is not None and e["default"] is None:
                        e["default"] = default
                    if rx.pattern.startswith("os\\.environ\\["):
                        e["required"] = True
                    if rel not in e["files"]:
                        e["files"].append(rel)
    return env


def classify_env(env: dict) -> dict:
    db = now = None
    secrets, files = [], []
    for name, info in sorted(env.items()):
        u = name.upper()
        d = info.get("default")
        dstr = d if isinstance(d, str) else ""
        if re.search(r"(DATABASE_URL|PG|POSTGRES|MYSQL|REDIS)", u) and "sqlite" not in dstr:
            continue
        if db is None and (re.search(r"(^|_)(DB|DATABASE|SQLITE)(_|$)", u) or dstr.endswith((".db", ".sqlite", ".sqlite3"))):
            db = name
            continue
        if re.search(r"(SECRET|_KEY$|^KEY$|TOKEN|SALT|SIGNING)", u):
            secrets.append(name)
            continue
        if re.search(r"(^|_)(NOW|FROZEN|FAKE_TIME|CLOCK|TIME_OVERRIDE)(_|$)", u):
            now = now or name
            continue
        if re.search(r"(STATIC|FILES|UPLOAD|MEDIA|TEMPLATE|ASSET)", u):
            files.append(name)
    return {"db_env": db, "secret_envs": secrets, "time_env": now, "file_envs": files}


def find_sqlite(project: str) -> list[str]:
    out = []
    for path in walk(project, exts=None, max_files=20000):
        try:
            if os.path.getsize(path) < 100:
                continue
            with open(path, "rb") as f:
                if f.read(16) == SQLITE_MAGIC:
                    out.append(_rel(project, path))
        except OSError:
            continue
    return out


def find_tests(project: str) -> list[str]:
    dirs = set()
    for path in walk(project):
        rel = _rel(project, path)
        fn = os.path.basename(rel)
        if fn.startswith("test_") or fn.endswith("_test.py"):
            parts = rel.split("/")
            for i, p in enumerate(parts[:-1]):
                if p in ("tests", "test"):
                    dirs.add("/".join(parts[: i + 1]))
                    break
            else:
                dirs.add("/".join(parts[:-1]) or ".")
    return sorted(dirs, key=lambda d: (d.count("/"), d))


def _dockerfile_facts(text: str) -> dict:
    out = {}
    m = re.search(r"^\s*EXPOSE\s+(\d+)", text, re.M | re.I)
    if m:
        out["port"] = int(m.group(1))
    m = re.search(r"--port[\s=]+(\d+)", text)
    if m:
        out["cmd_port"] = int(m.group(1))
    envs = {}
    for m in re.finditer(r"^\s*ENV\s+(.+)$", text, re.M | re.I):
        body = m.group(1).strip()
        if "=" in body:
            for k, v in re.findall(r"([A-Za-z_]\w*)=(\"[^\"]*\"|\S+)", body):
                envs[k] = v.strip('"')
        else:
            parts = body.split(None, 1)
            if len(parts) == 2:
                envs[parts[0]] = parts[1]
    out["env"] = envs
    return out


def find_deploy(project: str) -> dict:
    out = {"style": "unknown", "files": []}
    for name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"):
        p = os.path.join(project, name)
        if os.path.isfile(p):
            try:
                doc = yaml.safe_load(_read(p)) or {}
            except yaml.YAMLError:
                doc = {}
            services = doc.get("services") or {}
            pick = None
            for sname, svc in services.items():
                svc = svc or {}
                if svc.get("build") is not None:
                    pick = pick or sname
            if pick is None and services:
                pick = sorted(services)[0]
            svc = services.get(pick) or {}
            ports = []
            for pdef in svc.get("ports") or []:
                s = str(pdef.get("target") if isinstance(pdef, dict) else pdef)
                m = re.search(r"(?:(?:[\d.]+:)?(\d+):)?(\d+)(?:/\w+)?$", s)
                if m:
                    ports.append({"host": int(m.group(1)) if m.group(1) else None, "container": int(m.group(2)),
                                  "raw": pdef})
            envs = svc.get("environment") or {}
            if isinstance(envs, list):
                envs = dict(e.split("=", 1) if "=" in e else (e, "") for e in envs)
            out.update({"style": "compose", "compose_file": name, "service": pick, "ports": ports,
                        "service_env": {str(k): str(v) for k, v in envs.items()},
                        "volumes": svc.get("volumes") or []})
            out["files"].append(name)
            break
    df = os.path.join(project, "Dockerfile")
    if os.path.isfile(df):
        out["dockerfile"] = "Dockerfile"
        out["dockerfile_facts"] = _dockerfile_facts(_read(df))
        out["files"].append("Dockerfile")
        if out["style"] == "unknown":
            out["style"] = "dockerfile"
    if out["style"] == "unknown":
        for path in walk(project, exts=(".yaml", ".yml", ".service")):
            rel = _rel(project, path)
            if rel.endswith(".service"):
                out.update({"style": "systemd", "unit": rel})
                out["files"].append(rel)
                break
            text = _read(path, 50_000)
            if re.search(r"^kind:\s*Deployment", text, re.M) and "apiVersion" in text:
                out.update({"style": "k8s", "manifest": rel})
                out["files"].append(rel)
                break
    if out["style"] == "unknown" and os.path.isfile(os.path.join(project, "Procfile")):
        out.update({"style": "procfile"})
        out["files"].append("Procfile")
    return out


def detect(project: str) -> dict:
    project = os.path.realpath(project)
    assumptions = []
    has_py = any(os.path.isfile(os.path.join(project, f)) for f in ("pyproject.toml", "requirements.txt", "setup.py",
                                                                    "setup.cfg", "Pipfile"))
    reqs = " ".join(_read(os.path.join(project, f)).lower() for f in ("pyproject.toml", "requirements.txt", "setup.py",
                                                                      "setup.cfg", "Pipfile"))
    cands = find_asgi(project)
    if not cands:
        return {"project": project, "runtime": "unknown", "framework": None, "asgi": None, "asgi_candidates": [],
                "problems": ["no FastAPI/Starlette application instance found (only python-asgi is supported)"],
                "assumptions": assumptions, "deploy": find_deploy(project), "sqlite_files": find_sqlite(project)}
    c = cands[0]
    if len(cands) > 1:
        assumptions.append("several ASGI apps found (%s); using %s" % (", ".join(x["asgi"] for x in cands), c["asgi"]))
    if not has_py:
        assumptions.append("no pyproject/requirements file; python runtime inferred from the source")
    elif "fastapi" not in reqs and c["framework"] == "fastapi":
        assumptions.append("fastapi is not listed in the requirements files")
    mod = c["asgi"].split(":")[0]
    package = mod.split(".")[0]
    source_dir = os.path.dirname(c["file"]) or "."
    if source_dir == ".":
        assumptions.append("the app module is at the project root; the automatic fix may edit %s only" % c["file"])
        source_dir = c["file"]
    # release paths: top-level dirs with python code + root config files, minus data dirs
    sqlite = find_sqlite(project)
    data_tops = {s.split("/")[0] for s in sqlite if "/" in s}
    release = []
    for entry in sorted(os.listdir(project)):
        p = os.path.join(project, entry)
        if entry in SKIP_DIRS or entry.startswith("."):
            continue
        if os.path.isdir(p):
            if entry in data_tops and entry != package:
                continue
            if any(True for _ in walk(p)):
                release.append(entry)
        elif entry in ROOT_FILES or (entry.endswith(".py") and entry not in ("setup.py",)):
            release.append(entry)
    if package not in release and os.path.isdir(os.path.join(project, package)):
        release.insert(0, package)
    if source_dir == c["file"] and c["file"] not in release:
        release.append(c["file"])
    env = find_env(project, [d for d in release if not d.endswith((".ini", ".toml", ".cfg", ".txt"))])
    envc = classify_env(env)
    deploy = find_deploy(project)
    port, port_src = 8000, "default"
    dff = deploy.get("dockerfile_facts") or {}
    if deploy.get("ports"):
        port, port_src = deploy["ports"][0]["container"], "%s service %s" % (deploy.get("compose_file"), deploy.get("service"))
    elif dff.get("cmd_port") or dff.get("port"):
        port, port_src = dff.get("cmd_port") or dff.get("port"), "Dockerfile"
    if port_src == "default":
        assumptions.append("port not found in Dockerfile/compose; assuming 8000")
    tests = find_tests(project)
    tests = [t for t in tests if t.split("/")[0] in release or t == "."]
    tests_cmd = ""
    if tests:
        tests_cmd = "python -m pytest %s -q -p no:cacheprovider" % " ".join(tests)
        if "pytest" not in reqs and not os.path.isfile(os.path.join(project, "pytest.ini")):
            assumptions.append("pytest is not listed in the requirements; assuming the tests are pytest tests")
    # database: the env var's default if it exists on disk, else the only sqlite file found
    prod_db, db_src = None, None
    if envc["db_env"]:
        d = env[envc["db_env"]].get("default")
        df_env = (deploy.get("service_env") or {}).get(envc["db_env"]) or dff.get("env", {}).get(envc["db_env"])
        for cand in (d, df_env):
            if isinstance(cand, str) and not cand.startswith("<expr") and os.path.isfile(os.path.join(project, cand)):
                prod_db, db_src = cand, "default value of %s" % envc["db_env"]
                break
    if prod_db is None and len(sqlite) == 1:
        prod_db, db_src = sqlite[0], "only SQLite file in the project"
    elif prod_db is None and sqlite:
        prod_db, db_src = sqlite[0], "first of several SQLite files (%s)" % ", ".join(sqlite)
        assumptions.append("several SQLite files found; using %s as the production database" % sqlite[0])
    name = slug(c.get("title") or package)
    return {"project": project, "runtime": "python-asgi", "framework": c["framework"], "asgi": c["asgi"],
            "asgi_candidates": [x["asgi"] for x in cands], "app_file": c["file"], "title": c.get("title"),
            "name": name, "package": package, "source_dirs": [source_dir], "release_paths": release,
            "port": port, "port_source": port_src, "env": env, **envc, "tests": tests, "tests_command": tests_cmd,
            "deploy": deploy, "sqlite_files": sqlite, "prod_db": prod_db, "prod_db_source": db_src,
            "assumptions": assumptions, "problems": []}
