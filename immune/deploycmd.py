"""`.immune/deploy/` generation (init step 9) and `immune deploy`.

    generate(cfg, det) -> {"style", "files", "command"}     # writes the artefacts
    python -m immune.deploycmd [--project DIR] [--dry-run]  # `immune deploy`

compose / Dockerfile projects get `.immune/deploy/compose.immune.yaml`, an override for the project's own
compose file: the app service is no longer published, it joins the stack's internal prod network, and the
gateway publishes the app's host port. Without a compose file the override contains the app service itself
(built from the Dockerfile). Anything else gets manual steps. `.immune/DEPLOY.md` (copied to
`.immune/deploy/DEPLOY.md`) has the exact commands and what changes for traffic.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

import yaml

from immune import _cfg

GATEWAY_PORT = 8080


def _host_port(det: dict, cfg) -> int:
    for p in (det.get("deploy") or {}).get("ports") or []:
        if p.get("container") == cfg.app.port and p.get("host"):
            return int(p["host"])
    return cfg.app.port


def compose_override(cfg, det: dict) -> tuple[dict, str | None, str]:
    """(compose document, user compose file or None, app service name)."""
    d = det.get("deploy") or {}
    user_compose = d.get("compose_file") if d.get("style") == "compose" else None
    svc = d.get("service") or cfg.name
    host_port = _host_port(det, cfg)
    project = cfg.project_dir
    # own networks: `immune up` (P1) runs a separate stack (fleet-managed prod + gateway on 127.0.0.1); names must not clash
    net = {k: "%s-front_%s" % (cfg.compose_project, k) for k in ("prodnet", "clonenet", "ctrlnet", "edge")}
    common_env = {"IMMUNE_PROJECT": "/project", "PYTHONPATH": "/opt/immune", "RUN_ID": "deploy"}
    vols = ["%s:/opt/immune:ro" % _cfg.IMMUNE_HOME, "%s:/project/.immune:ro" % os.path.join(project, ".immune"),
            "%s:/project/.immune/runtime" % cfg.runtime_dir]
    if os.path.relpath(cfg.runtime_dir, project).startswith(".."):
        vols[-1] = "%s:/runtime" % cfg.runtime_dir
    rt = "/project/.immune/runtime" if vols[-1].endswith("/project/.immune/runtime") else "/runtime"
    services = {}
    app = {"networks": {"immune_prodnet": {"aliases": [svc]}}}
    if user_compose:
        app["ports"] = yaml_reset([])
    else:
        app.update({"build": {"context": project, "dockerfile": d.get("dockerfile") or "Dockerfile"},
                    "restart": "unless-stopped", "environment": {}})
    services[svc] = app
    services["immune-gateway"] = {
        "image": "immune-base:1", "container_name": "%s-front" % cfg.prefix, "command": "python -m gateway",
        "restart": "unless-stopped", "read_only": True, "cap_drop": ["ALL"], "tmpfs": ["/tmp"],
        "security_opt": ["no-new-privileges:true"], "working_dir": "/opt/immune",
        "environment": dict(common_env, PROD_ADDR="%s:%d" % (svc, cfg.app.port), PROD_RELEASE="t0",
                            OPENAPI_PATH="/project/.immune/%s" % os.path.relpath(cfg.openapi, os.path.join(project, ".immune")),
                            MANIFEST_PATH="%s/data/manifest.json" % rt,
                            RECORD_PATH="%s/recordings/requests.jsonl" % rt,
                            GW_DATA_PORT=str(GATEWAY_PORT)),
        "env_file": [os.path.join(project, ".immune", "deploy", "immune.env")],
        "volumes": vols,
        "networks": {"immune_prodnet": {"aliases": ["gateway"]}, "immune_clonenet": {"aliases": ["gateway"]},
                     "immune_ctrlnet": {"aliases": ["gateway"]}, "immune_edge": {}},
        "ports": ["%d:%d" % (host_port, GATEWAY_PORT)],
        "depends_on": [svc],
    }
    doc = {"services": services,
           "networks": {"immune_prodnet": {"name": net["prodnet"], "internal": True},
                        "immune_clonenet": {"name": net["clonenet"], "internal": True},
                        "immune_ctrlnet": {"name": net["ctrlnet"], "internal": True},
                        "immune_edge": {"name": net["edge"]}}}
    return doc, user_compose, svc


class yaml_reset(list):
    """Rendered as the compose `!reset` tag (drops the base file's value)."""


def _reset_representer(dumper, data):
    return dumper.represent_sequence("!reset", list(data), flow_style=True)


yaml.SafeDumper.add_representer(yaml_reset, _reset_representer)


def _env_file(path: str) -> None:
    if os.path.exists(path):
        return
    import secrets
    with open(path, "w") as f:
        f.write("# Secrets for the immune stack (generated once by `immune init`; keep out of git).\n")
        f.write("ADMIN_TOKEN=%s\nBUS_TOKEN=%s\n"
                "SHADOW_APP_SECRET=%s\n" % (secrets.token_hex(16), secrets.token_hex(16), secrets.token_hex(16)))
    os.chmod(path, 0o600)


def generate(cfg, det: dict) -> dict:
    ddir = os.path.join(cfg.project_dir, ".immune", "deploy")
    os.makedirs(ddir, exist_ok=True)
    d = det.get("deploy") or {}
    style = d.get("style", "unknown")
    files, cmd = [], None
    host_port = _host_port(det, cfg)
    proj = shlex.quote(cfg.project_dir)
    if style in ("compose", "dockerfile"):
        doc, user_compose, svc = compose_override(cfg, det)
        out = os.path.join(ddir, "compose.immune.yaml")
        with open(out, "w") as f:
            f.write("# Generated by `immune init`. Gateway in front of service %r: the app is no longer published;\n"
                    "# the gateway publishes host port %d and forwards clean traffic to %s:%d.\n"
                    % (svc, host_port, svc, cfg.app.port))
            yaml.safe_dump(doc, f, sort_keys=False, width=120)
        _env_file(os.path.join(ddir, "immune.env"))
        files.append(out)
        fs = (["-f", os.path.join(cfg.project_dir, user_compose)] if user_compose else []) + ["-f", out]
        cmd = ["docker", "compose", "--project-directory", cfg.project_dir] + fs + ["up", "-d"]
    text = deploy_md(cfg, det, style, cmd, host_port)
    for p in (os.path.join(cfg.project_dir, ".immune", "DEPLOY.md"), os.path.join(ddir, "DEPLOY.md")):
        with open(p, "w") as f:
            f.write(text)
        files.append(p)
    return {"style": style, "files": files, "command": cmd,
            "ready_command": ("immune deploy --project %s" % proj) if cmd else ("immune up --project %s" % proj)}


def deploy_md(cfg, det, style, cmd, host_port) -> str:
    d = det.get("deploy") or {}
    q = shlex.quote
    proj = q(cfg.project_dir)
    lines = ["# Deploying immune in front of %s" % cfg.name, "",
             "Generated by `immune init` (deploy style detected: **%s**%s)." % (
                 style, (", files: " + ", ".join(d.get("files") or [])) if d.get("files") else ""), ""]
    lines += ["## 1. Start the immune control plane", "",
              "```", "immune up --project %s" % proj, "```", "",
              "This starts the fleet (shadow clone pool), the pipeline (rules and patches) and the dashboard.", ""]
    if cmd:
        lines += ["## 2. Put the gateway in front of the app", "",
                  "```", "immune deploy --project %s" % proj, "# equivalent to:", " ".join(q(c) for c in cmd), "```", "",
                  "What changes for traffic:", "",
                  "- host port **%d** is now served by the gateway (`%s-front`), not by the app;" % (host_port, cfg.prefix),
                  "- the app service `%s` is no longer published; it is reachable only on the internal network `%s`;"
                  % (d.get("service") or cfg.name, "%s-front_prodnet" % cfg.compose_project),
                  "- clean requests are forwarded unchanged to `%s:%d`; suspicious ones run first on a shadow clone "
                  "with synthetic data; confirmed attacks get a deny or synthetic data (mode `%s`);"
                  % (d.get("service") or cfg.name, cfg.app.port, cfg.mode),
                  "- this front gateway is a separate container from the one `immune up` runs on 127.0.0.1:%d; "
                  "its admin API is not published." % cfg.ports.get("gateway", 8080), "",
                  "Roll back: run your own compose file without the override (`docker compose up -d`), then "
                  "`immune down --project %s`." % proj, ""]
    else:
        lines += ["## 2. Put the gateway in front of the app (manual)", "",
                  "No compose file or Dockerfile was found (style: %s), so nothing is applied automatically." % style, "",
                  "1. Stop publishing the app on its public port; bind it to an internal address only.",
                  "2. Run the gateway (`python -m gateway`, image `immune-base:1`) with `IMMUNE_PROJECT=%s`, "
                  "`PROD_ADDR=<app host>:%d`, and publish its port %d where the app used to listen (%d)."
                  % (proj, cfg.app.port, GATEWAY_PORT, host_port),
                  "3. Keep the gateway admin port (8081) on 127.0.0.1 only.",
                  "4. Check: `curl http://<host>:%d%s` answers through the gateway." % (host_port, cfg.app.health), ""]
    lines += ["## Data", "",
              "The shadow seed was derived from `%s` at init time (`data.prod_db`). Rebuild it after schema changes "
              "with `immune init --project %s --yes`." % (os.path.relpath(cfg.data.prod_db, cfg.project_dir), proj)]
    vols = d.get("volumes") or []
    if vols:
        lines += ["", "The compose service keeps its data in %s. If the live database is inside a volume, export it "
                  "(e.g. `docker compose cp %s:<db path> %s`) before rebuilding the shadow."
                  % (", ".join("`%s`" % v for v in vols), d.get("service"),
                     os.path.relpath(cfg.data.prod_db, cfg.project_dir))]
    lines += ["", "## Policy", "", "- mode: `%s` (`immune mode observe|enforce`)" % cfg.mode,
              "- autopatch: `%s` (`immune autopatch off|pr|merge`)%s" % (
                  cfg.autopatch, "" if cfg.tests_command else "; no tests command, so it is capped at `pr`"), ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="immune deploy")
    ap.add_argument("--project", default=None)
    ap.add_argument("--dry-run", action="store_true", help="print the command instead of running it")
    a = ap.parse_args(argv)
    cfg = _cfg.load(os.path.abspath(a.project) if a.project else None)
    ddir = os.path.join(cfg.project_dir, ".immune", "deploy")
    override = os.path.join(ddir, "compose.immune.yaml")
    md = os.path.join(cfg.project_dir, ".immune", "DEPLOY.md")
    if not os.path.isfile(override):
        if os.path.isfile(md):
            print(open(md).read())
        else:
            print("no deploy artefacts in %s; run `immune init` first" % ddir)
            return 1
        print("\nNo compose override was generated: follow the manual steps above.")
        return 0
    user = None
    d_path = os.path.join(cfg.project_dir, ".immune", "shadow", "detect.yaml")
    if os.path.isfile(d_path):
        with open(d_path) as f:
            det = yaml.safe_load(f) or {}
        uc = (det.get("deploy") or {}).get("compose_file")
        if uc and (det.get("deploy") or {}).get("style") == "compose":
            user = os.path.join(cfg.project_dir, uc)
    cmd = ["docker", "compose", "--project-directory", cfg.project_dir] + (["-f", user] if user else []) + \
          ["-f", override, "up", "-d"]
    print(" ".join(shlex.quote(c) for c in cmd))
    if a.dry_run:
        return 0
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
