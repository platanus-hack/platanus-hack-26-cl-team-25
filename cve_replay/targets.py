"""Replay targets: a real service pinned to the commit *before* an upstream patch.

A target is pure data. The orchestrator uses it to (1) bring up the vulnerable service,
(2) fire the public exploit and a legitimate request, (3) tell the oracle which roots are
legitimate, and (4) hand the patcher the source scope, editable files, sink and stack that
its own instrumentation + static localisation would produce.

Nothing here names the CVE to the patcher; the model only ever sees the generic evidence.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))


@dataclass
class Target:
    key: str
    service: str                       # human label (shown in the report, not to the model)
    cve: str
    vuln_class: str
    source_url: str
    source_subdir: str                 # release dir name under cve_replay/releases/
    image: str                         # docker image tag built from build_dir
    build_dir: str                     # dir with Dockerfile.vuln + config
    port: int
    allowed_roots: list[str]           # dirs the server may legitimately read from
    poc_path: str                      # raw request-target (sent with --path-as-is)
    poc_proof: str                     # substring that proves the exploit worked
    legit_path: str
    legit_proof: str
    app_subdirs: list[str]             # source copied into the patcher workspace
    editable_files: list[str]          # files the model may edit (root cause lives here)
    sink: dict                         # innermost localised frame
    stack: list[dict]                  # outermost-first, from static localisation
    param: dict
    route: str
    method: str = "GET"
    upstream_fixed_in: str = ""
    upstream_fix_file: str = ""
    bypass_note: str = ""
    bypass_path: str = ""      # CVE-2021-42013 double-encoded bypass of the 2.4.50 fix
    bypass_proof: str = ""


APACHE_2449 = Target(
    key="apache-2.4.49",
    service="Apache httpd 2.4.49",
    cve="CVE-2021-41773",
    vuln_class="traversal",
    source_url="https://archive.apache.org/dist/httpd/httpd-2.4.49.tar.gz",
    source_subdir="apache-2.4.49",
    image="immune-cve-apache:2.4.49",
    build_dir=os.path.join(HERE, "apache2449"),
    port=8088,
    allowed_roots=[
        "/usr/local/apache2/htdocs",
        "/usr/local/apache2/cgi-bin",
        "/usr/local/apache2/icons",
        "/usr/local/apache2/error",
    ],
    # classic public PoC: encoded dot-dot that survives normalisation, then decodes to ../
    poc_path="/static/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    poc_proof="root:x:0:0:",
    legit_path="/",
    legit_proof="It works!",
    bypass_path="/static/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
    bypass_proof="root:x:0:0:",
    app_subdirs=["server", "include", "os"],
    editable_files=["server/util.c"],
    sink={"file": "server/util.c", "line": 502, "func": "ap_normalize_path"},
    stack=[
        {"file": "server/request.c", "line": 209,
         "func": "ap_process_request_internal (normalise request-target)"},
        {"file": "server/request.c", "line": 250,
         "func": "ap_unescape_url (decode %2e in the path)"},
        {"file": "server/util.c", "line": 502, "func": "ap_normalize_path"},
    ],
    param={"in": "path", "name": "(request-target)"},
    route="/static/*",
    method="GET",
    upstream_fixed_in="2.4.50",
    upstream_fix_file="server/util.c",
    bypass_note=("The first upstream fix (2.4.50) was itself bypassed 3 days later by "
                 "CVE-2021-42013 (double-encoded %%32%%65); 2.4.51 was the complete fix. "
                 "A good patch must resist the bypass too."),
)

TARGETS = {APACHE_2449.key: APACHE_2449}
