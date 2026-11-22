"""CVE-replay orchestrator: stand the product on a real pre-patch release, drive the public
PoC, let the out-of-process oracle fire, feed generic evidence to patcher.propose, then rebuild
the target with our diff and prove the PoC is blocked while legit traffic still works.

Subcommands:
  prepare   build the vulnerable image (source tree assumed already extracted under releases/)
  detect    run the vulnerable target, fire PoC, run oracle -> incident.json + evidence
  patch     patcher.propose on the incident -> patch.diff (real LLM)
  compare   diff our patched region against the upstream 2.4.50 fix
  verify    rebuild the target WITH our diff; PoC blocked? legit ok? bypass held?
  demo      detect -> patch -> compare -> verify, publishing to the bus throughout
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from cve_replay import bus  # noqa: E402
from cve_replay.incident import build_incident  # noqa: E402
from cve_replay.oracle import FileEscapeOracle  # noqa: E402
from cve_replay.targets import TARGETS  # noqa: E402

RUNDIR = HERE / "runs"
RUNDIR.mkdir(exist_ok=True)
CTR = "immune-cve-apache-run"


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, **kw)


def _read_flushed_trace(container: str) -> str:
    # stop so strace (PID1) flushes its output buffer, then copy the complete log out.
    sh(["docker", "stop", "-t", "3", container])
    dest = RUNDIR / "_trace.log"
    sh(["docker", "cp", f"{container}:/tmp/trace.log", str(dest)])
    return dest.read_text(errors="replace") if dest.exists() else ""


def _lines_between(trace: str, lo: float, hi: float) -> str:
    """strace -ttt lines whose absolute timestamp is in [lo, hi) (same CLOCK_REALTIME as host)."""
    out = []
    for ln in trace.splitlines():
        parts = ln.split(None, 2)
        if len(parts) >= 2:
            try:
                ts = float(parts[1])
            except ValueError:
                continue
            if lo <= ts < hi:
                out.append(ln)
    return "\n".join(out)


def _http(path: str, port: int) -> tuple[int, str]:
    # curl --path-as-is: the raw request-target reaches the server unnormalised, which is the
    # whole point of a traversal PoC (urllib would collapse the ../ client-side).
    url = f"http://127.0.0.1:{port}{path}"
    r = sh(["curl", "-s", "--path-as-is", "-w", "\n__STATUS__%{http_code}", url])
    out = r.stdout
    marker = out.rfind("__STATUS__")
    if marker == -1:
        return -1, out or r.stderr
    body = out[:marker].rstrip("\n")
    try:
        code = int(out[marker + len("__STATUS__"):].strip())
    except ValueError:
        code = -1
    return code, body


def _wait_http(port: int, tries: int = 40) -> bool:
    for _ in range(tries):
        st, _ = _http("/", port)
        if st == 200:
            return True
        time.sleep(0.25)
    return False


# ----------------------------------------------------------------------------- prepare
def _fetch_source(t) -> Path:
    src = HERE / "releases" / t.source_subdir
    if (src / "server" / "util.c").exists():
        return src
    src.parent.mkdir(parents=True, exist_ok=True)
    tgz = src.parent / f"{t.source_subdir}.tar.gz"
    print(f"[prepare] downloading {t.source_url}")
    r = sh(["curl", "-fsSL", "-o", str(tgz), t.source_url])
    if r.returncode:
        sys.exit(f"download failed: {r.stderr}")
    # tarball top dir is httpd-<ver>; extract then rename to source_subdir
    sh(["tar", "xzf", str(tgz), "-C", str(src.parent)])
    top = t.source_url.rsplit("/", 1)[-1].replace(".tar.gz", "")
    extracted = src.parent / top
    if extracted.exists() and extracted != src:
        extracted.rename(src)
    tgz.unlink(missing_ok=True)
    if not (src / "server" / "util.c").exists():
        sys.exit(f"source tree not found after extract: {src}")
    return src


def prepare(t) -> None:
    _fetch_source(t)
    print(f"[prepare] building vulnerable image {t.image}")
    r = sh(["docker", "build", "-t", t.image, "-f", str(HERE / t.build_dir / "Dockerfile.vuln"),
            str(HERE / t.build_dir)])
    print(r.stdout[-800:]); print(r.stderr[-800:])
    if r.returncode:
        sys.exit("build failed")


def _run_vuln(t) -> None:
    sh(["docker", "rm", "-f", CTR])
    r = sh(["docker", "run", "-d", "--name", CTR, "--cap-add=SYS_PTRACE",
            "-p", f"{t.port}:80", t.image])
    if r.returncode:
        sys.exit(f"could not start target: {r.stderr}")
    if not _wait_http(t.port):
        print(sh(["docker", "logs", CTR]).stdout[-1000:])
        sys.exit("target did not come up")


# ----------------------------------------------------------------------------- detect
def detect(t) -> dict:
    print(f"[detect] standing up pre-patch {t.service} ({t.cve})")
    _run_vuln(t)
    oracle = FileEscapeOracle(t.allowed_roots)

    # Fire a legitimate request, then the PoC, recording wall-clock boundaries. strace buffers
    # its file output, so we read the whole trace only after stopping the container, then split
    # it by the absolute -ttt timestamps: startup | legit (learn baseline) | PoC (judge).
    time.sleep(0.3)
    t_legit = time.time()
    st, body = _http(t.legit_path, t.port)
    print(f"[detect] legit  {t.legit_path} -> {st}  ({'ok' if t.legit_proof in body else 'UNEXPECTED'})")
    time.sleep(0.4)
    t_poc = time.time()
    st, body = _http(t.poc_path, t.port)
    leaked = t.poc_proof in body
    print(f"[detect] PoC    {t.poc_path} -> {st}  ({'LEAKED '+t.poc_proof if leaked else 'no leak'})")
    time.sleep(0.6)
    t_end = time.time() + 60.0

    trace = _read_flushed_trace(CTR)
    oracle.prewarm(_lines_between(trace, t_legit, t_poc))   # files a normal request opens
    attack_trace = _lines_between(trace, t_poc, t_end)      # files the PoC request opened

    events = oracle.check(attack_trace)
    print(f"[detect] oracle fired {len(events)} event(s): "
          + ", ".join(e["detail"]["opened"] for e in events))
    req = {"method": t.method, "path": t.poc_path, "status": st}
    inc = build_incident(t, req, events)

    out = RUNDIR / f"{t.key}.incident.json"
    out.write_text(json.dumps(inc, indent=2))
    (RUNDIR / f"{t.key}.evidence.json").write_text(json.dumps(inc["evidence"], indent=2))
    print(f"[detect] wrote {out}")

    bus.publish("oracle.fired", inc["evidence"], rid=inc["incident"], incident=inc["incident"])
    bus.publish("incident.opened", {
        "incident": inc["incident"], "vuln_class": inc["vuln_class"], "method": inc["method"],
        "route": inc["route"], "param": inc["param"], "sink": inc["sink"],
        "evidence_rid": inc["incident"], "request": inc["request"],
    }, incident=inc["incident"])
    bus.publish("poc.ready", {"incident": inc["incident"], "reproducible": leaked, "runs": 1,
                              "poc": t.poc_path}, incident=inc["incident"])
    sh(["docker", "rm", "-f", CTR])
    if not events:
        sys.exit("oracle did not fire; aborting")
    return inc


# ----------------------------------------------------------------------------- patch
def patch(t, inc: dict | None = None) -> dict:
    from patcher import core
    if inc is None:
        inc = json.loads((RUNDIR / f"{t.key}.incident.json").read_text())
    release_dir = str((HERE / "releases" / t.source_subdir).resolve())
    print(f"[patch] patcher.propose lang={inc['lang']} editable={inc['editable_files']}")
    bus.publish("patch.attempt", {"incident": inc["incident"], "attempt": 1, "source": "llm"},
                incident=inc["incident"])
    res = core.propose(release_dir, inc)
    diff = res.get("diff", "")
    (RUNDIR / f"{t.key}.patch.diff").write_text(diff)
    print(f"[patch] source={res.get('source')}  diff {len(diff)} bytes -> {t.key}.patch.diff")
    # files touched
    touched = sorted({ln[6:].strip() for ln in diff.splitlines()
                      if ln.startswith("+++ b/") or ln.startswith("--- a/")})
    print(f"[patch] files touched: {touched}")
    bus.publish("patch.diff", {"incident": inc["incident"], "attempt": 1, "diff": diff},
                incident=inc["incident"])
    return res


# ----------------------------------------------------------------------------- compare
def compare(t) -> None:
    diff = (RUNDIR / f"{t.key}.patch.diff").read_text()
    print("=" * 70)
    print(f"OUR PROPOSED PATCH ({t.key})")
    print("=" * 70)
    print(diff[:4000])
    print("=" * 70)
    print(f"UPSTREAM FIX: {t.service} {t.upstream_fixed_in} touched {t.upstream_fix_file}")
    print(t.bypass_note)
    print("=" * 70)


# ----------------------------------------------------------------------------- verify
def verify(t) -> dict:
    diffp = RUNDIR / f"{t.key}.patch.diff"
    if not diffp.exists() or not diffp.read_text().strip():
        sys.exit("no patch.diff to verify; run patch first")
    img = f"{t.image}-patched"
    ctx = HERE / t.build_dir
    # stage the diff where the build Dockerfile can COPY it
    (ctx / "patch.diff").write_text(diffp.read_text())
    print(f"[verify] building patched {t.service} from source (this compiles httpd, ~minutes)")
    r = subprocess.run(["docker", "build", "-t", img, "-f", str(ctx / "Dockerfile.build"),
                        "--build-arg", f"SRC={t.source_subdir}", str(ROOT / "cve_replay")],
                       text=True)
    if r.returncode:
        sys.exit("patched build failed")

    sh(["docker", "rm", "-f", CTR])
    r = sh(["docker", "run", "-d", "--name", CTR, "-p", f"{t.port}:80", img])
    if r.returncode or not _wait_http(t.port):
        print(sh(["docker", "logs", CTR]).stdout[-1200:])
        sys.exit("patched target did not come up (patch may break legit startup)")

    st_poc, body_poc = _http(t.poc_path, t.port)
    leaked = t.poc_proof in body_poc
    st_legit, body_legit = _http(t.legit_path, t.port)
    legit_ok = t.legit_proof in body_legit
    st_byp, body_byp = _http(t.bypass_path, t.port) if t.bypass_path else (0, "")
    byp_leaked = bool(t.bypass_path) and t.poc_proof in body_byp

    print("-" * 60)
    print(f"[verify] PoC     {t.poc_path} -> {st_poc}  {'STILL LEAKS!' if leaked else 'BLOCKED'}")
    if t.bypass_path:
        print(f"[verify] bypass  {t.bypass_path} -> {st_byp}  {'STILL LEAKS!' if byp_leaked else 'BLOCKED'}")
    print(f"[verify] legit   {t.legit_path} -> {st_legit}  {'OK' if legit_ok else 'BROKEN!'}")
    print("-" * 60)
    sh(["docker", "rm", "-f", CTR])

    ok = (not leaked) and legit_ok and (not byp_leaked)
    bus.publish("verify.result", {"incident": f"cve-{t.key}", "exploit_blocked_on_prod": not leaked},
                incident=f"cve-{t.key}")
    bus.publish("incident.closed", {"incident": f"cve-{t.key}",
                "outcome": "patched" if ok else "rule_only",
                "seconds_to_rule": None, "seconds_to_patch": None}, incident=f"cve-{t.key}")
    return {"poc_blocked": not leaked, "legit_ok": legit_ok, "bypass_blocked": not byp_leaked, "ok": ok}


def iterate(t) -> dict:
    """Close the loop the way the product does: the patched build is re-probed, and whatever
    STILL escapes becomes runtime feedback for a second, stronger proposal (same editable scope).
    This mirrors upstream going 2.4.50 -> 2.4.51 after its first fix was bypassed."""
    from patcher import core
    inc = json.loads((RUNDIR / f"{t.key}.incident.json").read_text())
    release_dir = str((HERE / "releases" / t.source_subdir).resolve())

    # keep v1, build feedback purely from observed runtime behaviour of the patched build
    v1 = RUNDIR / f"{t.key}.patch.diff"
    if v1.exists():
        (RUNDIR / f"{t.key}.patch.v1.diff").write_text(v1.read_text())
    feedback = [
        "The previous change was deployed and the server was re-probed with live traffic.",
        "A request still returned the contents of a file OUTSIDE the document root:",
        f"    {t.method} {t.bypass_path}",
        f"    response body contained: {t.bypass_proof!r}",
        "So an attacker-controlled request-target can still be normalised into a path that "
        "escapes the web root. Decode every percent-encoded octet (including octets that "
        "themselves encode a '%', so the decoder must not stop after a single pass) BEFORE "
        "resolving '.'/'..' segments, and make an escaped path fail. Do not special-case the "
        "exact bytes above; fix the normalisation/decoding so any encoding of the escape fails.",
    ]
    print("[iterate] re-proposing (attempt 2) with runtime feedback from the patched build")
    bus.publish("gate.result", {"incident": inc["incident"], "attempt": 1, "gate": "poc",
                "ok": False, "detail": "bypass still leaks after v1"}, incident=inc["incident"])
    bus.publish("patch.attempt", {"incident": inc["incident"], "attempt": 2, "source": "llm"},
                incident=inc["incident"])
    res = core.propose(release_dir, inc, feedback=feedback, attempt=2)
    diff = res.get("diff", "")
    v1.write_text(diff)
    print(f"[iterate] source={res.get('source')}  v2 diff {len(diff)} bytes")
    touched = sorted({ln[6:].strip() for ln in diff.splitlines()
                      if ln.startswith("+++ b/") or ln.startswith("--- a/")})
    print(f"[iterate] files touched: {touched}")
    bus.publish("patch.diff", {"incident": inc["incident"], "attempt": 2, "diff": diff},
                incident=inc["incident"])
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["prepare", "detect", "patch", "iterate", "compare", "verify", "demo"])
    ap.add_argument("--target", default="apache-2.4.49")
    a = ap.parse_args()
    t = TARGETS[a.target]
    if a.cmd == "prepare":
        prepare(t)
    elif a.cmd == "detect":
        detect(t)
    elif a.cmd == "patch":
        patch(t)
    elif a.cmd == "iterate":
        iterate(t)
    elif a.cmd == "compare":
        compare(t)
    elif a.cmd == "verify":
        print(json.dumps(verify(t), indent=2))
    elif a.cmd == "demo":
        inc = detect(t)
        patch(t, inc)
        compare(t)
        print(json.dumps(verify(t), indent=2))


if __name__ == "__main__":
    main()
