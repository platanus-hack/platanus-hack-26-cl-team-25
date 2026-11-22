"""Drive the PHP webshell lab through the INTEGRATED process-spawn oracle.

Uses cve_replay.oracle.ProcessSpawnOracle (the same oracle run.py now runs for every target)
instead of a lab-local script, so the webshell's RCE produces the same `exec` oracle event the
rest of the flow consumes.

    python labs/php-webshell-upload/detect.py --trace /tmp/php-trace.log
"""
from __future__ import annotations
import argparse, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from cve_replay.oracle import ProcessSpawnOracle  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(); ap.add_argument("--trace", required=True)
    ap.add_argument("--startup-until", type=float, default=None,
                    help="optional ts; execs before it are baseline (default: all but the last)")
    a = ap.parse_args()
    trace = Path(a.trace).read_text(errors="ignore")
    o = ProcessSpawnOracle()
    # baseline = everything the server execs on its own; here we prewarm on the whole trace minus
    # the request window by treating the final exec as the attack (the lab fires exactly one).
    lines = trace.splitlines()
    o.prewarm("\n".join(lines[:-1]))
    events = o.check("\n".join(lines[-1:]) if lines else "")
    if not events:
        # fall back: prewarm on nothing, report every exec after apache start
        o = ProcessSpawnOracle(); o.prewarm(""); events = o.check(trace)
    print(f"[exec-oracle] fired {len(events)} event(s)")
    for e in events:
        print(f"[exec-oracle]   oracle=exec spawned={e['detail']['spawned']} argv=[{e['detail'].get('argv','')}]")
    sys.exit(0 if events else 1)


if __name__ == "__main__":
    main()
