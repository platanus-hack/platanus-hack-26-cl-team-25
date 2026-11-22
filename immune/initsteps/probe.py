"""Child-process probe (run through immune.initsteps.sandbox, never imported by the installer).

Job (stdin JSON): {"op": "inspect"|"call"|"openapi", "profile": module, "asgi": "mod:attr", "arg": ...}
Prints one JSON line on the real stdout.
"""
from __future__ import annotations

import importlib
import inspect
import json
import os
import sys
import traceback

REQUIRED = ("allowed_file_roots", "ensure_user", "mint_token", "load_markers", "public_paths")


def _load_app(spec):
    mod, _, attr = spec.partition(":")
    m = importlib.import_module(mod)
    obj = m
    for part in (attr or "app").split("."):
        obj = getattr(obj, part)
    return obj


def main():
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    out = {"ok": False}
    try:
        job = json.loads(sys.stdin.read() or "{}")
        op = job.get("op")
        if op == "openapi":
            app = _load_app(job["asgi"])
            if not hasattr(app, "openapi"):
                raise RuntimeError("%s has no openapi() (not a FastAPI app)" % job["asgi"])
            out = {"ok": True, "openapi": app.openapi()}
        elif op == "inspect":
            prof = importlib.import_module(job["profile"])
            fns = sorted(n for n, v in vars(prof).items() if callable(v) and not n.startswith("_"))
            missing = [f for f in REQUIRED if not callable(getattr(prof, f, None))]
            sigs = {}
            for f in REQUIRED + ("hash_password",):
                fn = getattr(prof, f, None)
                if callable(fn):
                    try:
                        sigs[f] = len(inspect.signature(fn).parameters)
                    except (TypeError, ValueError):
                        sigs[f] = None
            app_spec = getattr(prof, "APP", None)
            app_ok, app_err = False, ""
            if not isinstance(app_spec, str) or ":" not in app_spec:
                app_err = "APP must be a 'module:attribute' string (got %r)" % (app_spec,)
            else:
                try:
                    app = _load_app(app_spec)
                    app_ok = callable(app)
                    if not app_ok:
                        app_err = "%s is not callable" % app_spec
                except Exception as e:  # noqa: BLE001
                    app_err = "cannot import %s: %s: %s" % (app_spec, e.__class__.__name__, e)
            env = dict(os.environ)
            pub, roots, perr = None, None, []
            try:
                pub = list(prof.public_paths())
            except Exception as e:  # noqa: BLE001
                perr.append("public_paths(): %s: %s" % (e.__class__.__name__, e))
            try:
                roots = [str(r) for r in prof.allowed_file_roots(env)]
            except Exception as e:  # noqa: BLE001
                perr.append("allowed_file_roots(env): %s: %s" % (e.__class__.__name__, e))
            out = {"ok": True, "functions": fns, "missing": missing, "arity": sigs, "app": app_spec, "app_ok": app_ok,
                   "app_error": app_err, "public_paths": pub, "allowed_file_roots": roots, "errors": perr,
                   "file": getattr(prof, "__file__", None)}
        elif op == "call":
            prof = importlib.import_module(job["profile"])
            fn = getattr(prof, job["arg"]["fn"])
            arg = job["arg"]["arg"]
            if job["arg"]["fn"] == "hash_password":
                res = [fn(p) for p in arg]
            else:
                res = fn(arg)
            out = {"ok": True, "result": res}
        else:
            out = {"ok": False, "error": "unknown op %r" % op}
    except BaseException as e:  # noqa: BLE001
        out = {"ok": False, "error": "%s: %s" % (e.__class__.__name__, e), "trace": traceback.format_exc()[-2000:]}
    real_stdout.write("\n" + json.dumps(out, default=str) + "\n")
    real_stdout.flush()


if __name__ == "__main__":
    main()
