"""Prepare the OpenEMR 8.2.0 project for Immune: examples/openemr/app

    python examples/openemr/fetch.py [--dest DIR] [--repo LOCAL_CLONE]

1. clones https://github.com/openemr/openemr at tag v8_2_0 (depth 1, LF line endings whatever the host's git
   settings) or reuses --repo, and refuses anything whose tag does not resolve to the pinned commit
   6125a2fd8089c8bcc3848071c1293c60e27a7585 or whose version.php is not 8.2.0;
2. adds the onboarding (overlay/): .immune/ (config, OpenAPI, shadow classification, identity profile),
   immune-runtime/ (start, Apache, PHP, seed) and Dockerfile.immune. Not a single OpenEMR file changes:
   the script verifies that `git diff v8_2_0` of the tracked tree is empty;
3. commits the onboarding and tags it openemr-t0 (repo.t0_tag).

Then: bin/immune up --project examples/openemr/app
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

TAG = "v8_2_0"
COMMIT = "6125a2fd8089c8bcc3848071c1293c60e27a7585"
UPSTREAM = "https://github.com/openemr/openemr.git"
T0 = "openemr-t0"
HERE = os.path.dirname(os.path.abspath(__file__))
OVERLAY = os.path.join(HERE, "overlay")
LF = ["-c", "core.autocrlf=false", "-c", "core.eol=lf"]


def git(repo, *args, check=True, capture=True):
    p = subprocess.run(["git", *LF, "-C", repo, *args], text=True, capture_output=capture)
    if check and p.returncode != 0:
        sys.exit("git %s: %s" % (" ".join(args[:2]), (p.stderr or p.stdout or "").strip()[-600:]))
    return (p.stdout or "").strip()


def verify(dest):
    sha = git(dest, "rev-parse", "refs/tags/%s^{commit}" % TAG)
    if sha != COMMIT:
        sys.exit("tag %s resolves to %s, expected %s: refusing" % (TAG, sha, COMMIT))
    with open(os.path.join(dest, "version.php"), encoding="utf-8") as fh:
        v = fh.read()
    got = tuple(re.search(r"\$v_%s\s*=\s*'([^']*)'" % k, v).group(1) for k in ("major", "minor", "patch"))
    if got != ("8", "2", "0"):
        sys.exit("version.php says %s, expected 8.2.0" % ".".join(got))
    changed = git(dest, "diff", "--name-only", COMMIT, "--", ".", ":!.immune", ":!immune-runtime",
                  ":!Dockerfile.immune")
    if changed:
        sys.exit("OpenEMR files differ from %s:\n%s" % (TAG, changed))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fetch.py")
    ap.add_argument("--dest", default=os.path.join(HERE, "app"))
    ap.add_argument("--repo", help="an existing local clone that has the tag %s" % TAG)
    a = ap.parse_args(argv)
    dest = os.path.abspath(a.dest)
    if not os.path.isdir(os.path.join(dest, ".git")):
        if a.repo:
            subprocess.run(["git", *LF, "clone", "--no-checkout", a.repo, dest], check=True)
            git(dest, "fetch", "origin", "refs/tags/%s:refs/tags/%s" % (TAG, TAG))
        else:
            subprocess.run(["git", *LF, "clone", "--depth", "1", "--branch", TAG, "--no-checkout", UPSTREAM, dest],
                           check=True)
        git(dest, "config", "core.autocrlf", "false")
        git(dest, "config", "core.eol", "lf")
        git(dest, "checkout", "-q", "--detach", COMMIT)
    git(dest, "config", "core.autocrlf", "false")
    if git(dest, "rev-parse", "refs/tags/%s^{commit}" % TAG) != COMMIT:
        sys.exit("tag %s does not resolve to the pinned commit %s" % (TAG, COMMIT))
    head = git(dest, "rev-parse", "HEAD")
    if head != COMMIT and git(dest, "rev-parse", "HEAD~1", check=False) != COMMIT:
        sys.exit("%s is at %s, neither the pinned commit nor its onboarding commit" % (dest, head))

    # onboarding: copied on top, never over an OpenEMR file
    for root, dirs, files in os.walk(OVERLAY):
        dirs[:] = [d for d in dirs if d not in ("runtime", "__pycache__")]
        for name in files:
            src = os.path.join(root, name)
            rel = os.path.relpath(src, OVERLAY).replace(os.sep, "/")
            if not (rel.startswith((".immune/", "immune-runtime/")) or rel == "Dockerfile.immune"):
                sys.exit("overlay file %s is outside the onboarding paths" % rel)
            if git(dest, "ls-tree", "--name-only", COMMIT, rel, check=False):
                sys.exit("overlay file %s would replace an OpenEMR file" % rel)
            target = os.path.join(dest, *rel.split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(src, "rb") as fi, open(target, "wb") as fo:
                fo.write(fi.read().replace(b"\r\n", b"\n"))
    verify(dest)
    git(dest, "add", "-f", ".immune", "immune-runtime", "Dockerfile.immune")
    git(dest, "reset", "-q", "--", ".immune/runtime")
    if git(dest, "status", "--porcelain", "--", ".immune", "immune-runtime", "Dockerfile.immune"):
        if head != COMMIT:
            git(dest, "reset", "-q", "--soft", COMMIT)
        git(dest, "-c", "user.name=Immune", "-c", "user.email=inmune@localhost.invalid", "commit", "-q", "-m",
            "Immune onboarding for OpenEMR 8.2.0 (no OpenEMR file changed)")
    git(dest, "tag", "-f", T0)
    verify(dest)
    print("OpenEMR %s (%s) ready at %s, tag %s" % (TAG, COMMIT[:12], dest, T0))
    print("next: bin/immune up --project %s" % dest)


if __name__ == "__main__":
    main()
