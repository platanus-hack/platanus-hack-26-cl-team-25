#!/usr/bin/env sh
# install.sh: install the `immune` CLI from this checkout (contracts/product.md section 5).
#   ./install.sh            check Docker, git and Python >= 3.12, create .venv from deploy/requirements.txt,
#                           make sure the images exist, link bin/immune into ~/.local/bin, then report
#                           the optional prerequisites (`immune doctor --prereqs`)
# Idempotent: every step is skipped when already done. Never uses sudo.
# Env: IMMUNE_BIN_DIR (default ~/.local/bin), PYTHON (default python3), IMMUNE_SKIP_IMAGES=1,
#      IMMUNE_WITH_ANTICIPATE=1 (also build immune-cbuild:1, only used by `immune anticipate`)
set -eu

HOME_DIR=$(cd "$(dirname "$0")" && pwd)
BIN_DIR=${IMMUNE_BIN_DIR:-"$HOME/.local/bin"}
PY=${PYTHON:-python3}
VENV="$HOME_DIR/.venv"
REQ="$HOME_DIR/deploy/requirements.txt"

say() { printf 'install: %s\n' "$*"; }
die() { printf 'install: ERROR: %s\n' "$*" >&2; exit 1; }

# 1. Docker (no sudo: the user must be able to talk to the daemon)
command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install Docker Engine (https://docs.docker.com/engine/install/) and re-run."
if ! err=$(docker info 2>&1 >/dev/null); then
  me=$(id -un 2>/dev/null) || me=$(id -u)
  case "$err" in
    *"ermission denied"*) die "Docker is running but user $me may not use it. Add yourself to the 'docker' group (sudo usermod -aG docker $me), log in again and re-run; this script never uses sudo." ;;
    *) die "cannot reach the Docker daemon as $me: $(printf '%s' "$err" | tail -n 1). Start it (e.g. sudo systemctl start docker) and re-run." ;;
  esac
fi
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is missing ('docker compose version' failed). Install it (package docker-compose-plugin from Docker's repository, or docker-compose-v2 on Ubuntu; https://docs.docker.com/compose/install/linux/) and re-run."
say "docker ok ($(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'))"
# git: the pipeline, the patcher and `immune anticipate` build and apply every patch with it
command -v git >/dev/null 2>&1 || die "git is not installed (needed to build and apply patches). Install it (Debian/Ubuntu: the git package) and re-run."

# 2. Python >= 3.12
command -v "$PY" >/dev/null 2>&1 || die "$PY not found; install Python 3.12 or newer (or set PYTHON=/path/to/python3.12)."
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
  || die "Python >= 3.12 is required ($PY is $("$PY" -c 'import sys; print(sys.version.split()[0])')). Install a newer one and re-run with PYTHON=/path/to/python3.12 ./install.sh"
say "python ok ($("$PY" -c 'import sys; print(sys.version.split()[0])'))"

# 3. virtualenv with the pinned requirements
#    (.venv/.immune-requirements records which requirements.txt it was built from: a changed file reinstalls)
[ -f "$REQ" ] || die "$REQ not found (incomplete checkout)"
STAMP="$VENV/.immune-requirements"
want=$(cksum < "$REQ")
if [ -x "$VENV/bin/python" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$want" ] \
   && "$VENV/bin/python" -c 'import sys, fastapi, uvicorn, httpx, yaml, sqlglot, sqlparse, jsonschema, docker, pydantic, pytest; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
  say "venv ok ($VENV)"
else
  # a venv without a working python >= 3.12 and pip (e.g. left by a run without python3-venv) is rebuilt
  if [ -e "$VENV" ] && ! "$VENV/bin/python" -c 'import sys, pip; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
    say "removing unusable $VENV"
    rm -rf "$VENV"
  fi
  if [ ! -x "$VENV/bin/python" ]; then
    if ! out=$("$PY" -m venv "$VENV" 2>&1); then
      rm -rf "$VENV"
      v=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
      case "$out" in
        *ensurepip*|*"No module named venv"*) die "$PY cannot create virtualenvs: the venv module is not installed. On Debian/Ubuntu: sudo apt install python$v-venv ; then re-run." ;;
        *) die "cannot create $VENV: $(printf '%s' "$out" | tail -n 1)" ;;
      esac
    fi
  fi
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check -r "$REQ" \
    || die "pip install -r $REQ failed (network access to PyPI is needed once); fix the error above and re-run."
  printf '%s\n' "$want" > "$STAMP"
  say "venv ready ($VENV)"
fi

# 4. images (built locally from deploy/; nothing is pulled from a registry we do not control)
if [ "${IMMUNE_SKIP_IMAGES:-}" = "1" ]; then
  say "images skipped (IMMUNE_SKIP_IMAGES=1)"
else
  # immune-base:1: every stack and `immune init|doctor`; immune-sidecar:1: apps with app.runtime generic;
  # immune-cbuild:1: only `immune anticipate` (opt-in, it carries a C toolchain)
  specs="immune-base:1=Dockerfile.base immune-sidecar:1=Dockerfile.sidecar"
  [ "${IMMUNE_WITH_ANTICIPATE:-}" = "1" ] && specs="$specs immune-cbuild:1=Dockerfile.cbuild"
  for spec in $specs; do
    img=${spec%=*}; df=${spec#*=}
    if docker image inspect "$img" >/dev/null 2>&1; then
      say "image $img ok"
    elif [ -f "$HOME_DIR/deploy/$df" ]; then
      say "building $img from deploy/$df (pulls python:3.12-slim the first time; a few minutes)"
      docker build -q -f "$HOME_DIR/deploy/$df" -t "$img" "$HOME_DIR/deploy" >/dev/null \
        || die "docker build of $img failed (see the error above; network access to Docker Hub, PyPI and the Debian mirrors is needed)"
    else
      die "image $img is missing and deploy/$df does not exist (incomplete checkout)"
    fi
  done
fi

# 5. the CLI
[ -f "$HOME_DIR/bin/immune" ] || die "$HOME_DIR/bin/immune not found (incomplete checkout)"
chmod +x "$HOME_DIR/bin/immune" 2>/dev/null || true
mkdir -p "$BIN_DIR"
if [ -L "$BIN_DIR/immune" ] && [ "$(readlink "$BIN_DIR/immune")" = "$HOME_DIR/bin/immune" ]; then
  say "link ok ($BIN_DIR/immune)"
elif [ -e "$BIN_DIR/immune" ] && [ ! -L "$BIN_DIR/immune" ]; then
  die "$BIN_DIR/immune exists and is not a link to this checkout; remove it or set IMMUNE_BIN_DIR"
else
  ln -sfn "$HOME_DIR/bin/immune" "$BIN_DIR/immune"
  say "linked $BIN_DIR/immune -> $HOME_DIR/bin/immune"
fi
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) say "note: $BIN_DIR is not on your PATH; add it (e.g. in ~/.profile)";; esac

# 6. what the product needs at run time beyond this script (git, claude CLI, optional images): one place, immune/doctor.py
PYTHONPATH="$HOME_DIR" "$VENV/bin/python" -m immune.doctor --prereqs \
  || die "a required prerequisite is missing (see above); fix it and re-run."
say "done. Next: cd your-app && immune init   (built-in demo: immune up --project $HOME_DIR)"
