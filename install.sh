#!/usr/bin/env sh
# install.sh: install the `immune` CLI from this checkout (contracts/product.md section 5).
#   ./install.sh            check Docker + Python >= 3.12, create .venv from deploy/requirements.txt,
#                           make sure the images exist, link bin/immune into ~/.local/bin
# Idempotent: every step is skipped when already done. Never uses sudo.
# Env: IMMUNE_BIN_DIR (default ~/.local/bin), PYTHON (default python3), IMMUNE_SKIP_IMAGES=1
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
docker info >/dev/null 2>&1 || die "Docker is installed but not usable by $(id -un). Start the daemon and add yourself to the 'docker' group (then log in again); this script never uses sudo."
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is missing ('docker compose version' failed)."
say "docker ok ($(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'))"

# 2. Python >= 3.12
command -v "$PY" >/dev/null 2>&1 || die "$PY not found; install Python 3.12 or newer (or set PYTHON=/path/to/python3.12)."
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
  || die "Python >= 3.12 is required ($PY is $("$PY" -c 'import sys; print(sys.version.split()[0])'))."
say "python ok ($("$PY" -c 'import sys; print(sys.version.split()[0])'))"

# 3. virtualenv with the pinned requirements
if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c 'import sys, fastapi, uvicorn, httpx, yaml, sqlglot, jsonschema, docker; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
  say "venv ok ($VENV)"
else
  [ -f "$REQ" ] || die "$REQ not found"
  [ -x "$VENV/bin/python" ] || "$PY" -m venv "$VENV" || die "cannot create $VENV (on Debian/Ubuntu: the python3-venv package)"
  "$VENV/bin/python" -m pip install --quiet --upgrade pip
  "$VENV/bin/python" -m pip install --quiet -r "$REQ" || die "pip install -r $REQ failed"
  say "venv created ($VENV)"
fi

# 4. images (built locally from deploy/; nothing is pulled from a registry we do not control)
if [ "${IMMUNE_SKIP_IMAGES:-}" = "1" ]; then
  say "images skipped (IMMUNE_SKIP_IMAGES=1)"
else
  for spec in "immune-base:1 Dockerfile.base" "immune-sidecar:1 Dockerfile.sidecar"; do
    img=${spec% *}; df=${spec#* }
    if docker image inspect "$img" >/dev/null 2>&1; then
      say "image $img ok"
    elif [ -f "$HOME_DIR/deploy/$df" ]; then
      say "building $img from deploy/$df"
      docker build -q -f "$HOME_DIR/deploy/$df" -t "$img" "$HOME_DIR/deploy" >/dev/null || die "docker build of $img failed"
    elif [ "$img" = "immune-base:1" ]; then
      die "image $img is missing and deploy/$df does not exist"
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
say "done. Next: cd your-app && immune init"
