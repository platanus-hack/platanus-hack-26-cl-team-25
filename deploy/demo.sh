#!/usr/bin/env bash
# Thin wrapper kept for compatibility: the stack is driven by `bin/immune` (immune/__main__.py).
# Usage: deploy/demo.sh up|reset|down|status   (the built-in demo project = this repository)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "${1:-}" in
  up|reset|down|status) exec "$ROOT/bin/immune" "$1" --project "$ROOT" ;;
  *) echo "usage: $0 up|reset|down|status"; exit 2 ;;
esac
