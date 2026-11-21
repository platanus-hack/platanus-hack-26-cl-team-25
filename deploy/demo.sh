#!/usr/bin/env bash
# Orchestrates the local demo stack. Usage: deploy/demo.sh up|reset|down|status
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
PY="$ROOT/.venv/bin/python"; RT="$ROOT/runtime"
set -a; . deploy/demo.env; set +a
export RUNTIME_DIR="$RT" REPO_DIR="$ROOT" GATEWAY_ADMIN_URL=http://127.0.0.1:8081 FLEET_BUS_URL=http://127.0.0.1:8090 PYTHONPATH="$ROOT"
ADM=(-H "x-admin-token: $ADMIN_TOKEN" -H 'content-type: application/json')

seed() {  # fresh t0 data + release
  rm -rf "$RT/data" "$RT/recordings" "$RT/bus" "$RT/releases"
  mkdir -p "$RT/data/prod" "$RT/data/shadow" "$RT/recordings" "$RT/bus" "$RT/releases/t0" "$RT/logs"
  "$PY" -m victim.seed --out-prod "$RT/data/prod/app.db" --out-shadow "$RT/data/shadow/seed.db" \
     --manifest "$RT/data/manifest.json" --markers "$RT/data/shadow/markers.json" --seed 1 >/dev/null
  cp "$RT/data/shadow/markers.json" "$RT/data/markers.json"
  git archive "${T0_REF:-HEAD}" victim | tar -x -C "$RT/releases/t0"
  date +%m%d-%H%M%S > "$RT/run_id"
}
start_host() {  # name, module
  local name=$1 mod=$2
  if [ -f "$RT/logs/$name.pid" ] && kill -0 "$(cat "$RT/logs/$name.pid")" 2>/dev/null; then return; fi
  RUN_ID="$(cat "$RT/run_id")" nohup "$PY" -m "$mod" >"$RT/logs/$name.log" 2>&1 & echo $! >"$RT/logs/$name.pid"
}
stop_host() { for f in "$RT"/logs/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done; }
wait_url() { for _ in $(seq 60); do curl -fsS -m 2 "${@:2}" "$1" >/dev/null 2>&1 && return 0; sleep 0.5; done; echo "timeout: $1" >&2; return 1; }

case "${1:-}" in
  up|reset)
    stop_host; docker ps -aq --filter label=immune.run | xargs -r docker rm -f >/dev/null
    [ "$1" = reset ] && docker compose -f deploy/compose.yaml down >/dev/null 2>&1 || true
    seed
    RUN_ID="$(cat "$RT/run_id")" docker compose -f deploy/compose.yaml up -d --force-recreate >/dev/null
    wait_url http://127.0.0.1:8090/health; wait_url http://127.0.0.1:8081/_admin/health "${ADM[@]}"
    start_host fleet fleet; wait_url http://127.0.0.1:8070/state "${ADM[@]}"
    curl -fsS -m 180 "${ADM[@]}" -X POST http://127.0.0.1:8070/reset -d "{\"release\":\"t0\",\"pool_size\":${POOL_SIZE:-4}}"; echo
    [ -d "$ROOT/pipeline" ] && [ "${NO_PIPELINE:-}" = "" ] && start_host pipeline pipeline || true
    ;;
  down)
    stop_host; docker ps -aq --filter label=immune.run | xargs -r docker rm -f >/dev/null
    docker ps -aq --filter label=immune.run | xargs -r docker rm -f >/dev/null
    docker compose -f deploy/compose.yaml down >/dev/null 2>&1 || true ;;
  status)
    docker ps --format 'table {{.Names}}\t{{.Status}}' --filter name=immune
    curl -fsS -m 3 "${ADM[@]}" http://127.0.0.1:8070/state || true; echo ;;
  *) echo "usage: $0 up|reset|down|status"; exit 2 ;;
esac
