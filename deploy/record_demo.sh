#!/usr/bin/env bash
# Records the backup video of the demo: reset to t0, legitimate traffic in the background, the demo attacker in a
# loop until the seven exploits are blocked, and the dashboard with the attacker's terminal side by side.
#
#   deploy/record_demo.sh [OUT_DIR]          (default: runtime/recording-<date>)
#
# Needs: the built-in demo stack (`immune up`), Node with playwright-core (PLAYWRIGHT_CORE_DIR: the directory that
# contains node_modules/playwright-core) and a Chromium (CHROMIUM, default: the newest Playwright download).
# Output: demo.webm, attacker.log, dashboard screenshots at 1920x1080, 1280x720 and 1024x768.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/runtime/recording-$(date +%Y%m%d-%H%M%S)}"
PY="$ROOT/.venv/bin/python"
mkdir -p "$OUT"
LOG="$OUT/attacker.log"
: > "$LOG"; rm -f "$LOG.done"

CHROMIUM="${CHROMIUM:-$(ls -d "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux*/chrome 2>/dev/null | sort -V | tail -1)}"
[ -x "$CHROMIUM" ] || { echo "no Chromium: set CHROMIUM" >&2; exit 2; }
[ -n "${PLAYWRIGHT_CORE_DIR:-}" ] || { echo "set PLAYWRIGHT_CORE_DIR (dir containing node_modules/playwright-core)" >&2; exit 2; }

"$ROOT/bin/immune" reset
"$ROOT/bin/immune" status | tail -1

NODE_PATH="$PLAYWRIGHT_CORE_DIR/node_modules" node "$ROOT/deploy/record_demo.js" --log "$LOG" --out "$OUT" \
  --chromium "$CHROMIUM" --max-seconds "${MAX_SECONDS:-900}" &
REC=$!
sleep 4
cd "$ROOT"
"$PY" -m sim.legit --base http://127.0.0.1:8080 --rate 3 --duration 0 --json "$OUT/legit.json" >"$OUT/legit.log" 2>&1 &
LEGIT=$!
trap 'kill $LEGIT 2>/dev/null || true' EXIT
sleep 6
("$PY" -u -m sim.attacker --interval "${INTERVAL:-1.5}" --until-closed 2 \
   --max-seconds "${ATTACK_SECONDS:-780}" | tee "$LOG") || true
touch "$LOG.done"
wait $REC
kill $LEGIT 2>/dev/null || true
for _ in 1 2 3 4 5; do kill -0 $LEGIT 2>/dev/null || break; sleep 1; done
kill -9 $LEGIT 2>/dev/null || true
echo "recording in $OUT"
ls -la "$OUT"
