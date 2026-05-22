#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE="${ECHO_GATE_REMOTE:-vps}"
REMOTE_DIR="${ECHO_GATE_REMOTE_DIR:-/home/dustin/apps/echo-gate}"
HOST="${ECHO_GATE_BIND:-127.0.0.1}"
PORT="${ECHO_GATE_PORT:-8787}"
ADMIN_TOKEN="${ECHO_GATE_ADMIN_TOKEN:-}"
STORE="${ECHO_GATE_STORE:-convex}"

if [[ -z "$ADMIN_TOKEN" ]]; then
  echo "ECHO_GATE_ADMIN_TOKEN is required for VPS deploy" >&2
  exit 1
fi

if [[ "$STORE" == "convex" && -z "${CONVEX_URL:-}" ]]; then
  if [[ -f "$ROOT/.env.local" ]]; then
    # shellcheck disable=SC1091
    source "$ROOT/.env.local"
  fi
fi

if [[ "$STORE" == "convex" && -z "${CONVEX_URL:-}" ]]; then
  echo "CONVEX_URL is required for Convex-backed VPS deploy" >&2
  exit 1
fi

cd "$ROOT"

npm run build
npm test

rsync -az --delete \
  --exclude node_modules \
  --exclude .env \
  --exclude .env.local \
  --exclude .convex \
  --exclude '*.tgz' \
  "$ROOT/" "$REMOTE:$REMOTE_DIR/"

ssh "$REMOTE" "cd '$REMOTE_DIR' \
  && npm ci \
  && npm run build \
  && npm prune --omit=dev \
  && chmod +x bin/echo-gate.js scripts/deploy-vps.sh \
  && (pm2 delete echo-gate >/dev/null 2>&1 || true) \
  && (pm2 delete echo-gate-caddy-route >/dev/null 2>&1 || true) \
  && NODE_ENV=production ECHO_GATE_STORE='$STORE' CONVEX_URL='${CONVEX_URL:-}' ECHO_GATE_ADMIN_TOKEN='$ADMIN_TOKEN' ECHO_GATE_BIND='$HOST' ECHO_GATE_PORT='$PORT' pm2 start dist/src/server.js --name echo-gate \
  && ECHO_GATE_PORT='$PORT' pm2 start scripts/ensure-caddy-route.mjs --name echo-gate-caddy-route \
  && pm2 save"

ssh "$REMOTE" "node - <<'NODE'
const base = 'http://$HOST:$PORT';
const response = await fetch(base + '/health');
if (response.status !== 200) throw new Error('health ' + response.status + ' ' + await response.text());
const body = await response.json();
if (!body.ok || body.service !== 'echo-gate') throw new Error('bad health response');
console.log(JSON.stringify({ ok: true, service: 'echo-gate', port: $PORT }, null, 2));
NODE"
