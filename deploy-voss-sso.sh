#!/bin/bash
# ── Deploy Voss Proxy Worker (SSO Edition) ───────────────────
# Run from the directory containing voss-proxy-sso.js
# Note: ANTHROPIC_API_KEY secret persists across deploys — no need to re-set it.
# Usage: bash deploy-voss-sso.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_FILE="$SCRIPT_DIR/voss-proxy-sso.js"
CF_TOKEN="Q00qlVQZhaJGLbYSpCV5ysPS_0r6wdutWxqe09E5"
CF_ACCOUNT="3ac1c4e80287698bb11d1cf44ce0c49a"
SCRIPT_NAME="voss-proxy"

if [ ! -f "$WORKER_FILE" ]; then
  echo "❌ voss-proxy-sso.js not found at: $WORKER_FILE"
  exit 1
fi

echo "🚀 Deploying voss-proxy-sso.js to Cloudflare Worker '$SCRIPT_NAME'..."

METADATA='{"main_module":"voss-proxy-sso.js","compatibility_date":"2024-01-01"}'

HTTP_STATUS=$(curl -s -o /tmp/cf_voss_deploy.json -w "%{http_code}" \
  -X PUT "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT}/workers/scripts/${SCRIPT_NAME}" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -F "worker=@${WORKER_FILE};type=application/javascript+module;filename=voss-proxy-sso.js" \
  -F "metadata=${METADATA};type=application/json")

if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
  echo "✅ Voss proxy worker deployed! (HTTP $HTTP_STATUS)"
  echo "🌐 Live at: https://voss-proxy.mike-3ac.workers.dev"
  echo ""
  echo "Test: curl https://voss-proxy.mike-3ac.workers.dev/health"
else
  echo "❌ Deployment failed (HTTP $HTTP_STATUS)"
  cat /tmp/cf_voss_deploy.json | python3 -m json.tool 2>/dev/null || cat /tmp/cf_voss_deploy.json
  exit 1
fi
