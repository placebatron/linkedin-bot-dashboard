#!/bin/bash
# ── Deploy Leasing API Worker (SSO Edition) ──────────────────
# Run from the directory containing leasing-worker-sso.js
# Usage: bash deploy-leasing-sso.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_FILE="$SCRIPT_DIR/leasing-worker-sso.js"
CF_TOKEN="Q00qlVQZhaJGLbYSpCV5ysPS_0r6wdutWxqe09E5"
CF_ACCOUNT="3ac1c4e80287698bb11d1cf44ce0c49a"
SCRIPT_NAME="leasing-api"
KV_NAMESPACE_ID="fa0040d59fb7480492be0c122a9141be"

if [ ! -f "$WORKER_FILE" ]; then
  echo "❌ leasing-worker-sso.js not found at: $WORKER_FILE"
  exit 1
fi

echo "🚀 Deploying leasing-worker-sso.js to Cloudflare Worker '$SCRIPT_NAME'..."

METADATA=$(cat <<EOF
{
  "main_module": "leasing-worker-sso.js",
  "compatibility_date": "2024-01-01",
  "bindings": [
    {
      "type": "kv_namespace",
      "name": "LEASING_KV",
      "namespace_id": "${KV_NAMESPACE_ID}"
    }
  ]
}
EOF
)

HTTP_STATUS=$(curl -s -o /tmp/cf_leasing_deploy.json -w "%{http_code}" \
  -X PUT "https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT}/workers/scripts/${SCRIPT_NAME}" \
  -H "Authorization: Bearer ${CF_TOKEN}" \
  -F "worker=@${WORKER_FILE};type=application/javascript+module;filename=leasing-worker-sso.js" \
  -F "metadata=${METADATA};type=application/json")

if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
  echo "✅ Leasing API worker deployed! (HTTP $HTTP_STATUS)"
  echo "🌐 Live at: https://leasing-api.mike-3ac.workers.dev"
  echo ""
  echo "Test: curl https://leasing-api.mike-3ac.workers.dev/health"
else
  echo "❌ Deployment failed (HTTP $HTTP_STATUS)"
  cat /tmp/cf_leasing_deploy.json | python3 -m json.tool 2>/dev/null || cat /tmp/cf_leasing_deploy.json
  exit 1
fi
