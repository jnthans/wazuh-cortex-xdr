#!/usr/bin/env bash
# =============================================================================
# apply-index-template.sh
# Apply the Cortex XDR index template to the Wazuh indexer (OpenSearch).
#
# Maps data.xdr_* fields explicitly so they are searchable and aggregatable
# in the Wazuh dashboard. Without this, epoch-millisecond timestamps render
# as raw numbers and some fields cannot be filtered or visualised.
#
# Run once after deployment, or after upgrading the integration.
# Only new documents ingested after the template is applied are affected.
#
# USAGE
# ─────
#   # Bare metal — indexer on localhost:
#   INDEXER_HOST=https://localhost:9200 \
#   INDEXER_PASS=YourPassword \
#   bash doc/apply-index-template.sh
#
#   # Docker single-node — from inside the manager container:
#   docker exec -it single-node-wazuh.manager-1 bash
#   INDEXER_HOST=https://wazuh.indexer:9200 \
#   INDEXER_PASS=YourPassword \
#   bash /var/ossec/wodles/cortex-xdr/apply-index-template.sh
#
#   # Docker single-node — from the host (using published port):
#   INDEXER_HOST=https://localhost:9200 \
#   INDEXER_PASS=YourPassword \
#   bash doc/apply-index-template.sh
#
# CREDENTIALS
# ─────────────────────────────────────────────────────────────────────────────
#   INDEXER_HOST  Indexer base URL  (default: https://wazuh.indexer:9200)
#   INDEXER_USER  Username           (default: admin)
#   INDEXER_PASS  Password           (required — no safe default)
# =============================================================================

set -euo pipefail

INDEXER_HOST="${INDEXER_HOST:-https://wazuh.indexer:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-}"
TEMPLATE_NAME="wazuh-cortex-xdr"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="$SCRIPT_DIR/wazuh-cortex-xdr-index-template.json"

# ── Pre-flight checks ─────────────────────────────────────────────────────────

if [ ! -f "$TEMPLATE_FILE" ]; then
  echo "ERROR: Template file not found: $TEMPLATE_FILE"
  echo "       Ensure wazuh-cortex-xdr-index-template.json is in the same"
  echo "       directory as this script."
  exit 1
fi

if [ -z "$INDEXER_PASS" ]; then
  echo "ERROR: INDEXER_PASS is not set."
  echo "       Run with:  INDEXER_PASS=YourPassword bash apply-index-template.sh"
  exit 1
fi

if ! command -v curl &>/dev/null; then
  echo "ERROR: curl is not installed or not in PATH."
  exit 1
fi

# ── Connectivity check ────────────────────────────────────────────────────────
# A quick HEAD request before the PUT gives a clear connection error message
# rather than a cryptic HTTP 000 from the main request.

echo "Checking connectivity to $INDEXER_HOST ..."
if ! curl -sf --insecure --max-time 5 \
     -u "$INDEXER_USER:$INDEXER_PASS" \
     -o /dev/null \
     "$INDEXER_HOST" 2>/dev/null; then
  echo ""
  echo "ERROR: Cannot reach indexer at $INDEXER_HOST"
  echo ""
  echo "  Common causes:"
  echo "    - Wrong hostname: 'wazuh.indexer' is only valid inside the Docker network."
  echo "      From the host or bare metal, use: INDEXER_HOST=https://localhost:9200"
  echo "    - Port not published: check 'docker ps' to confirm port 9200 is exposed."
  echo "    - Wrong credentials: verify INDEXER_USER / INDEXER_PASS."
  echo "    - Indexer not running: check with 'docker ps' or 'systemctl status wazuh-indexer'."
  echo ""
  exit 1
fi

echo "Connection OK."
echo ""

# ── Apply template ────────────────────────────────────────────────────────────

RESPONSE_FILE="$(mktemp /tmp/xdr_template_response.XXXXXX.json)"
trap 'rm -f "$RESPONSE_FILE"' EXIT

echo "Applying index template '$TEMPLATE_NAME' ..."

HTTP_STATUS=$(curl -s \
  -o "$RESPONSE_FILE" \
  -w "%{http_code}" \
  --insecure \
  --max-time 30 \
  -X PUT "$INDEXER_HOST/_index_template/$TEMPLATE_NAME" \
  -u "$INDEXER_USER:$INDEXER_PASS" \
  -H "Content-Type: application/json" \
  -d @"$TEMPLATE_FILE")

CURL_EXIT=$?

echo "HTTP status: $HTTP_STATUS"

# Print the response body if present
if [ -s "$RESPONSE_FILE" ]; then
  echo "Response:"
  cat "$RESPONSE_FILE"
  echo ""
fi

if [ $CURL_EXIT -ne 0 ]; then
  echo "ERROR: curl exited with code $CURL_EXIT (connection or TLS error)"
  exit 1
fi

if [ "$HTTP_STATUS" = "200" ]; then
  echo "Template applied successfully."
  echo "New alerts will have data.xdr_* fields fully indexed and searchable."
  echo ""
  echo "To apply to existing documents, re-index today's alert index:"
  echo "  POST /_reindex"
  echo "  { \"source\": { \"index\": \"wazuh-alerts-4.x-$(date +%Y.%m.%d)\" },"
  echo "    \"dest\":   { \"index\": \"wazuh-alerts-4.x-$(date +%Y.%m.%d)-reindexed\" } }"
elif [ "$HTTP_STATUS" = "409" ]; then
  echo "NOTE: Template already exists (HTTP 409)."
  echo "      To force overwrite, delete the existing template first:"
  echo "      curl -s --insecure -X DELETE \"$INDEXER_HOST/_index_template/$TEMPLATE_NAME\" -u \"$INDEXER_USER:PASS\""
  exit 1
else
  echo "ERROR: Template application failed (HTTP $HTTP_STATUS)"
  exit 1
fi
