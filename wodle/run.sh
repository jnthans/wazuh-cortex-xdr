#!/usr/bin/env bash
# =============================================================================
# run.sh – Cortex XDR Wodle wrapper
# =============================================================================
# Sets non-sensitive runtime config and launches the Python entry point.
# Credentials are NOT stored here — see CREDENTIAL OPTIONS below.
#
# INSTALLATION
# ─────────────────────────────────────────────────────────────────────────────
#   mkdir -p /var/ossec/wodles/cortex-xdr
#   cp wodle/* /var/ossec/wodles/cortex-xdr/
#   chmod 750  /var/ossec/wodles/cortex-xdr/run.sh
#   chmod 755  /var/ossec/wodles/cortex-xdr/cortex_xdr.py
#   chown -R root:wazuh /var/ossec/wodles/cortex-xdr/
# =============================================================================


# ── Tenant config ─────────────────────────────────────────────────────────────
# Bare hostname only — no https://, no api- prefix, no trailing slash.
export XDR_FQDN="yourorg.xdr.us.paloaltonetworks.com"

# "advanced" = SHA-256(key + nonce + timestamp_ms)  [recommended]
# "standard" = SHA-256(key only)
export XDR_SECURITY_LEVEL="advanced"

# State file — records last-seen timestamps per data stream.
export XDR_STATE_FILE="/var/ossec/wodles/cortex-xdr/state.json"

# How far back to look on first run for ALERTS (before any state exists).
# Incidents always do a full history sweep on first run regardless of this.
export XDR_LOOKBACK_HOURS="24"

# Default ingestion mode when --mode is not passed on the command line.
# economy  — incidents only, minimal storage
# balanced — incidents + high/critical DETECTED alerts  (recommended)
# enriched — all alerts, all incidents, enrichment on
export XDR_MODE="balanced"


# ═════════════════════════════════════════════════════════════════════════════
# CREDENTIAL OPTIONS — choose ONE of the three approaches below.
# Priority chain: systemd credentials > secrets file > environment variables
# ═════════════════════════════════════════════════════════════════════════════

# ── OPTION 1 (RECOMMENDED): Dedicated secrets file ───────────────────────────
# Create /var/ossec/wodles/cortex-xdr/.secrets (mode 640, root:wazuh):
#   XDR_API_KEY=your-api-key-secret-value
#   XDR_API_KEY_ID=42
#
# export XDR_SECRETS_FILE="/var/ossec/wodles/cortex-xdr/.secrets"


# ── OPTION 2 (MOST SECURE): systemd LoadCredentialEncrypted ─────────────────
# See setup instructions in artifacts/guides/install-bare-metal.md (Step 3 — Option B).


# ── OPTION 3 (LEAST PREFERRED): Inline environment variables ─────────────────
# If used: chmod 600 this file, exclude from version control.
# export XDR_API_KEY="your-api-key-secret"
# export XDR_API_KEY_ID="42"


# ═════════════════════════════════════════════════════════════════════════════

PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null)

if [ -z "$PYTHON" ]; then
    echo '{"integration":"cortex-xdr","type":"error","xdr_error":"python3 not found in PATH"}'
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$PYTHON" "$SCRIPT_DIR/cortex_xdr.py" "$@"