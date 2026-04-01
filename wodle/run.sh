#!/usr/bin/env bash
# =============================================================================
# run.sh - Cortex XDR Wodle wrapper
# =============================================================================
# Sets runtime config and launches the Python entry point.
# Sensitive values (FQDN, API key, key ID) are NOT stored here - see below.
#
# INSTALLATION
# -----------------------------------------------------------------------------
#   mkdir -p /var/ossec/wodles/cortex-xdr
#   cp wodle/* /var/ossec/wodles/cortex-xdr/
#   chmod 750  /var/ossec/wodles/cortex-xdr/run.sh
#   chmod 755  /var/ossec/wodles/cortex-xdr/cortex_xdr.py
#   chown -R root:wazuh /var/ossec/wodles/cortex-xdr/
# =============================================================================

set -euo pipefail

# ── Runtime config ───────────────────────────────────────────────────────────
# "advanced" = SHA-256(key + nonce + timestamp_ms)  [recommended]
# "standard" = SHA-256(key only)
export XDR_SECURITY_LEVEL="advanced"

# State file - records last-seen timestamps per data stream.
export XDR_STATE_FILE="/var/ossec/wodles/cortex-xdr/state.json"

# Lookback window (hours). Used for first run and --all mode.
# Use --all --lookback 8760 for deeper backfills.
export XDR_LOOKBACK_HOURS="24"


# =============================================================================
# SENSITIVE CONFIG - choose ONE of the two approaches below.
# XDR_FQDN, XDR_API_KEY, and XDR_API_KEY_ID must not be stored in this file.
# =============================================================================

# ── OPTION 1 (RECOMMENDED): Dedicated secrets file ──────────────────────────
# Create /var/ossec/wodles/cortex-xdr/.secrets (chmod 640, chown root:wazuh):
#   XDR_FQDN=yourorg.xdr.us.paloaltonetworks.com
#   XDR_API_KEY=your-api-key-secret-value
#   XDR_API_KEY_ID=42
#
# export XDR_SECRETS_FILE="/var/ossec/wodles/cortex-xdr/.secrets"


# ── OPTION 2: Environment variables ──────────────────────────────────────────
# Lowest priority in the credential chain.
#
# export XDR_FQDN="yourorg.xdr.us.paloaltonetworks.com"
# export XDR_API_KEY="your-api-key-secret-value"
# export XDR_API_KEY_ID="42"


# ── OPTION 3 (MOST SECURE): systemd LoadCredentialEncrypted ──────────────────
# Inject via systemd unit LoadCredentialEncrypted=.
# Credential names: xdr_fqdn, xdr_api_key, xdr_api_key_id


# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/cortex_xdr.py" "$@"
