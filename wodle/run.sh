#!/usr/bin/env bash
# =============================================================================
# run.sh – Cortex XDR Wazuh Wodle runtime wrapper
# =============================================================================
#
# PURPOSE
# ───────
# This script is the single target for the ossec.conf <command> entry.
# It sets all runtime configuration as environment variables, resolves the
# Python interpreter, and execs cortex_xdr.py. ossec.conf never needs to
# change when configuration changes — only this file does.
#
# OSSEC.CONF REFERENCE
# ────────────────────
# <wodle name="command">
#   <disabled>no</disabled>
#   <tag>cortex-xdr</tag>
#   <command>/var/ossec/wodles/cortex-xdr/run.sh</command>
#   <interval>300</interval>
#   <ignore_output>no</ignore_output>
#   <run_on_start>yes</run_on_start>
#   <timeout>120</timeout>
# </wodle>
#
# INSTALLATION
# ────────────
#   mkdir -p /var/ossec/wodles/cortex-xdr
#   cp wodle/* /var/ossec/wodles/cortex-xdr/
#   chmod 750  /var/ossec/wodles/cortex-xdr/run.sh
#   chmod 640  /var/ossec/wodles/cortex-xdr/cortex_xdr.py \
#              /var/ossec/wodles/cortex-xdr/cortex_xdr_*.py
#   chown -R root:wazuh /var/ossec/wodles/cortex-xdr/
#
# Note: cortex_xdr.py does NOT need the execute bit — this wrapper invokes
# python3 explicitly, which avoids a class of exit-126 failures seen when
# the .py exec bit is dropped during install or when the kernel cannot
# resolve `/usr/bin/env python3` under wazuh-modulesd.
#
# CREDENTIAL PRIORITY (first match wins, handled by cortex_xdr_utils.get_secret)
# ──────────────────────────────────────────────────────────────────────────────
# 1. systemd $CREDENTIALS_DIRECTORY      (most secure — memory-backed)
# 2. .secrets file at $XDR_SECRETS_FILE  (recommended default)
# 3. XDR_FQDN / XDR_API_KEY / XDR_API_KEY_ID env vars  (least secure)
#
# =============================================================================

set -euo pipefail

# ── Wodle directory (resolved relative to this script's location) ────────────
WODLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─────────────────────────────────────────────────────────────────────────────
# Security level for Cortex XDR API authentication
#   "advanced" = SHA-256(key + nonce + timestamp_ms)  [recommended]
#   "standard" = SHA-256(key only)
# ─────────────────────────────────────────────────────────────────────────────
export XDR_SECURITY_LEVEL="${XDR_SECURITY_LEVEL:-advanced}"

# ─────────────────────────────────────────────────────────────────────────────
# State file path
# Records last-seen modification_time per data stream (alerts, incidents)
# between runs. Must be writable by the wazuh user.
# ─────────────────────────────────────────────────────────────────────────────
export XDR_STATE_FILE="${XDR_STATE_FILE:-/var/ossec/wodles/cortex-xdr/state.json}"

# ─────────────────────────────────────────────────────────────────────────────
# Lookback on first run (hours)
# Controls how far back the initial fetch reaches when no state exists, and
# the window used by --all backfill mode. Default 24 hours gives operators
# immediate dashboard visibility on day one. For deeper backfills, override
# at invocation: `run.sh --all --lookback 8760` (1 year).
# ─────────────────────────────────────────────────────────────────────────────
export XDR_LOOKBACK_HOURS="${XDR_LOOKBACK_HOURS:-24}"

# ─────────────────────────────────────────────────────────────────────────────
# Secrets file path
# Plain-text KEY=VALUE file containing XDR_FQDN, XDR_API_KEY, XDR_API_KEY_ID.
# Must be owned root:wazuh with permissions 640.
# See .secrets.example for the expected format.
# ─────────────────────────────────────────────────────────────────────────────
export XDR_SECRETS_FILE="${XDR_SECRETS_FILE:-${WODLE_DIR}/.secrets}"

# =============================================================================
# SENSITIVE CONFIG — choose ONE of the three approaches below.
# XDR_FQDN, XDR_API_KEY, and XDR_API_KEY_ID must NOT be hard-coded in this file.
# =============================================================================

# ── OPTION 1 (DEFAULT): Dedicated secrets file ───────────────────────────────
# Already wired up via XDR_SECRETS_FILE above. Create the file at
# ${WODLE_DIR}/.secrets (chmod 640, chown root:wazuh) with:
#   XDR_FQDN=yourorg.xdr.us.paloaltonetworks.com
#   XDR_API_KEY=your-api-key-secret-value
#   XDR_API_KEY_ID=42
#
# Override the path by exporting XDR_SECRETS_FILE before invoking this script.

# ── OPTION 2: Environment variables (lowest priority in the credential chain) ─
# export XDR_FQDN="yourorg.xdr.us.paloaltonetworks.com"
# export XDR_API_KEY="your-api-key-secret-value"
# export XDR_API_KEY_ID="42"

# ── OPTION 3 (MOST SECURE): systemd LoadCredentialEncrypted ──────────────────
# Inject via a systemd unit using LoadCredentialEncrypted=.
# Credential names: xdr_fqdn, xdr_api_key, xdr_api_key_id

# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# Python interpreter resolution
# Prefer python3 in standard locations. Wazuh bundles its own Python under
# /var/ossec/framework/python — fall back to that if system python3 is absent.
# Invoking python3 explicitly (rather than execing cortex_xdr.py directly)
# removes any dependency on the .py file's execute bit and shebang resolution.
# ─────────────────────────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
    PYTHON="$(command -v python3)"
elif [[ -x /var/ossec/framework/python/bin/python3 ]]; then
    PYTHON="/var/ossec/framework/python/bin/python3"
else
    echo '{"integration":"cortex_xdr","type":"error","xdr":{"source":"orchestrator","error_code":"PYTHON_VERSION_ERROR","error_message":"python3 not found in PATH or /var/ossec/framework/python/bin"}}'
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Execute
# ─────────────────────────────────────────────────────────────────────────────
exec "${PYTHON}" "${WODLE_DIR}/cortex_xdr.py" "$@"
