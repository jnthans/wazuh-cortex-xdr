#!/usr/bin/env python3
"""
cortex_xdr_utils.py – Shared utilities for the Cortex XDR Wazuh wodle.

Covers:
  - Advanced / Standard API auth header generation
  - HTTP POST to the Cortex XDR REST API
  - State file load/save (atomic write, timestamp bookmarks)
  - Structured JSON emit to stdout (Wazuh ingestion)
  - Tiered debug logging to stderr (never pollutes Wazuh stdout)

Secret loading priority (first match wins):
  1. systemd credentials directory  ($CREDENTIALS_DIRECTORY/xdr_api_key etc.)
  2. Secrets file                   ($XDR_SECRETS_FILE or default path)
  3. Environment variables          ($XDR_API_KEY, $XDR_API_KEY_ID)
"""

import hashlib
import json
import os
import random
import re
import string
import sys
import tempfile
import time
import urllib.error
import urllib.request

# ── Module-level config (populated by cortex_xdr.py at startup) ──────────────
config = {}

# Debug level: 0=off, 1=info, 2=verbose, 3=trace
_debug_level = 0

INTEGRATION_TAG = "cortex-xdr"

# Wodle envelope fields — added by emit(), not sourced from the XDR API.
# Defined at module level so emit() doesn't rebuild the set on every call.
_ENVELOPE = frozenset({"integration", "type"})

# Default secrets file path (non-executable, root:wazuh 640)
_DEFAULT_SECRETS_FILE = "/var/ossec/wodles/cortex-xdr/.secrets"


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def set_debug_level(level: int):
    global _debug_level
    _debug_level = level


def log(level: int, msg: str):
    """Write debug messages to stderr only – never pollutes Wazuh's stdout pipe."""
    if level <= _debug_level:
        prefix = ["", "[INFO]", "[DEBUG]", "[TRACE]"][min(level, 3)]
        print(f"{prefix} {msg}", file=sys.stderr, flush=True)


def log_error(msg: str):
    """Always print errors to stderr AND emit a structured error event to stdout."""
    print(f"[ERROR] {msg}", file=sys.stderr, flush=True)
    emit({"error": msg}, "error")


# ─────────────────────────────────────────────────────────────────────────────
# Auth header generation
# ─────────────────────────────────────────────────────────────────────────────

def _nonce(length: int = 64) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.SystemRandom().choice(chars) for _ in range(length))


def build_auth_headers() -> dict:
    """
    Build authentication headers based on the configured security level.

    Standard:  Authorization = SHA-256(api_key)
    Advanced:  Authorization = SHA-256(api_key + nonce + timestamp_ms)
               Additional headers: x-xdr-timestamp, x-xdr-nonce
    """
    api_key    = config["api_key"]
    api_key_id = config["api_key_id"]
    level      = config.get("security_level", "advanced").lower()

    if level == "standard":
        auth = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        headers = {
            "Content-Type":  "application/json",
            "x-xdr-auth-id": str(api_key_id),
            "Authorization": auth,
        }
        log(3, "Built Standard auth headers")
    else:
        timestamp_ms = str(int(time.time() * 1000))
        nonce        = _nonce()
        payload      = f"{api_key}{nonce}{timestamp_ms}"
        auth         = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        headers = {
            "Content-Type":    "application/json",
            "x-xdr-auth-id":   str(api_key_id),
            "x-xdr-timestamp": timestamp_ms,
            "x-xdr-nonce":     nonce,
            "Authorization":   auth,
        }
        log(3, f"Built Advanced auth headers (ts={timestamp_ms})")

    return headers


# ─────────────────────────────────────────────────────────────────────────────
# HTTP client
# ─────────────────────────────────────────────────────────────────────────────

def api_post(path: str, body: dict, api_version: str = None) -> dict:
    """
    POST to https://api-{FQDN}/public_api/{version}/{path}

    api_version: explicit version for this call (e.g. "v2" for alerts).
                 Falls back to config["api_version"] (default "v1").
                 Passing the version as a parameter avoids temporarily
                 mutating the shared config dict.

    Returns the parsed JSON response dict, or {} on error.
    """
    fqdn    = config["fqdn"]
    version = api_version or config.get("api_version", "v1")
    url     = f"https://api-{fqdn}/public_api/{version}/{path}"
    payload = json.dumps({"request_data": body}).encode("utf-8")
    headers = build_auth_headers()

    log(2, f"POST {url}")
    log(3, f"Request body: {json.dumps(body)}")

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            log(3, f"Response: {raw[:500]}")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        log_error(f"HTTP {exc.code} calling {path}: {body_text}")
        return {}
    except urllib.error.URLError as exc:
        log_error(f"URL error calling {path}: {exc.reason}")
        return {}
    except json.JSONDecodeError as exc:
        log_error(f"JSON decode error from {path}: {exc}")
        return {}
    except Exception as exc:
        log_error(f"Unexpected error calling {path}: {exc}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# State management
# ─────────────────────────────────────────────────────────────────────────────

def _state_path() -> str:
    return config.get("state_file", "/var/ossec/wodles/cortex-xdr/state.json")


def load_state() -> dict:
    path = _state_path()
    if os.path.isfile(path):
        try:
            with open(path) as f:
                state = json.load(f)
            log(2, f"Loaded state from {path}: {state}")
            return state
        except Exception as exc:
            log(1, f"Could not load state file ({exc}), starting fresh")
    return {}


def save_state(state: dict):
    """
    Write state atomically using a temp file + os.replace.
    Prevents corruption if the process is killed mid-write — the old
    state file remains intact until the new one is fully flushed.
    """
    path    = _state_path()
    dir_    = os.path.dirname(path)
    os.makedirs(dir_, exist_ok=True)

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=dir_, delete=False, suffix=".tmp"
        ) as tmp:
            json.dump(state, tmp)
            tmp_path = tmp.name

        os.replace(tmp_path, path)   # atomic on POSIX
        log(2, f"Saved state: {state}")
    except Exception as exc:
        log_error(f"Failed to save state: {exc}")
        # Clean up orphaned temp file if os.replace failed
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def ms_now() -> int:
    return int(time.time() * 1000)


# ─────────────────────────────────────────────────────────────────────────────
# Event emission
# ─────────────────────────────────────────────────────────────────────────────

def emit(record: dict, record_type: str):
    """
    Emit a single Wazuh-compatible JSON event to stdout.
    Each line is one event; Wazuh reads these via <ignore_output>no</ignore_output>.

    Field namespacing — all XDR API fields are prefixed with 'xdr_' to avoid
    collision with Wazuh's 13 reserved static field names (action, status, id,
    user, srcip, dstip, srcport, dstport, protocol, url, data, extra_data,
    system_name). Envelope fields ('integration', 'type') are not prefixed.

    Null filtering — None values are stripped before serialisation. The XDR
    API returns many null fields; emitting them wastes OpenSearch index space
    and event size budget with no analytical value.
    """
    out = {"integration": INTEGRATION_TAG, "type": record_type}
    for k, v in record.items():
        if v is None:
            continue   # drop nulls — reduces event size and index noise
        if k not in _ENVELOPE:
            out[f"xdr_{k}"] = v
        else:
            out[k] = v

    line = json.dumps(out)
    print(line, flush=True)
    log(3, f"Emitted ({record_type}): {line[:200]}")


# ─────────────────────────────────────────────────────────────────────────────
# Time helpers
# ─────────────────────────────────────────────────────────────────────────────

def ms_to_iso(ms: int) -> str:
    """Convert epoch milliseconds to a readable ISO 8601 UTC string for logging."""
    import datetime
    if not ms:
        return "epoch"
    return datetime.datetime.utcfromtimestamp(ms / 1000).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────────────────────────────────────
# Secret loading
# ─────────────────────────────────────────────────────────────────────────────

def _load_from_systemd_credentials() -> dict:
    """
    Read secrets injected by systemd via LoadCredential / LoadCredentialEncrypted.
    Returns a dict with keys 'api_key' and/or 'api_key_id' if found.
    """
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY", "")
    if not creds_dir or not os.path.isdir(creds_dir):
        return {}

    found = {}
    for cred_name, config_key in (
        ("xdr_api_key",    "api_key"),
        ("xdr_api_key_id", "api_key_id"),
    ):
        cred_path = os.path.join(creds_dir, cred_name)
        if os.path.isfile(cred_path):
            try:
                with open(cred_path) as f:
                    found[config_key] = f.read().strip()
                log(2, f"Loaded '{config_key}' from systemd credentials directory")
            except Exception as exc:
                log(1, f"Could not read systemd credential '{cred_name}': {exc}")

    return found


def _load_from_secrets_file(path: str) -> dict:
    """
    Read a simple KEY=value secrets file (no subshell evaluation).
    Format:
        XDR_API_KEY=your-secret-key
        XDR_API_KEY_ID=42
    Lines starting with '#' and blank lines are ignored.
    File should be: chmod 640, chown root:wazuh
    """
    if not path or not os.path.isfile(path):
        return {}

    found   = {}
    mapping = {"XDR_API_KEY": "api_key", "XDR_API_KEY_ID": "api_key_id"}

    try:
        with open(path) as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    log(2, f"Secrets file line {lineno} skipped (no '=')")
                    continue
                key, _, value = line.partition("=")
                key   = key.strip()
                value = value.strip().strip('"').strip("'")
                if key in mapping:
                    found[mapping[key]] = value
                    log(2, f"Loaded '{mapping[key]}' from secrets file")
    except PermissionError:
        print(
            f"[ERROR] Cannot read secrets file {path} – "
            f"check ownership (root:wazuh) and permissions (640)",
            file=sys.stderr,
        )
    except Exception as exc:
        log(1, f"Error reading secrets file {path}: {exc}")

    return found


def load_secrets():
    """
    Populate config['api_key'] and config['api_key_id'].
    Priority (first match wins per key):
      1. systemd $CREDENTIALS_DIRECTORY  (memory-backed, encrypted at rest)
      2. Secrets file                     ($XDR_SECRETS_FILE or default path)
      3. Environment variables            ($XDR_API_KEY, $XDR_API_KEY_ID)
    """
    from_env = {
        "api_key":    os.environ.get("XDR_API_KEY", ""),
        "api_key_id": os.environ.get("XDR_API_KEY_ID", ""),
    }
    from_file    = _load_from_secrets_file(
                       os.environ.get("XDR_SECRETS_FILE", _DEFAULT_SECRETS_FILE))
    from_systemd = _load_from_systemd_credentials()

    # Higher-priority sources override lower ones
    merged = {**from_env, **from_file, **from_systemd}
    config["api_key"]    = merged.get("api_key", "")
    config["api_key_id"] = merged.get("api_key_id", "")

    # Log winning source for each key (value never logged)
    sources = [("env", from_env), ("file", from_file), ("systemd", from_systemd)]
    for key in ("api_key", "api_key_id"):
        winner = "not set"
        for src_name, src_dict in reversed(sources):
            if src_dict.get(key):
                winner = src_name
                break
        log(2, f"Secret '{key}' sourced from: {winner}")


# ─────────────────────────────────────────────────────────────────────────────
# FQDN sanitisation and validation
# ─────────────────────────────────────────────────────────────────────────────

def _sanitise_fqdn(raw: str) -> str:
    """
    Normalise the FQDN — strip scheme, api- prefix, path, and port.
    The XDR console "Copy API URL" button copies the full URL; we want only
    the bare hostname (e.g. myorg.xdr.us.paloaltonetworks.com).
    """
    fqdn = raw.strip()
    fqdn = re.sub(r'^https?://', '', fqdn)   # strip scheme
    fqdn = re.sub(r'^api-', '', fqdn)         # strip api- prefix (code adds it)
    fqdn = fqdn.split('/')[0]                 # strip path
    fqdn = fqdn.split(':')[0]                 # strip port
    if fqdn != raw.strip():
        log(1, f"FQDN sanitised: '{raw.strip()}' → '{fqdn}'")
    return fqdn


def _validate_fqdn(fqdn: str):
    """Pattern-check the sanitised FQDN — no network call."""
    if not re.match(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$',
        fqdn,
    ):
        print(
            f"\n[ERROR] XDR_FQDN '{fqdn}' does not look like a valid hostname.\n"
            f"        Set XDR_FQDN to the bare tenant hostname without scheme or 'api-' prefix.\n"
            f"        Example:  myorg.xdr.us.paloaltonetworks.com\n"
            f"        NOT:      https://api-myorg.xdr.us.paloaltonetworks.com\n",
            file=sys.stderr,
        )
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Config validation (called once at startup)
# ─────────────────────────────────────────────────────────────────────────────

def validate_config():
    load_secrets()

    raw_fqdn = config.get("fqdn", "")
    if raw_fqdn:
        config["fqdn"] = _sanitise_fqdn(raw_fqdn)
        _validate_fqdn(config["fqdn"])

    required = {
        "api_key":    "XDR_API_KEY / secrets file / systemd credential",
        "api_key_id": "XDR_API_KEY_ID / secrets file / systemd credential",
        "fqdn":       "XDR_FQDN",
    }
    missing = [hint for key, hint in required.items() if not config.get(key)]
    if missing:
        print(f"[ERROR] Missing required config: {'; '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    log(1, f"Config OK – FQDN={config['fqdn']} key_id={config['api_key_id']} "
           f"level={config.get('security_level','advanced')} "
           f"api_key={'*' * 8} (len={len(config['api_key'])})")
