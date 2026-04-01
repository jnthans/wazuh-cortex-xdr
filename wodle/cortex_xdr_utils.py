#!/usr/bin/env python3
"""
cortex_xdr_utils.py - Shared utilities for the Cortex XDR Wazuh wodle.

Functions (framework order):
  1.  log()               - stderr, lazy formatting
  2.  emit()              - stdout, compact JSON, flush
  3.  emit_error()        - structured error event
  4.  load_secrets_file() - parse KEY=VALUE file
  5.  get_secret()        - three-tier credential chain
  6.  load_state()        - JSON file to dict
  7.  save_state()        - atomic write via tempfile + os.replace
  8.  http_post()         - POST with JSON body
  9.  http_with_retry()   - 429/5xx retry wrapper
  10. xdr_auth_headers()  - HMAC auth header builder

Secret loading priority (first match wins per key):
  1. systemd $CREDENTIALS_DIRECTORY  (encrypted at rest, memory-only)
  2. .secrets file                   (KEY=VALUE, chmod 640)
  3. Environment variable            (least secure, testing only)
"""

import datetime
import hashlib
import json
import os
import re
import secrets as secrets_mod
import string
import sys
import tempfile
import time
import urllib.error
import urllib.request

# ── Module-level constants ────────────────────────────────────────────────────

INTEGRATION_NAME = "cortex_xdr"
NAMESPACE = "xdr"
DEBUG_LEVEL = 0

# Epoch-millisecond fields from the XDR API.  build_event() converts these
# to ISO 8601 so OpenSearch dynamic mapping detects them as dates.
_TIMESTAMP_FIELDS = frozenset({
    # Incident timestamps
    "creation_time",
    "modification_time",
    "detection_time",
    "resolved_timestamp",
    # Alert timestamps
    "local_insert_ts",
    "last_modified_ts",
    "detection_timestamp",
    "end_match_attempt_ts",
    "event_timestamp",
    "causality_actor_process_execution_time",
    "dst_causality_actor_process_execution_time",
    "agent_host_boot_time",
})

# HTTP status codes eligible for automatic retry.
_TRANSIENT_CODES = frozenset({429, 500, 502, 503, 504})


# ─────────────────────────────────────────────────────────────────────────────
# 1. Logging
# ─────────────────────────────────────────────────────────────────────────────

def log(level, msg, *args):
    if level <= DEBUG_LEVEL:
        text = msg.format(*args) if args else msg
        sys.stderr.write("[{}] {}\n".format(INTEGRATION_NAME, text))
        sys.stderr.flush()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Event emission
# ─────────────────────────────────────────────────────────────────────────────

def emit(event):
    sys.stdout.write(json.dumps(event, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _ms_to_iso(ms):
    """Convert a single positive epoch-ms int to ISO 8601 UTC with ms precision.
    Returns None for zero, negative, or non-integer values."""
    if not isinstance(ms, int) or ms <= 0:
        return None
    dt = datetime.datetime.utcfromtimestamp(ms / 1000.0)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "{:03d}Z".format(ms % 1000)


def _convert_ts_field(value):
    """Convert a timestamp field (int or list[int]) from epoch-ms to ISO 8601.
    Returns None when the result would be empty so null-stripping drops it."""
    if isinstance(value, list):
        converted = [_ms_to_iso(ms) for ms in value if isinstance(ms, int) and ms > 0]
        return converted if converted else None
    return _ms_to_iso(value)


def build_event(record, event_type):
    """Transform a raw XDR API record into framework event format.

    Drops nulls, converts epoch-ms timestamp fields to ISO 8601, and wraps
    all vendor data under the NAMESPACE key.
    """
    inner = {"type": event_type}
    for k, v in record.items():
        if v is None:
            continue
        if k in _TIMESTAMP_FIELDS:
            v = _convert_ts_field(v)
            if v is None:
                continue
        inner[k] = v
    return {"integration": INTEGRATION_NAME, NAMESPACE: inner}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Error emission
# ─────────────────────────────────────────────────────────────────────────────

def emit_error(source, message, code=None):
    event = {
        "integration": INTEGRATION_NAME,
        NAMESPACE: {
            "type": "error",
            "error_source": source,
            "error_message": message[:500],
        },
    }
    if code is not None:
        event[NAMESPACE]["error_code"] = code
    emit(event)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Secrets file loading
# ─────────────────────────────────────────────────────────────────────────────

def load_secrets_file(path):
    """Parse KEY=VALUE secrets file.  Returns dict of raw key-value pairs."""
    if not path or not os.path.isfile(path):
        return {}

    try:
        st = os.stat(path)
        if st.st_mode & 0o007:
            sys.stderr.write(
                "[WARNING] Secrets file {} is accessible by others "
                "(mode {}).  Recommend: chmod 640, chown root:wazuh.\n".format(path, oct(st.st_mode & 0o777))
            )
            sys.stderr.flush()
    except OSError:
        pass

    found = {}
    try:
        with open(path) as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    log(2, "Secrets file line {} skipped (no '=')", lineno)
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and value:
                    found[key] = value
                    log(2, "Loaded '{}' from secrets file", key)
    except PermissionError:
        sys.stderr.write(
            "[ERROR] Cannot read secrets file {} - "
            "check ownership (root:wazuh) and permissions (640)\n".format(path)
        )
        sys.stderr.flush()
    except Exception as exc:
        log(1, "Error reading secrets file {}: {}", path, exc)

    return found


# ─────────────────────────────────────────────────────────────────────────────
# 5. Three-tier credential chain
# ─────────────────────────────────────────────────────────────────────────────

def get_secret(cred_name, env_var, secrets):
    # Tier 1: systemd credentials directory
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        cred_path = os.path.join(cred_dir, cred_name)
        if os.path.isfile(cred_path):
            try:
                with open(cred_path) as f:
                    value = f.read().strip()
                if value:
                    log(2, "Credential '{}' from systemd", cred_name)
                    return value
            except Exception as exc:
                log(1, "Could not read systemd credential '{}': {}", cred_name, exc)

    # Tier 2: secrets file
    if env_var in secrets:
        log(2, "Credential '{}' from secrets file", cred_name)
        return secrets[env_var]

    # Tier 3: environment variable
    value = os.environ.get(env_var)
    if value:
        log(2, "Credential '{}' from environment", cred_name)
        return value

    raise RuntimeError("Credential '{}' not found".format(cred_name))


# ─────────────────────────────────────────────────────────────────────────────
# 6. State loading
# ─────────────────────────────────────────────────────────────────────────────

def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# 7. State saving (atomic)
# ─────────────────────────────────────────────────────────────────────────────

def save_state(path, state):
    dir_name = os.path.dirname(path) or "."
    os.makedirs(dir_name, exist_ok=True)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, suffix=".tmp") as tmp:
            json.dump(state, tmp, indent=2)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = tmp.name
        os.replace(tmp_path, path)
        log(2, "Saved state to {}", path)
    except Exception as exc:
        log(1, "Failed to save state: {}", exc)
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# 8. HTTP POST
# ─────────────────────────────────────────────────────────────────────────────

def http_post(url, headers, body, timeout=30):
    """POST JSON body to url.  Returns parsed response dict.
    Raises urllib.error.HTTPError on HTTP errors (after logging body)."""
    payload = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    log(3, "POST {}", url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            log(3, "Response: {}", raw[:500])
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")[:200]
        log(1, "HTTP {} {}: {}", exc.code, url, body_text)
        raise


# ─────────────────────────────────────────────────────────────────────────────
# 9. HTTP retry wrapper
# ─────────────────────────────────────────────────────────────────────────────

def http_with_retry(request_fn, max_retries=3, max_wait=60):
    """Retry on transient HTTP errors (429, 5xx) and network errors."""
    for attempt in range(max_retries):
        try:
            return request_fn()
        except urllib.error.HTTPError as exc:
            if exc.code in _TRANSIENT_CODES and attempt < max_retries - 1:
                if exc.code == 429:
                    wait = min(int(exc.headers.get("Retry-After", "30")), max_wait)
                else:
                    wait = min(2 ** attempt, max_wait)
                log(1, "HTTP {} (attempt {}/{}), retrying in {}s",
                    exc.code, attempt + 1, max_retries, wait)
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < max_retries - 1:
                wait = min(2 ** attempt, max_wait)
                log(1, "Network error (attempt {}/{}): {}, retrying in {}s",
                    attempt + 1, max_retries, exc, wait)
                time.sleep(wait)
                continue
            raise


# ─────────────────────────────────────────────────────────────────────────────
# 10. Auth header builder
# ─────────────────────────────────────────────────────────────────────────────

def xdr_auth_headers(api_key_id, api_key, security_level="advanced"):
    """Build Cortex XDR auth headers.

    Standard:  Authorization = SHA-256(api_key)
    Advanced:  Authorization = SHA-256(api_key + nonce + timestamp_ms)
    """
    if security_level == "standard":
        auth = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        return {
            "Content-Type": "application/json",
            "x-xdr-auth-id": str(api_key_id),
            "Authorization": auth,
        }

    # Advanced mode (default)
    nonce = "".join(secrets_mod.choice(string.ascii_letters + string.digits) for _ in range(64))
    timestamp_ms = str(int(time.time() * 1000))
    auth_string = "{}{}{}".format(api_key, nonce, timestamp_ms)
    auth = hashlib.sha256(auth_string.encode("utf-8")).hexdigest()
    return {
        "Content-Type": "application/json",
        "x-xdr-auth-id": str(api_key_id),
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": timestamp_ms,
        "Authorization": auth,
    }


# ─────────────────────────────────────────────────────────────────────────────
# XDR API convenience wrapper
# ─────────────────────────────────────────────────────────────────────────────

def xdr_api_post(path, body, credentials, config):
    """POST to https://api-{fqdn}/public_api/v1/{path} with auth + retry.
    Fresh auth headers are generated per attempt (nonce/timestamp rotate)."""
    fqdn = config["fqdn"]
    url = "https://api-{}/public_api/v1/{}".format(fqdn, path)
    log(2, "XDR API POST {}", url)

    def make_request():
        headers = xdr_auth_headers(
            credentials["api_key_id"], credentials["api_key"],
            config.get("security_level", "advanced"))
        return http_post(url, headers, {"request_data": body})

    return http_with_retry(make_request)


# ─────────────────────────────────────────────────────────────────────────────
# FQDN sanitisation and validation
# ─────────────────────────────────────────────────────────────────────────────

def sanitize_fqdn(raw):
    """Normalise FQDN - strip scheme, api- prefix, path, and port."""
    fqdn = raw.strip()
    fqdn = re.sub(r'^https?://', '', fqdn)
    fqdn = re.sub(r'^api-', '', fqdn)
    fqdn = fqdn.split('/')[0]
    fqdn = fqdn.split(':')[0]
    if fqdn != raw.strip():
        log(1, "FQDN sanitised: '{}' -> '{}'", raw.strip(), fqdn)
    return fqdn


def validate_fqdn(fqdn):
    """Pattern-check the sanitised FQDN - no network call."""
    if not re.match(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$',
        fqdn,
    ):
        sys.stderr.write(
            "\n[ERROR] XDR_FQDN '{}' does not look like a valid hostname.\n"
            "        Set XDR_FQDN to the bare tenant hostname without scheme or 'api-' prefix.\n"
            "        Example:  myorg.xdr.us.paloaltonetworks.com\n"
            "        NOT:      https://api-myorg.xdr.us.paloaltonetworks.com\n\n".format(fqdn)
        )
        sys.stderr.flush()
        sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Time helpers
# ─────────────────────────────────────────────────────────────────────────────

def ms_to_iso_log(ms):
    """Convert epoch-ms to readable ISO 8601 for logging purposes."""
    if not ms:
        return "epoch"
    return datetime.datetime.utcfromtimestamp(ms / 1000).strftime("%Y-%m-%dT%H:%M:%SZ")


def ms_now():
    return int(time.time() * 1000)
