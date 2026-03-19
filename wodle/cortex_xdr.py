#!/usr/bin/env python3
"""
cortex_xdr.py – Cortex XDR → Wazuh Wodle (entry point)

Serves two purposes:
  1. Real-time alerting  — incidents and alerts fire Wazuh rules as they arrive.
  2. Long-term archival  — Cortex does not retain data indefinitely; events are
                           persisted in OpenSearch for compliance and forensics.

A single modification_time bookmark per data type captures the full incident
lifecycle (new → under_investigation → resolved). Status differentiation is
handled at the rules layer, not the fetch layer.

Run `cortex_xdr.py --help` for CLI usage. See configuration.md for env vars.
"""

import argparse
import os
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cortex_xdr_utils as utils
from cortex_xdr_alerts    import fetch_and_emit_alerts
from cortex_xdr_incidents import fetch_and_emit_incidents


# ─────────────────────────────────────────────────────────────────────────────
# Mode presets — default values for each CLI flag. None = no filter (fetch all).
# ─────────────────────────────────────────────────────────────────────────────

_MODES: Dict[str, dict] = {
    "economy": {
        "type":              "incidents",
        "alert_severities":  None,         # no alerts fetched
        "alert_actions":     None,
        "enrich":            False,
        "incident_mode":     "both",
    },
    "balanced": {
        "type":              "both",
        "alert_severities":  "high,critical",
        "alert_actions":     "all",
        "enrich":            False,
        "incident_mode":     "both",
    },
    "enriched": {
        "type":              "both",
        "alert_severities":  "all",        # all severities
        "alert_actions":     "all",        # DETECTED + BLOCKED
        "enrich":            True,
        "incident_mode":     "both",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cortex_xdr",
        description="Cortex XDR → Wazuh wodle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Mode examples (recommended interface):
  cortex_xdr.py                        # balanced mode, default
  cortex_xdr.py --mode economy         # incidents only
  cortex_xdr.py --mode balanced        # incidents + high/critical alerts
  cortex_xdr.py --mode enriched        # full fidelity, all data

Override a mode setting:
  cortex_xdr.py --mode balanced --alert-severities all
  cortex_xdr.py --mode economy --enrich

Backfill / test (no state update):
  cortex_xdr.py --mode enriched --all --lookback 8760  # 1 year history
  cortex_xdr.py --mode balanced --all --lookback 24 --debug 1
        """
    )

    # ── Primary interface ──────────────────────────────────────────────────
    parser.add_argument("-m", "--mode",
        choices=["economy", "balanced", "enriched"],
        default=None,          # None → resolved from XDR_MODE env var or "balanced"
        metavar="MODE",
        help=(
            "Ingestion mode preset: "
            "economy (incidents only), "
            "balanced (incidents + high/critical alerts, default), "
            "enriched (all data + enrichment). "
            "Individual flags override mode defaults."
        ))

    # ── Mode overrides (all default to None = use mode default) ───────────
    parser.add_argument("-t", "--type",
        choices=["alerts", "incidents", "both"],
        default=None,           # None = use mode default
        metavar="TYPE",
        help="Override mode: what to fetch: alerts | incidents | both")

    parser.add_argument("--alert-severities",
        default=None, dest="alert_severities", metavar="SEVERITIES",
        help=(
            "Override mode: comma-separated severities "
            "(low,medium,high,critical) or 'all'"
        ))

    parser.add_argument("--alert-actions",
        default=None, dest="alert_actions", metavar="ACTIONS",
        help=(
            "Override mode: comma-separated actions (DETECTED,BLOCKED) or 'all'. "
            "Applied client-side."
        ))

    parser.add_argument("-e", "--enrich",
        action="store_true", default=False, dest="enrich",
        help="Override mode: enable get_incident_extra_data enrichment per incident")

    # ── Advanced incident filter (rarely needed) ───────────────────────────
    parser.add_argument("--incident-mode",
        choices=["active", "closed", "both"], default=None,
        dest="incident_mode", metavar="INC_MODE",
        help=(
            "Advanced: narrow incident status filter. "
            "active=new+under_investigation, closed=resolved_*, both=all (default). "
            "Modes already default to 'both'; only set this to narrow a specific run."
        ))

    # ── Test / backfill ────────────────────────────────────────────────────
    parser.add_argument("-a", "--all",
        action="store_true", dest="all_mode",
        help=(
            "TEST/BACKFILL: ignore state, clear all filters, do not update state. "
            "Combine with --lookback to control the time window."
        ))

    parser.add_argument("-l", "--lookback",
        type=float, default=None, metavar="HOURS",
        help=(
            "Hours to look back in --all mode. "
            "(default: XDR_LOOKBACK_HOURS env var, or 1)"
        ))

    parser.add_argument("-d", "--debug",
        type=int, choices=[0, 1, 2, 3], default=0, metavar="LEVEL",
        help="Debug verbosity to stderr: 0=off 1=info 2=verbose 3=trace")

    return parser.parse_args()


def _apply_mode(args: argparse.Namespace) -> str:
    """
    Resolve the active mode and fill in any flag values that were not
    explicitly set by the user (i.e. still None).

    Priority: explicit CLI flag > XDR_MODE env var > "balanced" default.

    Returns the resolved mode name for logging.
    """
    mode_name = (
        args.mode
        or os.environ.get("XDR_MODE", "balanced").lower()
    )
    if mode_name not in _MODES:
        print(
            f"[ERROR] Invalid XDR_MODE value '{mode_name}'. "
            f"Must be one of: {', '.join(_MODES)}",
            file=sys.stderr,
        )
        sys.exit(1)

    preset = _MODES[mode_name]

    # Fill unset flags from the preset. --enrich is store_true so False means unset.
    if args.type            is None:  args.type            = preset["type"]
    if args.alert_severities is None: args.alert_severities = preset["alert_severities"]
    if args.alert_actions    is None: args.alert_actions    = preset["alert_actions"]
    if args.incident_mode    is None: args.incident_mode    = preset["incident_mode"]
    if not args.enrich:               args.enrich           = preset["enrich"]

    return mode_name


# ─────────────────────────────────────────────────────────────────────────────
# Config loading
# ─────────────────────────────────────────────────────────────────────────────

def load_config(args: argparse.Namespace):
    # api_key / api_key_id are loaded by validate_config() via the priority chain.
    utils.config.update({
        "security_level": os.environ.get("XDR_SECURITY_LEVEL", "advanced").lower(),
        "api_version":    os.environ.get("XDR_API_VERSION", "v1"),
        "state_file":     os.environ.get(
                              "XDR_STATE_FILE",
                              "/var/ossec/wodles/cortex-xdr/state.json"),
        "lookback_hours": float(
            args.lookback if args.lookback is not None
            else os.environ.get("XDR_LOOKBACK_HOURS", "1")
        ),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Filter resolution helpers
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_list_arg(value: Optional[str],
                       env_var: str) -> Optional[List]:
    """
    Resolve a comma-separated filter argument to a list, or None for 'all'.
    Priority: explicit value (from CLI or mode preset) > env var > None.
    Returns None when value is 'all' or absent (meaning: no filter applied).
    """
    raw = value or os.environ.get(env_var)
    if not raw or raw.strip().lower() == "all":
        return None
    return [s.strip() for s in raw.split(",") if s.strip()]


def _resolve_incident_statuses() -> Optional[List]:
    """
    XDR_INCIDENT_STATUSES env var allows explicit status override independent
    of --incident-mode. Intended for operators who need a custom combination
    without changing run.sh.
    """
    explicit = os.environ.get("XDR_INCIDENT_STATUSES")
    if explicit:
        if explicit.strip().lower() == "all":
            return None
        return [s.strip() for s in explicit.split(",") if s.strip()]
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Bookmark helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_bookmark(state: dict, key: str):
    """Returns (is_first_run, since_ms)."""
    first_run = key not in state
    since_ms  = 0 if first_run else state[key]
    return first_run, since_ms


def _write_bookmark(state: dict, key: str, latest_ts: int,
                    first_run: bool, current: int):
    """
    Save bookmark as latest_ts + 1ms to avoid re-fetching the last-seen
    record (API supports gte but not gt on modification_time / creation_time).
    Always writes after first run even when count=0.
    """
    new_ts = (latest_ts + 1) if latest_ts > 0 else utils.ms_now()
    if first_run or new_ts > current:
        state[key] = new_ts
        utils.log(1, f"Bookmark [{key}] → {new_ts}")


# ─────────────────────────────────────────────────────────────────────────────
# Test / backfill banner
# ─────────────────────────────────────────────────────────────────────────────

def _print_test_banner(args: argparse.Namespace, mode_name: str):
    hrs = utils.config["lookback_hours"]
    print(
        "\n"
        "╔══════════════════════════════════════════════════════════╗\n"
        "║          Cortex XDR Wodle – TEST / ALL MODE              ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        f"║  Mode    : {mode_name:<47}║\n"
        f"║  Type    : {args.type:<47}║\n"
        f"║  Lookback: {str(hrs) + 'h':<47}║\n"
        f"║  FQDN    : {utils.config['fqdn']:<47}║\n"
        f"║  Key ID  : {utils.config['api_key_id']:<47}║\n"
        f"║  Level   : {utils.config['security_level']:<47}║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║  All filters cleared. State NOT updated.                 ║\n"
        "╚══════════════════════════════════════════════════════════╝\n",
        file=sys.stderr,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if sys.version_info < (3, 8):
        import json
        print(json.dumps({
            "integration": "cortex-xdr", "xdr_type": "error",
            "xdr_error": f"Python {sys.version} too old. 3.8+ required.",
        }), flush=True)
        sys.exit(1)

    try:
        _run()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        import json, traceback
        tb = traceback.format_exc()
        print(json.dumps({
            "integration": "cortex-xdr", "xdr_type": "error",
            "xdr_error":     str(exc),
            "xdr_traceback": tb[-2000:] if len(tb) > 2000 else tb,
        }), flush=True)
        sys.exit(1)


def _run():
    args = parse_args()
    utils.set_debug_level(args.debug)

    # Resolve mode and fill any unset flags with mode defaults.
    mode_name = _apply_mode(args)

    load_config(args)
    utils.validate_config()

    utils.log(1, f"Mode: {mode_name} | type={args.type} | "
                 f"severities={args.alert_severities} | "
                 f"actions={args.alert_actions} | "
                 f"enrich={args.enrich}")

    if args.all_mode:
        _print_test_banner(args, mode_name)

    lookback_ms       = int(utils.config["lookback_hours"] * 60 * 60 * 1000)
    first_run_ms      = 30 * 24 * 60 * 60 * 1000   # 30-day cap for first run
    state             = utils.load_state()
    severity_filter   = _resolve_list_arg(args.alert_severities, "XDR_ALERT_SEVERITIES")
    action_filter     = _resolve_list_arg(args.alert_actions,    "XDR_ALERT_ACTIONS")
    explicit_statuses = _resolve_incident_statuses()

    # ── Alerts ────────────────────────────────────────────────────────────
    if args.type in ("alerts", "both"):
        if args.all_mode:
            since_ms  = utils.ms_now() - lookback_ms
            first_run = False
        else:
            first_run, since_ms = _read_bookmark(state, "last_alert_ts")
            if first_run:
                since_ms = utils.ms_now() - first_run_ms
                utils.log(1, "Alert first run: lookback 30 days")

        count, latest_ts = fetch_and_emit_alerts(
            since_ms,
            all_mode=args.all_mode,
            severity_filter=severity_filter,
            action_filter=action_filter,
        )

        if not args.all_mode:
            _write_bookmark(state, "last_alert_ts", latest_ts,
                            first_run, state.get("last_alert_ts", 0))

        utils.log(1, f"Alerts: {count} emitted")

    # ── Incidents ─────────────────────────────────────────────────────────
    if args.type in ("incidents", "both"):
        mode = args.incident_mode  # "active" | "closed" | "both"

        if explicit_statuses is not None:
            status_filter = explicit_statuses
        elif mode == "active":
            status_filter = ["new", "under_investigation"]
        elif mode == "closed":
            status_filter = ["resolved_true_positive", "resolved_false_positive"]
        else:
            status_filter = None   # all statuses — rules differentiate

        if args.all_mode:
            since_ms  = utils.ms_now() - lookback_ms
            first_run = False
        else:
            first_run, since_ms = _read_bookmark(state, "last_incident_ts")
            if first_run:
                since_ms = utils.ms_now() - first_run_ms
                utils.log(1, "Incident first run: lookback 30 days")

        count, latest_ts = fetch_and_emit_incidents(
            since_ms,
            all_mode=args.all_mode,
            enrich=args.enrich,
            incident_mode=mode,
            status_filter=status_filter,
        )

        if not args.all_mode:
            _write_bookmark(state, "last_incident_ts", latest_ts,
                            first_run, state.get("last_incident_ts", 0))

        utils.log(1, f"Incidents: {count} emitted")

    # ── Persist state ─────────────────────────────────────────────────────
    if not args.all_mode:
        utils.save_state(state)
    else:
        utils.log(1, "State NOT saved (--all mode)")


if __name__ == "__main__":
    main()
