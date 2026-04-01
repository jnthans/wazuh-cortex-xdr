#!/usr/bin/env python3
"""
cortex_xdr.py - Cortex XDR -> Wazuh Wodle (entry point / orchestrator)

Serves two purposes:
  1. Real-time alerting  - incidents and alerts fire Wazuh rules as they arrive.
  2. Long-term archival  - Cortex does not retain data indefinitely; events are
                           persisted in OpenSearch for compliance and forensics.

A single modification_time bookmark per data type captures the full incident
lifecycle (new -> under_investigation -> resolved).  Status differentiation is
handled at the rules layer, not the fetch layer.

Run `cortex_xdr.py --help` for CLI usage.  See configuration.md for env vars.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cortex_xdr_utils as utils
from cortex_xdr_alerts import fetch_alerts
from cortex_xdr_incidents import fetch_incidents


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="cortex_xdr",
        description="Cortex XDR -> Wazuh wodle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cortex_xdr.py                        # fetch both alerts and incidents
  cortex_xdr.py --source incidents     # incidents only
  cortex_xdr.py --source alerts        # alerts only

Backfill / test (no state update):
  cortex_xdr.py --all --lookback 8760  # 1 year history
  cortex_xdr.py --all --lookback 24 --debug 1
        """
    )

    parser.add_argument("-s", "--source",
        choices=["alerts", "incidents", "both"],
        default="both", metavar="SOURCE",
        help="What to fetch: alerts | incidents | both (default: both)")

    parser.add_argument("-a", "--all",
        action="store_true", dest="all_mode",
        help="TEST/BACKFILL: ignore state, do not update state")

    parser.add_argument("-l", "--lookback",
        type=float, default=None, metavar="HOURS",
        help="Hours to look back (default: XDR_LOOKBACK_HOURS or 24)")

    parser.add_argument("-d", "--debug",
        type=int, choices=[0, 1, 2, 3], default=0, metavar="LEVEL",
        help="Debug verbosity to stderr: 0=off 1=info 2=verbose 3=trace")

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Config loading
# ─────────────────────────────────────────────────────────────────────────────

def load_config(args):
    return {
        "security_level":    os.environ.get("XDR_SECURITY_LEVEL", "advanced").lower(),
        "state_file":        os.environ.get(
                                 "XDR_STATE_FILE",
                                 "/var/ossec/wodles/cortex-xdr/state.json"),
        "secrets_file":      os.environ.get(
                                 "XDR_SECRETS_FILE",
                                 "/var/ossec/wodles/cortex-xdr/.secrets"),
        "lookback_hours":    float(
            args.lookback if args.lookback is not None
            else os.environ.get("XDR_LOOKBACK_HOURS", "24")
        ),
    }


def _should_run(source, module_name):
    return source == "both" or source == module_name


# ─────────────────────────────────────────────────────────────────────────────
# Test / backfill banner
# ─────────────────────────────────────────────────────────────────────────────

def _print_test_banner(args, config, credentials):
    hrs = config["lookback_hours"]
    sys.stderr.write(
        "\n"
        "+" + "=" * 58 + "+\n"
        "|          Cortex XDR Wodle - TEST / ALL MODE              |\n"
        "+" + "=" * 58 + "+\n"
        "|  Source  : {:<47}|\n".format(args.source) +
        "|  Lookback: {:<47}|\n".format("{}h".format(hrs)) +
        "|  FQDN    : {:<47}|\n".format(credentials["fqdn"]) +
        "|  Key ID  : {:<47}|\n".format(credentials["api_key_id"]) +
        "|  Level   : {:<47}|\n".format(config["security_level"]) +
        "+" + "=" * 58 + "+\n"
        "|  State NOT updated.                                     |\n"
        "+" + "=" * 58 + "+\n\n"
    )
    sys.stderr.flush()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if sys.version_info < (3, 8):
        import json
        sys.stdout.write(json.dumps({
            "integration": "cortex_xdr",
            "xdr": {
                "type": "error",
                "error_source": "startup",
                "error_message": "Python {} too old. 3.8+ required.".format(sys.version),
            },
        }, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        sys.exit(1)

    try:
        _run()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        import traceback
        tb = traceback.format_exc()
        utils.emit_error("startup", str(exc))
        sys.stderr.write(tb[-2000:] if len(tb) > 2000 else tb)
        sys.stderr.flush()
        sys.exit(1)


def _run():
    args = parse_args()
    utils.DEBUG_LEVEL = args.debug

    config = load_config(args)

    # Load secrets and build credentials via three-tier chain
    secrets = utils.load_secrets_file(config["secrets_file"])
    credentials = {
        "fqdn":       utils.get_secret("xdr_fqdn", "XDR_FQDN", secrets),
        "api_key":    utils.get_secret("xdr_api_key", "XDR_API_KEY", secrets),
        "api_key_id": utils.get_secret("xdr_api_key_id", "XDR_API_KEY_ID", secrets),
    }

    # Sanitise and validate FQDN
    credentials["fqdn"] = utils.sanitize_fqdn(credentials["fqdn"])
    utils.validate_fqdn(credentials["fqdn"])

    # Validate api_key_id is numeric
    if not credentials["api_key_id"].isdigit():
        sys.stderr.write(
            "[ERROR] api_key_id must be a positive integer. "
            "Check XDR_API_KEY_ID in your secrets file.\n"
        )
        sys.exit(1)

    # Merge FQDN into config for domain modules
    config["fqdn"] = credentials["fqdn"]

    utils.log(1, "source={} | lookback={}h | security_level={}",
        args.source, config["lookback_hours"], config["security_level"])

    if args.all_mode:
        _print_test_banner(args, config, credentials)

    state = utils.load_state(config["state_file"])

    # ── Alerts ────────────────────────────────────────────────────────────
    if _should_run(args.source, "alerts"):
        if args.all_mode:
            cursor = None
        else:
            cursor = state.get("alerts_cursor")
        try:
            state["alerts_cursor"] = fetch_alerts(credentials, cursor, config)
        except Exception as e:
            utils.emit_error("alerts", str(e))
            utils.log(1, "Alert fetch failed: {}", e)

    # ── Incidents ─────────────────────────────────────────────────────────
    if _should_run(args.source, "incidents"):
        if args.all_mode:
            cursor = None
        else:
            cursor = state.get("incidents_cursor")
        try:
            state["incidents_cursor"] = fetch_incidents(credentials, cursor, config)
        except Exception as e:
            utils.emit_error("incidents", str(e))
            utils.log(1, "Incident fetch failed: {}", e)

    # ── Persist state ─────────────────────────────────────────────────────
    if not args.all_mode:
        utils.save_state(config["state_file"], state)
    else:
        utils.log(1, "State NOT saved (--all mode)")


if __name__ == "__main__":
    main()
