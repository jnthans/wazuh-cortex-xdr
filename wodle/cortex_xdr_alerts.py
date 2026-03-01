#!/usr/bin/env python3
"""
cortex_xdr_alerts.py – Fetch and emit Cortex XDR alerts.

Public surface:
    fetch_and_emit_alerts(since_ms, all_mode, severity_filter, action_filter)
    -> (count, latest_ts)

Filtering strategy:
    severity_filter — sent to the API (server-side). Reduces data transfer.
        Default: ["high", "critical"]
        All:     None  (no severity filter sent to API)

    action_filter — applied client-side after receiving each page.
        Default: ["DETECTED"]  — BLOCKED alerts mean Cortex stopped the threat;
                                  they are low-value noise in a SIEM context.
        All:     None  (emit regardless of action)

    In --all mode both filters are cleared — full historical fidelity.

API version note:
    Alerts moved from /v1/ to /v2/ in early 2025. Override with
    XDR_ALERTS_API_VERSION=v1 in run.sh if your tenant hasn't migrated.
"""

import os
from typing import List, Optional
from cortex_xdr_utils import api_post, emit, log, log_error, ms_to_iso

_PAGE_SIZE  = 100
_MAX_ALERTS = 10_000
_ENDPOINT   = "alerts/get_alerts_multi_events"

_ALERTS_API_VERSION = os.environ.get("XDR_ALERTS_API_VERSION", "v2")

# Default filters — applied when caller passes None
_DEFAULT_SEVERITIES = ["high", "critical"]
_DEFAULT_ACTIONS    = ["DETECTED"]


def _build_filter(since_ms: int,
                  severity_filter: Optional[List]) -> dict:
    """
    Build the API request body.

    severity_filter is sent to the API using the supported 'in' operator.
    action_filter is NOT sent to the API — it is applied client-side because
    'action' is remapped to 'xdr_action' by emit() and the raw field name
    varies between alert types.
    """
    body = {
        "sort_field": "creation_time",
        "sort_order": "asc",
    }

    filters = []

    if since_ms > 0:
        filters.append({
            "field":    "creation_time",
            "operator": "gte",
            "value":    since_ms,
        })

    if severity_filter:
        filters.append({
            "field":    "severity",
            "operator": "in",
            "value":    severity_filter,
        })

    if filters:
        body["filters"] = filters

    return body


def _fetch_page(since_ms: int,
                offset: int,
                severity_filter: Optional[List]) -> tuple:
    """Fetch one page. Returns (alerts_list, total_count)."""
    body = _build_filter(since_ms, severity_filter)
    body["search_from"] = offset
    body["search_to"]   = offset + _PAGE_SIZE

    log(2, f"Alerts API version: {_ALERTS_API_VERSION}")
    log(3, f"Alert request body: {body}")
    resp = api_post(_ENDPOINT, body, api_version=_ALERTS_API_VERSION)

    reply       = resp.get("reply") or {}
    alerts      = reply.get("alerts") or []
    total_count = reply.get("total_count", None)
    log(2, f"Alert page offset={offset}: got {len(alerts)}, total_count={total_count}")
    return alerts, total_count


def fetch_and_emit_alerts(since_ms: int,
                           all_mode: bool          = False,
                           severity_filter: Optional[List] = None,
                           action_filter: Optional[List]   = None) -> tuple:
    """
    Paginate through alerts, apply client-side action filter, emit each
    matching alert, and return (emitted_count, latest_creation_time_ms).

    Defaults (when None is passed):
        severity_filter → ["high", "critical"]
        action_filter   → ["DETECTED"]

    In --all mode both filters are cleared for full historical fidelity.
    """
    if all_mode:
        log(1, "Alert fetch: ALL mode – no filters applied")
        since_ms        = 0
        severity_filter = None
        action_filter   = None
    else:
        if severity_filter is None:
            severity_filter = _DEFAULT_SEVERITIES
        if action_filter is None:
            action_filter = _DEFAULT_ACTIONS

    sev_label    = str(severity_filter) if severity_filter else "all"
    action_label = str(action_filter)   if action_filter   else "all"
    log(1, f"Fetching alerts since ts={since_ms} ({ms_to_iso(since_ms)}), "
           f"severity={sev_label} (server-side), action={action_label} (client-side)")

    count     = 0
    fetched   = 0
    latest_ts = since_ms
    offset    = 0
    api_total = None

    while True:
        page, page_total = _fetch_page(since_ms, offset, severity_filter)

        if api_total is None and page_total is not None:
            api_total = page_total
            log(1, f"API reports {api_total} total alerts matching filters")

        if not page:
            log(2, "Alert page empty — pagination complete")
            break

        for alert in page:
            fetched += 1

            # Client-side action filter (raw field before xdr_ remapping)
            if action_filter is not None:
                raw_action = alert.get("action") or ""
                if raw_action not in action_filter:
                    log(3, f"Skipping alert {alert.get('alert_id')} "
                           f"(action={raw_action!r} not in {action_filter})")
                    ts = alert.get("creation_time") or 0
                    if ts > latest_ts:
                        latest_ts = ts
                    continue

            emit(alert, "alert")
            ts = alert.get("creation_time") or alert.get("local_insert_ts") or 0
            if ts > latest_ts:
                latest_ts = ts
            count += 1

        if api_total is not None and fetched >= api_total:
            log(1, f"Fetched {fetched}/{api_total} alerts from API — done")
            break

        if len(page) < _PAGE_SIZE:
            log(2, f"Short page ({len(page)}) — pagination complete")
            break

        if fetched >= _MAX_ALERTS:
            log_error(f"Alert fetch reached hard cap of {_MAX_ALERTS}.")
            break

        offset += _PAGE_SIZE

    log(1, f"Alert fetch complete: {count} emitted "
           f"({fetched} fetched, {fetched - count} filtered by action)")
    return count, latest_ts

