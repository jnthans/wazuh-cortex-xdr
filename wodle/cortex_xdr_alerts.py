#!/usr/bin/env python3
"""
cortex_xdr_alerts.py - Fetch and emit Cortex XDR alerts.

Public surface:
    fetch_alerts(credentials, cursor, config) -> updated_cursor

Uses the v1 get_alerts endpoint which returns flat alert objects with full
forensic context (process paths, file hashes, network info, MITRE mapping).
The v2 get_alerts_multi_events endpoint nests event arrays inside each alert,
producing much larger responses that risk timeout — avoid it for SIEM ingestion.
"""

from cortex_xdr_utils import (
    build_event, emit, emit_error, log, ms_to_iso_log, ms_now,
    xdr_api_post,
)

_PAGE_SIZE = 100
_MAX_ALERTS = 10_000
_ENDPOINT = "alerts/get_alerts"


def _build_request(since_ms):
    """Build the API request body for get_alerts."""
    body = {
        "sort": {
            "field": "creation_time",
            "keyword": "asc",
        },
    }

    if since_ms > 0:
        body["filters"] = [
            {
                "field":    "creation_time",
                "operator": "gte",
                "value":    since_ms,
            }
        ]

    return body


def _fetch_page(since_ms, offset, credentials, config):
    """Fetch one page.  Returns (alerts_list, total_count)."""
    body = _build_request(since_ms)
    body["search_from"] = offset
    body["search_to"] = offset + _PAGE_SIZE

    log(3, "Alert request body: {}", body)
    resp = xdr_api_post(_ENDPOINT, body, credentials, config)

    reply = resp.get("reply") or {}
    alerts = reply.get("alerts") or []
    total_count = reply.get("total_count", None)
    log(2, "Alert page offset={}: got {}, total_count={}", offset, len(alerts), total_count)
    return alerts, total_count


def fetch_alerts(credentials, cursor, config):
    """Paginate through alerts, emit each, return updated cursor (epoch-ms).

    cursor:  epoch-ms start time (from state or computed by orchestrator).
             None triggers lookback calculation.
    """
    if cursor:
        since_ms = cursor
    else:
        since_ms = ms_now() - int(config["lookback_hours"] * 3600 * 1000)

    log(1, "Fetching alerts since ts={} ({})", since_ms, ms_to_iso_log(since_ms))

    count = 0
    fetched = 0
    latest_ts = since_ms
    offset = 0
    api_total = None

    while True:
        page, page_total = _fetch_page(since_ms, offset, credentials, config)

        if api_total is None and page_total is not None:
            api_total = page_total
            log(1, "API reports {} total alerts", api_total)

        if not page:
            log(2, "Alert page empty - pagination complete")
            break

        for alert in page:
            fetched += 1
            emit(build_event(alert, "alert"))
            ts = alert.get("creation_time") or alert.get("local_insert_ts") or 0
            if ts > latest_ts:
                latest_ts = ts
            count += 1

        if api_total is not None and fetched >= api_total:
            log(1, "Fetched {}/{} alerts from API - done", fetched, api_total)
            break

        if len(page) < _PAGE_SIZE:
            log(2, "Short page ({}) - pagination complete", len(page))
            break

        if fetched >= _MAX_ALERTS:
            emit_error("alerts",
                       "Alert fetch reached hard cap of {}. "
                       "Next run continues from here.".format(_MAX_ALERTS))
            break

        offset += _PAGE_SIZE

    log(1, "Alerts: {} emitted", count)

    # Return updated cursor: +1ms to avoid re-fetch (API uses gte, not gt)
    if latest_ts > since_ms:
        return latest_ts + 1
    return cursor or ms_now()
