#!/usr/bin/env python3
"""
cortex_xdr_incidents.py - Fetch and emit Cortex XDR incidents.

Public surface:
    fetch_incidents(credentials, cursor, config) -> updated_cursor

Uses modification_time bookmark (not creation_time) so that status transitions
on existing incidents are captured by incremental runs.  A single poll captures
the full lifecycle (new -> under_investigation -> resolved).  Rules differentiate
by status.
"""

from cortex_xdr_utils import (
    build_event, emit, emit_error, log, ms_to_iso_log, ms_now,
    xdr_api_post,
)

_PAGE_SIZE = 100
_MAX_INCIDENTS = 10_000
_ENDPOINT = "incidents/get_incidents"


def _build_request(since_ms):
    """Build the API request body for get_incidents.

    Time filter omitted when since_ms is 0 (first run):
    sending value=0 causes HTTP 500 "value param is missing".
    """
    body = {
        "sort": {
            "field":   "modification_time",
            "keyword": "asc",
        },
    }

    if since_ms > 0:
        body["filters"] = [
            {
                "field":    "modification_time",
                "operator": "gte",
                "value":    since_ms,
            }
        ]

    return body


def _fetch_page(since_ms, offset, credentials, config):
    """Fetch one page.  Returns (incidents_list, total_count)."""
    body = _build_request(since_ms)
    body["search_from"] = offset
    body["search_to"] = offset + _PAGE_SIZE
    log(3, "Incident request body: {}", body)
    resp = xdr_api_post(_ENDPOINT, body, credentials, config)
    reply = resp.get("reply") or {}
    incidents = reply.get("incidents") or []
    total_count = reply.get("total_count", None)
    log(2, "Incident page offset={}: got {}, total_count={}",
        offset, len(incidents), total_count)
    return incidents, total_count


def fetch_incidents(credentials, cursor, config):
    """Paginate through incidents, emit each, return updated cursor (epoch-ms).

    cursor:  epoch-ms start time (from state or computed by orchestrator).
             None triggers lookback calculation.
    """
    if cursor:
        since_ms = cursor
    else:
        since_ms = ms_now() - int(config["lookback_hours"] * 3600 * 1000)

    log(1, "Fetching incidents since ts={} ({})", since_ms, ms_to_iso_log(since_ms))

    count = 0
    fetched = 0
    latest_ts = since_ms
    offset = 0
    api_total = None

    while True:
        page, page_total = _fetch_page(since_ms, offset, credentials, config)

        if api_total is None and page_total is not None:
            api_total = page_total
            log(1, "API reports {} total incidents", api_total)

        if not page:
            log(2, "Incident page empty - pagination complete")
            break

        for inc in page:
            fetched += 1

            ts = inc.get("modification_time") or inc.get("creation_time") or 0
            if ts > latest_ts:
                latest_ts = ts

            emit(build_event(inc, "incident"))
            count += 1

        if api_total is not None and fetched >= api_total:
            log(1, "Fetched {}/{} incidents - done", fetched, api_total)
            break

        if len(page) < _PAGE_SIZE:
            log(2, "Short page ({}) - pagination complete", len(page))
            break

        if fetched >= _MAX_INCIDENTS:
            emit_error("incidents",
                       "Incident fetch reached hard cap of {}. "
                       "Next run continues from here.".format(_MAX_INCIDENTS))
            break

        offset += _PAGE_SIZE

    log(1, "Incidents: {} emitted", count)

    # Return updated cursor: +1ms to avoid re-fetch (API uses gte, not gt)
    if latest_ts > since_ms:
        return latest_ts + 1
    return cursor or ms_now()
