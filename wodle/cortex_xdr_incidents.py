#!/usr/bin/env python3
"""
cortex_xdr_incidents.py – Fetch and emit Cortex XDR incidents.

Public surface:
    fetch_and_emit_incidents(since_ms, all_mode, enrich, incident_mode,
                             status_filter) -> (count, latest_ts)

Incident modes:
    "both"    (default) — fetches all statuses via modification_time bookmark.
              A single poll captures the full lifecycle (new → under_investigation
              → resolved) naturally. Rules differentiate by status.

    "active"  — fetches new + under_investigation only. Real-time alerting stream.

    "closed"  — fetches resolved_true_positive + resolved_false_positive only.
              Archival/closure records. Level 3 rules.

    Status filtering is applied CLIENT-SIDE. The XDR API's server-side status
    filter returns 0 results even when matching incidents exist.

Enrichment:
    Disabled by default. Enable with enrich=True / --enrich flag.
    Merges scalar fields from get_incident_extra_data. Skips nested arrays
    (alerts, artifacts) which would exceed Wazuh's 65535-byte line limit.
    The base incident object carries sufficient data for SIEM alerting;
    the xdr_url field links directly to the full Cortex investigation.
"""

from typing import List, Optional
from cortex_xdr_utils import api_post, emit, log, log_error, ms_to_iso

_PAGE_SIZE      = 100
_MAX_INCIDENTS  = 10_000
_ENDPOINT_LIST  = "incidents/get_incidents"
_ENDPOINT_EXTRA = "incidents/get_incident_extra_data"

_ACTIVE_STATUSES = ["new", "under_investigation"]
_CLOSED_STATUSES = ["resolved_true_positive", "resolved_false_positive"]

# Types skipped during enrichment merge — nested objects exceed the
# 65,535-byte Wazuh line limit and have no value for SIEM alerting.
_ENRICH_SKIP = (list, dict)


def _build_filter(since_ms: int) -> dict:
    """
    Build the API request body for get_incidents.

    Status filtering is intentionally NOT sent to the API — applied
    client-side instead (server-side 'in' operator returns 0 results).

    Time filter omitted when since_ms is 0 (first run / all-mode):
    sending value=0 causes HTTP 500 "value param is missing".

    Uses modification_time (not creation_time) so that status transitions
    on existing incidents are captured by incremental runs.
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


def _fetch_page(since_ms: int, offset: int) -> tuple:
    """Fetch one page. Returns (incidents_list, total_count)."""
    body = _build_filter(since_ms)
    body["search_from"] = offset
    body["search_to"]   = offset + _PAGE_SIZE
    log(3, f"Incident request body: {body}")
    resp        = api_post(_ENDPOINT_LIST, body)
    reply       = resp.get("reply") or {}
    incidents   = reply.get("incidents") or []
    total_count = reply.get("total_count", None)
    log(2, f"Incident page offset={offset}: got {len(incidents)}, "
           f"total_count={total_count}")
    return incidents, total_count


def _fetch_extra(incident_id: str) -> dict:
    """
    Fetch supplementary scalar fields from get_incident_extra_data.
    Requests alerts_limit=0 to avoid receiving the nested alerts array,
    which can be 50KB+ and would exceed Wazuh's line size limit.
    """
    resp = api_post(_ENDPOINT_EXTRA, {
        "incident_id":  incident_id,
        "alerts_limit": 0,
    })
    return (resp.get("reply") or {}).get("incident") or {}


def fetch_and_emit_incidents(since_ms: int,
                              all_mode: bool               = False,
                              enrich: bool                 = False,
                              incident_mode: str           = "both",
                              status_filter: Optional[List] = None) -> tuple:
    """
    Paginate through incidents, apply client-side status filter, optionally
    enrich, emit each matching incident, and return
    (emitted_count, latest_modification_time_ms).

    status_filter is resolved by the caller (cortex_xdr.py):
        "active"  → ["new", "under_investigation"]
        "closed"  → ["resolved_true_positive", "resolved_false_positive"]
        "both"    → None  (no filter — all statuses ingested)

    In --all mode, status_filter is cleared regardless of what was passed.

    Bookmark is saved as latest_ts + 1ms by the caller (cortex_xdr.py) to
    work around the API's lack of a 'gt' operator (only 'gte' is supported).
    """
    if all_mode:
        log(1, "Incident fetch: ALL mode – no time filter, no status filter")
        since_ms      = 0
        status_filter = None
    # else: use status_filter as passed by the caller (cortex_xdr.py resolves
    # the correct value per mode; None means no filter — all statuses)

    mode_label   = incident_mode if not all_mode else "all"
    status_label = str(status_filter) if status_filter else "all"
    log(1, f"Fetching incidents [{mode_label}] since ts={since_ms} "
           f"({ms_to_iso(since_ms)}), status filter (client-side)={status_label}")
    log(2, f"Enrichment {'enabled' if enrich else 'disabled'}")

    count     = 0
    fetched   = 0
    latest_ts = since_ms
    offset    = 0
    api_total = None

    while True:
        page, page_total = _fetch_page(since_ms, offset)

        if api_total is None and page_total is not None:
            api_total = page_total
            log(1, f"API reports {api_total} total incidents matching time filter")

        if not page:
            log(2, "Incident page empty — pagination complete")
            break

        for inc in page:
            fetched += 1

            # Advance bookmark even for skipped incidents so the time window
            # moves forward regardless of how many are filtered by status.
            ts = inc.get("modification_time") or inc.get("creation_time") or 0
            if ts > latest_ts:
                latest_ts = ts

            # Client-side status filter
            if status_filter is not None:
                inc_status = inc.get("status") or ""
                if inc_status not in status_filter:
                    log(3, f"Skip incident {inc.get('incident_id')} "
                           f"(status={inc_status!r})")
                    continue

            # Enrichment (opt-in)
            inc_id = inc.get("incident_id")
            if enrich and inc_id:
                extra = _fetch_extra(str(inc_id))
                if extra:
                    merged = skipped_fields = 0
                    for k, v in extra.items():
                        if isinstance(v, _ENRICH_SKIP):
                            skipped_fields += 1
                        elif k not in inc:
                            inc[k] = v
                            merged += 1
                    log(3, f"Enriched {inc_id}: +{merged} fields, "
                           f"skipped {skipped_fields} arrays")

            emit(inc, "incident")
            count += 1

        if api_total is not None and fetched >= api_total:
            log(1, f"Fetched {fetched}/{api_total} — done")
            break

        if len(page) < _PAGE_SIZE:
            log(2, f"Short page ({len(page)}) — pagination complete")
            break

        if fetched >= _MAX_INCIDENTS:
            log_error(f"Incident fetch reached hard cap of {_MAX_INCIDENTS}. "
                      f"Bookmark set to last-seen ts — next run continues from here.")
            break

        offset += _PAGE_SIZE

    log(1, f"Incident fetch [{mode_label}] complete: {count} emitted "
           f"({fetched} fetched, {fetched - count} filtered by status)")
    return count, latest_ts

