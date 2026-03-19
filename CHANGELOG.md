# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.1.0] – 2026-03-19

### Fixed

- **Critical:** `incident_mode="both"` (the default for all ingestion modes) silently applied
  a closed-only status filter, causing `new` and `under_investigation` incidents to be dropped.
  All modes now correctly ingest all incident statuses as intended.
- **Critical:** Alert severity and action filters were re-applied internally even when the caller
  passed `None` (meaning "all"). In enriched mode this caused all alerts to be silently dropped
  if none matched the default `high`/`critical` + `DETECTED` filters.
- `run.sh` Python-not-found error emitted `"type":"error"` instead of `"xdr_type":"error"`,
  causing the error event to be silently dropped by rule 100599. Now emits the correct field name.
- `wazuh-logtest` example in `troubleshooting.md` used the old `"type"` field name; corrected
  to `"xdr_type"`.
- Alert rule descriptions referenced non-existent fields `$(xdr_alert_name)` and
  `$(xdr_agent_hostname)`, producing empty descriptions on the dashboard. Corrected to
  `$(xdr_name)` and `$(xdr_host_name)` matching the actual Cortex XDR API field names.
- First-run lookback capped at 30 days for both alerts and incidents to prevent
  timeouts on tenants with large histories. Use `--all --lookback 8760` for deeper backfills.

### Security

- API version values (`XDR_API_VERSION`, `XDR_ALERTS_API_VERSION`) are now validated against
  an allowlist (`v1`, `v2`) before being interpolated into request URLs.
- `XDR_API_KEY_ID` is now validated as a positive integer at startup; an invalid value exits
  with a clear error instead of causing a confusing 401 from the API.
- Nonce generation for Advanced auth now uses Python's `secrets` module instead of `random`,
  making the cryptographic intent explicit.
- Secrets file permissions are checked at load time; a warning is printed to stderr if the
  file is readable by group or other (recommended mode: 640).
- `XDR_FQDN`, `XDR_API_KEY`, and `XDR_API_KEY_ID` moved out of `run.sh` into the `.secrets`
  file, keeping all sensitive values out of the shell wrapper. Systemd credential support
  extended to include `xdr_fqdn`.

### Changed

- API calls now retry up to 3 times with exponential backoff (1 s, 2 s) on transient failures
  (network errors, HTTP 429/500/502/503/504). Permanent errors (HTTP 400/401/403) are not
  retried. Auth headers are regenerated on each attempt to keep the nonce and timestamp fresh.
- Hard-cap log messages now clarify that the bookmark was preserved and the next run will
  continue from the last-seen timestamp.
- Default wodle `<timeout>` increased from 120 s to 300 s in the ossec.conf example. Enriched
  mode with many incidents and retry backoff can exceed the old 2-minute limit.
- Removed redundant installation guides (bare-metal, Docker, Kubernetes); operators deploy
  wodle files using their own standard procedures.
- Removed the custom OpenSearch index template; epoch-millisecond timestamps are now converted
  to ISO 8601 strings at emission time, allowing OpenSearch dynamic mapping to detect them as
  date fields automatically.
- Removed alert action/source/category rules (100515–100520) that competed with severity rules
  due to Wazuh's last-match-wins evaluation. Severity (100511–100514) is now the sole
  determinant of rule level. Action, source, and category data remain in event fields for
  dashboard filtering.
- Alert rule levels aligned to documented severity mapping: medium 9→10, high 12→13.
- Balanced mode now fetches all actions for high/critical alerts (was DETECTED only).
  Both DETECTED and BLOCKED alerts are important for SOC visibility at this severity tier.

---

## [1.0.0] – 2026-03-01

Initial public release.
