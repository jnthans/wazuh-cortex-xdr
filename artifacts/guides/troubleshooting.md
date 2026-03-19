# Troubleshooting

---

## Test commands

Run these manually to verify credentials, connectivity, and event output before relying on the scheduled wodle.

| Goal | Command |
|---|---|
| Test credentials + see recent events | `run.sh --mode balanced --all --lookback 2 --debug 1 2>&1` |
| Full HTTP trace | `run.sh --mode balanced --all --lookback 1 --debug 3 2>&1` |
| Dump all incidents (last 24h) | `run.sh --mode enriched --all --lookback 24 2>&1` |
| Economy mode dry-run | `run.sh --mode economy --all --lookback 4 --debug 1 2>&1` |
| Historical backfill (1 year) | `run.sh --mode enriched --all --lookback 8760 2>&1` |
| Reset state (re-ingest from scratch) | `rm /var/ossec/wodles/cortex-xdr/state.json` |

Prepend `sudo -u wazuh` on bare metal. Use `docker exec -it <container>` on Docker.

---

## Common errors

### HTTP 000 — no response

curl got no response at all. The XDR API is not reachable from where the command is running.

Check that the host can reach `https://api-<fqdn>/public_api/v1/`. Verify firewall rules and proxy settings.

### HTTP 400 — bad request

Usually a malformed FQDN. Check that `XDR_FQDN` in `.secrets` is the bare hostname only — no `https://`, no trailing slash, no `api-` prefix. Example: `yourorg.xdr.us.paloaltonetworks.com`.

### HTTP 401 / 403 — authentication failure

Wrong credentials or wrong security level. Verify `XDR_API_KEY` and `XDR_API_KEY_ID` in `.secrets` match what was generated in the Cortex XDR console. Verify `XDR_SECURITY_LEVEL` in `run.sh` matches the key type. Advanced keys require SHA-256 authentication; Standard keys use a simpler scheme.

### HTTP 429 — rate limited

The tenant's API rate limit has been hit. The 5-minute poll interval is safe for most tenants. If you're running backfills or multiple tenants against the same API key, stagger the schedules.

### `CRITICAL: (1220): Error loading the rules`

The rules file is not owned by `wazuh:wazuh` inside the container. On Docker, confirm the compose override is being applied (check `docker inspect <container>` for the entrypoint). On bare metal, verify ownership with `ls -la /var/ossec/etc/rules/cortex_xdr_rules.xml`.

### `ERROR: wazuh user not found` (Docker init entrypoint)

The init entrypoint runs before the wazuh user exists. This should not happen with official Wazuh images — if it does, check that the base image is a Wazuh manager image and not a plain Linux base.

### Events appear in `ossec.log` but not in the dashboard

1. Check the decoder is installed: `ls /var/ossec/etc/decoders/ | grep cortex`
2. Validate with wazuh-logtest:
   ```bash
   echo '{"integration":"cortex-xdr","xdr_type":"incident","xdr_incident_id":"1","xdr_severity":"high","xdr_status":"new","xdr_description":"Test"}' \
     | /var/ossec/bin/wazuh-logtest
   ```
   Expected: `Rule id: 100533`
3. Refresh the index pattern: **Dashboard management → Dashboards Management → wazuh-alerts-\* → Refresh field list**

### `Mitre Technique ID 'TAxxxx' not found in database` in ossec.log

Expected and harmless. Wazuh's MITRE database contains technique IDs (`T####`), not tactic IDs (`TA####`). The warning fires but does not affect rule matching or event storage. See [rules-reference.md](rules-reference.md#mitre-attck-tactic-rules-100571100578) for full explanation.

---

## State and backfill

The state file (`state.json`) stores two bookmarks:

| Key | Description |
|---|---|
| `last_alert_ts` | Epoch-ms timestamp of the most recent alert processed |
| `last_incident_ts` | Epoch-ms timestamp of the most recently modified incident processed |

**Reset and re-ingest everything:**

```bash
rm /var/ossec/wodles/cortex-xdr/state.json
```

The next run will fetch the last 30 days of alerts and incidents (first-run cap).

**Backfill a specific window without touching production state:**

```bash
# Pull the last 30 days without updating state
sudo -u wazuh /var/ossec/wodles/cortex-xdr/run.sh \
  --mode enriched --all --lookback 720 2>&1
```

`--all` mode never reads or writes the state file, so it is safe to run alongside the scheduled wodle.

> **Note:** After a backfill run, the next scheduled poll re-fetches any overlapping window from the saved bookmark — this is intentional. Events will not be duplicated in Wazuh because the decoder and rules are stateless; however, if duplicate suppression matters, ensure the bookmarks from the scheduled wodle are ahead of the backfill window before running.

---

## Useful log locations

| Log | Purpose |
|---|---|
| `/var/ossec/logs/ossec.log` | Manager activity including wodle execution and rule loading |
| `/var/ossec/logs/alerts/alerts.json` | Raw alert documents as JSON (one per line) |
| stderr of the wodle | Debug output — only visible when running manually with `--debug` |

On Docker, access logs with:

```bash
docker exec -it <container> tail -f /var/ossec/logs/ossec.log
docker logs <container>
```