# Configuration Reference

---

## Environment variables

Runtime config is passed via environment variables set in `run.sh`. Sensitive values (`XDR_FQDN`, `XDR_API_KEY`, `XDR_API_KEY_ID`) must be stored in the secrets file or systemd credentials — not in `run.sh`. See [Credential priority chain](#credential-priority-chain) below.

| Variable | Default | Purpose |
|---|---|---|
| `XDR_FQDN` | *(required, secrets file)* | Bare tenant hostname — e.g. `yourorg.xdr.us.paloaltonetworks.com`. No `https://` prefix. |
| `XDR_API_KEY` | *(required, secrets file)* | API key secret. |
| `XDR_API_KEY_ID` | *(required, secrets file)* | Numeric API key ID. |
| `XDR_SECURITY_LEVEL` | `advanced` | Auth scheme: `advanced` (SHA-256 + nonce + timestamp) or `standard`. |
| `XDR_MODE` | `balanced` | Ingestion mode preset: `economy` \| `balanced` \| `enriched`. |
| `XDR_LOOKBACK_HOURS` | `1` | Lookback window for `--all` mode (hours). First run for both alerts and incidents is capped at 30 days. |
| `XDR_STATE_FILE` | `/var/ossec/wodles/cortex-xdr/state.json` | Path to the state file that stores bookmarks between runs. |
| `XDR_SECRETS_FILE` | `/var/ossec/wodles/cortex-xdr/.secrets` | Path to the `KEY=value` credentials file. |
| `XDR_ALERT_SEVERITIES` | `high,critical` | Alert severity filter. Comma-separated (`low,medium,high,critical`) or `all`. Applied server-side. |
| `XDR_ALERT_ACTIONS` | `all` | Alert action filter. `DETECTED`, `BLOCKED`, or `all`. Applied client-side. |
| `XDR_INCIDENT_STATUSES` | *(unset)* | Explicit incident status filter, overrides `--incident-mode`. Comma-separated or `all`. |
| `XDR_API_VERSION` | `v1` | Cortex XDR API version for the incidents endpoint. |
| `XDR_ALERTS_API_VERSION` | `v2` | Cortex XDR API version for the alerts endpoint. Set to `v1` if your tenant has not migrated. |

---

## CLI flags

```
run.sh [--mode MODE] [options]

Primary:
  -m, --mode       economy | balanced | enriched     (default: XDR_MODE or balanced)

Mode overrides (override the mode's default for this run only):
  -t, --type       alerts | incidents | both
  --alert-severities  low,medium,high,critical | all
  --alert-actions  DETECTED,BLOCKED | all
  -e, --enrich     Enable get_incident_extra_data enrichment per incident

Advanced:
  --incident-mode  active | closed | both            (default: both)

Test / backfill:
  -a, --all        Ignore state; do not update state. Use with --lookback.
  -l, --lookback   Hours to look back in --all mode (default: XDR_LOOKBACK_HOURS or 1)

Diagnostics:
  -d, --debug      0=off  1=info  2=verbose  3=trace  (stderr only, default: 0)
```

---

## Ingestion modes

Modes are named presets. Individual flags always override the mode for the current run.

| Mode | Type | Alert severities | Alert actions | Enrichment |
|---|---|---|---|:---:|
| `economy` | incidents | — | — | Off |
| `balanced` | both | high, critical | all | Off |
| `enriched` | both | all | all | On |

**Mode override examples:**

```bash
# Balanced but pull all alert severities
run.sh --mode balanced --alert-severities all

# Economy but with enrichment
run.sh --mode economy --enrich

# Enriched but incidents only this run
run.sh --mode enriched --type incidents

# Balanced but include BLOCKED alerts
run.sh --mode balanced --alert-actions all
```

---

## Credential priority chain

The wodle evaluates both sources on every run. The highest-priority source that provides a value wins.

```
systemd $CREDENTIALS_DIRECTORY  >  .secrets file
```

| Option | Plaintext on disk | Requires |
|---|:---:|---|
| systemd encrypted credentials | No | systemd 250+, bare metal/VM only |
| Secrets file (`root:wazuh 640`) | Yes, restricted | Nothing extra |

Copy `.secrets.example` to `.secrets` and populate `XDR_FQDN`, `XDR_API_KEY`, and `XDR_API_KEY_ID`. Set `chmod 640, chown root:wazuh` on the file.

---

## Multi-tenant setup

Deploy a separate directory per tenant, each with its own `run.sh` and credentials:

```bash
# Tenant A
mkdir -p /var/ossec/wodles/cortex-xdr-tenant-a
cp wodle/* /var/ossec/wodles/cortex-xdr-tenant-a/
# Edit run.sh: set XDR_MODE and runtime config for Tenant A
# Edit .secrets: set XDR_FQDN, XDR_API_KEY, XDR_API_KEY_ID for Tenant A

# Tenant B
mkdir -p /var/ossec/wodles/cortex-xdr-tenant-b
cp wodle/* /var/ossec/wodles/cortex-xdr-tenant-b/
# Edit run.sh: set XDR_MODE and runtime config for Tenant B
# Edit .secrets: set XDR_FQDN, XDR_API_KEY, XDR_API_KEY_ID for Tenant B
```

Add one `<wodle>` block per tenant in `ossec.conf` with a distinct `<tag>`:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>cortex-xdr-tenant-a</tag>
  <command>/var/ossec/wodles/cortex-xdr-tenant-a/run.sh</command>
  <interval>5m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>120</timeout>
</wodle>

<wodle name="command">
  <disabled>no</disabled>
  <tag>cortex-xdr-tenant-b</tag>
  <command>/var/ossec/wodles/cortex-xdr-tenant-b/run.sh</command>
  <interval>5m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>120</timeout>
</wodle>
```

Each tenant directory has its own `state.json`, so bookmarks are fully independent.

---

## Key rotation

| Environment | Method | Restart required? |
|---|---|:---:|
| Bare metal – secrets file | Update `.secrets` in place | No (read on next poll) |
| Bare metal – systemd credentials | Re-encrypt with `systemd-creds encrypt`, restart manager | Yes |
| Docker Compose | Replace host secrets file, recreate container | Yes |
| Docker Swarm | `docker secret create` new version, update service | Rolling |
| Kubernetes | `kubectl create secret` with `--dry-run -o yaml \| kubectl apply` | No (kubelet syncs) |