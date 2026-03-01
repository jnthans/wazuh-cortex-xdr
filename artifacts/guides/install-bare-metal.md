# Installation — Bare Metal / VM

This guide covers deploying the Cortex XDR integration on a Wazuh manager running directly on a Linux host (bare metal or VM). All commands are run as `root` unless noted.

**Requirements:** Wazuh manager 4.x+, Python 3.8+ (`python3 --version`), network access to the Cortex XDR API.

---

## Step 0 — Generate a Cortex XDR API key

<!-- GIF: Navigating to API key creation in Cortex XDR console -->

1. In the Cortex XDR console go to **Settings → Configurations → API Keys → New Key**
2. Choose **Advanced** security level (recommended) or **Standard**
3. Set the role to **Viewer** (read-only is sufficient)
4. Copy the **Key**, **Key ID**, and your tenant **FQDN**

The FQDN format is `yourorg.xdr.us.paloaltonetworks.com` — bare hostname only, no `https://` prefix.

---

## Step 1 — Clone the repository

```bash
cd /opt   # or any working directory
git clone https://github.com/YOUR_ORG/wazuh-cortex-xdr.git
cd wazuh-cortex-xdr
```

---

## Step 2 — Configure `run.sh`

<!-- GIF: Editing run.sh with FQDN and mode -->

Open `wodle/run.sh` and set your tenant FQDN and preferred ingestion mode:

```bash
nano wodle/run.sh
```

Key settings:

```bash
export XDR_FQDN="yourorg.xdr.us.paloaltonetworks.com"
export XDR_SECURITY_LEVEL="advanced"   # or "standard"
export XDR_MODE="balanced"             # economy | balanced | enriched
export XDR_LOOKBACK_HOURS="24"         # alert lookback window on first run only
```

**Modes at a glance:**

| Mode | What it ingests | Good for |
|---|---|---|
| `economy` | Incidents only | Storage-constrained environments |
| `balanced` | Incidents + high/critical DETECTED alerts | **Most production deployments** |
| `enriched` | Everything, full enrichment | Compliance, forensic archival |

See [configuration.md](configuration.md) for all available settings.

---

## Step 3 — Configure credentials

The wodle resolves credentials using a priority chain — the highest-priority source wins:

```
systemd encrypted credentials  >  secrets file  >  environment variable
```

### Option A — Secrets file (recommended)

A dedicated file holds only the secret values. It can be rotated independently without touching `run.sh` or `ossec.conf`.

```bash
cp wodle/secrets.example wodle/.secrets
nano wodle/.secrets
```

Add your credentials:

```
XDR_API_KEY=your-api-key-secret-value
XDR_API_KEY_ID=42
```

Deploy and lock it down:

```bash
mkdir -p /var/ossec/wodles/cortex-xdr
cp wodle/* /var/ossec/wodles/cortex-xdr/
chown root:wazuh /var/ossec/wodles/cortex-xdr/.secrets
chmod 640 /var/ossec/wodles/cortex-xdr/.secrets
```

### Option B — systemd encrypted credentials (most secure)

Credentials are encrypted with a machine-bound key and decrypted into tmpfs at service start. Plaintext never touches disk.

**Requires systemd 250+** — Ubuntu 22.10+, Debian 12+, RHEL/Rocky 9+. Check with `systemctl --version`.

```bash
# Create encrypted credential store
mkdir -p /etc/credstore.encrypted
chmod 700 /etc/credstore.encrypted

# Encrypt key and key ID
printf 'YOUR_API_KEY_SECRET' | \
    systemd-creds encrypt --name=xdr_api_key - \
    /etc/credstore.encrypted/xdr_api_key.cred

printf 'YOUR_KEY_ID' | \
    systemd-creds encrypt --name=xdr_api_key_id - \
    /etc/credstore.encrypted/xdr_api_key_id.cred

chmod 600 /etc/credstore.encrypted/*.cred

# Install the systemd drop-in
mkdir -p /etc/systemd/system/wazuh-manager.service.d/
cp artifacts/configs/cortex-xdr-credentials.conf \
   /etc/systemd/system/wazuh-manager.service.d/

systemctl daemon-reload
```

No changes to `run.sh` are needed — the wodle reads `$CREDENTIALS_DIRECTORY` automatically.

> **Key rotation:** re-encrypt with `systemd-creds encrypt`, then `systemctl restart wazuh-manager`.
> **Host migration:** credentials are machine-bound. Re-encrypt on the new host.

### Option C — Environment variables in `run.sh`

Use this only when neither Option A nor B is feasible (e.g. ephemeral environments).

Uncomment in `run.sh`:

```bash
export XDR_API_KEY="your-api-key-secret"
export XDR_API_KEY_ID="42"
```

Set `chmod 600 run.sh` and exclude it from version control if you use this option.

### Deploy the wodle files

```bash
mkdir -p /var/ossec/wodles/cortex-xdr
cp wodle/* /var/ossec/wodles/cortex-xdr/

chmod 750 /var/ossec/wodles/cortex-xdr/run.sh
chmod 755 /var/ossec/wodles/cortex-xdr/cortex_xdr.py
chown -R root:wazuh /var/ossec/wodles/cortex-xdr/
```

---

## Step 4 — Apply the OpenSearch index template

This maps `data.xdr_*` fields explicitly so timestamps render correctly and all fields are sortable and aggregatable in the dashboard. Without it, epoch-millisecond timestamps are stored as plain integers.

**Via script:**

```bash
INDEXER_HOST=https://localhost:9200 \
INDEXER_PASS=YourIndexerPassword \
bash artifacts/index_template/apply-index-template.sh
```

**Manually via curl:**

```bash
curl -s --insecure \
  -X PUT "https://localhost:9200/_index_template/wazuh-cortex-xdr" \
  -u admin:YourPassword \
  -H "Content-Type: application/json" \
  -d @artifacts/index_template/wazuh-cortex-xdr-index-template.json | python3 -m json.tool
```

The template applies to all future `wazuh-alerts-*` indices. Existing documents are not retroactively remapped.

---

## Step 5 — Install rules, decoder, and ossec.conf stanza

<!-- GIF: Editing ossec.conf to add the wodle block -->

**Copy the decoder and rules:**

```bash
cp rules/cortex_xdr_decoder.xml /var/ossec/etc/decoders/
cp rules/cortex_xdr_rules.xml   /var/ossec/etc/rules/
```

**Add the wodle stanza to `/var/ossec/etc/ossec.conf`** inside `<ossec_config>`:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>cortex-xdr</tag>
  <command>/var/ossec/wodles/cortex-xdr/run.sh</command>
  <interval>5m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>120</timeout>
</wodle>
```

The mode is controlled by `XDR_MODE` in `run.sh`. To make it explicit in the config:

```xml
<command>/var/ossec/wodles/cortex-xdr/run.sh --mode balanced</command>
```

See `artifacts/configs/ossec_cortex_xdr.conf` for additional examples including multi-tenant blocks and backfill commands.

---

## Step 6 — Restart and verify

<!-- GIF: Watching ossec.log for cortex events and checking the dashboard -->

**Test the connection before restarting:**

```bash
sudo -u wazuh /var/ossec/wodles/cortex-xdr/run.sh \
  --mode balanced --all --lookback 2 --debug 1 2>&1
```

Expected output: one JSON line per event on stdout, debug messages on stderr. HTTP 401/403 means wrong credentials. HTTP 400 usually means the FQDN is wrong (check for `https://` prefix — it should not be there).

**Restart the manager:**

```bash
systemctl restart wazuh-manager

# Watch for wodle activity
tail -f /var/ossec/logs/ossec.log | grep cortex
```

**Validate the decoder and rules:**

```bash
echo '{"integration":"cortex-xdr","type":"incident","xdr_incident_id":"1","xdr_severity":"high","xdr_status":"new","xdr_description":"Test"}' \
  | /var/ossec/bin/wazuh-logtest
```

Expected: `Rule id: 100533`, `Groups: cortex-xdr,cortex_xdr,cortex_xdr_incident,high_severity`.

---

## Permissions reference

| Path | Owner | Mode |
|------|-------|------|
| `/var/ossec/wodles/cortex-xdr/` | `root:wazuh` | `750` |
| `cortex_xdr.py` | `root:wazuh` | `755` |
| `run.sh` | `root:wazuh` | `750` |
| `.secrets` | `root:wazuh` | `640` |
| `state.json` | `wazuh:wazuh` | `640` (auto-created) |
| `/etc/credstore.encrypted/*.cred` | `root:root` | `600` |

---

## Next steps

- [Configuration reference](configuration.md) — all environment variables and CLI flags
- [Troubleshooting](troubleshooting.md) — common errors, debug commands, state reset
- [Rules reference](rules-reference.md) — rule IDs, severity mapping, compliance groups