# Configuration Reference

---

## Environment variables

Runtime config is set in `run.sh`. Sensitive values (`XDR_FQDN`, `XDR_API_KEY`, `XDR_API_KEY_ID`) must be stored in the secrets file or systemd credentials — not in `run.sh`. See [Credential priority chain](#credential-priority-chain) below.

| Variable | Default | Purpose |
|---|---|---|
| `XDR_FQDN` | *(required, secrets file)* | Bare tenant hostname — e.g. `yourorg.xdr.us.paloaltonetworks.com`. No `https://` prefix. |
| `XDR_API_KEY` | *(required, secrets file)* | API key secret. |
| `XDR_API_KEY_ID` | *(required, secrets file)* | Numeric API key ID. |
| `XDR_SECURITY_LEVEL` | `advanced` | Auth scheme: `advanced` (SHA-256 + nonce + timestamp) or `standard`. |
| `XDR_LOOKBACK_HOURS` | `24` | Lookback window (hours). Used on first run and with `--all` mode. |
| `XDR_STATE_FILE` | `/var/ossec/wodles/cortex-xdr/state.json` | Path to the state file that stores bookmarks between runs. |
| `XDR_SECRETS_FILE` | `/var/ossec/wodles/cortex-xdr/.secrets` | Path to the `KEY=VALUE` credentials file. |

---

## CLI flags

```
run.sh [options]

Data selection:
  -s, --source     alerts | incidents | both       (default: both)

Test / backfill:
  -a, --all        Ignore state; do not update state. Use with --lookback.
  -l, --lookback   Hours to look back (default: XDR_LOOKBACK_HOURS or 24)

Diagnostics:
  -d, --debug      0=off  1=info  2=verbose  3=trace  (stderr only, default: 0)
```

---

## Credential priority chain

The wodle evaluates all sources on every run. The highest-priority source that provides a value wins.

```
systemd $CREDENTIALS_DIRECTORY  >  .secrets file  >  environment variable
```

| Option | Plaintext on disk | Requires |
|---|:---:|---|
| systemd encrypted credentials | No | systemd 250+, bare metal/VM only |
| Secrets file (`root:wazuh 640`) | Yes, restricted | Nothing extra |
| Environment variables | Yes, visible in process table | Nothing extra |

Copy `.secrets.example` to `.secrets` and populate `XDR_FQDN`, `XDR_API_KEY`, and `XDR_API_KEY_ID`. Set `chmod 640, chown root:wazuh` on the file.

See [cortex-xdr-credentials.conf](../configs/cortex-xdr-credentials.conf) for systemd encrypted credential setup.

---

## Multi-tenant setup

Deploy a separate directory per tenant, each with its own `run.sh` and credentials:

```bash
# Tenant A
mkdir -p /var/ossec/wodles/cortex-xdr-tenant-a
cp wodle/* /var/ossec/wodles/cortex-xdr-tenant-a/
# Edit .secrets: set XDR_FQDN, XDR_API_KEY, XDR_API_KEY_ID for Tenant A

# Tenant B
mkdir -p /var/ossec/wodles/cortex-xdr-tenant-b
cp wodle/* /var/ossec/wodles/cortex-xdr-tenant-b/
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
  <timeout>300</timeout>
</wodle>

<wodle name="command">
  <disabled>no</disabled>
  <tag>cortex-xdr-tenant-b</tag>
  <command>/var/ossec/wodles/cortex-xdr-tenant-b/run.sh</command>
  <interval>5m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>300</timeout>
</wodle>
```

Each tenant directory has its own `state.json`, so bookmarks are fully independent.

---

## Key rotation

| Environment | Method | Restart required? |
|---|---|:---:|
| Bare metal — secrets file | Update `.secrets` in place | No (read on next poll) |
| Bare metal — systemd credentials | Re-encrypt with `systemd-creds encrypt`, restart manager | Yes |
| Docker Compose | Replace host secrets file, recreate container | Yes |
| Kubernetes | `kubectl create secret` with `--dry-run -o yaml \| kubectl apply` | No (kubelet syncs) |
