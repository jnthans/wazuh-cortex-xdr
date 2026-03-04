# Installation — Docker

This guide covers deploying the Cortex XDR integration with the official [wazuh-docker](https://github.com/wazuh/wazuh-docker) stack, for both single-node and multi-node deployments.

The compose override files handle file ownership automatically at container startup — no host-side `chown` required. This works on **Linux, macOS, and Windows Docker Desktop** regardless of image version.

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

The volume paths in the override files assume `wazuh-cortex-xdr` sits **alongside** `wazuh-docker`, not inside it:

```
your-workspace/
├── wazuh-docker/
│   └── single-node/          ← run docker compose from here
└── wazuh-cortex-xdr/
    ├── wodle/
    ├── rules/
    └── artifacts/
        └── overrides/        ← compose override files live here
```

```bash
cd your-workspace
git clone https://github.com/wazuh/wazuh-docker.git
git clone https://github.com/jnthans/wazuh-cortex-xdr.git
```

If you clone `wazuh-cortex-xdr` **inside** `wazuh-docker`, adjust every volume source path in the override file: `../wodle` → `../wazuh-cortex-xdr/wodle`, and so on.

---

## Step 2 — Configure `run.sh`

<!-- GIF: Editing run.sh with FQDN and mode -->

```bash
# Linux / macOS
nano wazuh-cortex-xdr/wodle/run.sh

# Windows (PowerShell)
notepad wazuh-cortex-xdr\wodle\run.sh
```

Set your tenant FQDN and mode:

```bash
export XDR_FQDN="yourorg.xdr.us.paloaltonetworks.com"
export XDR_SECURITY_LEVEL="advanced"   # or "standard"
export XDR_MODE="balanced"             # economy | balanced | enriched
export XDR_LOOKBACK_HOURS="24"
```

See [configuration.md](configuration.md) for all available settings.

---

## Step 3 — Configure credentials

Create the secrets file from the template:

```bash
# Linux / macOS
cp wazuh-cortex-xdr/wodle/secrets.example wazuh-cortex-xdr/wodle/.secrets

# Windows (PowerShell)
Copy-Item wazuh-cortex-xdr\wodle\secrets.example wazuh-cortex-xdr\wodle\.secrets
```

Edit the file and add your credentials:

```
XDR_API_KEY=your-api-key-secret-value
XDR_API_KEY_ID=42
```

The `.gitignore` in this repo excludes `.secrets` and `state.json`. Never commit credentials.

> **Permissions are set automatically.** The compose override runs an inline entrypoint that detects the `wazuh` UID/GID at container startup and applies correct ownership to all bind-mounted files. No host-side `chown` is needed — this is what makes the deployment work on Windows.

---

## Step 4 — Apply the OpenSearch index template

This maps `data.xdr_*` fields explicitly so timestamps render correctly and all fields are sortable in the dashboard.

Run after the stack is up and the indexer is healthy:

```bash
# From the host (indexer port published to localhost)
INDEXER_HOST=https://localhost:9200 \
INDEXER_PASS=YourIndexerPassword \
bash wazuh-cortex-xdr/artifacts/index_template/apply-index-template.sh
```

Or from inside the manager container:

```bash
docker exec -it single-node-wazuh.manager-1 bash

INDEXER_HOST=https://wazuh.indexer:9200 \
INDEXER_PASS=YourIndexerPassword \
bash /var/ossec/wodles/cortex-xdr/apply-index-template.sh
```

> Replace `single-node-wazuh.manager-1` with your actual container name from `docker ps`.

---

## Step 5 — Add the wodle stanza to ossec.conf

<!-- GIF: Editing wazuh_manager.conf and adding the wodle block -->

The Wazuh manager configuration is mounted from the host via the `wazuh_cluster` config directory. Add the wodle stanza to:

- **Single-node:** `wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf`
- **Multi-node master:** `wazuh-docker/multi-node/config/wazuh_cluster/wazuh_manager.conf`

Add inside `<ossec_config>`:

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

See `artifacts/configs/ossec_cortex_xdr.conf` for additional examples.

---

## Step 6 — Launch the stack with the override files

<!-- GIF: Running docker compose up and watching the container start -->

### Single-node

Run from `wazuh-docker/single-node/`:

```bash
docker compose \
  -f docker-compose.yml \
  -f ../../wazuh-cortex-xdr/artifacts/overrides/docker-compose.single-node.override.yml \
  up -d
```

Or set `COMPOSE_FILE` once in your shell to avoid repeating the flags:

```bash
export COMPOSE_FILE="\
  docker-compose.yml:\
  ../../wazuh-cortex-xdr/artifacts/overrides/docker-compose.single-node.override.yml"

docker compose up -d
```

### Multi-node

Run from `wazuh-docker/multi-node/`:

```bash
docker compose \
  -f docker-compose.yml \
  -f ../../wazuh-cortex-xdr/artifacts/overrides/docker-compose.multi-node.override.yml \
  up -d
```

### Multi-node: what runs where

| Component | Master | Worker(s) |
|---|:---:|:---:|
| Wodle Python files + `run.sh` | ✅ | ❌ |
| `.secrets` credentials file | ✅ | ❌ |
| `cortex_xdr_rules.xml` | ✅ | ✅ |
| `cortex_xdr_decoder.xml` | ✅ | ✅ |

The override handles this split automatically. If you have more than one worker, duplicate the `wazuh.worker` block in the override and update the service name to match each worker in your base compose file.

---

## Verifying the deployment

```bash
# Confirm the init entrypoint fixed ownership
docker exec -it single-node-wazuh.manager-1 \
  ls -la /var/ossec/wodles/cortex-xdr/

# Confirm rules and decoder are loaded
docker exec -it single-node-wazuh.manager-1 \
  ls /var/ossec/etc/rules/ | grep cortex

# Test the wodle manually
docker exec -it single-node-wazuh.manager-1 \
  /var/ossec/wodles/cortex-xdr/run.sh \
  --mode balanced --all --lookback 2 --debug 1 2>&1
```

Expected: one JSON line per event on stdout, debug messages on stderr.

> Replace `single-node-wazuh.manager-1` with your actual container name (`docker ps`). For multi-node use `multi-node-wazuh.master-1`.

---

## Notes

- **Wazuh 5.x:** The install root changed from `/var/ossec/` to `/var/wazuh-manager/`. Update all volume target paths in the override files if you are running 5.x.
- **Windows Docker Desktop:** No extra steps required. The inline entrypoint handles ownership inside the container.
- **Indexer hostname:** `wazuh.indexer` only resolves inside the Docker network. Use `https://localhost:9200` when running `apply-index-template.sh` from the host.

---

## Next steps

- [Configuration reference](configuration.md) — all environment variables and CLI flags
- [Troubleshooting](troubleshooting.md) — common errors, debug commands, state reset
- [Rules reference](rules-reference.md) — rule IDs, severity mapping, compliance groups