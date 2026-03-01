# wazuh-cortex-xdr

Wazuh wodle that ingests **alerts** and **incidents** from Palo Alto Cortex XDR into Wazuh SIEM via the Cortex XDR REST API.

---

## Features

- **Three ingestion modes** — `economy` (incidents only), `balanced` (incidents + high/critical alerts, default), `enriched` (full fidelity). Set once in `run.sh`.
- **Single wodle block** — one scheduled command captures the full incident lifecycle: new, under investigation, and closed. No duplicate API calls.
- **Stateful** — bookmarks last-seen timestamps per data type. Each run only pulls what changed. No duplicates.
- **Long-term archival** — Cortex does not retain data indefinitely. This integration persists all events in OpenSearch for compliance, forensics, and historical investigation.
- **MITRE ATT&CK tactic tagging** — incidents with tactic mappings are tagged with `mitre_*` groups for custom dashboard filtering.
- **Closed incident tracking** — resolved incidents are ingested as level 3 archival records.
- **Secure credential management** — systemd encrypted credentials, secrets file, or environment variables. Priority chain evaluated on every run.
- **Multi-tenant** — deploy a separate directory and `run.sh` per tenant.
- **Zero external Python dependencies** — stdlib only.

---

## Installation guides

Choose the guide that matches your deployment:

| Environment | Guide |
|---|---|
| Bare metal or VM | [artifacts/guides/install-bare-metal.md](artifacts/guides/install-bare-metal.md) |
| Docker (single-node or multi-node) | [artifacts/guides/install-docker.md](artifacts/guides/install-docker.md) |
| Kubernetes | [artifacts/guides/install-kubernetes.md](artifacts/guides/install-kubernetes.md) |

---

## Repository structure

```
wazuh-cortex-xdr/
├── wodle/
│   ├── cortex_xdr.py            ← Entry point, CLI, mode system, orchestration
│   ├── cortex_xdr_alerts.py     ← Alert fetch, pagination, action filter
│   ├── cortex_xdr_incidents.py  ← Incident fetch, pagination, status filter, enrichment
│   ├── cortex_xdr_utils.py      ← Auth, HTTP, atomic state, emit, logging, secrets
│   ├── run.sh                   ← Runtime config wrapper (ossec.conf <command> target)
│   └── secrets.example         ← Credentials template (copy to .secrets)
├── rules/
│   ├── cortex_xdr_rules.xml     ← Custom Wazuh rules (IDs 100500–100599)
│   └── cortex_xdr_decoder.xml   ← JSON decoder registration
├── artifacts/
│   ├── configs/
│   │   ├── ossec_cortex_xdr.conf               ← ossec.conf wodle stanza examples
│   │   └── cortex-xdr-credentials.conf         ← systemd drop-in for encrypted credentials
│   ├── guides/
│   │   ├── install-bare-metal.md               ← Bare metal / VM installation guide
│   │   ├── install-docker.md                   ← Docker installation guide
│   │   ├── install-kubernetes.md               ← Kubernetes installation guide
│   │   ├── configuration.md                    ← All env vars, CLI flags, modes, multi-tenant
│   │   ├── rules-reference.md                  ← Rule families, severity mapping, MITRE, compliance
│   │   └── troubleshooting.md                  ← Test commands, common errors, reset / backfill
│   ├── index_template/
│   │   ├── wazuh-cortex-xdr-index-template.json     ← OpenSearch field mapping template (API)
│   │   ├── wazuh-cortex-xdr-index-template-gui.json ← OpenSearch field mapping template (Dashboard GUI)
│   │   └── apply-index-template.sh             ← Script to apply the index template
│   └── overrides/
│       ├── docker-compose.single-node.override.yml ← Docker volume mapping (single-node)
│       └── docker-compose.multi-node.override.yml  ← Docker volume mapping (multi-node)
├── .gitignore
└── README.md
```

---

## Ingestion modes

| Mode | Incidents | Alerts | Enrichment | Use when |
|---|---|---|:---:|---|
| `economy` | All statuses | None | Off | Storage-constrained; incidents already aggregate alert data |
| `balanced` | All statuses | High + critical, DETECTED only | Off | **Recommended** for most environments |
| `enriched` | All statuses | All severities, DETECTED + BLOCKED | On | Full archival fidelity, compliance, forensic requirements |

Set the mode in `run.sh` via `XDR_MODE`, or pass `--mode` on the command line. The default is `balanced`. Individual flags override the mode for a single run. See [configuration reference](artifacts/guides/configuration.md) for details.

---

## How it works

```
ossec.conf <wodle command>
    └─► run.sh  (sets XDR_FQDN, XDR_MODE, credentials; execs cortex_xdr.py)
            └─► cortex_xdr.py  (parses args, applies mode preset, loads state)
                    ├─► cortex_xdr_alerts.py     → api_post() → emit() → stdout
                    └─► cortex_xdr_incidents.py  → api_post() → emit() → stdout
                                                      ↑
                                          cortex_xdr_utils.py
                              (auth headers, HTTP, atomic state, emit, secrets)
                                          ↑
                          Secret priority chain (first match wins):
                          [systemd $CREDENTIALS_DIRECTORY]
                                    > [.secrets file]
                                    > [env var]

stdout ──► Wazuh wodle manager ──► cortex_xdr_decoder.xml ──► cortex_xdr_rules.xml
                                                                       ↓
                                                           OpenSearch / Dashboard
```

Each event is emitted as a single JSON line. All XDR API fields are prefixed with `xdr_` to avoid collisions with Wazuh's reserved field names. Wazuh's JSON decoder flattens all fields into `data.*` for rule matching and dashboard display.

### Deployment topology

The wodle can run on three different hosts — the choice does not affect the wodle code itself:

- **Manager / master node** (default) — simplest to deploy.
- **Dedicated Wazuh agent host** — credentials never touch the manager; polling is independent of manager restarts and cluster failovers. The agent forwards events to the manager over the standard encrypted channel.
- **Existing agent on a connected host** — any agent host with network access to the Cortex XDR API (e.g. a SOAR server or jump host) can run the wodle with no additional infrastructure.

---

## Reference docs

- [Configuration reference](artifacts/guides/configuration.md) — all environment variables, CLI flags, mode overrides, multi-tenant setup
- [Rules reference](artifacts/guides/rules-reference.md) — rule families, severity mapping, MITRE ATT&CK, compliance groups
- [Troubleshooting](artifacts/guides/troubleshooting.md) — test commands, common errors, state reset, backfill