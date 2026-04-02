# Cortex XDR - Wazuh Integration

Wazuh wodle that ingests **alerts** and **incidents** from Palo Alto Networks Cortex XDR into Wazuh SIEM via the Cortex XDR REST API.

---

## Dashboard

![Cortex XDR dashboard](artifacts/images/wazuh_cortex_xdr_dash_pv.png)

*Custom Cortex XDR dashboard showing alert counts by severity, event type word cloud, category breakdown, top endpoints, MITRE tactic mappings, and other metrics.*

![Wazuh Threat Hunting dashboard with Cortex XDR incidents](artifacts/images/wazuh_xdr_th_pv.png)

*Wazuh Threat Hunting dashboard filtered by integration `cortex-xdr`, showing ingested incidents with severity levels, rule IDs, and descriptions.*

---

## Features

- **Single wodle block** — one scheduled command captures both alerts and incidents, including the full incident lifecycle: new, under investigation, and closed.
- **Stateful** — bookmarks last-seen timestamps per data stream. Each run only pulls what changed.
- **Long-term archival** — Cortex does not retain data indefinitely. This integration persists all events in OpenSearch for compliance, forensics, and historical investigation.
- **MITRE ATT&CK tactic tagging** — incidents with tactic mappings are tagged with `mitre_*` groups for custom dashboard filtering.
- **Closed incident tracking** — resolved incidents are ingested as level 3 archival records.
- **Secure credential management** — FQDN, API key, and key ID stored in a restricted secrets file or systemd encrypted credentials.
- **Multi-tenant** — deploy a separate directory and `run.sh` per tenant.
- **Zero external Python dependencies** — stdlib only.

---

## Installation

1. Copy `wodle/*` to `/var/ossec/wodles/cortex-xdr/` on the Wazuh manager (or agent host).
2. Create `.secrets` from `.secrets.example` — set `XDR_FQDN`, `XDR_API_KEY`, `XDR_API_KEY_ID`. Set permissions `chmod 640, chown root:wazuh`.
3. Copy `rules/cortex_xdr_rules.xml` to `/var/ossec/etc/rules/` and `rules/cortex_xdr_decoder.xml` to `/var/ossec/etc/decoders/`.
4. Add a wodle stanza to `/var/ossec/etc/ossec.conf` using the example in [artifacts/configs/ossec_cortex_xdr.conf](artifacts/configs/ossec_cortex_xdr.conf).
5. Restart Wazuh manager.

See [artifacts/configs/](artifacts/configs/) for ossec.conf examples and systemd credential configuration.

---

## Repository structure

```
wazuh-cortex-xdr/
├── wodle/
│   ├── cortex_xdr.py            ← Entry point, CLI, orchestration
│   ├── cortex_xdr_alerts.py     ← Alert fetch and pagination
│   ├── cortex_xdr_incidents.py  ← Incident fetch and pagination
│   ├── cortex_xdr_utils.py      ← Auth, HTTP, atomic state, emit, logging, secrets
│   ├── run.sh                   ← Runtime config wrapper (ossec.conf <command> target)
│   └── .secrets.example         ← Credentials template (copy to .secrets)
├── rules/
│   ├── cortex_xdr_rules.xml     ← Custom Wazuh rules (IDs 100500–100599)
│   └── cortex_xdr_decoder.xml   ← JSON decoder registration
├── artifacts/
│   ├── configs/
│   │   ├── ossec_cortex_xdr.conf               ← ossec.conf wodle stanza examples
│   │   └── cortex-xdr-credentials.conf         ← systemd drop-in for encrypted credentials
│   ├── guides/
│   │   ├── configuration.md                    ← All env vars, CLI flags, multi-tenant
│   │   ├── rules-reference.md                  ← Rule families, severity mapping, MITRE, compliance
│   │   └── troubleshooting.md                  ← Test commands, common errors, reset / backfill
│   ├── images/
│   │   ├── wazuh_cortex_xdr_dash_pv.png        ← Cortex XDR dashboard screenshot
│   │   └── wazuh_xdr_th_pv.png                 ← Wazuh Threat Hunting dashboard screenshot
│   └── objects/
│       └── Cortex XDR.ndjson                    ← OpenSearch Dashboards saved object (importable)
├── .gitignore
└── README.md
```

---

## How it works

```
ossec.conf <wodle command>
    └─► run.sh  (sets runtime config; execs cortex_xdr.py)
            └─► cortex_xdr.py  (parses args, loads state, orchestrates fetchers)
                    ├─► cortex_xdr_alerts.py     → xdr_api_post() → emit() → stdout
                    └─► cortex_xdr_incidents.py  → xdr_api_post() → emit() → stdout
                                                      ↑
                                          cortex_xdr_utils.py
                              (auth headers, HTTP, atomic state, emit, secrets)
                                          ↑
                          Secret priority chain (first match wins):
                          [systemd $CREDENTIALS_DIRECTORY]
                                    > [.secrets file]
                                    > [environment variable]

stdout ──► Wazuh wodle manager ──► cortex_xdr_decoder.xml ──► cortex_xdr_rules.xml
                                                                       ↓
                                                           OpenSearch / Dashboard
```

Each event is emitted as a single JSON line. All XDR API fields are nested under the `xdr` key to avoid collisions with Wazuh's reserved field names. Wazuh's JSON decoder maps nested fields as `xdr.field_name` for rule matching and `data.xdr.field_name` in OpenSearch.

Epoch-millisecond timestamp fields returned by the Cortex XDR API are converted to ISO 8601 strings before emission (e.g. `1706540499609` → `"2024-01-29T18:41:39.609Z"`). This causes OpenSearch's dynamic field mapping to detect them as date fields automatically — no custom index template is required.

### Deployment topology

The wodle can run on three different hosts — the choice does not affect the wodle code itself:

- **Manager / master node** (default) — simplest to deploy.
- **Dedicated Wazuh agent host** — credentials never touch the manager; polling is independent of manager restarts and cluster failovers.
- **Existing agent on a connected host** — any agent host with network access to the Cortex XDR API can run the wodle with no additional infrastructure.

---

## Reference docs

- [Configuration reference](artifacts/guides/configuration.md) — all environment variables, CLI flags, multi-tenant setup
- [Rules reference](artifacts/guides/rules-reference.md) — rule families, severity mapping, MITRE ATT&CK, compliance groups
- [Troubleshooting](artifacts/guides/troubleshooting.md) — test commands, common errors, state reset, backfill
