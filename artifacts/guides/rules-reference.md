# Rules Reference

Custom Wazuh rules are in `rules/cortex_xdr_rules.xml`. Default ID range: **100500–100599**. If this conflicts with existing custom rules, renumber both the rule IDs and all `if_sid` references within the file.

All fields emitted by the wodle are prefixed `data.xdr_*` in the Wazuh/OpenSearch index (e.g. `data.xdr_severity`, `data.xdr_incident_id`).

---

## Rule families

| ID range | Family | Fires on |
|---|---|---|
| 100500 | Base | All Cortex XDR wodle events — parent for all rules below |
| 100510–100520 | Alerts | Raw detections: severity tiers, malware, DETECTED/BLOCKED actions, sources |
| 100530–100538 | Active incidents | `new` + `under_investigation`: severity tiers, correlated alerts |
| 100550–100554 | Closed incidents | `resolved_true_positive` / `resolved_false_positive`: archival records |
| 100570–100578 | MITRE ATT&CK tactics | Incident tactic mapping: Persistence, Privilege Escalation, etc. |
| 100599 | Errors | Wodle/API errors — fires an alert so failures are visible in the dashboard |

---

## Severity → Wazuh level mapping

| XDR severity | Alert rule level | Active incident rule level |
|:---:|:---:|:---:|
| low | 5 | 6 |
| medium | 9 | 10 |
| high | 12 | 13 |
| critical | 15 | 15 |

Closed incident rules fire at level 3 (false positive) or 3–10 by severity (true positive) — treated as archival records rather than active alerts.

---

## Incident lifecycle rules

The `modification_time` bookmark means every status transition surfaces on the next poll. Rules differentiate by status:

| `xdr_status` | Rule level | Purpose |
|---|:---:|---|
| `new` | 6–15 (by severity) | Real-time SOC alerting |
| `under_investigation` | 6 | Analyst activity tracking |
| `resolved_true_positive` | 3–10 (by severity) | Archival + compliance |
| `resolved_false_positive` | 3 | Archival + tuning feedback |

---

## MITRE ATT&CK tactic rules (100571–100578)

When a Cortex XDR incident carries `xdr_mitre_tactics_ids_and_names`, dedicated rules fire alongside the severity rules. Each rule matches on the tactic label text and tags the event with a specific group for filtering.

Covered tactics: Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, Exfiltration, Command and Control, Impact.

> **Why the built-in MITRE ATT&CK dashboard does not populate from XDR incidents:**
> Wazuh's native MITRE module requires technique IDs (`T1078`, `T1059.003`) in the `<mitre><id>` rule tag. The Cortex XDR incidents API only provides tactic IDs (`TA0003`, `TA0004`) — the parent category level of the ATT&CK hierarchy. Tactic IDs are not present in Wazuh's local database; when an ID is not found, Wazuh suppresses writing `rule.mitre.id` entirely, leaving the dashboard empty.
>
> Mapping tactics to arbitrary techniques would fabricate specificity that doesn't exist in the source data, so `<mitre>` blocks are intentionally absent. Use the `mitre_*` group tags in custom OpenSearch dashboards and alert filters instead.

---

## Compliance groups

High and critical severity rules carry:
`gdpr_IV_35.7.d`, `hipaa_164.312.b`, `nist_800_53_SI.4`, `pci_dss_11.4`, `tsc_CC7.2`

Closed true-positive incident rules additionally carry:
`nist_800_53_IR.4`, `pci_dss_12.10`
