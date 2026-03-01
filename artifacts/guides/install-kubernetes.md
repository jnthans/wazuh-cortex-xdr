# Installation — Kubernetes

This guide covers deploying the Cortex XDR integration in a Kubernetes environment running Wazuh. The wodle files and credentials are delivered as a `ConfigMap` and `Secret`, and the permission fix is handled via an init container.

> This guide assumes you have an existing Wazuh deployment on Kubernetes and are familiar with `kubectl`. For a full Wazuh on Kubernetes setup, refer to the [official Wazuh Kubernetes guide](https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/index.html).

---

## Step 0 — Generate a Cortex XDR API key

1. In the Cortex XDR console go to **Settings → Configurations → API Keys → New Key**
2. Choose **Advanced** security level (recommended) or **Standard**
3. Set the role to **Viewer** (read-only is sufficient)
4. Copy the **Key**, **Key ID**, and your tenant **FQDN**

---

## Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_ORG/wazuh-cortex-xdr.git
cd wazuh-cortex-xdr
```

---

## Step 2 — Configure `run.sh`

Edit `wodle/run.sh` and set your FQDN and mode. Do **not** put credentials here — they will come from the Kubernetes Secret mounted as a file.

```bash
export XDR_FQDN="yourorg.xdr.us.paloaltonetworks.com"
export XDR_SECURITY_LEVEL="advanced"
export XDR_MODE="balanced"
export XDR_LOOKBACK_HOURS="24"
export XDR_SECRETS_FILE="/run/secrets/cortex-xdr/.secrets"
```

The `XDR_SECRETS_FILE` path points to the Kubernetes Secret mount defined in Step 3.

---

## Step 3 — Configure credentials

Create the Kubernetes Secret in the `wazuh` namespace:

```bash
kubectl create secret generic cortex-xdr-credentials \
  --from-literal=XDR_API_KEY=your-api-key-secret \
  --from-literal=XDR_API_KEY_ID=42 \
  -n wazuh
```

> **Important:** Kubernetes `Secret` objects are only base64-encoded in etcd by default — they are not encrypted at rest. For production clusters, enable `EncryptionConfiguration` or use an External Secrets Operator backed by AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager, or Azure Key Vault.

The Secret will be mounted as a file volume in the manager pod (Step 6). The wodle reads it via `XDR_SECRETS_FILE` — no code changes required.

---

## Step 4 — Apply the OpenSearch index template

Run once after the indexer is healthy:

```bash
# From a host with kubectl access — port-forward the indexer first
kubectl port-forward svc/wazuh-indexer 9200:9200 -n wazuh &

INDEXER_HOST=https://localhost:9200 \
INDEXER_PASS=YourIndexerPassword \
bash artifacts/index_template/apply-index-template.sh
```

Or exec directly into the manager pod:

```bash
kubectl exec -it deployment/wazuh-manager -n wazuh -- bash

INDEXER_HOST=https://wazuh-indexer:9200 \
INDEXER_PASS=YourIndexerPassword \
bash /var/ossec/wodles/cortex-xdr/apply-index-template.sh
```

---

## Step 5 — Add the wodle stanza to ossec.conf

In your Wazuh Kubernetes deployment, `ossec.conf` is typically managed via a `ConfigMap`. Add the wodle stanza to that ConfigMap:

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

Apply the updated ConfigMap:

```bash
kubectl apply -f your-wazuh-manager-configmap.yaml -n wazuh
```

---

## Step 6 — Mount files and restart the manager

Patch the Wazuh manager deployment to:
- Mount the wodle files via a `ConfigMap`
- Mount credentials via the `Secret`
- Fix ownership via an init container

### Create a ConfigMap for the wodle files

```bash
kubectl create configmap cortex-xdr-wodle \
  --from-file=wodle/ \
  -n wazuh
```

### Patch the manager deployment

Add the following to your manager `Deployment` spec:

```yaml
spec:
  template:
    spec:
      initContainers:
        - name: cortex-xdr-init
          image: busybox
          command:
            - sh
            - -c
            - |
              cp /configmap/* /var/ossec/wodles/cortex-xdr/
              chown -R 1000:1000 /var/ossec/wodles/cortex-xdr
              chmod 750 /var/ossec/wodles/cortex-xdr/run.sh
          volumeMounts:
            - name: cortex-xdr-wodle-cm
              mountPath: /configmap
            - name: cortex-xdr-wodle
              mountPath: /var/ossec/wodles/cortex-xdr

      containers:
        - name: wazuh-manager
          volumeMounts:
            - name: cortex-xdr-wodle
              mountPath: /var/ossec/wodles/cortex-xdr
            - name: cortex-xdr-secrets
              mountPath: /run/secrets/cortex-xdr
              readOnly: true
            - name: cortex-xdr-rules
              mountPath: /var/ossec/etc/rules/cortex_xdr_rules.xml
              subPath: cortex_xdr_rules.xml
            - name: cortex-xdr-decoder
              mountPath: /var/ossec/etc/decoders/cortex_xdr_decoder.xml
              subPath: cortex_xdr_decoder.xml

      volumes:
        - name: cortex-xdr-wodle-cm
          configMap:
            name: cortex-xdr-wodle
        - name: cortex-xdr-wodle
          emptyDir: {}
        - name: cortex-xdr-secrets
          secret:
            secretName: cortex-xdr-credentials
            defaultMode: 0440
        - name: cortex-xdr-rules
          configMap:
            name: cortex-xdr-wodle
        - name: cortex-xdr-decoder
          configMap:
            name: cortex-xdr-wodle
```

> **UID note:** The init container uses `1000:1000`. Verify the wazuh UID in your image with `kubectl exec -it <pod> -- id -u wazuh` and update if different.

Apply and restart:

```bash
kubectl apply -f your-updated-deployment.yaml -n wazuh
kubectl rollout restart deployment/wazuh-manager -n wazuh
```

---

## Verifying the deployment

```bash
# Confirm files are in place with correct ownership
kubectl exec -it deployment/wazuh-manager -n wazuh -- \
  ls -la /var/ossec/wodles/cortex-xdr/

# Test the wodle manually
kubectl exec -it deployment/wazuh-manager -n wazuh -- \
  /var/ossec/wodles/cortex-xdr/run.sh \
  --mode balanced --all --lookback 2 --debug 1 2>&1
```

---

## Key rotation

```bash
# Update the secret (zero-downtime — kubelet syncs within the kubelet sync period)
kubectl create secret generic cortex-xdr-credentials \
  --from-literal=XDR_API_KEY=new-api-key-secret \
  --from-literal=XDR_API_KEY_ID=42 \
  -n wazuh \
  --dry-run=client -o yaml | kubectl apply -f -
```

No pod restart required — the mounted secret file updates automatically.

---

## Next steps

- [Configuration reference](configuration.md) — all environment variables and CLI flags
- [Troubleshooting](troubleshooting.md) — common errors, debug commands, state reset
- [Rules reference](rules-reference.md) — rule IDs, severity mapping, compliance groups