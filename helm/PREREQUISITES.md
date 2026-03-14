# Prerequisites

Before installing the Carbide Helm chart, the following infrastructure components, secrets, and configuration must be in place. The `prereqs/` Helm chart previously handled some of this setup automatically, but these resources must now be created manually prior to installation.

---

## 1. Cluster Operators

### cert-manager

Required for automatic TLS certificate management. All Carbide services rely on cert-manager for SPIFFE-based mTLS.

- A `ClusterIssuer` must be configured (the chart defaults to the name `vault-forge-issuer`).
- Install cert-manager if it is not already present:

```bash
helm repo add jetstack https://charts.jetstack.io --force-update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true
```

### HashiCorp Vault

Required for PKI (certificate signing) and secret storage. Vault serves as the backend for the cert-manager issuer and provides secrets to various Carbide components.

- Vault must be deployed and unsealed.
- A **PKI secrets engine** must be enabled at mount path **`forgeca`**:

```bash
vault secrets enable -path=forgeca pki
vault secrets tune -max-lease-ttl=87600h forgeca
```

- A **PKI role** named **`forge-cluster`** must be created under the `forgeca` mount. This role name is referenced by `carbide-api` via the `VAULT_PKI_ROLE_NAME` environment variable:

```bash
vault write forgeca/roles/forge-cluster \
  allowed_domains="forge.local,svc.cluster.local" \
  allow_subdomains=true \
  allow_bare_domains=true \
  max_ttl=8760h
```

- **Kubernetes auth** must be enabled with a role for the **cert-manager service account**, so the `vault-forge-issuer` ClusterIssuer (Section 5) can authenticate to Vault:

```bash
vault auth enable kubernetes
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443"
vault write auth/kubernetes/role/cert-manager \
  bound_service_account_names=cert-manager \
  bound_service_account_namespaces=cert-manager \
  policies=forge-pki-policy \
  ttl=1h
```

- A **Vault policy** must grant the cert-manager role permission to sign certificates:

```bash
vault policy write forge-pki-policy - <<EOF
path "forgeca/sign/forge-cluster" {
  capabilities = ["create", "update"]
}
path "forgeca/issue/forge-cluster" {
  capabilities = ["create"]
}
EOF
```

- The `VAULT_SERVICE` URL must be provided to the cluster via a ConfigMap (see Section 4).

For additional Vault configuration details, see the [Site Setup guide](book/src/manuals/site-setup.md#vault-pki-and-secrets).

### External Secrets Operator (Optional)

Can be used to synchronize secrets from Vault into Kubernetes automatically. This is not required if you create all necessary secrets manually (see Section 3).

### Prometheus Operator (Optional)

If you want Prometheus metrics collection, install the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator) (or [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)). This provides the `ServiceMonitor` and `PodMonitor` CRDs used by Carbide services.

- Service monitors are **disabled by default**. To enable them, set `serviceMonitor.enabled: true` in each subchart's values (or in the umbrella chart).
- Carbide functions normally without the Prometheus Operator installed.

---

## 2. PostgreSQL Database

An SSL-enabled PostgreSQL instance is required by `carbide-api` for persistent storage.

- **Recommended:** Use a PostgreSQL operator such as Crunchy PGO or Zalando Postgres Operator (v1.10.1 with Spilo-15 image 3.0-p1 validated) to manage the database lifecycle.
- **Database and user:** Create a dedicated database named `carbide` with a dedicated user named `carbide`. Do not use the default `postgres` superuser for Carbide services.
- **Required extensions:** The following PostgreSQL extensions must be created before the migration job runs:

```bash
psql "postgres://<POSTGRES_USER>:<POSTGRES_PASSWORD>@<POSTGRES_HOST>:<POSTGRES_PORT>/<POSTGRES_DB>?sslmode=require" \
  -c 'CREATE EXTENSION IF NOT EXISTS btree_gin;' \
  -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'
```

- **Schema creation:** The migration job included in the `carbide-api` subchart handles schema creation and migrations automatically after extensions are in place. You do not need to run migrations manually.
- **Connection details:** Provided to the chart via a ConfigMap and a Secret (see Sections 3 and 4 below).

For additional PostgreSQL configuration details (TLS, ESO integration, per-namespace credentials), see the [Site Setup guide](book/src/manuals/site-setup.md#postgresql-db).

---

## 2a. Temporal (Required for bare-metal-manager-rest only)

Temporal is **not required** by the Carbide core Helm chart. You can operate Carbide core
standalone using `admin-cli` with direct gRPC commands.

Temporal **is required** if you deploy the
[bare-metal-manager-rest](https://github.com/NVIDIA/bare-metal-manager-rest) layer
(cloud-api, cloud-workflow, site-manager, elektra-site-agent). The REST components use
Temporal for workflow orchestration between the cloud control plane and site agents.

If you plan to deploy bare-metal-manager-rest:

- **Reference version:** Temporal server v1.22.6, admin tools v1.22.4, UI v2.16.2
- **Visibility store:** Elasticsearch 7.17.3
- **Persistence:** PostgreSQL (can share the same cluster as Carbide, with separate
  databases `temporal` and `temporal_visibility`)
- **Frontend endpoint:** `temporal-frontend.temporal.svc:7233` (cluster-internal)
- **Required namespaces:** Register `cloud` and `site` after Temporal is running:

```bash
tctl --ns cloud namespace register
tctl --ns site namespace register
```

- **mTLS:** The REST components expect Temporal client TLS certificates. These are
  issued by the `vault-issuer` ClusterIssuer created by cloud-cert-manager (credsmgr),
  which is part of bare-metal-manager-rest. See the
  [End-to-End Installation Guide](book/src/manuals/installation-guide.md) for the
  full deployment order.

---

## 3. Kubernetes Secrets

All secrets should be created in the `forge-system` namespace (or whichever namespace you are deploying into) before installing the chart.

### `forge-system.carbide.forge-pg-cluster.credentials`

Database credentials for `carbide-api`.

**Required keys:** `username`, `password`, `host`, `port`, `dbname`, `uri`

```bash
kubectl create secret generic forge-system.carbide.forge-pg-cluster.credentials \
  --namespace forge-system \
  --from-literal=username=carbide \
  --from-literal=password='<password>' \
  --from-literal=host=postgresql.forge-system.svc.cluster.local \
  --from-literal=port=5432 \
  --from-literal=dbname=carbide \
  --from-literal=uri='postgres://carbide:<password>@postgresql.forge-system.svc.cluster.local:5432/carbide?sslmode=require'
```

### `carbide-vault-approle-tokens`

Vault AppRole credentials for automated secret access by Carbide services.

**Required keys:** `VAULT_ROLE_ID`, `VAULT_SECRET_ID`

To obtain these values, enable AppRole auth in Vault and create a role for Carbide:

```bash
vault auth enable approle

vault write auth/approle/role/carbide \
  token_policies="forge-pki-policy,forge-kv-policy" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0
```

Then read the role ID and generate a secret ID:

```bash
vault read -field=role_id auth/approle/role/carbide/role-id
vault write -field=secret_id -f auth/approle/role/carbide/secret-id
```

Create the Kubernetes secret with the values returned above:

```bash
kubectl create secret generic carbide-vault-approle-tokens \
  --namespace forge-system \
  --from-literal=VAULT_ROLE_ID='<role-id-from-above>' \
  --from-literal=VAULT_SECRET_ID='<secret-id-from-above>'
```

### `carbide-vault-token`

Vault token for direct API access. This token is used by Carbide services that
authenticate to Vault directly rather than via AppRole.

**Required keys:** `VAULT_TOKEN`

Generate a token with the policies Carbide needs:

```bash
vault token create \
  -policy=forge-pki-policy \
  -policy=forge-kv-policy \
  -ttl=768h \
  -display-name=carbide-api
```

The `token` field in the output is your `VAULT_TOKEN`. Create the Kubernetes secret:

```bash
kubectl create secret generic carbide-vault-token \
  --namespace forge-system \
  --from-literal=VAULT_TOKEN='<token-from-above>'
```

**Note:** The policies referenced above (`forge-pki-policy`, `forge-kv-policy`) must
be created first. See the [Vault section](#hashicorp-vault) above for the PKI policy.
For the KV policy:

```bash
vault policy write forge-kv-policy - <<EOF
path "secrets/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
```

### `ssh-host-key` (for carbide-ssh-console-rs)

SSH host key used by the console proxy service. This key must be generated ahead of time.

**Required keys:** `ssh_host_ed25519_key`

```bash
ssh-keygen -t ed25519 -f /tmp/ssh_host_ed25519_key -N ""
kubectl create secret generic ssh-host-key \
  --namespace forge-system \
  --from-file=ssh_host_ed25519_key=/tmp/ssh_host_ed25519_key
```

### `azure-sso-carbide-web-client-secret` (Optional -- only if using OAuth2)

OAuth2 client secret for SSO integration with Azure AD or another identity provider.

**Required keys:** `CARBIDE_WEB_OAUTH2_CLIENT_SECRET`

```bash
kubectl create secret generic azure-sso-carbide-web-client-secret \
  --namespace forge-system \
  --from-literal=CARBIDE_WEB_OAUTH2_CLIENT_SECRET='<client-secret>'
```

### Image Pull Secrets (if using a private registry)

If your container images are hosted in a private registry, create an image pull secret:

```bash
kubectl create secret docker-registry my-registry-secret \
  --namespace forge-system \
  --docker-server=<registry-url> \
  --docker-username=<username> \
  --docker-password=<password>
```

Then reference it in your values file:

```yaml
global:
  imagePullSecrets:
    - name: my-registry-secret
```

---

## 4. ConfigMaps

### `vault-cluster-info`

Provides Vault connection information to Carbide services.

**Required keys:** `VAULT_SERVICE`, `FORGE_VAULT_MOUNT`, `FORGE_VAULT_PKI_MOUNT`

```bash
kubectl create configmap vault-cluster-info \
  --namespace forge-system \
  --from-literal=VAULT_SERVICE='https://vault.example.com' \
  --from-literal=FORGE_VAULT_MOUNT='secrets' \
  --from-literal=FORGE_VAULT_PKI_MOUNT='forgeca'
```

**Note:** Alternatively, populate `carbide-api.vaultClusterInfo` in your `values.yaml` to have the chart create this ConfigMap for you.

### `forge-system-carbide-database-config`

Non-secret database connection information for `carbide-api`.

**Required keys:** `DB_HOST`, `DB_PORT`, `DB_NAME`

```bash
kubectl create configmap forge-system-carbide-database-config \
  --namespace forge-system \
  --from-literal=DB_HOST='postgresql.forge-system.svc.cluster.local' \
  --from-literal=DB_PORT='5432' \
  --from-literal=DB_NAME='carbide'
```

**Note:** Alternatively, populate `carbide-api.databaseConfig` in your `values.yaml` to have the chart manage this ConfigMap automatically.

---

## 5. ClusterIssuer

A cert-manager `ClusterIssuer` must be configured for certificate signing. The default issuer name expected by the chart is `vault-forge-issuer`.

### Example: Vault PKI ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: vault-forge-issuer
spec:
  vault:
    path: forgeca/sign/forge-cluster
    server: https://vault.example.com
    auth:
      kubernetes:
        role: cert-manager
        mountPath: /v1/auth/kubernetes
        serviceAccountRef:
          name: cert-manager
```

If you are using a different issuer (for example, self-signed or Let's Encrypt), update the issuer reference in your values file:

```yaml
global:
  certificate:
    issuerRef:
      name: my-custom-issuer
      kind: ClusterIssuer
```

---

## 6. Network Requirements

Several Carbide services require direct network connectivity to bare metal hosts. Ensure the following network conditions are met before installation:

- **carbide-dhcp** and **carbide-pxe** need layer 2 network access to the bare metal hosts they manage. These services must be able to send and receive broadcast traffic on the provisioning network.
- **carbide-dns** must be reachable by managed machines for DNS resolution. Configure your network so that provisioned hosts use the `carbide-dns` service as their DNS server.
- **NTP**: Managed machines require access to an NTP server for time synchronization. Provide NTP through your existing infrastructure (e.g., datacenter NTP servers, host-level `chronyd`, or a cloud time source). Configure the NTP server address in your DHCP settings (`carbide-ntpserver` in the Kea config).
- **Recursive DNS**: Managed machines need a recursive DNS resolver that can forward internal queries (e.g., `*.forge.local`) to `carbide-dns` and external queries to upstream DNS. You can either configure your existing resolver with the appropriate forwarding rules, or enable the bundled `unbound` subchart (`unbound.enabled: true`) which comes pre-configured for this layered DNS architecture.
- If you are using **MetalLB** or a similar load balancer for bare metal environments, configure `LoadBalancer` services via the `externalService` settings in each subchart's values. For example:

```yaml
carbide-dhcp:
  externalService:
    enabled: true
    type: LoadBalancer
    annotations:
      metallb.universe.tf/address-pool: provisioning
```

Ensure that firewall rules and network policies allow traffic between Carbide services and the bare metal hosts on all required ports.

---

## 7. Loki (Optional — for SSH Console Log Shipping)

The `carbide-ssh-console-rs` subchart includes an optional OpenTelemetry Collector Contrib sidecar that ships SSH console logs to Loki. This sidecar is **disabled by default** (`lokiLogCollector.enabled: false`).

If you want console logs shipped to Loki, you must:

1. Deploy a Loki instance reachable at `http://loki.loki.svc.cluster.local:3100` from the `forge-system` namespace (the default endpoint configured in `helm/charts/carbide-ssh-console-rs/files/otelcol-config.yaml`).
2. Enable the sidecar and provide the collector image in your values such as:

```yaml
carbide-ssh-console-rs:
  lokiLogCollector:
    enabled: true
    image:
      repository: ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector-contrib
      tag: "0.81.0"
```

If Loki is not deployed, leave `lokiLogCollector.enabled: false` (the default). The SSH console proxy will function normally without log shipping.
