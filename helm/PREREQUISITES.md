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
- A PKI secrets engine must be configured for certificate signing.
- The `VAULT_SERVICE` URL must be provided to the cluster via a ConfigMap (see Section 4).

### External Secrets Operator (Optional)

Can be used to synchronize secrets from Vault into Kubernetes automatically. This is not required if you create all necessary secrets manually (see Section 3).

### Prometheus Operator (Optional)

If you want Prometheus metrics collection, install the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator) (or [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)). This provides the `ServiceMonitor` and `PodMonitor` CRDs used by Carbide services.

- Service monitors are **disabled by default**. To enable them, set `serviceMonitor.enabled: true` in each subchart's values (or in the umbrella chart).
- Carbide functions normally without the Prometheus Operator installed.

---

## 2. PostgreSQL Database

An SSL-enabled PostgreSQL instance is required by `carbide-api` for persistent storage.

- **Recommended:** Use a PostgreSQL operator such as Crunchy PGO or Zalando Postgres Operator to manage the database lifecycle.
- **Database name:** `carbide` (configurable via values).
- **Schema creation:** The migration job included in the `carbide-api` subchart handles schema creation and migrations automatically. You do not need to run migrations manually.
- **Connection details:** Provided to the chart via a ConfigMap and a Secret (see Sections 3 and 4 below).

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

```bash
kubectl create secret generic carbide-vault-approle-tokens \
  --namespace forge-system \
  --from-literal=VAULT_ROLE_ID='<role-id>' \
  --from-literal=VAULT_SECRET_ID='<secret-id>'
```

### `carbide-vault-token`

Vault token for direct API access.

**Required keys:** `VAULT_TOKEN`

```bash
kubectl create secret generic carbide-vault-token \
  --namespace forge-system \
  --from-literal=VAULT_TOKEN='<vault-token>'
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
