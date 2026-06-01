# Reference Installation — Manual Phase-by-Phase

This guide breaks down every phase of NICo's `setup.sh` installation with the exact commands being run. Use this if you need to re-run a single phase, debug a failure, or understand what the script does before running it.

For the automated end-to-end installation using `setup.sh`, see the [Quick Start Guide](../quick-start.md).

**Prerequisites:** complete all configuration steps in [Step 3 of the Quick Start Guide](../quick-start.md#step-3--configure-the-site) before running any phase manually.

All commands below assume you are in the `helm-prereqs/` directory with the required environment variables set:

```bash
cd helm-prereqs/
export KUBECONFIG=/path/to/kubeconfig
export REGISTRY_PULL_SECRET=<your-pull-secret>
export NCX_IMAGE_REGISTRY=<your-registry>
export NCX_CORE_IMAGE_TAG=<ncx-core-tag>
export NCX_REST_IMAGE_TAG=<ncx-rest-tag>
export NCX_REPO=/path/to/ncx-infra-controller-rest   # or let preflight auto-detect
```

---

## Phase 0 — DNS check

Detects cluster type and verifies DNS is ready before any workloads are deployed.

- **Kubespray clusters** — checks if the `nodelocaldns` DaemonSet is ready; deploys `operators/nodelocaldns-daemonset.yaml` if missing and waits for rollout
- **kubeadm / other** — checks CoreDNS readyReplicas >= 1; warns but does not fail if not ready

```bash
# Kubespray: deploy NodeLocal DNSCache if missing
if kubectl get configmap nodelocaldns -n kube-system &>/dev/null; then
    kubectl apply -f operators/nodelocaldns-daemonset.yaml 2>/dev/null || true
    kubectl rollout status daemonset/nodelocaldns -n kube-system --timeout=120s
else
    # kubeadm: just verify CoreDNS is up
    kubectl get deployment coredns -n kube-system
fi
```

---

## Phase 1 — local-path-provisioner

Deploys StorageClasses for Vault and PostgreSQL PVCs. The `local-path-persistent` StorageClass uses `reclaimPolicy: Retain` so data survives pod deletion and node restarts.

```bash
kubectl apply -f operators/local-path-provisioner.yaml
# Delete before re-apply - the provisioner field is immutable
kubectl delete -f operators/storageclass-local-path-persistent.yaml --ignore-not-found 2>/dev/null || true
kubectl apply -f operators/storageclass-local-path-persistent.yaml
kubectl rollout status deployment/local-path-provisioner -n local-path-storage --timeout=120s
# Mark local-path as the cluster default StorageClass
kubectl annotate storageclass local-path \
    storageclass.kubernetes.io/is-default-class=true --overwrite
```

---

## Phase 1b — postgres-operator

Installs the Zalando PostgreSQL Operator. Must be up before Phase 5 creates the `nico-pg-cluster` resource — the `postgresql.acid.zalan.do` CRD must be registered first.

```bash
helmfile sync -l name=postgres-operator
```

---

## Phase 1c — MetalLB

Installs MetalLB 0.14.5 with the FRR BGP speaker, then applies your site-specific IP pool and BGP configuration.

```bash
helmfile sync -l name=metallb
kubectl wait --for=condition=Available deployment/metallb-controller \
    -n metallb-system --timeout=120s
kubectl apply -f values/metallb-config.yaml
```

Expected result: MetalLB controller and speaker pods running in `metallb-system`. BGPPeer sessions established with your TOR switches.

---

## Phase 2 — cert-manager + Vault TLS bootstrap

Three sub-steps — all must complete before Phase 3 (Vault).

### 2a — cert-manager

```bash
helmfile sync -l name=cert-manager
```

### 2b — Vault TLS bootstrap

Vault requires TLS to start — but the Vault-backed issuer can't exist before Vault is running. This step breaks the chicken-and-egg problem by using `site-issuer` (backed by `site-root` CA) to issue Vault's own TLS certs before Vault starts.

```bash
kubectl create namespace vault --dry-run=client -o yaml | kubectl apply -f -
# Run from the helm-prereqs/ directory (the chart root)
helm template nico-prereqs . \
    --show-only templates/site-root-certificate.yaml \
    --show-only templates/vault-tls-certs.yaml \
    | kubectl apply --server-side --field-manager=helm -f -
# Wait for all three certs to be issued
kubectl wait --for=condition=Ready certificate/site-root -n cert-manager --timeout=120s
kubectl wait --for=condition=Ready certificate/nicoca-vault-client -n vault --timeout=120s
kubectl wait --for=condition=Ready certificate/vault-raft-tls -n vault --timeout=120s
```

---

## Phase 3 — Vault

Installs HashiCorp Vault 0.25.0 in 3-replica HA Raft mode. TLS secrets exist in the `vault` namespace by this point so pods start immediately.

```bash
helmfile sync -l name=vault
```

---

## Phase 4 — Initialize and unseal Vault

```bash
./unseal_vault.sh
./bootstrap_ssh_host_key.sh
```

`unseal_vault.sh` handles both first-run init and re-unseal on subsequent runs:
- First run: `vault operator init -key-shares=5 -key-threshold=3`, stores init JSON as `vault-cluster-keys` secret, unseals all three pods
- Creates the `nico-system` namespace with Helm ownership labels
- Copies root token to `nico-vault-token` in `nico-system` for the `vault-pki-config` Job

`bootstrap_ssh_host_key.sh` pre-creates the `ssh-host-key` Secret in OpenSSH PEM format (idempotent — skips if the secret already exists).

To verify Vault is unsealed:

```bash
kubectl exec -n vault vault-0 -c vault -- vault status
```

---

## Phase 5 — external-secrets + nico-prereqs

```bash
helmfile sync -l name=external-secrets
helmfile sync -l name=nico-prereqs
```

After `nico-prereqs` installs, wait for the PostgreSQL cluster to provision and for ESO to sync credentials:

```bash
# Wait for the Patroni cluster to reach Running state (can take 3-5 minutes)
kubectl wait --for=jsonpath='{.status.PostgresClusterStatus}'=Running \
    postgresql/nico-pg-cluster -n postgres --timeout=600s

# Verify ESO synced the DB credentials into nico-system
kubectl get secret nico-system.nico.nico-pg-cluster.credentials -n nico-system
```

---

## Phase 6 — NCX Core

Deploys the main NCX Core application chart. Run from the **repo root** (`ncx-infra-controller-core/`), not from `helm-prereqs/`.

```bash
cd ..   # repo root (ncx-infra-controller-core/)
helm upgrade --install nico ./helm \
    --namespace nico-system \
    -f helm-prereqs/values/ncx-core.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}/nvmetal-nico" \
    --set global.image.tag="${NCX_CORE_IMAGE_TAG}" \
    --timeout 600s --wait
```

Verify LoadBalancer IPs were assigned from your MetalLB pool:

```bash
kubectl get svc -n nico-system | grep LoadBalancer
```

---

## Phase 7 — NCX REST (nico-rest)

All sub-steps run from the NCX REST repo directory (`$NCX_REPO`).

### 7a — CA signing secret

Generates the `ca-signing-secret` used by the `nico-rest-ca-issuer` ClusterIssuer for Temporal mTLS. Idempotent — skips if the secret already exists.

```bash
(cd "${NCX_REPO}" && bash scripts/gen-site-ca.sh)
```

### 7b — nico-rest-ca-issuer

```bash
(cd "${NCX_REPO}" && kubectl apply -k deploy/kustomize/base/cert-manager-io)
```

### 7c — NCX REST postgres

```bash
(cd "${NCX_REPO}" && kubectl apply -k deploy/kustomize/base/postgres)
kubectl rollout status statefulset/postgres -n postgres --timeout=300s
```

### 7d — Keycloak

```bash
(cd "${NCX_REPO}" && kubectl apply -k deploy/kustomize/base/keycloak -n nico-rest)
kubectl rollout status deployment/keycloak -n nico-rest --timeout=300s
```

### 7e — Temporal TLS bootstrap

```bash
(cd "${NCX_REPO}" && kubectl apply -f deploy/kustomize/base/temporal-helm/namespace.yaml)
(cd "${NCX_REPO}" && kubectl apply -f deploy/kustomize/base/temporal-helm/db-creds.yaml)
(cd "${NCX_REPO}" && kubectl apply -f deploy/kustomize/base/temporal-helm/certificates.yaml)
# Wait for the three mTLS certs to be issued by nico-rest-ca-issuer
kubectl wait --for=condition=Ready certificate/server-interservice-cert -n temporal --timeout=120s
kubectl wait --for=condition=Ready certificate/server-cloud-cert -n temporal --timeout=120s
kubectl wait --for=condition=Ready certificate/server-site-cert -n temporal --timeout=120s
```

### 7f — Temporal

```bash
helm upgrade --install temporal "${NCX_REPO}/temporal-helm/temporal" \
    --namespace temporal \
    -f "${NCX_REPO}/temporal-helm/temporal/values-kind.yaml" \
    --timeout 600s --wait

# Create the Temporal namespaces for NCX REST workers
_TEMPORAL_ADDR="temporal-frontend.temporal:7233"
_TEMPORAL_TLS="--tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt \
    --tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key \
    --tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt \
    --tls-server-name interservice.server.temporal.local"
kubectl exec -n temporal deploy/temporal-admintools -- \
    sh -c "temporal operator namespace create -n cloud --address ${_TEMPORAL_ADDR} ${_TEMPORAL_TLS}" 2>/dev/null || true
kubectl exec -n temporal deploy/temporal-admintools -- \
    sh -c "temporal operator namespace create -n site --address ${_TEMPORAL_ADDR} ${_TEMPORAL_TLS}" 2>/dev/null || true
```

### 7g — NCX REST helm chart

```bash
# Build the image pull secret dockerconfigjson
_ncx_docker_cfg="$(printf '{"auths":{"nvcr.io":{"username":"$oauthtoken","password":"%s"}}}' \
    "${REGISTRY_PULL_SECRET}" | base64 | tr -d '\n')"

helm upgrade --install nico-rest "${NCX_REPO}/helm/charts/nico-rest" \
    --namespace nico-rest \
    -f values/ncx-rest.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}" \
    --set global.image.tag="${NCX_REST_IMAGE_TAG}" \
    --set "nico-rest-common.secrets.imagePullSecret.dockerconfigjson=${_ncx_docker_cfg}" \
    --timeout 600s --wait
```

### 7h — NCX REST site-agent

The deployment order is critical — do not skip steps.

```bash
NCX_SITE_UUID="${NCX_SITE_UUID:-a1b2c3d4-e5f6-4000-8000-000000000001}"
NCX_SITE_AGENT_CHART="${NCX_REPO}/helm/charts/nico-rest-site-agent"

# Step 1 - pre-apply the gRPC client cert so it exists before the pod starts
helm template nico-rest-site-agent "${NCX_SITE_AGENT_CHART}" \
    --namespace nico-rest \
    -f values/ncx-site-agent.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}" \
    --set global.image.tag="${NCX_REST_IMAGE_TAG}" \
    --show-only templates/certificate.yaml | kubectl apply -f -
kubectl annotate certificate/core-grpc-client-site-agent-certs -n nico-rest \
    "meta.helm.sh/release-name=nico-rest-site-agent" \
    "meta.helm.sh/release-namespace=nico-rest" --overwrite
kubectl label certificate/core-grpc-client-site-agent-certs -n nico-rest \
    "app.kubernetes.io/managed-by=Helm" --overwrite
kubectl wait --for=condition=Ready certificate/core-grpc-client-site-agent-certs \
    -n nico-rest --timeout=120s

# Step 2 - create per-site Temporal namespace (site-agent panics without it)
_TEMPORAL_ADDR="temporal-frontend.temporal:7233"
_TEMPORAL_TLS="--tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt \
    --tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key \
    --tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt \
    --tls-server-name interservice.server.temporal.local"
kubectl exec -n temporal deploy/temporal-admintools -- \
    sh -c "temporal operator namespace create -n '${NCX_SITE_UUID}' --address ${_TEMPORAL_ADDR} ${_TEMPORAL_TLS}" 2>/dev/null || true

# Step 3 - install site-agent (pre-install hook registers site and creates site-registration secret)
helm upgrade --install nico-rest-site-agent "${NCX_SITE_AGENT_CHART}" \
    --namespace nico-rest \
    -f values/ncx-site-agent.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}" \
    --set global.image.tag="${NCX_REST_IMAGE_TAG}" \
    --set "envConfig.CLUSTER_ID=${NCX_SITE_UUID}" \
    --set "envConfig.TEMPORAL_SUBSCRIBE_NAMESPACE=${NCX_SITE_UUID}" \
    --set "envConfig.TEMPORAL_SUBSCRIBE_QUEUE=site" \
    --timeout 300s --wait

# Step 4 - verify gRPC connection to nico-api
kubectl logs -n nico-rest -l app.kubernetes.io/name=nico-rest-site-agent --prefix \
    | grep "NicoClient:"
```

---

## PKI architecture

The PKI has three layers, built bottom-up:

```
selfsigned-bootstrap ClusterIssuer
  └── site-root CA Certificate  (10-year self-signed CA, Secret "site-root" in cert-manager ns)
        └── site-issuer ClusterIssuer  (issues Vault's own TLS certs - no Vault dependency)
              ├── nicoca-vault-client  (Vault port 8200 listener TLS, Secret in vault ns)
              └── vault-raft-tls        (Vault Raft port 8201 peer TLS, Secret in vault ns)

vault (running, unsealed)
  └── vault-pki-config Job  (imports site-root CA into Vault PKI engine "nicoca")
        └── vault-nico-issuer ClusterIssuer  (issues all workload SPIFFE certs via Vault PKI)
```

NCX REST has its own parallel PKI chain for internal services:

```
nico-rest-ca-issuer ClusterIssuer  (backed by ca-signing-secret in nico-rest ns)
  └── Temporal mTLS certificates      (server-interservice-cert, server-cloud-cert, server-site-cert)

vault-nico-issuer ClusterIssuer      (same Vault PKI CA as NCX Core)
  └── site-agent gRPC client cert     (core-grpc-client-site-agent-certs in nico-rest ns)
        SPIFFE URI: spiffe://nico.local/nico-system/sa/elektra-site-agent
```

The site-agent uses the Vault PKI CA for both directions of mTLS with nico-api:
- Site-agent presents its client cert (Vault-signed) — nico-api trusts it via the same CA.
- Site-agent verifies nico-api's server cert using `ca.crt` from the issued secret (Vault PKI CA).

### Layer 1 — Bootstrap (no external dependencies)

`selfsigned-bootstrap` is a cert-manager `selfSigned` ClusterIssuer with no dependencies. It issues `site-root`: a 10-year CA certificate stored as Secret `site-root` in the `cert-manager` namespace. This is the trust anchor for the entire cluster.

### Layer 2 — site-issuer (Vault TLS bootstrap)

`site-issuer` is a `ca` ClusterIssuer backed by `site-root`. It can issue certificates without Vault being up.

**This solves the Vault TLS chicken-and-egg problem.** Vault requires TLS to start — but `vault-nico-issuer` (the Vault-backed issuer) can't exist before Vault is running. `site-issuer` breaks the cycle by issuing Vault's own TLS secrets before Vault starts:

| Secret | Namespace | Purpose |
|--------|-----------|---------|
| `nicoca-vault-client` | `vault` | Port 8200 listener cert (mounted at `/vault/userconfig/nicoca-vault/`) |
| `vault-raft-tls` | `vault` | Raft port 8201 peer cert (mounted at `/vault/userconfig/vault-raft-tls/`) |

These secrets must exist **before** `helmfile sync -l name=vault` — setup.sh creates them explicitly in Phase 2 using `helm template | kubectl apply`.

### Layer 3 — vault-nico-issuer (workload PKI)

Once Vault is running and unsealed, the `vault-pki-config` Job (Helm post-install hook) configures Vault as a PKI backend:

1. Enables the `nicoca` PKI secrets engine, tunes it to a 10-year max TTL.
2. Imports `site-root` (cert + key) into Vault PKI — Vault becomes an intermediate CA under the same trust root.
3. Creates PKI role `nico-cluster` — allows any name, allows SPIFFE URI SANs, 720h max TTL, EC P-256.
4. Enables Kubernetes auth and writes two policies: `cert-manager-nico-policy` (sign via PKI) and `nico-vault-policy` (read KV secrets).
5. Enables KV v2 at `secrets/` and AppRole auth for the `nico` role.

`vault-nico-issuer` is then created as a cert-manager ClusterIssuer authenticating to Vault via Kubernetes auth. All NCX Core workload SPIFFE certificates and the site-agent's gRPC client certificate are issued through this issuer.

### nico-roots — CA distribution

The `nico-roots` Secret (containing `site-root`'s `ca.crt`) must be present in every namespace where NCX workloads run so pods can verify each other's SPIFFE certificates.

```
site-root Secret (cert-manager ns)
  → ClusterSecretStore "cert-manager-ns-secretstore" (Kubernetes provider)
    → ClusterExternalSecret "nico-roots-eso"
      → ExternalSecret in every namespace labeled nico.nvidia.com/managed=true
        → Secret "nico-roots" (ca.crt)
```

`creationPolicy: Orphan` prevents Kubernetes GC from cascading a delete to `nico-roots` if the ExternalSecret is recreated on helm upgrade.

---

## PostgreSQL architecture

PostgreSQL is deployed as a production-grade 3-node HA cluster managed by the **Zalando PostgreSQL Operator** (`acid.zalan.do`). NCX REST also deploys its own simpler postgres StatefulSet in the same `postgres` namespace for temporal, keycloak, and NCX REST databases.

```
postgres-operator (postgres ns)
  └── nico-pg-cluster postgresql CRD (postgres ns)        ← NCX Core
        ├── nico-pg-cluster-0  (Patroni leader)
        ├── nico-pg-cluster-1  (Patroni replica)
        └── nico-pg-cluster-2  (Patroni replica)
              each pod: postgres + postgres-exporter sidecar

postgres StatefulSet (postgres ns, service: postgres)      ← NCX REST
  └── Databases: nico, temporal, temporal_visibility, keycloak, elektratest
```

### Credential flow (NCX Core)

The operator automatically creates a per-user credential Secret in the `postgres` namespace:
```
nico-system.nico.nico-pg-cluster.credentials.postgresql.acid.zalan.do
  username: nico-system.nico
  password: <operator-generated>
```

ESO's `nico-db-eso` ClusterExternalSecret mirrors this into `nico-system` as:
```
nico-system.nico.nico-pg-cluster.credentials
  username: nico-system.nico
  password: <same>
```

### nico-pg-cluster-env ConfigMap

The operator injects the `nico-pg-cluster-env` ConfigMap (in the `postgres` namespace) into every postgres pod as environment variables. Currently provides:

```
TMP_SITE = <Values.siteName>
```

The ConfigMap is rendered by the `nico-prereqs` chart (from `Values.siteName`) so it flows in at install time and can be overridden per-site with `--set siteName=<name>`.

### ssh-host-key format

`ssh-console-rs` requires the SSH host key in **OpenSSH PEM format** (`-----BEGIN OPENSSH PRIVATE KEY-----`). Helm's `genPrivateKey "ed25519"` produces PKCS8 format which the binary rejects at startup. `bootstrap_ssh_host_key.sh` pre-creates the secret using `ssh-keygen` before `helmfile sync -l name=nico-prereqs` runs. The `lookup` in `templates/_helpers.tpl` detects the existing secret and reuses it, so Helm never overwrites it.

---

## Secrets reference

All secrets created by setup. The Vault unseal keys (`vault-cluster-keys`) are the most sensitive — back them up to a secure location after first install.

| Secret | Namespace | Created by | Purpose |
|--------|-----------|------------|---------|
| `site-root` | `cert-manager` | cert-manager (selfsigned-bootstrap) | Self-signed root CA cert + key. Trust anchor for all PKI. |
| `nicoca-vault-client` | `vault` | cert-manager (site-issuer) | Vault port 8200 TLS listener cert |
| `vault-raft-tls` | `vault` | cert-manager (site-issuer) | Vault Raft port 8201 TLS peer cert |
| `vault-cluster-keys` | `vault` | `unseal_vault.sh` | Full Vault init JSON (5 unseal keys + root token). **Back this up.** |
| `vaultunsealkeys` | `vault` | `unseal_vault.sh` | Individual unseal keys (0-4) for automated re-unseal |
| `vaultroottoken` | `vault` | `unseal_vault.sh` | Vault root token. Limit use after setup. |
| `nico-system.nico.nico-pg-cluster.credentials.postgresql.acid.zalan.do` | `postgres` | Zalando operator | Operator-generated DB credentials (source of truth) |
| `nico-vault-token` | `nico-system` | `unseal_vault.sh` | Root token copy for `vault-pki-config` Job |
| `nico-vault-approle-tokens` | `nico-system` | `vault-pki-config` Job | AppRole role-id and secret-id for NCX Core services |
| `nvcr-nico-dev` | `nico-system` | `nico-prereqs` chart | Image pull secret for NCX Core registry |
| `ssh-host-key` | `nico-system` | `bootstrap_ssh_host_key.sh` | ed25519 host key for `nico-ssh-console-rs` in OpenSSH format |
| `nico-roots` | `nico-system` | ESO (nico-roots-eso) | Site-root CA cert (`ca.crt`) for SPIFFE cert verification |
| `nico-system.nico.nico-pg-cluster.credentials` | `nico-system` | ESO (nico-db-eso) | DB credentials mirrored from `postgres` ns for `nico-api` |
| `ca-signing-secret` | `nico-rest` | `gen-site-ca.sh` | NCX REST internal CA for Temporal mTLS |
| `core-grpc-client-site-agent-certs` | `nico-rest` | cert-manager (vault-nico-issuer) | Site-agent mTLS client cert for nico-api gRPC |

### ClusterIssuers

| Name | Backed by | Issues |
|------|-----------|--------|
| `selfsigned-bootstrap` | cert-manager selfSigned | `site-root` CA only |
| `site-issuer` | `site-root` CA Secret | Vault TLS certs (`nicoca-vault-client`, `vault-raft-tls`) |
| `vault-nico-issuer` | Vault PKI engine (`nicoca/sign/nico-cluster`) | All NCX Core SPIFFE certs + site-agent gRPC client cert |
| `nico-rest-ca-issuer` | `ca-signing-secret` | Temporal mTLS certs |

### ClusterSecretStores

| Name | Reads from | Used for |
|------|------------|---------|
| `cert-manager-ns-secretstore` | `cert-manager` namespace | Syncing `site-root` CA to `nico-roots` |
| `postgres-ns-secretstore` | `postgres` namespace | Syncing operator DB credentials to `nico-system` |

## Troubleshooting

### nico-api CrashLoopBackOff — siteConfig parse error

If `nico-api` crashes immediately after Phase 6 with a config parse error, the most common cause is empty required fields in the `nicoApiSiteConfig` TOML block. Fields that must be non-empty:

- `[networks.admin]` — `prefix` and `gateway` (empty string crashes the binary)
- `[pools.lo-ip]`, `[pools.vlan-id]`, `[pools.vni]` — `ranges` must have at least one entry

Check the pod logs for the specific field:
```bash
kubectl logs -n nico-system -l app.kubernetes.io/name=nico-api --previous
```

Fix the value in `values/ncx-core.yaml` and re-run:
```bash
helm upgrade nico ./helm --namespace nico-system -f helm-prereqs/values/ncx-core.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}/nvmetal-nico" \
    --set global.image.tag="${NCX_CORE_IMAGE_TAG}"
```

### DNS resolution failing in pods

On **Kubespray clusters**, setup.sh deploys the NodeLocal DNSCache DaemonSet automatically. If it is not ready:
```bash
kubectl get daemonset nodelocaldns -n kube-system
kubectl apply -f operators/nodelocaldns-daemonset.yaml
kubectl rollout status daemonset/nodelocaldns -n kube-system
```

On **kubeadm clusters**, NodeLocal DNSCache is not used — setup.sh checks CoreDNS readyReplicas instead:
```bash
kubectl get pods -n kube-system -l k8s-app=kube-dns
kubectl rollout restart deployment/coredns -n kube-system
```

### Vault TLS bootstrap certificates not Ready

```bash
kubectl get certificate -n cert-manager
kubectl get certificate -n vault
kubectl describe certificate nicoca-vault-client -n vault
```

Common cause: cert-manager webhook not ready yet. Wait 30 seconds and re-run Phase 2.

### Vault pods stuck in Init or CrashLoop

```bash
kubectl get secret nicoca-vault-client vault-raft-tls -n vault
kubectl logs vault-0 -n vault -c vault
```

### vault-pki-config Job failing

```bash
kubectl logs -n nico-system job/vault-pki-config -c wait-vault
kubectl logs -n nico-system job/vault-pki-config -c configure
```

Common causes:
- Vault still sealed — `kubectl exec -n vault vault-0 -c vault -- vault status`
- `nico-vault-token` missing — re-run `./unseal_vault.sh`
- `site-root` Secret not readable by the Job's service account

### nico-pg-cluster not reaching Running state

```bash
kubectl get postgresql nico-pg-cluster -n postgres
kubectl describe postgresql nico-pg-cluster -n postgres
kubectl get pods -n postgres
kubectl logs -n postgres nico-pg-cluster-0 -c postgres
```

Common causes:
- `local-path-persistent` StorageClass missing — re-run Phase 1
- `nico-pg-cluster-env` ConfigMap missing in `postgres` namespace — re-run Phase 5
- Insufficient node resources — tune `postgresql.resources` in `values.yaml`

### DB credentials not appearing in nico-system

```bash
kubectl get clustersecretstore postgres-ns-secretstore
kubectl get clusterexternalsecret nico-db-eso
kubectl describe externalsecret -n nico-system
```

The source secret (`nico-system.nico.nico-pg-cluster.credentials.postgresql.acid.zalan.do`) is created by the operator only after the cluster reaches `Running` state. If the ClusterSecretStore shows `Invalid`, check that the `eso-postgres-ns` ServiceAccount token exists in the `postgres` namespace:
```bash
kubectl get secret eso-postgres-ns-token -n postgres
```

### nico-roots Secret not appearing

```bash
kubectl get clustersecretstore cert-manager-ns-secretstore
kubectl get clusterexternalsecret nico-roots-eso
kubectl get namespace nico-system --show-labels
# Should include: nico.nvidia.com/managed=true
```

If the label is missing:
```bash
kubectl label namespace nico-system nico.nvidia.com/managed=true
```

### Site-agent gRPC connection to nico-api failing (nil NicoClient)

The site-agent connects to nico-api at startup with a 5-second deadline. If the connection fails, the `NicoClient` stays nil permanently and all inventory activities panic with a nil-pointer dereference. setup.sh detects this and restarts the StatefulSet automatically, but you can also diagnose manually:

```bash
# Check which pods connected successfully
kubectl logs -n nico-rest -l app.kubernetes.io/name=nico-rest-site-agent --prefix \
    | grep -E "NicoClient: (successfully connected|failed to get version)"

# Check mTLS cert was issued
kubectl get certificate core-grpc-client-site-agent-certs -n nico-rest

# Check the cert was projected into the pod
kubectl exec -n nico-rest nico-rest-site-agent-0 -- ls /etc/nico-certs/

# Check DNS resolution of nico-api from the pod
kubectl exec -n nico-rest nico-rest-site-agent-0 -- \
    nslookup nico-api.nico-system.svc.cluster.local
```

Common causes and fixes:

| Symptom | Cause | Fix |
|---------|-------|-----|
| `DeadlineExceeded` in pod logs | DNS cold cache on the node at startup | `kubectl rollout restart statefulset/nico-rest-site-agent -n nico-rest` |
| `certificate signed by unknown authority` | Site-agent cert issued by wrong CA | Check `values/ncx-site-agent.yaml` — `global.certificate.issuerRef.name` must be `vault-nico-issuer` |
| `Unauthenticated` from nico-api | SPIFFE URI does not match `InternalRBACRules` | Check `values/ncx-site-agent.yaml` — `certificate.uris` must be `spiffe://nico.local/nico-system/sa/elektra-site-agent` |
| `transport: error while dialing` | Wrong `NICO_SEC_OPT` | Check `envConfig.NICO_SEC_OPT: "2"` in `ncx-site-agent.yaml` (2 = MutualTLS) |
| cert secret missing at pod start | Race: StatefulSet started before cert was issued | Re-run Phase 7h — pre-apply Certificate step ensures cert exists first |

### Temporal namespace not found (site-agent startup panic)

If the site-agent panics on startup with a nil pointer in `RegisterCron`:
```bash
kubectl exec -n temporal deploy/temporal-admintools -- \
    sh -c "temporal operator namespace list --address temporal-frontend.temporal:7233 \
        --tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt \
        --tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key \
        --tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt \
        --tls-server-name interservice.server.temporal.local"
```

If the namespace for the site UUID is missing, create it manually:
```bash
kubectl exec -n temporal deploy/temporal-admintools -- \
    sh -c "temporal operator namespace create -n '<site-uuid>' \
        --address temporal-frontend.temporal:7233 ..."
```
Then restart the site-agent.

### MetalLB LoadBalancer services stuck in `<pending>`

If NCX Core services never get an external IP:

```bash
kubectl get pods -n metallb-system
kubectl get ipaddresspool -n metallb-system
kubectl get bgppeer -n metallb-system
kubectl describe bgppeer -n metallb-system
kubectl logs -n metallb-system -l app=metallb,component=speaker --tail=50
kubectl get svc -n nico-system -l app.kubernetes.io/name=nico-api
```

Common causes:

| Symptom | Cause | Fix |
|---------|-------|-----|
| `IPAddressPool` not found | `values/metallb-config.yaml` was not applied | Re-run `kubectl apply -f values/metallb-config.yaml` |
| BGP session `Idle` / never establishes | Wrong `peerAddress` or ASN, or firewall blocking TCP 179 | Verify with your network team |
| BGP session up but no IP assigned | IP pool addresses exhausted or CIDR is wrong | Check `kubectl describe ipaddresspool -n metallb-system` |
| All services pending after MetalLB looks healthy | FRR speaker not running | Set `speaker.frr.enabled: true` in `operators/values/metallb.yaml` and re-run Phase 1c |

### Checking overall health after setup

```bash
kubectl get clusterissuer
kubectl get clustersecretstore
kubectl get pods -n metallb-system
kubectl get ipaddresspool,bgppeer -n metallb-system
kubectl get pods -n postgres
kubectl get pods -n nico-system
kubectl get jobs -n nico-system
kubectl get secret nico-roots -n nico-system
kubectl get secret nico-system.nico.nico-pg-cluster.credentials -n nico-system
kubectl get pods -n nico-rest
kubectl get pods -n temporal
kubectl get certificate core-grpc-client-site-agent-certs -n nico-rest
```
