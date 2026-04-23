# Setup phases - step by step

`setup.sh` runs all phases sequentially and handles ordering, waiting, and error recovery automatically. This document breaks down every phase with the exact commands being run - useful if you need to re-run a single phase, debug a failure, or understand what the script does before running it.

**Prerequisites:** complete all steps in [Section 0 of README.md](README.md#0-before-you-run-setupsh--site-configuration-checklist) before running any phase manually.

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

## Phase 0 - DNS check

Detects cluster type and verifies DNS is ready before any workloads are deployed.

- **Kubespray clusters** - checks if the `nodelocaldns` DaemonSet is ready; deploys `operators/nodelocaldns-daemonset.yaml` if missing and waits for rollout
- **kubeadm / other** - checks CoreDNS readyReplicas >= 1; warns but does not fail if not ready

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

## Phase 1 - local-path-provisioner

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

## Phase 1b - postgres-operator

Installs the Zalando PostgreSQL Operator. Must be up before Phase 5 creates the `forge-pg-cluster` resource - the `postgresql.acid.zalan.do` CRD must be registered first.

```bash
helmfile sync -l name=postgres-operator
```

---

## Phase 1c - MetalLB

Installs MetalLB 0.14.5 with the FRR BGP speaker, then applies your site-specific IP pool and BGP configuration.

```bash
helmfile sync -l name=metallb
kubectl wait --for=condition=Available deployment/metallb-controller \
    -n metallb-system --timeout=120s
kubectl apply -f values/metallb-config.yaml
```

Expected result: MetalLB controller and speaker pods running in `metallb-system`. BGPPeer sessions established with your TOR switches.

---

## Phase 2 - cert-manager + Vault TLS bootstrap

Three sub-steps - all must complete before Phase 3 (Vault).

### 2a - cert-manager

```bash
helmfile sync -l name=cert-manager
```

### 2b - Vault TLS bootstrap

Vault requires TLS to start - but the Vault-backed issuer can't exist before Vault is running. This step breaks the chicken-and-egg problem by using `site-issuer` (backed by `site-root` CA) to issue Vault's own TLS certs before Vault starts.

```bash
kubectl create namespace vault --dry-run=client -o yaml | kubectl apply -f -
# Run from the helm-prereqs/ directory (the chart root)
helm template carbide-prereqs . \
    --show-only templates/site-root-certificate.yaml \
    --show-only templates/vault-tls-certs.yaml \
    | kubectl apply --server-side --field-manager=helm -f -
# Wait for all three certs to be issued
kubectl wait --for=condition=Ready certificate/site-root -n cert-manager --timeout=120s
kubectl wait --for=condition=Ready certificate/forgeca-vault-client -n vault --timeout=120s
kubectl wait --for=condition=Ready certificate/vault-raft-tls -n vault --timeout=120s
```

---

## Phase 3 - Vault

Installs HashiCorp Vault 0.25.0 in 3-replica HA Raft mode. TLS secrets exist in the `vault` namespace by this point so pods start immediately.

```bash
helmfile sync -l name=vault
```

---

## Phase 4 - Initialize and unseal Vault

```bash
./unseal_vault.sh
./bootstrap_ssh_host_key.sh
```

`unseal_vault.sh` handles both first-run init and re-unseal on subsequent runs:
- First run: `vault operator init -key-shares=5 -key-threshold=3`, stores init JSON as `vault-cluster-keys` secret, unseals all three pods
- Creates the `forge-system` namespace with Helm ownership labels
- Copies root token to `carbide-vault-token` in `forge-system` for the `vault-pki-config` Job

`bootstrap_ssh_host_key.sh` pre-creates the `ssh-host-key` Secret in OpenSSH PEM format (idempotent - skips if the secret already exists).

To verify Vault is unsealed:

```bash
kubectl exec -n vault vault-0 -c vault -- vault status
```

---

## Phase 5 - external-secrets + carbide-prereqs

```bash
helmfile sync -l name=external-secrets
helmfile sync -l name=carbide-prereqs
```

After `carbide-prereqs` installs, wait for the PostgreSQL cluster to provision and for ESO to sync credentials:

```bash
# Wait for the Patroni cluster to reach Running state (can take 3-5 minutes)
kubectl wait --for=jsonpath='{.status.PostgresClusterStatus}'=Running \
    postgresql/forge-pg-cluster -n postgres --timeout=600s

# Verify ESO synced the DB credentials into forge-system
kubectl get secret forge-system.carbide.forge-pg-cluster.credentials -n forge-system
```

---

## Phase 6 - NCX Core

Deploys the main NCX Core application chart. Run from the **repo root** (`ncx-infra-controller-core/`), not from `helm-prereqs/`.

```bash
cd ..   # repo root (ncx-infra-controller-core/)
helm upgrade --install carbide ./helm \
    --namespace forge-system \
    -f helm-prereqs/values/ncx-core.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}/nvmetal-carbide" \
    --set global.image.tag="${NCX_CORE_IMAGE_TAG}" \
    --timeout 600s --wait
```

Verify LoadBalancer IPs were assigned from your MetalLB pool:

```bash
kubectl get svc -n forge-system | grep LoadBalancer
```

---

## Phase 7 - NCX REST (carbide-rest)

All sub-steps run from the NCX REST repo directory (`$NCX_REPO`).

### 7a - CA signing secret

Generates the `ca-signing-secret` used by the `carbide-rest-ca-issuer` ClusterIssuer for Temporal mTLS. Idempotent - skips if the secret already exists.

```bash
(cd "${NCX_REPO}" && bash scripts/gen-site-ca.sh)
```

### 7b - carbide-rest-ca-issuer

```bash
(cd "${NCX_REPO}" && kubectl apply -k deploy/kustomize/base/cert-manager-io)
```

### 7c - NCX REST postgres

```bash
(cd "${NCX_REPO}" && kubectl apply -k deploy/kustomize/base/postgres)
kubectl rollout status statefulset/postgres -n postgres --timeout=300s
```

### 7d - Keycloak

```bash
(cd "${NCX_REPO}" && kubectl apply -k deploy/kustomize/base/keycloak -n carbide-rest)
kubectl rollout status deployment/keycloak -n carbide-rest --timeout=300s
```

### 7e - Temporal TLS bootstrap

```bash
(cd "${NCX_REPO}" && kubectl apply -f deploy/kustomize/base/temporal-helm/namespace.yaml)
(cd "${NCX_REPO}" && kubectl apply -f deploy/kustomize/base/temporal-helm/db-creds.yaml)
# Wait for the three mTLS certs to be issued by carbide-rest-ca-issuer
kubectl wait --for=condition=Ready certificate/server-interservice-cert -n temporal --timeout=120s
kubectl wait --for=condition=Ready certificate/server-cloud-cert -n temporal --timeout=120s
kubectl wait --for=condition=Ready certificate/server-site-cert -n temporal --timeout=120s
```

### 7f - Temporal

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

### 7g - NCX REST helm chart

```bash
# Build the image pull secret dockerconfigjson
_ncx_docker_cfg="$(printf '{"auths":{"nvcr.io":{"username":"$oauthtoken","password":"%s"}}}' \
    "${REGISTRY_PULL_SECRET}" | base64 | tr -d '\n')"

helm upgrade --install carbide-rest "${NCX_REPO}/helm/charts/carbide-rest" \
    --namespace carbide-rest \
    -f values/ncx-rest.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}" \
    --set global.image.tag="${NCX_REST_IMAGE_TAG}" \
    --set "carbide-rest-common.secrets.imagePullSecret.dockerconfigjson=${_ncx_docker_cfg}" \
    --timeout 600s --wait
```

### 7h - NCX REST site-agent

The deployment order is critical - do not skip steps.

```bash
NCX_SITE_UUID="${NCX_SITE_UUID:-a1b2c3d4-e5f6-4000-8000-000000000001}"
NCX_SITE_AGENT_CHART="${NCX_REPO}/helm/charts/carbide-rest-site-agent"

# Step 1 - pre-apply the gRPC client cert so it exists before the pod starts
helm template carbide-rest-site-agent "${NCX_SITE_AGENT_CHART}" \
    --namespace carbide-rest \
    -f values/ncx-site-agent.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}" \
    --set global.image.tag="${NCX_REST_IMAGE_TAG}" \
    --show-only templates/certificate.yaml | kubectl apply -f -
kubectl annotate certificate/core-grpc-client-site-agent-certs -n carbide-rest \
    "meta.helm.sh/release-name=carbide-rest-site-agent" \
    "meta.helm.sh/release-namespace=carbide-rest" --overwrite
kubectl label certificate/core-grpc-client-site-agent-certs -n carbide-rest \
    "app.kubernetes.io/managed-by=Helm" --overwrite
kubectl wait --for=condition=Ready certificate/core-grpc-client-site-agent-certs \
    -n carbide-rest --timeout=120s

# Step 2 - create per-site Temporal namespace (site-agent panics without it)
_TEMPORAL_ADDR="temporal-frontend.temporal:7233"
_TEMPORAL_TLS="--tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt \
    --tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key \
    --tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt \
    --tls-server-name interservice.server.temporal.local"
kubectl exec -n temporal deploy/temporal-admintools -- \
    sh -c "temporal operator namespace create -n '${NCX_SITE_UUID}' --address ${_TEMPORAL_ADDR} ${_TEMPORAL_TLS}" 2>/dev/null || true

# Step 3 - install site-agent (pre-install hook registers site and creates site-registration secret)
helm upgrade --install carbide-rest-site-agent "${NCX_SITE_AGENT_CHART}" \
    --namespace carbide-rest \
    -f values/ncx-site-agent.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}" \
    --set global.image.tag="${NCX_REST_IMAGE_TAG}" \
    --set "envConfig.CLUSTER_ID=${NCX_SITE_UUID}" \
    --set "envConfig.TEMPORAL_SUBSCRIBE_NAMESPACE=${NCX_SITE_UUID}" \
    --set "envConfig.TEMPORAL_SUBSCRIBE_QUEUE=site" \
    --timeout 300s --wait

# Step 4 - verify gRPC connection to carbide-api
kubectl logs -n carbide-rest -l app.kubernetes.io/name=carbide-rest-site-agent --prefix \
    | grep "CarbideClient:"
```

---

## Secrets reference

All secrets created by setup. The Vault unseal keys (`vault-cluster-keys`) are the most sensitive - back them up to a secure location after first install.

| Secret | Namespace | Created by | Purpose |
|--------|-----------|------------|---------|
| `site-root` | `cert-manager` | cert-manager (selfsigned-bootstrap) | Self-signed root CA cert + key. Trust anchor for all PKI. |
| `forgeca-vault-client` | `vault` | cert-manager (site-issuer) | Vault port 8200 TLS listener cert |
| `vault-raft-tls` | `vault` | cert-manager (site-issuer) | Vault Raft port 8201 TLS peer cert |
| `vault-cluster-keys` | `vault` | `unseal_vault.sh` | Full Vault init JSON (5 unseal keys + root token). **Back this up.** |
| `vaultunsealkeys` | `vault` | `unseal_vault.sh` | Individual unseal keys (0-4) for automated re-unseal |
| `vaultroottoken` | `vault` | `unseal_vault.sh` | Vault root token. Limit use after setup. |
| `forge-system.carbide.forge-pg-cluster.credentials.postgresql.acid.zalan.do` | `postgres` | Zalando operator | Operator-generated DB credentials (source of truth) |
| `carbide-vault-token` | `forge-system` | `unseal_vault.sh` | Root token copy for `vault-pki-config` Job |
| `carbide-vault-approle-tokens` | `forge-system` | `vault-pki-config` Job | AppRole role-id and secret-id for NCX Core services |
| `nvcr-carbide-dev` | `forge-system` | `carbide-prereqs` chart | Image pull secret for NCX Core registry |
| `ssh-host-key` | `forge-system` | `bootstrap_ssh_host_key.sh` | ed25519 host key for `carbide-ssh-console-rs` in OpenSSH format |
| `forge-roots` | `forge-system` | ESO (forge-roots-eso) | Site-root CA cert (`ca.crt`) for SPIFFE cert verification |
| `forge-system.carbide.forge-pg-cluster.credentials` | `forge-system` | ESO (carbide-db-eso) | DB credentials mirrored from `postgres` ns for `carbide-api` |
| `ca-signing-secret` | `carbide-rest` | `gen-site-ca.sh` | NCX REST internal CA for Temporal mTLS |
| `core-grpc-client-site-agent-certs` | `carbide-rest` | cert-manager (vault-forge-issuer) | Site-agent mTLS client cert for carbide-api gRPC |

### ClusterIssuers

| Name | Backed by | Issues |
|------|-----------|--------|
| `selfsigned-bootstrap` | cert-manager selfSigned | `site-root` CA only |
| `site-issuer` | `site-root` CA Secret | Vault TLS certs (`forgeca-vault-client`, `vault-raft-tls`) |
| `vault-forge-issuer` | Vault PKI engine (`forgeca/sign/forge-cluster`) | All NCX Core SPIFFE certs + site-agent gRPC client cert |
| `carbide-rest-ca-issuer` | `ca-signing-secret` | Temporal mTLS certs |

### ClusterSecretStores

| Name | Reads from | Used for |
|------|------------|---------|
| `cert-manager-ns-secretstore` | `cert-manager` namespace | Syncing `site-root` CA to `forge-roots` |
| `postgres-ns-secretstore` | `postgres` namespace | Syncing operator DB credentials to `forge-system` |
