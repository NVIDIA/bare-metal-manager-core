# End-to-End Installation Guide

This guide ties together the build, deploy, and configuration steps needed to go from
a ready Kubernetes cluster to your first provisioned bare-metal host. It links to
existing documentation for each major step and fills the gaps between them.

The order of operations below follows the sequence validated by NVIDIA engineering
and SA teams during production deployments.

## Order of Operations

| Step | What | Where to find details |
|------|------|----------------------|
| 1 | [Build and push all container images](#1-build-and-push-containers) | [Building NICo Containers](building_nico_containers.md), [REST repo](https://github.com/NVIDIA/ncx-infra-controller-rest) |
| 2 | [Provision site controller OS and Kubernetes](#2-site-controller-and-kubernetes) | [Site Reference Architecture](site-reference-arch.md) |
| 3 | [Deploy foundation services](#3-foundation-services) | [Site Setup](site-setup.md), [helm/PREREQUISITES.md](../../helm/PREREQUISITES.md) |
| 4 | [Deploy site CA, credsmgr, and Temporal](#4-site-ca-credsmgr-and-temporal) | This guide, [REST repo](https://github.com/NVIDIA/ncx-infra-controller-rest) |
| 5 | [Deploy Carbide REST / cloud components](#5-deploy-carbide-rest-components) | This guide, [REST repo](https://github.com/NVIDIA/ncx-infra-controller-rest) |
| 6 | [Deploy Carbide core](#6-deploy-carbide-core) | [Helm README](../../helm/README.md), [deploy/README.md](../../deploy/README.md) |
| 7 | [Install admin-cli](#7-install-admin-cli) | This guide |
| 8 | [Deploy Elektra site agent](#8-deploy-elektra-site-agent) | This guide, [REST repo](https://github.com/NVIDIA/ncx-infra-controller-rest) |
| 9 | [Ingest managed hosts](#9-ingest-hosts) | [Ingesting Hosts](ingesting_machines.md) |
| 10 | [Verify end-to-end](#10-verification) | This guide |

---

## 1. Build and Push Containers

All container images must be built from source and pushed to a registry your cluster
can access. There are no pre-built public images available.

```{note}
If you encounter `nvcr.io/nvidian/...` image references in documentation or manifests,
those are NVIDIA-internal paths not accessible externally. Replace them with your own
registry paths after building from source.
```

### NICo Core

Follow the [Building NICo Containers](building_nico_containers.md) guide for build steps,
then [Tagging and Pushing Containers](pushing_containers.md) to push images to your
private registry. It covers
prerequisites, build steps for x86_64 and aarch64, tagging, pushing to a private
registry, and a summary table of all images produced.

### NICo REST

Clone [ncx-infra-controller-rest](https://github.com/NVIDIA/ncx-infra-controller-rest)
and build with:

```bash
REGISTRY=<your-registry.example.com/carbide>
TAG=<your-version-tag>

make docker-build IMAGE_REGISTRY=$REGISTRY IMAGE_TAG=$TAG

for image in carbide-rest-api carbide-rest-workflow carbide-rest-site-manager \
             carbide-rest-site-agent carbide-rest-db carbide-rest-cert-manager \
             carbide-rla carbide-psm carbide-nsm; do
    docker push "$REGISTRY/$image:$TAG"
done
```

See the [ncx-infra-controller-rest README](https://github.com/NVIDIA/ncx-infra-controller-rest#building-docker-images)
for the full list of images and build options.

---

## 2. Site Controller and Kubernetes

Customers are expected to provision their own site controller OS and Kubernetes cluster.

See the [Site Reference Architecture](site-reference-arch.md) for hardware requirements,
Kubernetes versions, networking best practices, and IP pool sizing.

In summary, you need:

* 3 or 5 site controller nodes running Ubuntu 24.04 LTS with Kubernetes v1.30.x
* CNI (Calico v3.28.1 validated), ingress controller (Contour), load balancer (MetalLB)
* OOB switch VLANs with DHCP relay pointing at the Carbide DHCP service VIP
* In-band ToR switches with BGP unnumbered on DPU-facing ports, EVPN enabled
* IP pools allocated per the reference architecture

---

## 3. Foundation Services

Deploy the following services before any Carbide components. The order within this
step matters.

**For baselines and versions**, see [Site Setup](site-setup.md).

**For the Secrets, ConfigMaps, and ClusterIssuer** that the Helm chart expects, see
[helm/PREREQUISITES.md](../../helm/PREREQUISITES.md) -- it provides `kubectl create`
commands for every required resource.

Deploy in this order:

1. **External Secrets Operator (ESO)** -- optional, but simplifies secret management.
   If you skip ESO, create all Kubernetes Secrets manually.

2. **cert-manager** (v1.11.1+) with approver-policy (v0.6.3). Create the
   `vault-forge-issuer` ClusterIssuer as described in
   [helm/PREREQUISITES.md](../../helm/PREREQUISITES.md#5-clusterissuer).

3. **PostgreSQL** -- SSL-enabled, with required extensions:

```bash
psql "postgres://<USER>:<PASS>@<HOST>:<PORT>/<DB>?sslmode=require" \
  -c 'CREATE EXTENSION IF NOT EXISTS btree_gin;' \
  -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'
```

4. **Vault** -- deployed and unsealed, with:
   * PKI secrets engine at mount path **`forgeca`**
   * PKI role named **`forge-cluster`**
   * Kubernetes auth enabled with a role for the cert-manager service account
   * Vault policy granting sign/issue capabilities

These Vault configuration steps are documented in detail in
[helm/PREREQUISITES.md](../../helm/PREREQUISITES.md#hashicorp-vault).

---

## 4. Site CA, credsmgr, and Temporal

This step sets up the certificate infrastructure that both the REST / cloud components
and Temporal depend on.

### 4.1 Create Site CA Secret

Generate a root CA and create the `ca-signing-secret` used by the
`carbide-rest-ca-issuer` ClusterIssuer and credsmgr. From the
`ncx-infra-controller-rest` repository:

```bash
./scripts/gen-site-ca.sh
```

This creates a `kubernetes.io/tls` secret named `ca-signing-secret` in both the
`carbide-rest` and `cert-manager` namespaces. Run `./scripts/gen-site-ca.sh --help`
for options (custom CN, output to disk, dry-run).

### 4.2 Create carbide-rest-ca-issuer and deploy credsmgr

Create the `carbide-rest-ca-issuer` ClusterIssuer (backed by `ca-signing-secret`
from Step 4.1) and deploy credsmgr. From the `ncx-infra-controller-rest` repository:

```bash
kubectl apply -k deploy/kustomize/base/cert-manager-io
kubectl apply -k deploy/kustomize/base/cert-manager
kubectl get clusterissuer carbide-rest-ca-issuer
```

Verify `carbide-rest-ca-issuer` shows `Ready=True` before proceeding.

### 4.3 Provision Temporal TLS Certificates

Apply the Temporal namespace, database credentials, and mTLS certificate manifests.
From the `ncx-infra-controller-rest` repository:

```bash
kubectl apply -f deploy/kustomize/base/temporal-helm/namespace.yaml
kubectl apply -f deploy/kustomize/base/temporal-helm/db-creds.yaml
kubectl apply -k deploy/kustomize/base/common
```

Verify the mTLS certificates are issued:

```bash
kubectl wait --for=condition=Ready certificate/server-interservice-cert -n temporal --timeout=120s
kubectl wait --for=condition=Ready certificate/server-cloud-cert -n temporal --timeout=120s
kubectl wait --for=condition=Ready certificate/server-site-cert -n temporal --timeout=120s
```

### 4.4 Deploy Temporal

Deploy Temporal server v1.22.6 with Elasticsearch 7.17.3 for visibility.
Use the TLS certificates provisioned above for mTLS.

After all Temporal pods are `Running`, register the required namespaces via
`temporal-admintools`:

```bash
kubectl exec -n temporal deploy/temporal-admintools -- \
  temporal operator namespace create --namespace cloud \
    --address temporal-frontend.temporal:7233 \
    --tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt \
    --tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key \
    --tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt \
    --tls-server-name interservice.server.temporal.local

kubectl exec -n temporal deploy/temporal-admintools -- \
  temporal operator namespace create --namespace site \
    --address temporal-frontend.temporal:7233 \
    --tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt \
    --tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key \
    --tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt \
    --tls-server-name interservice.server.temporal.local
```

```{note}
If Temporal pods are stuck in `Init:0/1`, the Elasticsearch index may not be ready.
Check `kubectl -n temporal logs elasticsearch-master-0` and wait for ES to become
healthy, or create the index manually.
```

---

## 5. Deploy Carbide REST Components

The REST / cloud layer provides the customer-facing API, workflow orchestration, and
site management. Deploy from the
[ncx-infra-controller-rest](https://github.com/NVIDIA/ncx-infra-controller-rest) repository.

All REST components deploy into the `carbide-rest` namespace via a single Helm
umbrella chart:

```bash
helm upgrade --install carbide-rest helm/charts/carbide-rest \
  --namespace carbide-rest --create-namespace \
  -f <your-ncx-rest-values.yaml> \
  --set global.image.repository=<your-registry> \
  --set global.image.tag=<your-rest-tag> \
  --timeout 600s --wait
```

This deploys: `carbide-rest-api`, `carbide-rest-workflow` (cloud-worker and
site-worker), `carbide-rest-site-manager`, `carbide-rest-db` (migration job),
`carbide-rest-cert-manager` (credsmgr), and Keycloak (dev IdP).

Verify:

```bash
kubectl get pods -n carbide-rest
```

All deployments should reach `Running` and the db-migration job should show
`Completed`.

---

## 6. Deploy Carbide Core

This deploys the on-site gRPC API and all supporting services (DHCP, DNS, PXE,
hardware health, SSH console, and optionally Unbound) into the `forge-system` namespace.

There are two deployment methods: **Helm** (recommended) and **Kustomize** (legacy).

### Helm (Recommended)

See the [Helm chart README](../../helm/README.md) for full documentation and
[helm/PREREQUISITES.md](../../helm/PREREQUISITES.md) for the Secrets and ConfigMaps
that must exist before install.

1. Copy `helm/examples/values-minimal.yaml` (or `values-full.yaml`) and customize:
   * `global.image.repository` and `global.image.tag` -- your built core image
   * `global.imagePullSecrets` -- if using a private registry
   * `carbide-api.hostname` -- your API FQDN
   * `carbide-api.siteConfig.carbideApiSiteConfig` -- site-specific TOML overrides
   * MetalLB `externalService` annotations for each service VIP
   * Kea DHCP configuration under `carbide-dhcp.config`

2. Install:

```bash
helm upgrade --install carbide ./helm \
  --namespace forge-system --create-namespace \
  -f values-mysite.yaml
```

3. Verify:

```bash
kubectl -n forge-system get pods
kubectl -n forge-system get certificates
```

The migration job runs automatically. Pods may briefly restart until the database is ready.

### Kustomize (Alternative)

See [deploy/README.md](../../deploy/README.md) for the full list of inputs.
Populate `deploy/kustomization.yaml` and `deploy/files/`, then:

```bash
cd deploy
kustomize build . --enable-helm --enable-alpha-plugins --enable-exec | kubectl apply -f -
```

### Verify the API

```bash
curl -k https://<CARBIDE_API_EXTERNAL_IP>:1079/healthz
```

If the API VIP is not externally reachable:

```bash
kubectl port-forward svc/carbide-api 1079:1079 -n forge-system
curl -k https://localhost:1079/healthz
```

---

## 7. Install admin-cli

Build from source in the `ncx-infra-controller-core` repository:

```bash
cargo make build-cli
```

The binary is at `target/release/admin-cli`. Point it at your API:

```bash
admin-cli -c https://api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME> site info
```

If the API is not externally reachable:

```bash
kubectl port-forward svc/carbide-api 1079:1079 -n forge-system &
admin-cli -c https://localhost:1079 site info
```

---

## 8. Deploy Elektra Site Agent

Elektra bridges the on-site Carbide core to the cloud REST layer via Temporal.
It deploys as a StatefulSet in the `carbide-rest` namespace.

1. Pre-apply the gRPC client certificate so it exists before the pod starts:

```bash
helm template carbide-rest-site-agent helm/charts/carbide-rest-site-agent \
  --namespace carbide-rest \
  -f <your-site-agent-values.yaml> \
  --set global.image.repository=<your-registry> \
  --set global.image.tag=<your-rest-tag> \
  --show-only templates/certificate.yaml | kubectl apply -f -

kubectl wait --for=condition=Ready certificate/core-grpc-client-site-agent-certs \
  -n carbide-rest --timeout=120s
```

2. Create the per-site Temporal namespace (the site-agent panics without it):

```bash
SITE_UUID=<your-site-uuid>

kubectl exec -n temporal deploy/temporal-admintools -- \
  temporal operator namespace create --namespace "$SITE_UUID" \
    --address temporal-frontend.temporal:7233 \
    --tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt \
    --tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key \
    --tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt \
    --tls-server-name interservice.server.temporal.local
```

3. Install the site-agent Helm chart (the pre-install hook registers the site
   and creates the `site-registration` secret):

```bash
helm upgrade --install carbide-rest-site-agent helm/charts/carbide-rest-site-agent \
  --namespace carbide-rest \
  -f <your-site-agent-values.yaml> \
  --set global.image.repository=<your-registry> \
  --set global.image.tag=<your-rest-tag> \
  --set "envConfig.CLUSTER_ID=$SITE_UUID" \
  --set "envConfig.TEMPORAL_SUBSCRIBE_NAMESPACE=$SITE_UUID" \
  --timeout 300s --wait
```

4. Verify:

```bash
kubectl get pods -n carbide-rest -l app.kubernetes.io/name=carbide-rest-site-agent
kubectl logs -n carbide-rest -l app.kubernetes.io/name=carbide-rest-site-agent --tail=20
```

---

## 9. Ingest Hosts

See [Ingesting Hosts](ingesting_machines.md) for the complete procedure.

For each managed host, you need the **BMC MAC address**, **chassis serial number**, and
**factory BMC username/password** (from your asset management system or server vendor).

```bash
# Set desired credentials NICo will apply to all hosts
admin-cli -c <api-url> credential add-bmc --kind=site-wide-root --password='<PASSWORD>'
admin-cli -c <api-url> credential add-uefi --kind=host --password='<PASSWORD>'

# Upload expected machines manifest
admin-cli -c <api-url> credential em replace-all --filename expected_machines.json

# Approve for measured boot ingestion
admin-cli -c <api-url> mb site trusted-machine approve \* persist --pcr-registers="0,3,5,6"
```

NICo then automatically: assigns IPs via DHCP, discovers BMCs via Redfish, rotates
credentials, provisions DPUs, PXE-boots hosts into Scout for hardware discovery, and
moves machines to the `Available` pool.

Monitor progress:

```bash
admin-cli -c <api-url> machine list
```

---

## 10. Verification

Once hosts are `Available`, verify the full deployment:

```bash
# All core pods running
kubectl -n forge-system get pods

# API healthy
curl -k https://<CARBIDE_API_EXTERNAL_IP>:1079/healthz

# Machines discovered and available
admin-cli -c <api-url> machine list

# Admin UI accessible
# https://api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>/admin
# Or via port-forward: kubectl port-forward svc/carbide-api 1079:1079 -n forge-system
```

To complete the hello-world test, create an instance to provision Ubuntu on a managed
host, then SSH to verify:

```bash
ssh -p 22 <instance-id>@<CARBIDE_SSH_CONSOLE_EXTERNAL_IP>
```

---

## Troubleshooting

### Temporal Pods Stuck in Init

Pods stuck in `Init:0/1` -- usually Elasticsearch index not ready.
Check `kubectl -n temporal logs elasticsearch-master-0`.

### kubectl Connection Refused

When accessing through a jump host: `ssh -L 6443:localhost:6443 <jump-host>`

### External API Access Blocked

Use port-forwarding: `kubectl port-forward svc/carbide-api 1079:1079 -n forge-system`

### carbide-rest-site-manager Fails to Start

`unable to start container process` -- verify the image was built with the production
Dockerfile (`docker/production/Dockerfile.carbide-rest-site-manager`), not the local
dev Dockerfile.

### Pods Stuck in ImagePullBackOff

Missing `imagePullSecrets`. Verify: `kubectl -n <ns> get secret imagepullsecret`

### nvcr.io/nvidian Image References

Internal NVIDIA paths. Build from source (Step 1) and replace with your registry URL.

### Machines Not Progressing

Check state controller logs:
`kubectl -n forge-system logs -l app=carbide-api --tail=100 | grep state_controller`

Common causes: DHCP relay not configured on OOB switch, BMC MACs not matching the
expected machines table, network boot not first in boot order.
