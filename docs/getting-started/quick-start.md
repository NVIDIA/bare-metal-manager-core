# Quick Start Guide

This guide walks through deploying NICo end-to-end: from building containers to discovering your first managed host. The core deployment is orchestrated by `setup.sh` in the `helm-prereqs/` directory, which installs all prerequisites and NICo components in the correct order.

Before starting, review the [Prerequisites](prerequisites/hardware.md) for hardware, networking, software, and BMC/OOB requirements.

## Step 1 — Build NICo Containers

Build all NICo container images from source on Ubuntu 24.04. This produces images for NCX Core, DPU BFB artifacts, and the admin CLI.

See [Building NICo Containers](../manuals/building_nico_containers.md) for full build instructions, including x86_64 and aarch64 cross-compilation steps.

Push the built images to your container registry before proceeding.

## Step 2 — Prepare the Kubernetes Cluster

NICo requires a Kubernetes cluster with at least 3 schedulable nodes (Ready, not tainted NoSchedule/NoExecute) for HA Vault and PostgreSQL. NICo does not provision the cluster itself — operators are expected to provision their own Kubernetes cluster meeting the requirements below using their preferred tooling (kubeadm, Kubespray, managed K8s, etc.).

**Validated baseline:**

| Component | Version |
|---|---|
| Kubernetes | v1.30.4 |
| kubelet | v1.26.15 |
| containerd | 1.7.1 |
| CNI (Calico) | v3.28.1 |
| OS | Ubuntu 24.04.1 LTS |

The cluster must have:
- `net.bridge.bridge-nf-call-iptables=1` and `net.ipv4.ip_forward=1` on every node
- DNS resolution working (`kubernetes.default.svc.cluster.local` resolves on every node)
- Network connectivity to your container registry

### Required tools (local machine)

The following tools must be installed on the machine where you will run `setup.sh` — not on the Kubernetes cluster itself.

| Tool | Min version | Mac | Linux |
|------|-------------|-----|-------|
| `kubectl` | 1.26 | `brew install kubectl` | `snap install kubectl --classic` or [binary](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/) |
| `helm` | 3.12 | `brew install helm` | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |
| `helmfile` | 0.162 | `brew install helmfile` | [binary from GitHub releases](https://github.com/helmfile/helmfile/releases) |
| `helm-diff` plugin | any | `helm plugin install https://github.com/databus23/helm-diff` | same |
| `jq` | 1.6 | `brew install jq` | `apt install jq` / `yum install jq` |
| `ssh-keygen` | any | built-in | built-in |

> **helmfile requires the `helm-diff` plugin.** Install it once:
> ```bash
> helm plugin install https://github.com/databus23/helm-diff
> ```

## Step 3 — Configure the Site

Everything in this step must be done **before** running `setup.sh`. Skipping any item will either cause setup to fail or result in a deployment with incorrect site configuration that is hard to fix after the fact.

### 3a. Set required environment variables

```bash
export KUBECONFIG=/path/to/kubeconfig          # your cluster kubeconfig
export REGISTRY_PULL_SECRET=<pull-secret-or-api-key>  # your registry pull credential
export NCX_IMAGE_REGISTRY=my-registry.example.com/ncx  # base registry for all NCX images
export NCX_CORE_IMAGE_TAG=<ncx-core-image-tag>  # e.g. v2025.12.30-rc1
export NCX_REST_IMAGE_TAG=<ncx-rest-image-tag>      # e.g. v1.0.4
```

`NCX_IMAGE_REGISTRY` is used for both NCX Core (`<registry>/nvmetal-carbide`) and NCX REST (`<registry>/carbide-rest-*`). Push all images to this registry before running setup.

Obtain an NGC API key at [ngc.nvidia.com](https://ngc.nvidia.com) → **API Keys** → **Generate Personal Key**.

| Variable | Required | Description |
|----------|----------|-------------|
| `REGISTRY_PULL_SECRET` | **Yes** | Pull secret / API key for your image registry. Used to create the image pull secret for both NCX Core and NCX REST. |
| `NCX_IMAGE_REGISTRY` | **Yes** | Base image registry for all NCX images (e.g. `my-registry.example.com/ncx`). Used for NCX Core (`<registry>/nvmetal-carbide`) and NCX REST (`<registry>/carbide-rest-*`). |
| `NCX_CORE_IMAGE_TAG` | **Yes** | NCX Core (ncx-infra-controller-core) image tag (e.g. `v2025.12.30`). |
| `NCX_REST_IMAGE_TAG` | **Yes** | NCX REST (ncx-infra-controller-rest) image tag (e.g. `v1.0.4`). |
| `KUBECONFIG` | **Yes** | Path to your cluster kubeconfig. |
| `NCX_REPO` | No | Path to a local clone of `ncx-infra-controller-rest`. Auto-detected from sibling directories; `preflight.sh` offers to clone it if not found. |
| `NCX_SITE_UUID` | No | Stable UUID for this site. Defaults to `a1b2c3d4-e5f6-4000-8000-000000000001`. |

### 3b. Set your site name

Open `helm-prereqs/values.yaml` and change `siteName` from the placeholder to your actual site identifier:

```yaml
siteName: "mysite"   # ← replace "TMP_SITE" with your site name (e.g. "examplesite", "prod-us-east")
```

This value is injected into every postgres pod as the `TMP_SITE` environment variable. It must match the `sitename` in the NCX Core `siteConfig` block below.

To tune PostgreSQL resources for your node capacity (the defaults are conservative for dev):
```yaml
postgresql:
  instances: 3
  volumeSize: "10Gi"
  resources:
    limits:
      cpu: "4"
      memory: "4Gi"
    requests:
      cpu: "500m"
      memory: "1Gi"
```

### 3c. Configure NCX Core site deployment

Open `helm-prereqs/values/ncx-core.yaml` and update:

**API hostname** — the external DNS name for the NCX Core API:
```yaml
carbide-api:
  hostname: "carbide.mysite.example.com"   # ← must resolve to your cluster's ingress/LB
```

**`siteConfig` TOML block** — site identity, network topology, and resource pools. The fields most likely to differ per site:

| Field | What to set |
|-------|-------------|
| `sitename` | Short identifier matching `siteName` in `values.yaml` |
| `initial_domain_name` | Base DNS domain for the site (e.g. `mysite.example.com`) |
| `dhcp_servers` | List of DHCP server IPs reachable from bare-metal hosts, or `[]` |
| `site_fabric_prefixes` | CIDRs that are part of the site fabric (instance-to-instance traffic) |
| `deny_prefixes` | CIDRs instances must not reach (OOB, control plane, management) |
| `[pools.lo-ip]` ranges | Loopback IP range allocated to bare-metal hosts |
| `[pools.vlan-id]` ranges | VLAN ID allocation range |
| `[pools.vni]` ranges | VXLAN Network Identifier range |
| `[networks.admin]` | Admin network CIDR, gateway, and MTU |
| `[networks.<underlay>]` | Underlay data-plane network(s) — one block per L3 segment |

All fields are documented with inline comments in the file.

> **Required fields — do not leave empty:** `[networks.admin]` `prefix` and `gateway` must be set to real values. `carbide-api` crashes at startup with a parse error if these are empty strings. Similarly, `[pools.lo-ip]`, `[pools.vlan-id]`, and `[pools.vni]` ranges must be non-empty.
>
> Fields that are safe to leave as empty arrays: `dhcp_servers`, `site_fabric_prefixes`, `deny_prefixes`. Do not delete any field from the TOML block — missing keys cause a different crash than empty ones.

### 3d. Get the NCX REST repository

NCX REST (`ncx-infra-controller-rest`) is a separate repository that contains the Helm chart, kustomize bases, and helper scripts that `setup.sh` uses for Phase 7. It is **not** bundled inside this repo — you need a local clone before running setup.

**Option A — Let `setup.sh` handle it automatically (recommended)**

`setup.sh` looks for the repo in these locations in order:

1. `NCX_REPO` env var (explicit path — use this if you cloned it somewhere non-standard)
2. Sibling directories next to this repo: `../carbide-rest`, `../ncx-infra-controller-rest`, `../ncx`
3. If not found anywhere, `preflight.sh` offers to clone it for you before setup proceeds

If you place the clone next to this repo (the recommended layout), no env var is needed:

```
your-workspace/
  ncx-infra-controller-core/   ← this repo
  ncx-infra-controller-rest/   ← NCX REST repo (clone here)
```

**Option B — Clone it manually**

```bash
git clone https://github.com/NVIDIA/ncx-infra-controller-rest.git
# Then either place it as a sibling, or:
export NCX_REPO=/path/to/ncx-infra-controller-rest
```

### 3e. Configure NCX REST authentication

The default configuration uses the **dev Keycloak instance** that `setup.sh` deploys automatically. No changes are needed if you're running a dev/test environment.

For **production** or if you are bringing your own IdP, edit `helm-prereqs/values/ncx-rest.yaml`:

**Option A — Use your own Keycloak or OIDC-compatible IdP:**
```yaml
carbide-rest-api:
  config:
    keycloak:
      enabled: true
      baseURL: "https://keycloak.mysite.example.com"
      externalBaseURL: "https://keycloak.mysite.example.com"
      realm: "your-realm"
      clientID: "carbide-api"
```

**Option B — Disable Keycloak and use a generic OIDC issuer:**
```yaml
carbide-rest-api:
  config:
    keycloak:
      enabled: false
    issuers:
      - issuer: "https://your-oidc-provider.example.com"
        audience: "carbide-api"
```

When `keycloak.enabled: false`, the Keycloak deployment is still created by setup.sh but `carbide-rest-api` will not use it for token validation.

### 3f. Review site-agent config

The defaults in `helm-prereqs/values/ncx-site-agent.yaml` match the dev postgres instance deployed by setup.sh.

`DB_USER` and `DB_PASSWORD` are injected at runtime from the `db-creds` Kubernetes Secret (created by the `carbide-rest-common` sub-chart during Phase 7g). The Secret is referenced via `secrets.dbCreds` in the site-agent values.

For production or a different database, override the Secret name and connection config:

```yaml
secrets:
  dbCreds: my-site-agent-db-secret   # Secret must have DB_USER and DB_PASSWORD keys

envConfig:
  DB_DATABASE: "my-database"
  DB_ADDR: "my-postgres.my-namespace.svc.cluster.local"
```

### 3g. Configure MetalLB

MetalLB provides LoadBalancer IPs for NCX Core services (carbide-api, DHCP, DNS, PXE, SSH console, NTP). Without it those services stay in `<pending>` state and the site is unreachable.

Edit `helm-prereqs/values/metallb-config.yaml` — **the file ships pre-populated with worked example values**. Replace all values labeled `# EXAMPLE` with your site-specific configuration before running setup.sh.

| Field | Example value in file | What to put for your site |
|-------|----------------------|--------------------------|
| `IPAddressPool.spec.addresses` (internal) | `10.180.126.160/28` | Your internal VIP CIDR |
| `IPAddressPool.spec.addresses` (external) | `10.180.126.176/28` | Your external VIP CIDR |
| `BGPPeer.spec.myASN` | `4244766850` | Your cluster-side ASN (same for all nodes) |
| `BGPPeer.spec.peerASN` | `4244766851/852/853` | TOR ASN per node (unique per node) |
| `BGPPeer.spec.peerAddress` | `10.180.248.80/82/84` | TOR switch IP reachable from each node |
| `BGPPeer.spec.nodeSelectors` hostnames | `rno1-m04-d04-cpu-{1,2,3}` | Your actual node hostnames (`kubectl get nodes`) |

Add or remove `BGPPeer` blocks to match your node count — one block per worker node.

**If your environment does not use BGP** (local dev, flat network): comment out the `BGPPeer` and `BGPAdvertisement` sections and uncomment the `L2Advertisement` section at the bottom of the file.

### 3h. Assign service VIPs

Each NCX Core service that exposes a LoadBalancer needs a **specific, stable IP** from your MetalLB pool. Without explicit assignments, MetalLB picks IPs randomly on each install — which means your DHCP relay, DNS records, PXE config, and API hostname cannot be pre-configured and will break on redeploy.

Open `helm-prereqs/values/ncx-core.yaml` and update the VIP for each service:

| Service | Values key | Pool to use |
|---------|-----------|-------------|
| `carbide-api` external API | `carbide-api.externalService.annotations` | External (client-facing) |
| `carbide-dhcp` | `carbide-dhcp.externalService.annotations` | Internal (cluster-facing) |
| `carbide-dns` instance-0 | `carbide-dns.externalService.perPodAnnotations[0]` | Internal or External |
| `carbide-dns` instance-1 | `carbide-dns.externalService.perPodAnnotations[1]` | Internal or External |
| `carbide-pxe` | `carbide-pxe.externalService.annotations` | Internal (cluster-facing) |
| `carbide-ssh-console-rs` | `carbide-ssh-console-rs.externalService.annotations` | Internal (cluster-facing) |
| `carbide-ntp` instance-0 | `carbide-ntp.externalService.perPodAnnotations[0]` | Internal (cluster-facing) |
| `carbide-ntp` instance-1 | `carbide-ntp.externalService.perPodAnnotations[1]` | Internal (cluster-facing) |
| `carbide-ntp` instance-2 | `carbide-ntp.externalService.perPodAnnotations[2]` | Internal (cluster-facing) |

All IPs must be within the `IPAddressPool` ranges you defined in `values/metallb-config.yaml` and must be unique across services.

> **carbide-dhcp note:** `externalService.enabled: true` must be set explicitly — it defaults to false in the chart.
>
> **carbide-dns and carbide-ntp note:** these use `perPodAnnotations` (a list) rather than `annotations` because each replica gets its own VIP.
>
> **carbide-api IP and DNS:** the carbide-api VIP must resolve in external DNS to the `hostname` you set in Step 3c.

### 3i. (Optional) Set a stable site UUID

If you want a specific site UUID instead of the default placeholder:

```bash
export NCX_SITE_UUID=<your-uuid>   # must be a valid UUID v4
```

This UUID is used as the Temporal namespace for the site and as the `CLUSTER_ID` passed to the site-agent. Once set and deployed, changing it requires redeploying the site-agent and re-registering the site.

### 3j. Validate configuration

Run the pre-flight check to catch issues before deployment:

```bash
cd helm-prereqs/
source ./preflight.sh
```

`preflight.sh` is also run automatically at the start of every `setup.sh` invocation.

**What it checks:**

| Category | Checks |
|----------|--------|
| Environment variables | Required vars are set; format checks: no `https://` prefix on registry, version tags start with `v`, UUID is valid if set, KUBECONFIG path exists if set |
| Required tools | `helm`, `helmfile`, `kubectl`, `jq`, `ssh-keygen` are in PATH |
| `values/metallb-config.yaml` | File exists; YAML is valid; at least one IPAddressPool defined; exactly one advertisement mode active (BGP or L2, not both); example placeholder hostnames not still present |
| Cluster reachability | `kubectl` can reach the API server |
| Node resources | At least 3 schedulable nodes |
| Per-node: kernel parameters | `net.bridge.bridge-nf-call-iptables=1` and `net.ipv4.ip_forward=1` on every node |
| Per-node: DNS | `kubernetes.default.svc.cluster.local` resolves on every node |
| Registry connectivity | The registry host responds to an HTTPS probe |
| NCX REST repo | Resolves the repo from `NCX_REPO` env var, sibling directories, or offers to clone from GitHub |

> **Air-gapped clusters:** the per-node checks pull `busybox:1.36` by default. If your cluster cannot reach Docker Hub, set `PREFLIGHT_CHECK_IMAGE` to a local mirror:
> ```bash
> export PREFLIGHT_CHECK_IMAGE=my-registry.example.com/busybox:1.36
> ```

## Step 4 — Run setup.sh

```bash
cd helm-prereqs/
./setup.sh        # interactive — prompts before deploying NCX Core and NCX REST
./setup.sh -y     # non-interactive — deploys everything
```

`setup.sh` installs all prerequisites and NICo components in sequential phases:

| Phase | What it installs |
|-------|-----------------|
| 0 | DNS check (NodeLocal DNSCache or CoreDNS) |
| 1 | local-path-provisioner + StorageClasses |
| 1b | postgres-operator (Zalando) |
| 1c | MetalLB + site BGP/L2 config |
| 2 | cert-manager + Vault TLS bootstrap (PKI chain) |
| 3 | HashiCorp Vault (3-node HA Raft) |
| 4 | Vault init + unseal + SSH host key |
| 5 | external-secrets + carbide-prereqs + forge-pg-cluster |
| 6 | **NCX Core** (carbide helm release) |
| 7a-7h | **NCX REST** full stack (postgres, Keycloak, Temporal, carbide-rest, site-agent) |

**What gets deployed:**

```
local-path-provisioner     (raw manifest - StorageClasses for Vault + PostgreSQL PVCs)
metallb                    (metallb/metallb 0.14.5 - LoadBalancer IPs via BGP or L2)
postgres-operator          (zalando/postgres-operator 1.10.1 - manages forge-pg-cluster)
cert-manager               (jetstack/cert-manager v1.17.1)
vault                      (hashicorp/vault 0.25.0, 3-node HA Raft, TLS)
external-secrets           (external-secrets/external-secrets 0.14.3)
carbide-prereqs            (this Helm chart - forge-system namespace)
NCX Core                   (../helm - ncx-core.yaml values)
NCX REST                   (ncx-infra-controller-rest/helm/charts/carbide-rest)
  ├── carbide-rest-ca-issuer ClusterIssuer (cert-manager.io)
  ├── postgres StatefulSet  (temporal + keycloak + NCX databases)
  ├── keycloak              (dev OIDC IdP, carbide-dev realm)
  ├── temporal              (temporal-helm/temporal, mTLS)
  ├── carbide-rest          (API, cert-manager, workflow, site-manager)
  └── carbide-rest-site-agent (StatefulSet, bootstrap via site-manager)
```

For manual phase-by-phase installation, re-running individual phases, or debugging failures, see the [Reference Installation](installation-options/reference-install.md) guide.

## Step 5 — Verify the Site Controller

Before ingesting hosts, verify that all site controller components are healthy.

### Check all pods are running

```bash
kubectl get pods -n forge-system        # NCX Core
kubectl get pods -n carbide-rest        # NCX REST
kubectl get pods -n temporal            # Temporal
```

### Verify site-agent is connected

```bash
kubectl logs -n carbide-rest -l app.kubernetes.io/name=carbide-rest-site-agent --prefix \
    | grep "CarbideClient"
```

Look for "successfully connected to server".

### Verify LoadBalancer IPs

```bash
kubectl get svc -n forge-system | grep LoadBalancer
```

All LoadBalancer services should have an external IP from your `IPAddressPool` ranges. If any show `<pending>`, MetalLB has not assigned an IP — check BGP session status on your TOR switches and verify `values/metallb-config.yaml` has correct peer addresses.

### Verify DHCP and PXE are serving

```bash
kubectl get svc carbide-dhcp carbide-pxe -n forge-system
```

Both external IPs should be within your internal VIP pool range.

### Acquire a Keycloak access token

This section only applies if `keycloak.enabled: true` in `values/ncx-rest.yaml` (the default). If you disabled the bundled Keycloak and pointed `carbide-rest-api` at your own IdP, obtain tokens from that IdP instead.

`setup.sh` deploys a dev Keycloak instance with a `carbide` realm pre-loaded with the `ncx-service` client (M2M / `client_credentials`).

| Value | Setting |
|-------|---------|
| Token endpoint | `http://keycloak.carbide-rest:8082/realms/carbide/protocol/openid-connect/token` |
| `grant_type` | `client_credentials` |
| `client_id` | `ncx-service` |
| `client_secret` | `carbide-local-secret` |

> **Fetch tokens from inside the cluster.** Do NOT port-forward Keycloak and request tokens against `localhost` — the resulting JWT's `iss` claim will not match what `carbide-rest-api` expects, and the token will be rejected.

Use the helper script (runs `curl` from a throw-away in-cluster pod):

```bash
TOKEN=$(helm-prereqs/keycloak/get-token.sh)
```

Verify the token against `carbide-rest-api`:

```bash
kubectl run -i --rm --restart=Never --image=curlimages/curl curl-test \
  -n carbide-rest --quiet -- \
  -sf http://carbide-rest-api.carbide-rest:8388/v2/org/ncx/carbide/user/current \
  -H "Authorization: Bearer $TOKEN"
```

### Set up carbide-cli and create your first site

NICo has two CLIs for different purposes:

| CLI | Talks to | Used for |
|---|---|---|
| `carbide-cli` | NICo REST (REST API) | Site management, org bootstrap, instance operations |
| `admin-cli` | NICo Core (gRPC API) | Host ingestion, credentials, expected machines, TPM approval |

`carbide-cli` is built from the NCX REST repo. `admin-cli` is built from the NCX Core repo (`crates/admin-cli`).

**1. Build and install the CLI:**

```bash
cd "$NCX_REPO"
make carbide-cli        # installs to $(go env GOPATH)/bin/carbide-cli
```

**2. Generate the default config file:**

```bash
carbide-cli init         # writes ~/.carbide/config.yaml
```

**3. Port-forward `carbide-rest-api` to localhost:**

```bash
kubectl port-forward -n carbide-rest svc/carbide-rest-api 8388:8388
```

**4. Edit `~/.carbide/config.yaml`:**

```yaml
api:
  base: http://localhost:8388
  org: ncx
  name: carbide
auth:
  token: <paste value of $TOKEN here>
```

**5. Bootstrap the org (required one-time call):**

```bash
TOKEN=$(helm-prereqs/keycloak/get-token.sh)

curl -sS -H "Authorization: Bearer $TOKEN" \
    http://localhost:8388/v2/org/ncx/carbide/service-account/current \
    | python3 -m json.tool
```

**6. Create your first site:**

```bash
carbide-cli site create --name mysite --description 'first site'
carbide-cli site list
```

### Overall health check

```bash
kubectl get clusterissuer
kubectl get clustersecretstore
kubectl get pods -n metallb-system
kubectl get ipaddresspool,bgppeer -n metallb-system
kubectl get pods -n postgres
kubectl get pods -n forge-system
kubectl get jobs -n forge-system
kubectl get secret forge-roots -n forge-system
kubectl get secret forge-system.carbide.forge-pg-cluster.credentials -n forge-system
kubectl get pods -n carbide-rest
kubectl get pods -n temporal
kubectl get certificate core-grpc-client-site-agent-certs -n carbide-rest
```

For troubleshooting common issues, see the [Reference Installation — Troubleshooting](installation-options/reference-install.md#troubleshooting) guide.

## Step 6 — Connect the OOB Network

Configure the out-of-band network to relay BMC DHCP requests to the NICo DHCP service.

1. **Configure DHCP relay** on your OOB switches to forward DHCP requests to the `carbide-dhcp` LoadBalancer VIP (assigned in Step 3h).

2. **Verify DHCP requests are reaching NICo** by checking the DHCP service logs:

```bash
kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-dhcp --tail=20
```

For detailed OOB network requirements, see [BMC and Out-of-Band Setup](prerequisites/bmc-oob-setup.md).

## Step 7 — Discover Your First Host

This step uses `carbide-admin-cli`, the gRPC CLI for NICo Core. Build it from the NCX Core repo:

```bash
cd ncx-infra-controller-core/
cargo build --release -p carbide-admin-cli
# Binary: target/release/carbide-admin-cli
```

Alternatively, use the containerized version bundled in the `carbide-api` pod (available at `/opt/carbide/forge-admin-cli` inside the container). In the examples below, `admin-cli` refers to `carbide-admin-cli`.

The `<api-url>` in the commands below is the NICo Core gRPC API endpoint — this is the `carbide-api` hostname configured in [Step 3c](#3c-configure-ncx-core-site-deployment), not the REST API used in Step 5. The format is typically `https://api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>`. You can also retrieve it from the LoadBalancer VIP:

```bash
kubectl get svc carbide-api -n forge-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

### Set site-wide credentials

Configure the credentials NICo will apply to BMCs and UEFI after ingestion:

```bash
admin-cli -c <api-url> credential add-bmc --kind=site-wide-root --password='<password>'
admin-cli -c <api-url> host generate-host-uefi-password
admin-cli -c <api-url> credential add-uefi --kind=host --password='<password>'
```

### Upload the expected machines manifest

Prepare an `expected_machines.json` with the BMC MAC address, factory default credentials, and chassis serial number for each host:

```json
{
  "expected_machines": [
    {
      "bmc_mac_address": "C4:5A:B1:C8:38:0D",
      "bmc_username": "root",
      "bmc_password": "default-password",
      "chassis_serial_number": "SERIAL-1"
    }
  ]
}
```

Upload it:

```bash
admin-cli -c <api-url> credential em replace-all --filename expected_machines.json
```

### Approve the host for ingestion

NICo uses Measured Boot with TPM v2.0 to enforce cryptographic identity:

```bash
admin-cli -c <api-url> mb site trusted-machine approve \* persist --pcr-registers="0,3,5,6"
```

NICo will now discover the host via Redfish, pair it with its DPU(s), provision the DPU, and bring the host to a ready state. For more details, see [Ingesting Hosts](../provisioning/ingesting-hosts.md).

### Monitor host discovery

```bash
kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-api --tail=50 \
    | grep -i "site explorer\|bmc\|discovery"
```

## Teardown

To remove everything:

```bash
cd helm-prereqs/
./clean.sh
```

This removes NCX REST, NCX Core, all helmfile releases, cluster-scoped resources, namespaces, and released PersistentVolumes. For details on what `clean.sh` does and the removal order, see the [Reference Installation](installation-options/reference-install.md) guide.
