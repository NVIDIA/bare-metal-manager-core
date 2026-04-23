# helm-prereqs

Installs the full prerequisite stack for NCX Core and NCX REST on a bare-metal Kubernetes cluster. Everything is orchestrated by a single script:

```bash
export REGISTRY_PULL_SECRET=<your-ngc-api-key>
export NCX_CORE_IMAGE_TAG=<ncx-core-image-tag>
export NCX_IMAGE_REGISTRY=<ncx-rest-image-registry>
export NCX_REST_IMAGE_TAG=<ncx-rest-image-tag>
./setup.sh        # interactive - prompts before deploying NCX Core and NCX REST
./setup.sh -y     # non-interactive - deploys everything
```

---

## Table of contents

0. [Before you run setup.sh - site configuration checklist](#0-before-you-run-setupsh--site-configuration-checklist)
   - [Step 4 - Get the NCX REST repository](#step-4--get-the-ncx-rest-repository)
   - [Step 6b - Assign service VIPs](#step-6b--assign-service-vips-valuesnc-coreyaml)
   - [Validate your configuration with preflight.sh](#validate-your-configuration-with-preflightsh)
1. [Prerequisites](#1-prerequisites)
2. [Quick start](#2-quick-start)
3. [What gets deployed](#3-what-gets-deployed)
4. [PKI architecture](#4-pki-architecture)
5. [PostgreSQL architecture](#5-postgresql-architecture)
6. [Setup phases - step by step](#6-setup-phases--step-by-step)
7. [Teardown](#7-teardown)
8. [After setup completes - next steps](#8-after-setup-completes--next-steps)
   - [Verify the deployment](#verify-the-deployment)
   - [Acquiring a Keycloak access token](#acquiring-a-keycloak-access-token)
   - [Setting up carbidecli against this cluster](#setting-up-carbidecli-against-this-cluster)
   - [Bootstrap the org and create your first site](#bootstrap-the-org-and-create-your-first-site)
   - [Next: IP blocks and downstream resources](#next-ip-blocks-and-downstream-resources)
9. [Troubleshooting](#9-troubleshooting)

---

## 0. Before you run setup.sh - site configuration checklist

Everything in this section must be done **before** the first `setup.sh` run. Skipping any item will either cause setup to fail or result in a deployment with incorrect site configuration that is hard to fix after the fact.

### Step 1 - Set required environment variables

```bash
export KUBECONFIG=/path/to/kubeconfig          # your cluster kubeconfig
export REGISTRY_PULL_SECRET=<pull-secret-or-api-key>  # your registry pull credential
export NCX_IMAGE_REGISTRY=my-registry.example.com/ncx  # base registry for all NCX images
export NCX_CORE_IMAGE_TAG=<ncx-core-image-tag>  # e.g. v2025.12.30-rc1
export NCX_REST_IMAGE_TAG=<ncx-rest-image-tag>      # e.g. v1.0.4
```

`NCX_IMAGE_REGISTRY` is used for both NCX Core (`<registry>/nvmetal-carbide`) and NCX REST (`<registry>/carbide-rest-*`). Push all images to this registry before running setup.

### Step 2 - Set your site name (`values.yaml`)

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

### Step 3 - Configure NCX Core site deployment (`values/ncx-core.yaml`)

This is the most important file to get right. Open `helm-prereqs/values/ncx-core.yaml` and update:

**a. API hostname** - the external DNS name for the NCX Core API:
```yaml
carbide-api:
  hostname: "carbide.mysite.example.com"   # ← must resolve to your cluster's ingress/LB
```

**b. `siteConfig` TOML block** - site identity, network topology, and resource pools. The fields most likely to differ per site:

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
| `[networks.<underlay>]` | Underlay data-plane network(s) - one block per L3 segment |

All fields are documented with inline comments in the file.

> **Required fields - do not leave empty:** `[networks.admin]` `prefix` and `gateway` must be set to real values. `carbide-api` crashes at startup with a parse error if these are empty strings. Similarly, `[pools.lo-ip]`, `[pools.vlan-id]`, and `[pools.vni]` ranges must be non-empty.
>
> Fields that are safe to leave as empty arrays: `dhcp_servers`, `site_fabric_prefixes`, `deny_prefixes`. Do not delete any field from the TOML block - missing keys cause a different crash than empty ones.

### Step 4 - Get the NCX REST repository

NCX REST (`ncx-infra-controller-rest`) is a separate repository that contains the Helm chart, kustomize bases, and helper scripts that `setup.sh` uses for Phase 7. It is **not** bundled inside `carbide-helm` - you need a local clone before running setup.

**Option A - Let `setup.sh` handle it automatically (recommended)**

`setup.sh` looks for the repo in these locations in order:

1. `NCX_REPO` env var (explicit path - use this if you cloned it somewhere non-standard)
2. Sibling directories next to `carbide-helm`: `../carbide-rest`, `../ncx-infra-controller-rest`, `../ncx`
3. If not found anywhere, `preflight.sh` offers to clone it for you before setup proceeds

If you place the clone next to `carbide-helm` (the recommended layout), no env var is needed:

```
your-workspace/
  carbide-helm/               ← this repo
  ncx-infra-controller-rest/  ← NCX REST repo (clone here)
```

**Option B - Clone it manually**

```bash
git clone https://github.com/NVIDIA/ncx-infra-controller-rest.git
# Then either place it as a sibling of carbide-helm, or:
export NCX_REPO=/path/to/ncx-infra-controller-rest
```

> **Why is this separate?** NCX Core and NCX REST have independent release cycles and may be deployed independently. Keeping them in separate repos lets you pin each to a specific version tag without coupling the two release trains.

### Step 4b - Configure NCX REST authentication (`values/ncx-rest.yaml`)

The default configuration uses the **dev Keycloak instance** that `setup.sh` deploys automatically (step 7d). No changes are needed if you're running a dev/test environment.

For **production** or if you are bringing your own IdP, you have two options:

**Option A - Use your own Keycloak or OIDC-compatible IdP:**
```yaml
carbide-rest-api:
  config:
    keycloak:
      enabled: true
      baseURL: "https://keycloak.mysite.example.com"          # ← internal URL (cluster-internal or direct)
      externalBaseURL: "https://keycloak.mysite.example.com"  # ← URL returned to clients in tokens
      realm: "your-realm"
      clientID: "carbide-api"
```

**Option B - Disable Keycloak and use a generic OIDC issuer:**
```yaml
carbide-rest-api:
  config:
    keycloak:
      enabled: false
    issuers:
      - issuer: "https://your-oidc-provider.example.com"
        audience: "carbide-api"
```
When `keycloak.enabled: false`, the Keycloak deployment at step 7d is still created by setup.sh (it is part of the NCX REST kustomize base) but `carbide-rest-api` will not use it for token validation.

### Step 5 - Review site-agent config (`values/ncx-site-agent.yaml`)

The defaults in this file match the dev postgres instance deployed by setup.sh.

`DB_USER` and `DB_PASSWORD` are **not** in `ncx-site-agent.yaml`. They are injected at runtime from the `db-creds` Kubernetes Secret (created by the `carbide-rest-common` sub-chart during step 7g). The Secret is referenced via `secrets.dbCreds` in the site-agent values.

For production or a different database, override the Secret name and connection config:

```yaml
secrets:
  dbCreds: my-site-agent-db-secret   # Secret must have DB_USER and DB_PASSWORD keys

envConfig:
  DB_DATABASE: "my-database"
  DB_ADDR: "my-postgres.my-namespace.svc.cluster.local"
```

> **Dev environments:** The defaults work with the postgres StatefulSet that setup.sh deploys. No changes needed.
>
> **Production:** Create a Secret with `DB_USER` and `DB_PASSWORD` keys, set `secrets.dbCreds` to its name, and update `DB_DATABASE` / `DB_ADDR`. Also set `DEV_MODE: "false"` and `ENABLE_DEBUG: "false"`.

### Step 6 - Configure MetalLB (`values/metallb-config.yaml`)

MetalLB provides LoadBalancer IPs for NCX Core services (carbide-api, DHCP, DNS, PXE, SSH console, NTP). Without it those services stay in `<pending>` state and the site is unreachable.

**The file ships pre-populated with worked example values** (from an internal NVIDIA test site). Replace all values labeled `# EXAMPLE` with your site-specific configuration before running setup.sh - setup.sh will warn you if it detects example placeholder values are still present.

Fields to update for your site:

| Field | Example value in file | What to put for your site |
|-------|----------------------|--------------------------|
| `IPAddressPool.spec.addresses` (internal) | `10.180.126.160/28` | Your internal VIP CIDR |
| `IPAddressPool.spec.addresses` (external) | `10.180.126.176/28` | Your external VIP CIDR |
| `BGPPeer.spec.myASN` | `4244766850` | Your cluster-side ASN (same for all nodes) |
| `BGPPeer.spec.peerASN` | `4244766851/852/853` | TOR ASN per node (unique per node) |
| `BGPPeer.spec.peerAddress` | `10.180.248.80/82/84` | TOR switch IP reachable from each node |
| `BGPPeer.spec.nodeSelectors` hostnames | `rno1-m04-d04-cpu-{1,2,3}` | Your actual node hostnames (`kubectl get nodes`) |
| `BGPAdvertisement.metadata.name` | `my-site` | Your site name |
| `IPAddressPool.metadata.name` | `vip-pool-int` / `vip-pool-ext` | Rename to match your site |

Add or remove `BGPPeer` blocks to match your node count - one block per worker node.

**If your environment does not use BGP** (local dev, flat network): comment out the `BGPPeer` and `BGPAdvertisement` sections and uncomment the `L2Advertisement` section at the bottom of the file.

### Step 6b - Assign service VIPs (`values/ncx-core.yaml`)

Each NCX Core service that exposes a LoadBalancer needs a **specific, stable IP** from your MetalLB pool. Without explicit assignments, MetalLB picks IPs randomly on each install - which means your DHCP relay, DNS records, PXE config, and API hostname cannot be pre-configured and will break on redeploy.

Open `helm-prereqs/values/ncx-core.yaml` and update the VIP for each service:

| Service | Values key | Pool to use | Example IP in file |
|---------|-----------|-------------|-------------------|
| `carbide-api` external API | `carbide-api.externalService.annotations` | External (client-facing) | `10.180.126.177` |
| `carbide-dhcp` | `carbide-dhcp.externalService.annotations` | Internal (cluster-facing) | `10.180.126.160` |
| `carbide-dns` instance-0 | `carbide-dns.externalService.perPodAnnotations[0]` | Internal or External | `10.180.126.180` |
| `carbide-dns` instance-1 | `carbide-dns.externalService.perPodAnnotations[1]` | Internal or External | `10.180.126.179` |
| `carbide-pxe` | `carbide-pxe.externalService.annotations` | Internal (cluster-facing) | `10.180.126.162` |
| `carbide-ssh-console-rs` | `carbide-ssh-console-rs.externalService.annotations` | Internal (cluster-facing) | `10.180.126.164` |
| `carbide-ntp` instance-0 | `carbide-ntp.externalService.perPodAnnotations[0]` | Internal (cluster-facing) | `10.180.126.165` |
| `carbide-ntp` instance-1 | `carbide-ntp.externalService.perPodAnnotations[1]` | Internal (cluster-facing) | `10.180.126.166` |
| `carbide-ntp` instance-2 | `carbide-ntp.externalService.perPodAnnotations[2]` | Internal (cluster-facing) | `10.180.126.167` |

The file ships pre-populated with example values (labeled `# EXAMPLE`). All IPs must be within the `IPAddressPool` ranges you defined in `values/metallb-config.yaml` and must be unique across services.

> **carbide-dhcp note:** `externalService.enabled: true` must be set explicitly - it defaults to false in the chart.
>
> **carbide-dns and carbide-ntp note:** these use `perPodAnnotations` (a list) rather than `annotations` because each replica gets its own VIP. The chart creates separate UDP + TCP services per pod that share the same IP via `metallb.universe.tf/allow-shared-ip`.
>
> **carbide-api IP and DNS:** the carbide-api VIP must resolve in external DNS to the `hostname` you set in Step 3a. The example in the file (`api-examplesite.example.com` → `10.180.126.177`) is a placeholder - replace both with your own hostname and IP.

### Step 7 - (Optional) Set a stable site UUID

If you want a specific site UUID instead of the default placeholder:

```bash
export NCX_SITE_UUID=<your-uuid>   # must be a valid UUID v4
```

This UUID is used as the Temporal namespace for the site and as the `CLUSTER_ID` passed to the site-agent. Once set and deployed, changing it requires redeploying the site-agent and re-registering the site.

### Validate your configuration with preflight.sh

Once the steps above are done, run the pre-flight check before `setup.sh` to catch issues early:

```bash
source ./preflight.sh
```

`preflight.sh` is also run automatically at the start of every `setup.sh` invocation, so this step is optional - but running it standalone lets you iterate on your config files without triggering any cluster changes.

**What it checks:**

| Category | Checks |
|----------|--------|
| Environment variables | Required vars are set (`REGISTRY_PULL_SECRET`, `NCX_IMAGE_REGISTRY`, `NCX_CORE_IMAGE_TAG`, `NCX_REST_IMAGE_TAG`); format checks: no `https://` prefix on registry, version tags start with `v`, `NCX_SITE_UUID` is a valid UUID if set, `KUBECONFIG` path exists if set |
| Required tools | `helm`, `helmfile`, `kubectl`, `jq`, `ssh-keygen` are in PATH |
| `values/metallb-config.yaml` | File exists; YAML is valid; at least one IPAddressPool defined; exactly one advertisement mode active (BGP or L2, not both); BGPPeer has a matching BGPAdvertisement; ASNs are non-zero; example placeholder node hostnames not still present |
| Cluster reachability | `kubectl` can reach the API server - fails fast so the remaining cluster checks are skipped if unreachable |
| Node resources | At least 3 schedulable nodes (Ready and not tainted NoSchedule/NoExecute) - required for HA Vault and Postgres |
| Per-node: kernel parameters | `net.bridge.bridge-nf-call-iptables=1` and `net.ipv4.ip_forward=1` on every node - checked via a short-lived pod that mounts `/proc/sys` from the host |
| Per-node: DNS | `kubernetes.default.svc.cluster.local` resolves on every node - each check pod does a live `nslookup` |
| Registry connectivity | The registry host (`NCX_IMAGE_REGISTRY`) responds to an HTTPS probe - image pulls won't fail at the network level |
| NCX REST repo | Resolves the repo from `NCX_REPO` env var, sibling directories, or offers to clone from GitHub |

> **Air-gapped clusters:** the per-node checks pull `busybox:1.36` by default. If your cluster cannot reach Docker Hub, set `PREFLIGHT_CHECK_IMAGE` to a local mirror:
> ```bash
> export PREFLIGHT_CHECK_IMAGE=my-registry.example.com/busybox:1.36
> ```

If everything passes, `preflight.sh` prints one line and exits. If issues are found, it lists them and asks whether you want to continue anyway - hard errors (likely to cause failures) default to **no**, warnings default to **yes**.

---

## 1. Prerequisites

### Tools

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

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `REGISTRY_PULL_SECRET` | **Yes** | Pull secret / API key for your image registry. Used to create the image pull secret for both NCX Core and NCX REST. |
| `NCX_IMAGE_REGISTRY` | **Yes** | Base image registry for all NCX images (e.g. `my-registry.example.com/ncx`). Used for NCX Core (`<registry>/nvmetal-carbide`) and NCX REST (`<registry>/carbide-rest-*`). |
| `NCX_CORE_IMAGE_TAG` | **Yes** | NCX Core (ncx-infra-controller-core) image tag (e.g. `v2025.12.30`). |
| `NCX_REST_IMAGE_TAG` | **Yes** | NCX REST (ncx-infra-controller-rest) image tag (e.g. `v1.0.4`). |
| `KUBECONFIG` | **Yes** | Path to your cluster kubeconfig. |
| `NCX_REPO` | No | Path to a local clone of `ncx-infra-controller-rest` ([github.com/NVIDIA/ncx-infra-controller-rest](https://github.com/NVIDIA/ncx-infra-controller-rest)). Auto-detected from sibling directories; `preflight.sh` offers to clone it if not found. |
| `NCX_SITE_UUID` | No | Stable UUID for this site. Defaults to `a1b2c3d4-e5f6-4000-8000-000000000001`. |

Obtain an NGC API key at [ngc.nvidia.com](https://ngc.nvidia.com) → **API Keys** → **Generate Personal Key**.

---

## 2. Quick start

### Required: set these values for your site before running

| File | Key | Description |
|------|-----|-------------|
| `values.yaml` | `siteName` | Short site identifier (e.g. `examplesite`). Injected into postgres pods as `TMP_SITE`. Default is `"TMP_SITE"` - **must be changed**. |
| `values/ncx-core.yaml` | `carbide-api.hostname` | Hostname for the NCX Core API (e.g. `carbide.mysite.local`). |
| `values/ncx-core.yaml` | `carbide-api.siteConfig` | Full site config block - network pools, VLAN ranges, VNI ranges, domain name, IB config. |
| `values/ncx-rest.yaml` | *(registry-agnostic)* | NCX REST umbrella chart values. Image registry/tag passed via env vars - no edits needed for most deployments. |

```bash
# 1. Point at your cluster
export KUBECONFIG=/path/to/kubeconfig

# 2. Set your NGC pull key
export REGISTRY_PULL_SECRET=<key>

# 3. Set image registry and tags
#    NCX_IMAGE_REGISTRY is the base registry for all NCX images.
#    Push your images there first; setup.sh appends /nvmetal-carbide for NCX Core.
export NCX_IMAGE_REGISTRY=my-registry.example.com/ncx
export NCX_CORE_IMAGE_TAG=<ncx-core-tag>
export NCX_REST_IMAGE_TAG=<ncx-rest-tag>

# 4. Set your site name in values.yaml
#    Edit helm-prereqs/values.yaml and set:  siteName: "<your-site>"

# 5. Set your site-specific values in values/ncx-core.yaml
#    Edit helm-prereqs/values/ncx-core.yaml - hostname, siteConfig

# 6. Run - prompts before NCX Core and NCX REST installs
cd helm-prereqs
./setup.sh

# To deploy everything non-interactively (CI/CD):
./setup.sh -y
```

To tear everything down, see [Teardown](#7-teardown).

---

## 3. What gets deployed

```
local-path-provisioner     (raw manifest - StorageClasses for Vault + PostgreSQL PVCs)
metallb                    (metallb/metallb 0.14.5 - LoadBalancer IPs via BGP or L2)
postgres-operator          (zalando/postgres-operator 1.10.1 - manages forge-pg-cluster)
cert-manager               (jetstack/cert-manager v1.17.1)
vault                      (hashicorp/vault 0.25.0, 3-node HA Raft, TLS)
external-secrets           (external-secrets/external-secrets 0.14.3)
carbide-prereqs            (this Helm chart - forge-system namespace)
NCX Core                   (../helm - ncx-core.yaml values, prompted at Phase 6)
NCX REST                   (ncx-infra-controller-rest/helm/charts/carbide-rest - ncx-rest.yaml values)
  ├── carbide-rest-ca-issuer ClusterIssuer (cert-manager.io)
  ├── postgres StatefulSet  (temporal + keycloak + NCX databases)
  ├── keycloak              (dev OIDC IdP, carbide-dev realm)
  ├── temporal              (temporal-helm/temporal, mTLS)
  ├── carbide-rest          (API, cert-manager, workflow, site-manager)
  └── carbide-rest-site-agent (StatefulSet, bootstrap via site-manager)
```

All helmfile releases are managed by `helmfile.yaml`. NCX Core and NCX REST are deployed by `setup.sh` directly via `helm upgrade --install`.

### Why setup.sh exists instead of a single `helmfile sync`

helmfile v1.4 has two ordering constraints that make a single `helmfile sync` impossible for this stack:

1. **`prepare` hooks fire before `needs` ordering.** If a prepare hook polls for a resource that another release must install first, it deadlocks immediately.
2. **`postSync` hooks do not block dependent releases.** A vault unseal in a postSync hook would not complete before external-secrets or carbide-prereqs started.

`setup.sh` solves this by calling `helmfile sync -l name=<release>` in explicit sequential phases, so each phase fully completes before the next begins.

---

## 4. PKI architecture

The PKI has three layers, built bottom-up:

```
selfsigned-bootstrap ClusterIssuer
  └── site-root CA Certificate  (10-year self-signed CA, Secret "site-root" in cert-manager ns)
        └── site-issuer ClusterIssuer  (issues Vault's own TLS certs - no Vault dependency)
              ├── forgeca-vault-client  (Vault port 8200 listener TLS, Secret in vault ns)
              └── vault-raft-tls        (Vault Raft port 8201 peer TLS, Secret in vault ns)

vault (running, unsealed)
  └── vault-pki-config Job  (imports site-root CA into Vault PKI engine "forgeca")
        └── vault-forge-issuer ClusterIssuer  (issues all workload SPIFFE certs via Vault PKI)
```

NCX REST has its own parallel PKI chain for internal services:

```
carbide-rest-ca-issuer ClusterIssuer  (backed by ca-signing-secret in carbide-rest ns)
  └── Temporal mTLS certificates      (server-interservice-cert, server-cloud-cert, server-site-cert)

vault-forge-issuer ClusterIssuer      (same Vault PKI CA as NCX Core)
  └── site-agent gRPC client cert     (core-grpc-client-site-agent-certs in carbide-rest ns)
        SPIFFE URI: spiffe://forge.local/forge-system/sa/elektra-site-agent
```

The site-agent uses the Vault PKI CA for both directions of mTLS with carbide-api:
- Site-agent presents its client cert (Vault-signed) - carbide-api trusts it via the same CA.
- Site-agent verifies carbide-api's server cert using `ca.crt` from the issued secret (Vault PKI CA).

### Layer 1 - Bootstrap (no external dependencies)

`selfsigned-bootstrap` is a cert-manager `selfSigned` ClusterIssuer with no dependencies. It issues `site-root`: a 10-year CA certificate stored as Secret `site-root` in the `cert-manager` namespace. This is the trust anchor for the entire cluster.

### Layer 2 - site-issuer (Vault TLS bootstrap)

`site-issuer` is a `ca` ClusterIssuer backed by `site-root`. It can issue certificates without Vault being up.

**This solves the Vault TLS chicken-and-egg problem.** Vault requires TLS to start - but `vault-forge-issuer` (the Vault-backed issuer) can't exist before Vault is running. `site-issuer` breaks the cycle by issuing Vault's own TLS secrets before Vault starts:

| Secret | Namespace | Purpose |
|--------|-----------|---------|
| `forgeca-vault-client` | `vault` | Port 8200 listener cert (mounted at `/vault/userconfig/forgeca-vault/`) |
| `vault-raft-tls` | `vault` | Raft port 8201 peer cert (mounted at `/vault/userconfig/vault-raft-tls/`) |

These secrets must exist **before** `helmfile sync -l name=vault` - setup.sh creates them explicitly in Phase 2 using `helm template | kubectl apply`.

### Layer 3 - vault-forge-issuer (workload PKI)

Once Vault is running and unsealed, the `vault-pki-config` Job (Helm post-install hook) configures Vault as a PKI backend:

1. Enables the `forgeca` PKI secrets engine, tunes it to a 10-year max TTL.
2. Imports `site-root` (cert + key) into Vault PKI - Vault becomes an intermediate CA under the same trust root.
3. Creates PKI role `forge-cluster` - allows any name, allows SPIFFE URI SANs, 720h max TTL, EC P-256.
4. Enables Kubernetes auth and writes two policies: `cert-manager-forge-policy` (sign via PKI) and `forge-vault-policy` (read KV secrets).
5. Enables KV v2 at `secrets/` and AppRole auth for the `carbide` role.

`vault-forge-issuer` is then created as a cert-manager ClusterIssuer authenticating to Vault via Kubernetes auth. All NCX Core workload SPIFFE certificates and the site-agent's gRPC client certificate are issued through this issuer.

### forge-roots - CA distribution

The `forge-roots` Secret (containing `site-root`'s `ca.crt`) must be present in every namespace where NCX workloads run so pods can verify each other's SPIFFE certificates.

```
site-root Secret (cert-manager ns)
  → ClusterSecretStore "cert-manager-ns-secretstore" (Kubernetes provider)
    → ClusterExternalSecret "forge-roots-eso"
      → ExternalSecret in every namespace labeled carbide.nvidia.com/managed=true
        → Secret "forge-roots" (ca.crt)
```

`creationPolicy: Orphan` prevents Kubernetes GC from cascading a delete to `forge-roots` if the ExternalSecret is recreated on helm upgrade.

---

## 5. PostgreSQL architecture

PostgreSQL is deployed as a production-grade 3-node HA cluster managed by the **Zalando PostgreSQL Operator** (`acid.zalan.do`), matching the setup in `carbide-external/manifests/forge-pg-cluster-app`. NCX REST also deploys its own simpler postgres StatefulSet in the same `postgres` namespace for temporal, keycloak, and NCX REST databases.

```
postgres-operator (postgres ns)
  └── forge-pg-cluster postgresql CRD (postgres ns)        ← NCX Core
        ├── forge-pg-cluster-0  (Patroni leader)
        ├── forge-pg-cluster-1  (Patroni replica)
        └── forge-pg-cluster-2  (Patroni replica)
              each pod: postgres + postgres-exporter sidecar

postgres StatefulSet (postgres ns, service: postgres)      ← NCX REST
  └── Databases: forge, temporal, temporal_visibility, keycloak, elektratest
```

The NCX REST postgres is a simple StatefulSet deployed by `kubectl apply -k deploy/kustomize/base/postgres` from the NCX repo. It uses service name `postgres` so temporal and NCX REST values files work without modification.

### Credential flow (NCX Core)

The operator automatically creates a per-user credential Secret in the `postgres` namespace:
```
forge-system.carbide.forge-pg-cluster.credentials.postgresql.acid.zalan.do
  username: forge-system.carbide
  password: <operator-generated>
```

ESO's `carbide-db-eso` ClusterExternalSecret mirrors this into `forge-system` as:
```
forge-system.carbide.forge-pg-cluster.credentials
  username: forge-system.carbide
  password: <same>
```

### forge-pg-cluster-env ConfigMap

The operator injects the `forge-pg-cluster-env` ConfigMap (in the `postgres` namespace) into every postgres pod as environment variables. Currently provides:

```
TMP_SITE = <Values.siteName>
```

The ConfigMap is rendered by the `carbide-prereqs` chart (from `Values.siteName`) so it flows in at install time and can be overridden per-site with `--set siteName=<name>`.

### ssh-host-key format

`ssh-console-rs` requires the SSH host key in **OpenSSH PEM format** (`-----BEGIN OPENSSH PRIVATE KEY-----`). Helm's `genPrivateKey "ed25519"` produces PKCS8 format which the binary rejects at startup. `bootstrap_ssh_host_key.sh` pre-creates the secret using `ssh-keygen` before `helmfile sync -l name=carbide-prereqs` runs. The `lookup` in `templates/_helpers.tpl` detects the existing secret and reuses it, so Helm never overwrites it.

---

## 6. Setup phases - step by step

`setup.sh` orchestrates all phases sequentially. For a full breakdown of what each phase does, the exact commands it runs, and how to re-run individual phases manually, see **[SETUP_PHASES.md](SETUP_PHASES.md)**.

The phases in order:

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
| 6 | NCX Core (`carbide` helm release) |
| 7a-7h | NCX REST full stack (postgres, Keycloak, Temporal, carbide-rest, site-agent) |

---

## 7. Teardown

```bash
./clean.sh
```

Removes in order:
1. **NCX REST stack** - `carbide-rest-site-agent`, `carbide-rest`, `temporal` helm releases; `carbide-rest-ca-issuer` ClusterIssuer; `carbide-rest` and `temporal` namespaces (waits for termination)
2. **NCX Core** - `carbide` helm release in `forge-system`
3. **All helmfile releases** - `carbide-prereqs`, `external-secrets`, `vault`, `cert-manager`, `postgres-operator`, `metallb`
   - MetalLB site config resources (IPAddressPool, BGPPeer, BGPAdvertisement) deleted before the operator is removed to avoid stuck finalizers
   - Explicitly deletes all CRDs (metallb, postgres-operator, cert-manager, external-secrets) - Helm does not delete CRDs on uninstall
   - Deletes all cluster-scoped RBAC and webhooks for each component - handles ArgoCD/kustomize orphans that Helm cannot reclaim
4. **Cluster-scoped hook resources** - ClusterIssuers, ClusterSecretStores, ClusterExternalSecrets, ClusterRoles created by Helm hooks (survive uninstall due to `before-hook-creation` delete policy)
5. **Namespaces** - `forge-system`, `vault`, `cert-manager`, `external-secrets`, `postgres`, `metallb-system` - waits for termination
   - Also purges the `default` namespace of any ESO resources deployed there by ArgoCD (deployments, services, secrets, serviceaccounts labeled `app.kubernetes.io/name=external-secrets`)
6. **Released PersistentVolumes** - `local-path-persistent` PVs owned by this stack (Retain policy - survive namespace deletion)
7. **local-path-provisioner** - StorageClass and DaemonSet

### Why clean.sh deletes CRDs and cluster-scoped RBAC explicitly

Helm never deletes CRDs on uninstall (to prevent accidental data loss). In environments where components were previously deployed by ArgoCD or kustomize, those tools own the cluster-scoped resources with their own field manager. Helm cannot reclaim these resources and will fail with "cannot be imported into the current release" on reinstall. `clean.sh` deletes them all explicitly so `setup.sh` can perform a clean reinstall every time.

---

## 8. After setup completes - next steps

When `setup.sh` finishes without error, the infrastructure stack is running but the site is not yet operational. These steps are required before the site can discover and manage bare-metal hosts.

### Verify the deployment

```bash
# All NCX Core pods running in forge-system
kubectl get pods -n forge-system

# All NCX REST pods running in carbide-rest
kubectl get pods -n carbide-rest

# Site-agent connected to carbide-api (look for "successfully connected to server")
kubectl logs -n carbide-rest -l app.kubernetes.io/name=carbide-rest-site-agent --prefix \
    | grep "CarbideClient"

# MetalLB assigned IPs to LoadBalancer services
kubectl get svc -n forge-system | grep LoadBalancer
```

All LoadBalancer services should have an external IP from your `IPAddressPool` ranges. If any show `<pending>`, MetalLB has not assigned an IP - check BGP session status on your TOR switches and verify `values/metallb-config.yaml` has correct peer addresses.

### Verify DHCP is serving

If your site has DHCP servers configured in `siteConfig`, check that the DHCP service is reachable:

```bash
kubectl get svc carbide-dhcp -n forge-system
```

The external IP should be within your internal VIP pool range. If bare-metal hosts should PXE boot, also check:

```bash
kubectl get svc carbide-pxe -n forge-system
```

### Check site explorer status

Once the site-agent is connected and host ingestion is configured (see the host ingestion documentation), monitor the site explorer:

```bash
kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-api --tail=50 \
    | grep -i "site explorer\|bmc\|discovery"
```

### Acquiring a Keycloak access token

This section only applies if `keycloak.enabled: true` in `values/ncx-rest.yaml` (the default). If you disabled the bundled Keycloak and pointed `carbide-rest-api` at your own IdP, obtain tokens from that IdP instead.

`setup.sh` deploys a dev Keycloak instance with a `carbide` realm pre-loaded with the `ncx-service` client (M2M / `client_credentials`). Its service account token carries the `ncx:FORGE_PROVIDER_ADMIN` and `ncx:FORGE_TENANT_ADMIN` realm roles that `carbide-rest-api` authorizes against.

| Value | Setting |
|-------|---------|
| Token endpoint | `http://keycloak.carbide-rest:8082/realms/carbide/protocol/openid-connect/token` |
| `grant_type` | `client_credentials` |
| `client_id` | `ncx-service` |
| `client_secret` | `carbide-local-secret` |

> **Fetch tokens from inside the cluster.** Do NOT port-forward Keycloak and request tokens against `localhost` — the resulting JWT's `iss` claim will be `http://localhost:.../realms/carbide`, but `carbide-rest-api` expects `http://keycloak.carbide-rest:8082/realms/carbide` (configured via `keycloak.externalBaseURL` in `ncx-rest.yaml`). Any token fetched via `localhost` is rejected with `invalid_issuer`.

Use the helper script (runs `curl` from a throw-away in-cluster pod):

```bash
TOKEN=$(helm-prereqs/keycloak/get-token.sh)
```

Or the equivalent raw `kubectl run`:

```bash
TOKEN=$(kubectl run -i --rm --restart=Never --image=curlimages/curl curl-token \
  -n carbide-rest --quiet -- \
  -sf -X POST http://keycloak.carbide-rest:8082/realms/carbide/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=ncx-service&client_secret=carbide-local-secret" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

Verify the token against `carbide-rest-api`:

```bash
kubectl run -i --rm --restart=Never --image=curlimages/curl curl-test \
  -n carbide-rest --quiet -- \
  -sf http://carbide-rest-api.carbide-rest:8388/v2/org/ncx/carbide/user/current \
  -H "Authorization: Bearer $TOKEN"
```

For a full end-to-end demo (token fetch + JWT decode + API call + `forge.user` dump) run `helm-prereqs/keycloak/example.sh`. Further Keycloak detail (realm/client/role layout, how the API maps `realm_access.roles` onto orgs) lives in [`helm-prereqs/keycloak/README.md`](keycloak/README.md).

### Setting up carbidecli against this cluster

`carbidecli` is the interactive client for `carbide-rest-api`. It is built from the `ncx-infra-controller-rest` repo (the clone that `setup.sh` resolves as `$NCX_REPO`).

**1. Build and install the CLI**

```bash
cd "$NCX_REPO"
make carbide-cli        # installs to $(go env GOPATH)/bin/carbidecli
```

**2. Generate the default config file**

```bash
carbidecli init         # writes ~/.carbide/config.yaml
```

**3. Port-forward `carbide-rest-api` to localhost**

```bash
kubectl port-forward -n carbide-rest svc/carbide-rest-api 8388:8388
```

**4. Edit `~/.carbide/config.yaml` so the `api` block matches this cluster**

```yaml
# Carbide CLI configuration
api:
  base: http://localhost:8388
  org: ncx
  name: carbide
```

**5. Configure auth**

`carbidecli` will not make any API calls until one auth method is configured. When the bundled Keycloak is enabled, the simplest option is to paste the `$TOKEN` from the previous section straight in as a bearer token:

```yaml
auth:
  token: <paste value of $TOKEN here>
```

One-liner to fetch and capture it:

```bash
TOKEN=$(helm-prereqs/keycloak/get-token.sh)
# then paste $TOKEN as the value of auth.token in ~/.carbide/config.yaml
```

If you are bringing your own IdP (Keycloak disabled), configure `auth.oidc` or `auth.api_key` in `~/.carbide/config.yaml` instead.

### Bootstrap the org and create your first site

Once the CLI is configured, a one-time org bootstrap call must be made **before** any `site` / `vpc` / `instance` create operation. Without it, `site create` returns `404 "Org does not have an Infrastructure Provider"`.

`GET /v2/org/ncx/carbide/service-account/current` is idempotent and, on first call, lazily creates the `InfrastructureProvider`, `Tenant` (with `targetedInstanceCreation=true`), and `TenantAccount` for the `ncx` org. Using plain `curl` so this works even without `carbidecli` installed:

```bash
TOKEN=$(helm-prereqs/keycloak/get-token.sh)

curl -sS -H "Authorization: Bearer $TOKEN" \
    http://localhost:8388/v2/org/ncx/carbide/service-account/current \
    | python3 -m json.tool
```

Expected response (UUIDs will differ):

```json
{
  "enabled": true,
  "infrastructureProviderId": "<uuid>",
  "tenantId":                 "<uuid>"
}
```

With the org bootstrapped, create your first site:

```bash
carbidecli --version
carbidecli site list                                    # should be empty
carbidecli site create --name examplesite --description 'local dev site'
carbidecli site list                                    # now shows one row
```

For everyday use, drop into the interactive TUI:

```bash
carbidecli tui
```

### Next: IP blocks and downstream resources

A site needs at least one IP block (and, depending on your workload, service accounts, SSH keys, VPCs, etc.) before instances can be provisioned against it. Once the site is created:

```bash
carbidecli ipblock create   --help   # allocate tenant IP ranges to the site
carbidecli service-account create --help
carbidecli ssh-key create  --help
```

The TUI (`carbidecli tui`) lists every resource kind with its required fields and is the recommended way to explore the API surface before scripting it.

---

## 9. Troubleshooting

### carbide-api CrashLoopBackOff - siteConfig parse error

If `carbide-api` crashes immediately after Phase 6 with a config parse error, the most common cause is empty required fields in the `carbideApiSiteConfig` TOML block. Fields that must be non-empty:

- `[networks.admin]` - `prefix` and `gateway` (empty string crashes the binary)
- `[pools.lo-ip]`, `[pools.vlan-id]`, `[pools.vni]` - `ranges` must have at least one entry

Check the pod logs for the specific field:
```bash
kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-api --previous
```

Fix the value in `values/ncx-core.yaml` and re-run:
```bash
helm upgrade carbide ./helm --namespace forge-system -f helm-prereqs/values/ncx-core.yaml \
    --set global.image.repository="${NCX_IMAGE_REGISTRY}/nvmetal-carbide" \
    --set global.image.tag="${NCX_CORE_IMAGE_TAG}"
```

### DNS resolution failing in pods

On **Kubespray clusters**, setup.sh deploys the NodeLocal DNSCache DaemonSet automatically. If it is not ready:
```bash
kubectl get daemonset nodelocaldns -n kube-system
kubectl apply -f operators/nodelocaldns-daemonset.yaml
kubectl rollout status daemonset/nodelocaldns -n kube-system
```

On **kubeadm clusters**, NodeLocal DNSCache is not used - setup.sh checks CoreDNS readyReplicas instead. If DNS is failing on a kubeadm cluster:
```bash
kubectl get pods -n kube-system -l k8s-app=kube-dns
kubectl rollout restart deployment/coredns -n kube-system
```

### Vault TLS bootstrap certificates not Ready

```bash
kubectl get certificate -n cert-manager
kubectl get certificate -n vault
kubectl describe certificate forgeca-vault-client -n vault
```

Common cause: cert-manager webhook not ready yet. Wait 30 seconds and re-run Phase 2.

### Vault pods stuck in Init or CrashLoop

```bash
kubectl get secret forgeca-vault-client vault-raft-tls -n vault
kubectl logs vault-0 -n vault -c vault
```

### vault-pki-config Job failing

```bash
kubectl logs -n forge-system job/vault-pki-config -c wait-vault
kubectl logs -n forge-system job/vault-pki-config -c configure
```

Common causes:
- Vault still sealed - `kubectl exec -n vault vault-0 -c vault -- vault status`
- `carbide-vault-token` missing - re-run `./unseal_vault.sh`
- `site-root` Secret not readable by the Job's service account

### forge-pg-cluster not reaching Running state

```bash
kubectl get postgresql forge-pg-cluster -n postgres
kubectl describe postgresql forge-pg-cluster -n postgres
kubectl get pods -n postgres
kubectl logs -n postgres forge-pg-cluster-0 -c postgres
```

Common causes:
- `local-path-persistent` StorageClass missing - re-run Phase 1
- `forge-pg-cluster-env` ConfigMap missing in `postgres` namespace - re-run Phase 5
- Insufficient node resources - tune `postgresql.resources` in `values.yaml`

### DB credentials not appearing in forge-system

```bash
kubectl get clustersecretstore postgres-ns-secretstore
kubectl get clusterexternalsecret carbide-db-eso
kubectl describe externalsecret -n forge-system
```

The source secret (`forge-system.carbide.forge-pg-cluster.credentials.postgresql.acid.zalan.do`) is created by the operator only after the cluster reaches `Running` state. If the ClusterSecretStore shows `Invalid`, check that the `eso-postgres-ns` ServiceAccount token exists in the `postgres` namespace:
```bash
kubectl get secret eso-postgres-ns-token -n postgres
```

### forge-roots Secret not appearing

```bash
kubectl get clustersecretstore cert-manager-ns-secretstore
kubectl get clusterexternalsecret forge-roots-eso
kubectl get namespace forge-system --show-labels
# Should include: carbide.nvidia.com/managed=true
```

If the label is missing:
```bash
kubectl label namespace forge-system carbide.nvidia.com/managed=true
```

### Site-agent gRPC connection to carbide-api failing (nil CarbideClient)

The site-agent connects to carbide-api at startup with a 5-second deadline. If the connection fails, the `CarbideClient` stays nil permanently and all inventory activities panic with a nil-pointer dereference. setup.sh detects this and restarts the StatefulSet automatically, but you can also diagnose manually:

```bash
# Check which pods connected successfully
kubectl logs -n carbide-rest -l app.kubernetes.io/name=carbide-rest-site-agent --prefix \
    | grep -E "CarbideClient: (successfully connected|failed to get version)"

# Check mTLS cert was issued
kubectl get certificate core-grpc-client-site-agent-certs -n carbide-rest

# Check the cert was projected into the pod
kubectl exec -n carbide-rest carbide-rest-site-agent-0 -- ls /etc/carbide-certs/

# Check DNS resolution of carbide-api from the pod
kubectl exec -n carbide-rest carbide-rest-site-agent-0 -- \
    nslookup carbide-api.forge-system.svc.cluster.local
```

Common causes and fixes:

| Symptom | Cause | Fix |
|---------|-------|-----|
| `DeadlineExceeded` in pod logs | DNS cold cache on the node at startup - FQDN lookup timed out during the 5-second deadline | `kubectl rollout restart statefulset/carbide-rest-site-agent -n carbide-rest` |
| `certificate signed by unknown authority` | Site-agent cert issued by wrong CA (not `vault-forge-issuer`) | Check `values/ncx-site-agent.yaml` - `global.certificate.issuerRef.name` must be `vault-forge-issuer` |
| `Unauthenticated` from carbide-api | SPIFFE URI does not match `InternalRBACRules` | Check `values/ncx-site-agent.yaml` - `certificate.uris` must be `spiffe://forge.local/forge-system/sa/elektra-site-agent` |
| `transport: error while dialing` | Wrong `CARBIDE_SEC_OPT` (e.g. `0` = insecure against a TLS server) | Check `envConfig.CARBIDE_SEC_OPT: "2"` in `ncx-site-agent.yaml` (2 = MutualTLS) |
| cert secret missing at pod start | Race: StatefulSet started before cert was issued | Re-run setup.sh Phase 7h - pre-apply Certificate step ensures cert exists first |

The StatefulSet uses `dnsConfig: options: [{name: ndots, value: "1"}]` to prevent the Kubernetes search domain from expanding short names to 4-part FQDNs - this eliminates the DNS cold-cache timeout on `carbide-api.forge-system.svc.cluster.local` at startup.

### Temporal namespace not found (site-agent startup panic)

If the site-agent panics on startup with a nil pointer in `RegisterCron`:
```bash
# Check the Temporal namespace was created
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
# Check MetalLB pods are running
kubectl get pods -n metallb-system

# Check IP pools are configured
kubectl get ipaddresspool -n metallb-system

# Check BGP peers were created and are connected
kubectl get bgppeer -n metallb-system
kubectl describe bgppeer -n metallb-system

# Check speaker logs for BGP session state
kubectl logs -n metallb-system -l app=metallb,component=speaker --tail=50

# Check the service itself
kubectl get svc -n forge-system -l app.kubernetes.io/name=carbide-api
```

Common causes:

| Symptom | Cause | Fix |
|---------|-------|-----|
| `IPAddressPool` not found | `values/metallb-config.yaml` was not applied | Re-run `kubectl apply -f values/metallb-config.yaml` |
| BGP session `Idle` / never establishes | Wrong `peerAddress` or ASN in `metallb-config.yaml`, or firewall blocking TCP 179 | Verify with your network team - `peerAddress` must be the TOR switch IP reachable from that node |
| BGP session up but no IP assigned | IP pool addresses are exhausted or CIDR is wrong | Check `kubectl describe ipaddresspool -n metallb-system` |
| All services pending after MetalLB looks healthy | FRR speaker not running (frr.enabled=false in metallb.yaml) | Set `speaker.frr.enabled: true` in `operators/values/metallb.yaml` and re-run Phase 1c |
| L2 mode: service gets IP but is unreachable | ARP not reaching the right node | Check `kubectl get l2advertisement -n metallb-system` and node network config |

### Checking overall health after setup

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
