
# Kustomization inputs

The `deploy/kustomization.yaml` file drives the top‑level deployment. Populate the placeholders below before applying any overlays.

| Value | Description |
| --- | --- |
| `yourdockerregistry.com/path/to/carbide-core` | Registry URL that hosts the Carbide core (`nvmetal-carbide`) image. |
| `CARBIDE_REGISTRY_PATH` | URL to the registry that hosts all Carbide components; shared path for component images. |
| `CARBIDE_TAG` | Version tag for the `nvmetal-carbide` component. |
| `yourdockerregistry.com/path/to/boot-artifacts-aarch64` | Registry URL for the `boot-artifacts-aarch64` image. |
| `BOOT_ARTIFACTS_AARCH64_TAG` | Version tag for the `boot-artifacts-aarch64` component. |
| `yourdockerregistry.com/path/to/boot-artifacts-x86_64` | Registry URL for the `boot-artifacts-x86_64` image. |
| `BOOT_ARTIFACTS_X86_TAG` | Version tag for the `boot-artifacts-x86_64` component. |
| `yourdockerregistry.com/path/to/nvmetal-scout-burn-in` | Registry URL for the `machine_validation` image. |
| `MACHINE_VALIDATION_TAG` | Version tag for the `machine_validation` component. |
| `CARBIDE_DHCP_EXTERNAL_IP` | IP address used by the Carbide DHCP service. |
| `CARBIDE_DNS_INSTANCE_0_IP` | First IP address for Carbide DNS; allocate contiguous pair. |
| `CARBIDE_DNS_INSTANCE_1_IP` | Second IP address for Carbide DNS; allocate contiguous pair. |
| `CARBIDE_PXE_IP` | IP address for the Carbide PXE service. |
| `CARBIDE_API_EXTERNAL_IP` | IP address for the API service; typically also mapped to `api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>`. |
| `CARBIDE_SSH_CONSOLE_EXTERNAL_IP` | IP address for BMC console access service in Carbide. |
| `FORGE_UNBOUND_EXTERNAL_IP` | IP address for the Unbound recursive DNS service. |
| `ENVIORNMENT_NAME` | Site name used to identify this Carbide deployment. |
| `SITE_DOMAIN_NAME` | Site domain name used for Carbide endpoints (e.g., `api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>`). |
| `CARBIDE_NTP_SERVERS_IP_0` | First NTP service IP address. |
| `CARBIDE_NTP_SERVERS_IP_1` | Second NTP service IP address. |
| `CARBIDE_NTP_SERVERS_IP_2` | Third NTP service IP address. |

## Files inputs (deploy/files/)

The templates in `deploy/files/` are mounted into services and must be filled with your site‑specific values. Use your IP plan, DNS domain, and certificate authority to derive the values; avoid copying any sample values.

- `deploy/files/carbide-api/admin_root_cert_pem` – place the PEM‑encoded root CA chain used to authenticate Carbide admins (matches the CA trusted by the admin CLI). Generate this from your CA and keep private keys elsewhere.
- `deploy/files/carbide-api/carbide-api-site-config.toml` – set site identifiers (`ENVIRONMENT_NAME`, `SITE_DOMAIN_NAME`), admin network pool and gateway, service VIPs (API, DHCP, DNS, PXE, SSH console, NGINX/proxy, Unbound), tenant overlay prefixes, and IPMI pools/names for controllers and managed hosts. Ensure service VIPs come from your chosen /27 (or equivalent) VIP pool and that IPMI pools each have a gateway and unique network name.
- `deploy/files/unbound/forwarders.conf` – list upstream recursive DNS endpoints reachable from the cluster. Use IPs for resolvers allowed to recurse for your site.
- `deploy/files/unbound/local_data.conf` – define static DNS records for Carbide services (e.g., `api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>` and any other internal names). Map each hostname to the corresponding service VIP you selected above.
- `deploy/files/kea_config.json` – provide the Kea DHCPv4 configuration tailored to your admin/tenant networks, including option definitions, subnets, pools, and relay settings. Reference the same service IPs used elsewhere and ensure leases align with the admin network pool.
- `deploy/files/vtysh.conf` – FRRouting vtysh shell configuration. Align hostname and service addresses here with the FRR service IPs chosen from your service VIP pool.

After populating `deploy/kustomization.yaml` and all files under `deploy/files/`, deploy everything with:

```bash
kustomize build . --enable-helm --enable-alpha-plugins --enable-exec | kubectl apply -f -
```

# Carbide core services (bare‑metal provisioning)

This document summarizes the Kubernetes components that make up the **Carbide core** bare‑metal provisioning system and how to get started deploying them.

Carbide is responsible for:

- Managing the full lifecycle of bare‑metal machines in one or more L2 networks (subnets).
- Owning DHCP and IP addressing within those subnets.
- Discovering new machines automatically
- Driving machines through a state machine using power control (IPMI / Redfish).
- Inventorying hardware
- Exposing a single **gRPC API** that all Carbide services and external clients talk to.

All examples below assume you have chosen a namespace such as **`forge-system`**; adjust as needed.

---

## Carbide API

**Role**  
The **carbide‑api** deployment is the control‑plane API for all bare‑metal operations. Other Carbide services (DHCP, DNS, hardware‑health, PXE, UI, etc.) and cloud components talk to this service over mTLS‑protected gRPC.

### What it deploys

Path: `deploy/carbide-base/api/`

- Deployment `carbide-api` (gRPC API)
- Job `carbide-api-migrate` (database migrations)
- Services
    - `carbide-api` – gRPC, port **1079**
    - `carbide-api-metrics` – metrics, port **1080**
    - `carbide-api-profiler` – profiler, port **1081**
- ConfigMaps
    - `carbide-api-config-files` – base config (`carbide-api-config.toml`, `casbin-policy.csv`)
    - `carbide-api-site-config-files` – overlay for site‑specific TOML (empty in base)
- TLS
    - `Certificate/carbide-api-certificate` → `Secret/carbide-api-certificate` (SPIFFE‑style mTLS)
- RBAC
    - `ServiceAccount/carbide-api`
    - `Role/RoleBinding carbide-api` – allows creating cert‑manager `CertificateRequest`s

### External inputs you must provide

- **Database access**
    - Secret with DB credentials: `<CARBIDE_DB_CREDENTIALS_SECRET>` (keys: `username`, `password`)
    - ConfigMap for DB endpoint: `<CARBIDE_DB_CONFIGMAP>` (keys: `DB_HOST`, `DB_PORT`, `DB_NAME`)
- **Vault access**
    - Secret `<CARBIDE_VAULT_TOKEN_SECRET>` or AppRole secret with `VAULT_ROLE_ID` / `VAULT_SECRET_ID`
    - ConfigMap `<VAULT_CLUSTER_INFO_CONFIGMAP>` with
        - `VAULT_SERVICE`
        - `CARBIDE_VAULT_MOUNT`
        - `CARBIDE_VAULT_PKI_MOUNT`
- **Root CA bundle**
    - Secret `<CARBIDE_ROOT_CA_SECRET>` mounted where `carbide-api-config.toml` expects it.

### Configuration notes

- Runtime config lives in `carbide-api-config.toml` and is overlaid by a site‑specific TOML in `carbide-api-site-config-files`.
- Important knobs include:
    - listen/metrics/profiler ports
    - firmware/DPU settings
    - site explorer enablement
    - TLS paths under `[tls]` (aligned with the SPIFFE Secret mount)
    - Casbin policy path under `[auth]`
- For SA / lab environments it is common to run with **permissive authorization** (for example by enabling an “allow all trusted certs” rule in the Casbin policy). A hardened deployment should tighten these rules.

### Quick start

1. Create the DB credentials Secret and DB endpoint ConfigMap for your environment.
2. Create the Vault token/AppRole Secret and Vault cluster ConfigMap.
3. Optionally add a `carbide-api-site-config.toml` via an overlay and include it in `carbide-api-site-config-files`.
4. Apply the base (or your overlay):

   ```bash
   kubectl apply -k deploy/carbide-base/api -n <CARBIDE_NAMESPACE>
   ```

---

## Carbide DHCP

**Role**  
`carbide-dhcp` is the **authoritative DHCP server** for Carbide‑managed subnets. It runs Kea DHCPv4 and is the endpoint that **tenant ToR switches or DHCP relays point to**. When a tenant node PXE boots or requests an address, this service assigns IPs and options according to your Kea configuration.

### What it deploys

Path: `deploy/carbide-base/dhcp/`

- Deployment `carbide-dhcp`
- Services
    - `carbide-dhcp` – DHCP on UDP **67**
    - `carbide-dhcp-metrics` – metrics on TCP **1089**
- TLS
    - `Certificate/carbide-dhcp-certificate` → `Secret/carbide-dhcp-certificate`
- RBAC
    - `ServiceAccount/carbide-dhcp`
    - `Role/RoleBinding carbide-dhcp`

The pod:

- Runs Kea DHCPv4 via `kea-dhcp4 -c /tmp/kea_config.json`
- Mounts SPIFFE client certs at `/var/run/secrets/spiffe.io`
- Mounts a `ConfigMap` at `/tmp` that must contain `kea_config.json`

### External inputs you must provide

- ConfigMap `<CARBIDE_DHCP_CONFIGMAP>` with your Kea JSON config (key/file mapping to `/tmp/kea_config.json`).
- A cert‑manager `ClusterIssuer` capable of issuing `carbide-dhcp-certificate` (for SPIFFE‑style mTLS to carbide‑api or other services).

### Quick start

1. Write a small Kea config JSON for your tenant subnet and create the DHCP ConfigMap.
2. Point your tenant switches / DHCP relay to the `carbide-dhcp` Service IP (UDP/67).
3. Deploy DHCP:

   ```bash
   kubectl apply -k deploy/carbide-base/dhcp -n <CARBIDE_NAMESPACE>
   ```

---

## Carbide DNS

**Role**  
`carbide-dns` is the **authoritative DNS service** for Carbide‑managed hosts and internal services. It answers queries for the internal zones and forwards anything else to a recursive resolver such as the Unbound deployment.

### What it deploys

Path: `deploy/carbide-base/dns/`

- StatefulSet `carbide-dns`
- Service `carbide-dns` – UDP/TCP **53**
- TLS
    - `Certificate/carbide-dns-certificate` → `Secret/carbide-dns-certificate`
- RBAC
    - `ServiceAccount/carbide-dns`
    - `Role/RoleBinding carbide-dns`

### External inputs you must provide

- ConfigMap `<CARBIDE_DNS_CONFIGMAP>` with at least:
    - `CARBIDE_API` – URL for the carbide‑api gRPC endpoint (e.g. `https://carbide-api.<CARBIDE_NAMESPACE>.svc.cluster.local:1079`).
    - Any additional DNS or zone settings your environment requires.
- A cert‑manager `ClusterIssuer` for `carbide-dns-certificate`.

### Quick start

1. Create the DNS ConfigMap with `CARBIDE_API` pointing at your carbide‑api Service.
2. Ensure cert‑manager is running and the ClusterIssuer for `carbide-dns-certificate` exists.
3. Deploy DNS:

   ```bash
   kubectl apply -k deploy/carbide-base/dns -n <CARBIDE_NAMESPACE>
   ```

---

## Carbide Hardware Health

**Role**  
`carbide-hardware-health` continuously polls host and DPU BMCs for health information (fans, temperatures, leak sensors, etc.), exposes those metrics via Prometheus, and notifies carbide‑api when it detects problems so operators get alerts on failing hardware.

### What it deploys

Path: `deploy/carbide-base/hardware-health/`

- Deployment `carbide-hardware-health`
- Service `carbide-hardware-health` – HTTP metrics on TCP **9009**
- TLS
    - `Certificate/carbide-hardware-health-certificate` → `Secret/carbide-hardware-health-certificate`
- RBAC
    - `ServiceAccount/carbide-hardware-health`
    - `Role/RoleBinding carbide-hardware-health`

The pod:

- Uses SPIFFE certs from `/var/run/secrets/spiffe.io` to talk back to carbide‑api.
- Exposes Prometheus metrics at `:9009/metrics`.

### External inputs you must provide

- A reachable carbide‑api endpoint.
- A Prometheus instance (or other metrics system) scraping the `carbide-hardware-health` Service.
- A cert‑manager `ClusterIssuer` for the hardware‑health certificate.

### Quick start

1. Confirm carbide‑api is running and reachable from `<CARBIDE_NAMESPACE>`.
2. Deploy hardware health:

   ```bash
   kubectl apply -k deploy/carbide-base/hardware-health -n <CARBIDE_NAMESPACE>
   ```

3. Point Prometheus at `carbide-hardware-health:9009` to ingest metrics.

---

## Carbide NTP

**Role**  
`carbide-ntp` provides a redundant chrony‑based NTP service for Carbide clusters.

### What it deploys

Path: `deploy/carbide-base/ntp/`

- StatefulSet `carbide-ntp` (3 replicas with pod anti‑affinity)
- Headless Service `carbide-ntp` – NTP on UDP **123** (pods reachable via `carbide-ntp-<i>.carbide-ntp.<CARBIDE_NAMESPACE>.svc`)

The container runs `dockurr/chrony` and reads `NTP_SERVERS` / `NTP_DIRECTIVES` from env vars.

### External inputs you must provide

- Update `NTP_SERVERS` to point at your upstream time sources plus the peer pods (adjust the default `forge-system` namespace in an overlay).
- Optionally set `NTP_DIRECTIVES` for additional chrony tuning.

### Quick start

1. Patch the StatefulSet env to your upstream NTP servers.
2. Deploy NTP:

   ```bash
   kubectl apply -k deploy/carbide-base/ntp -n <CARBIDE_NAMESPACE>
   ```

3. Hand out the `carbide-ntp` pod hostnames via DHCP option 42 or node configs.

---

## Carbide PXE

**Role**  
`carbide-pxe` serves the HTTP/iPXE entrypoint and boot artifacts for tenant machines, using SPIFFE certs to call back into Carbide services.

### What it deploys

Path: `deploy/carbide-base/pxe/`

- Deployment `carbide-pxe`
- Services
    - `carbide-pxe` – HTTP on TCP **8080**
    - `carbide-pxe-metrics` – metrics on TCP **8080**
- TLS
    - `Certificate/carbide-pxe-certificate` → `Secret/carbide-pxe-certificate`
- RBAC
    - `ServiceAccount/carbide-pxe`
    - `Role/RoleBinding carbide-pxe` (CertificateRequests for cert‑manager)

The pod mounts SPIFFE material at `/var/run/secrets/spiffe.io`, reads Rocket/pxe config from `/tmp/carbide`, and reloads when the `carbide-pxe-config` ConfigMap changes.

### External inputs you must provide

- A published PXE image (override `yourdockerregistry.com/path/to/carbide-core:latest`).
- ConfigMap(s) with `Rocket.toml` / templates at `/tmp/carbide` plus any env ConfigMap (`carbide-pxe-env-config`) your boot flow requires.
- A cert‑manager `ClusterIssuer` for the SPIFFE certificate.

### Quick start

1. Build/publish the PXE image and patch the Deployment to use it.
2. Create the config/env ConfigMaps referenced above.
3. Deploy PXE:

   ```bash
   kubectl apply -k deploy/carbide-base/pxe -n <CARBIDE_NAMESPACE>
   ```

---

## Carbide SSH Console

**Role**  
`carbide-ssh-console-rs` exposes SSH access to server and DPU consoles, querying carbide‑api for targets and shipping console logs through an embedded OpenTelemetry collector.

### What it deploys

Path: `deploy/carbide-base/ssh-console-rs/`

- Deployment `carbide-ssh-console-rs` (SSH server + OTel collector sidecar)
- Services
    - `carbide-ssh-console-rs` – SSH on TCP **22**
    - `carbide-ssh-console-rs-metrics` – metrics on TCP **9009**
- Config
    - ConfigMaps `ssh-console-rs-config-files` (`config.toml`) and `ssh-console-rs-otelcol-config`
    - KSOPS generator `ssh-host-key-secret-generator.yaml` → `Secret/ssh-host-key`
- TLS
    - `Certificate/carbide-ssh-console-rs-certificate` → `Secret/carbide-ssh-console-rs-certificate`
- RBAC
    - `ServiceAccount/carbide-ssh-console-rs`
    - `Role/RoleBinding carbide-ssh-console-rs` (CertificateRequests)

Key settings live in `config-files/config.toml` (carbide‑api URL, SPIFFE cert paths, SSH CA fingerprints, logging paths). The sidecar tails `/var/log/consoles` using the OTel config.

### External inputs you must provide

- Fill out `config.toml` with your carbide‑api endpoint, trusted CA fingerprints, and any authorized keys or test settings.
- Provide an encrypted `secrets/ssh_host_key.enc.yaml` so KSOPS can create `ssh-host-key`.
- Add exporters/remote targets to `config-files/otelcol-config.yaml` (for example, a Loki endpoint).
- A cert‑manager `ClusterIssuer` compatible with the SPIFFE certificate.

### Quick start

1. Update the ConfigMaps and KSOPS secret with your site settings.
2. Ensure cert‑manager can issue via `vault-forge-issuer` (or patch the issuerRef).
3. Deploy SSH console:

   ```bash
   kubectl apply -k deploy/carbide-base/ssh-console-rs -n <CARBIDE_NAMESPACE>
   ```

---

## Carbide Base Kustomization

**Role**  
`deploy/carbide-base/kustomization.yaml` bundles the core Carbide services into one base for overlays.

### What it includes

- Applies shared labels and disables name suffix hashing for stable resource names.
- Aggregates:
    - `api`
    - `dhcp`
    - `dns`
    - `hardware-health`
    - `pxe`
    - `ssh-console-rs`
    - `ntp`

### Quick start

- Apply the full base (optionally with your overlay):

   ```bash
   kubectl apply -k deploy/carbide-base -n <CARBIDE_NAMESPACE>
   ```

---

## Carbide Unbound Base

**Role**  
`carbide-unbound` provides a **recursive DNS resolver** for Carbide deployments. Authoritative services (like `carbide-dns`) can forward unknown lookups here, and the included exporter publishes Prometheus metrics for Unbound.

### What it deploys

Path: `deploy/carbide-unbound-base/`

- Deployment `carbide-unbound` with the Unbound server and `unbound_exporter` sidecar (config reload via Stakater reloader annotations).
- Service `carbide-unbound` – DNS on UDP/TCP **53**, metrics on TCP **9167**.
- ConfigMaps
    - `unbound-envvars` from `unbound.env` (sets `LOCAL_CONFIG_DIR`, `BROKEN_DNSSEC`, `UNBOUND_CONTROL_DIR`).
    - `unbound-local-config` from `local.conf.d/*.conf`, including access controls, verbosity, extended statistics, and an `unknowndomain` blocklist plus a placeholder `forwarders.conf` you should replace with your upstream resolvers.
- Volumes
    - ConfigMap mount at `/etc/unbound/local.conf.d`
    - EmptyDir at `/etc/unbound/keys` for Unbound control keys shared with the exporter
- Image pull secret reference: `imagepullsecret` (patch or replace for your registry).

### External inputs you must provide

- Publish or point the Deployment images to your registry (`unbound` and `unbound_exporter`).
- Provide upstream DNS forwarders by replacing `local.conf.d/patchme.conf` (the source for `forwarders.conf`) with the `forward-zone`/`stub-zone` config your environment requires.
- Ensure the `imagepullsecret` exists in the namespace or update the Deployment to the correct secret name.
- Optionally tighten `access_control.conf` to limit which networks can query the resolver.

### Quick start

1. Add your upstream resolver config to `local.conf.d/patchme.conf` (or replace the `forwarders.conf` entry in kustomization) and update the container images.
2. Confirm the image pull secret name matches your registry credentials.
3. Deploy Unbound:

   ```bash
   kubectl apply -k deploy/carbide-unbound-base -n <CARBIDE_NAMESPACE>
   ```

---

## Components

**Role**  
Reusable Kustomize components that layer registry credentials and boot artifact sidecars onto Carbide workloads.

### What it includes

Path: `deploy/components/`

- Component `boot-artifacts-containers` – JSON6902 patch that adds an EmptyDir volume plus sidecar containers to `carbide-pxe` and `carbide-api` Deployments. The sidecars copy `x86_64`, `aarch64`, `apt`, `firmware`, and machine-validation artifacts into `/forge-boot-artifacts/blobs/internal`, including a legacy x86_64 image for backward compatibility.
- Component `imagepullsecret` – JSON6902 patch that injects an `imagepullsecret` reference into all Deployments, Jobs, and StatefulSets.

### External inputs you must provide

- Publish the boot artifact container images (x86_64, aarch64, legacy x86_64, machine-validation) to your registry and override the placeholders in the parent Kustomization.
- Create the `imagepullsecret` Secret in the target namespace or change the referenced name in the patch.

### Quick start

1. Add the components to your overlay:

   ```yaml
   components:
     - ../components/boot-artifacts-containers
     - ../components/imagepullsecret
   ```

2. Ensure the boot artifact images are available and the `imagepullsecret` exists.
3. Components are used in `forge-system` kustomization
---

## Forge System

**Role**  
Reference overlay that deploys Carbide + Unbound into the `forge-system` namespace with external access points and environment defaults.

### What it deploys

Path: `deploy/forge-system/`

- Namespace `forge-system` plus a Kustomize base that pulls in `../carbide-base` and `../carbide-unbound-base`.
- Components `../components/imagepullsecret` and `../components/boot-artifacts-containers`.
- External `Service`s for DHCP, PXE (80/8080), API (443→1079), SSH console (22), DNS (per‑pod TCP/UDP 53), and NTP (per‑pod UDP 123).
- ConfigMaps generated for `carbide-dns`, `forge-system-carbide-database-config`, and `vault-cluster-info` with default literals for this environment.
- Certificate patches that add namespace‑specific DNSNames and SPIFFE URIs for all Carbide cert-manager `Certificate`s, plus a patch targeting the `forge-pg-cluster` Postgres resource.
- Name suffix hashing disabled to keep stable names.

### External inputs you must provide

- Assign LoadBalancer IPs / addresses for the external Services (for example via the parent `deploy/kustomization.yaml` Metallb patches) or adapt to your cloud LB configuration.
- Ensure the `forge-pg-cluster` Postgres instance and the secret referenced by `SECRET_REF` exist, or update the literals.
- Point the Vault settings (`VAULT_SERVICE`, mounts) at your Vault cluster, or patch the ConfigMap.
- Provide the `imagepullsecret` Secret in `forge-system` and publish the boot artifact images referenced by the components.

### Quick start

1. Update the literals and image overrides in `deploy/forge-system/kustomization.yaml` (and the top-level `deploy/kustomization.yaml` if you use the Metallb IP patches) to match your environment.
2. Apply the overlay:

   ```bash
   kubectl apply -k deploy/forge-system
   ```

3. Confirm LoadBalancer IPs are assigned and cert-manager issues the Carbide certificates.
