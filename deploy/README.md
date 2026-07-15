
# Kustomization inputs

The `deploy/kustomization.yaml` file drives the top‑level deployment. Populate the placeholders below before applying any overlays.

| Value | Description |
| --- | --- |
| `yourdockerregistry.com/path/to/nico-core` | Source image placeholder rewritten to `NICO_REGISTRY_PATH/nico-core` by `deploy/kustomization.yaml`. |
| `NICO_REGISTRY_PATH` | URL to the registry that hosts all NICo components; shared path for component images. |
| `NICO_TAG` | Version tag for the NICo Core (`nico-core`) image. |
| `yourdockerregistry.com/path/to/boot-artifacts-aarch64` | Registry URL for the `boot-artifacts-aarch64` image. |
| `BOOT_ARTIFACTS_AARCH64_TAG` | Version tag for the `boot-artifacts-aarch64` component. |
| `yourdockerregistry.com/path/to/boot-artifacts-x86_64` | Registry URL for the `boot-artifacts-x86_64` image. |
| `BOOT_ARTIFACTS_X86_TAG` | Version tag for the `boot-artifacts-x86_64` component. |
| `yourdockerregistry.com/path/to/nvmetal-scout-burn-in` | Registry URL for the `machine_validation` image. |
| `MACHINE_VALIDATION_TAG` | Version tag for the `machine_validation` component. |
| `NICO_DHCP_EXTERNAL_IP` | IP address used by the NICo DHCP service. |
| `NICO_DNS_INSTANCE_0_IP` | First IP address for NICo DNS; allocate contiguous pair. |
| `NICO_DNS_INSTANCE_1_IP` | Second IP address for NICo DNS; allocate contiguous pair. |
| `NICO_PXE_IP` | IP address for the NICo PXE service. |
| `NICO_API_EXTERNAL_IP` | IP address for the API service; typically also mapped to `api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>`. |
| `NICO_SSH_CONSOLE_EXTERNAL_IP` | IP address for BMC console access service in NICo. |
| `NICO_UNBOUND_EXTERNAL_IP` | IP address for the Unbound recursive DNS service. |
| `ENVIORNMENT_NAME` | Site name used to identify this NICo deployment. |
| `SITE_DOMAIN_NAME` | Site domain name used for NICo endpoints (e.g., `api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>`). |
| `NICO_NTP_SERVERS_IP_0` | First NTP service IP address. |
| `NICO_NTP_SERVERS_IP_1` | Second NTP service IP address. |
| `NICO_NTP_SERVERS_IP_2` | Third NTP service IP address. |
| `NICO_STATIC_PXE_IP` | IP address for the static boot asset server (`nico-static-pxe.nico`). |
| `SOCKS_EXTERNAL_IP` | IP address for the SOCKS5 outbound proxy (`socks.nico`). |

## Files inputs (deploy/files/)

The templates in `deploy/files/` are mounted into services and must be filled with your site‑specific values. Use your IP plan, DNS domain, and certificate authority to derive the values; avoid copying any sample values.

- `deploy/files/nico-api/admin_root_cert_pem` – place the PEM‑encoded root CA chain used to authenticate NICo admins (matches the CA trusted by the admin CLI). Generate this from your CA and keep private keys elsewhere.
- `deploy/files/nico-api/nico-api-site-config.toml` – set site identifiers (`ENVIRONMENT_NAME`, `SITE_DOMAIN_NAME`), admin network pool and gateway, service VIPs (API, DHCP, DNS, PXE, SSH console, NGINX/proxy, Unbound), tenant overlay prefixes, and IPMI pools/names for controllers and managed hosts. Ensure service VIPs come from your chosen /27 (or equivalent) VIP pool and that IPMI pools each have a gateway and unique network name.
- `deploy/files/unbound/forwarders.conf` – list upstream recursive DNS endpoints reachable from the cluster. Use IPs for resolvers allowed to recurse for your site.
- `deploy/files/unbound/local_data.conf` – defines static DNS A records for NICo services, including all `.nico` service endpoints (API, PXE, static PXE, NTP, Unbound, otel-receiver, and SOCKS proxy) and any additional site-specific names (e.g., `api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>`). Map each hostname to the corresponding service VIP you selected above. Several `.nico` hostnames are hardcoded in compiled binaries and must resolve correctly before DPU agents can start. See [`.nico` DNS Zone — Service Endpoint Reference](DNS.md) for the full list of hostnames, required ports, and which entries are hardcoded.
- `deploy/files/kea_config.json` – provide the Kea DHCPv4 configuration tailored to your admin/tenant networks, including option definitions, subnets, pools, and relay settings. Reference the same service IPs used elsewhere and ensure leases align with the admin network pool.
- `deploy/files/vtysh.conf` – FRRouting vtysh shell configuration. Align hostname and service addresses here with the FRR service IPs chosen from your service VIP pool.

After populating `deploy/kustomization.yaml` and all files under `deploy/files/`, deploy everything with:

```bash
kustomize build . --enable-helm --enable-alpha-plugins --enable-exec | kubectl apply -f -
```

# NICo core services (bare‑metal provisioning)

This document summarizes the Kubernetes components that make up the **NICo core** bare‑metal provisioning system and how to get started deploying them.

NICo is responsible for:

- Managing the full lifecycle of bare‑metal machines in one or more L2 networks (subnets).
- Owning DHCP and IP addressing within those subnets.
- Discovering new machines automatically
- Driving machines through a state machine using power control (IPMI / Redfish).
- Inventorying hardware
- Exposing a single **gRPC API** that all NICo services and external clients talk to.

All examples below assume you have chosen a namespace such as **`nico-system`**; adjust as needed.

---

## NICo API

**Role**  
The **nico‑api** deployment is the control‑plane API for all bare‑metal operations. Other NICo services (DHCP, DNS, hardware‑health, PXE, UI, etc.) and cloud components talk to this service over mTLS‑protected gRPC.

### What it deploys

Path: `deploy/nico-base/api/`

- Deployment `nico-api` (gRPC API)
- Job `nico-api-migrate` (database migrations)
- Services
    - `nico-api` – gRPC, port **1079**
    - `nico-api-metrics` – metrics, port **1080**
    - `nico-api-profiler` – profiler, port **1081**
- ConfigMaps
    - `nico-api-config-files` – base config (`nico-api-config.toml`, `casbin-policy.csv`)
    - `nico-api-site-config-files` – overlay for site‑specific TOML (empty in base)
- TLS
    - `Certificate/nico-api-certificate` → `Secret/nico-api-certificate` (SPIFFE‑style mTLS)
- RBAC
    - `ServiceAccount/nico-api`
    - `Role/RoleBinding nico-api` – allows creating cert‑manager `CertificateRequest`s

### External inputs you must provide

- **Database access**
    - Secret with DB credentials: `<NICO_DB_CREDENTIALS_SECRET>` (keys: `username`, `password`)
    - ConfigMap for DB endpoint: `<NICO_DB_CONFIGMAP>` (keys: `DB_HOST`, `DB_PORT`, `DB_NAME`)
- **Vault access**
    - Secret `<NICO_VAULT_TOKEN_SECRET>` or AppRole secret with `VAULT_ROLE_ID` / `VAULT_SECRET_ID`
    - ConfigMap `<VAULT_CLUSTER_INFO_CONFIGMAP>` with
        - `VAULT_SERVICE`
        - `NICO_VAULT_MOUNT`
        - `NICO_VAULT_PKI_MOUNT`
- **Root CA bundle**
    - Secret `<NICO_ROOT_CA_SECRET>` mounted where `nico-api-config.toml` expects it.

### Configuration notes

- Runtime config lives in `nico-api-config.toml` and is overlaid by a site‑specific TOML in `nico-api-site-config-files`.
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
3. Optionally add a `nico-api-site-config.toml` via an overlay and include it in `nico-api-site-config-files`.
4. Apply the base (or your overlay):

   ```bash
   kubectl apply -k deploy/nico-base/api -n <NICO_NAMESPACE>
   ```

---

## NICo DHCP

**Role**  
`nico-dhcp` is the **authoritative DHCP server** for NICo‑managed subnets. It runs Kea DHCPv4 and is the endpoint that **tenant ToR switches or DHCP relays point to**. When a tenant node PXE boots or requests an address, this service assigns IPs and options according to your Kea configuration.

### What it deploys

Path: `deploy/nico-base/dhcp/`

- Deployment `nico-dhcp`
- Services
    - `nico-dhcp` – DHCP on UDP **67**
    - `nico-dhcp-metrics` – metrics on TCP **1089**
- TLS
    - `Certificate/nico-dhcp-certificate` → `Secret/nico-dhcp-certificate`
- RBAC
    - `ServiceAccount/nico-dhcp`
    - `Role/RoleBinding nico-dhcp`

The pod:

- Runs Kea DHCPv4 via `kea-dhcp4 -c /tmp/kea_config.json`
- Mounts SPIFFE client certs at `/var/run/secrets/spiffe.io`
- Mounts a `ConfigMap` at `/tmp` that must contain `kea_config.json`

### External inputs you must provide

- ConfigMap `<NICO_DHCP_CONFIGMAP>` with your Kea JSON config (key/file mapping to `/tmp/kea_config.json`).
- A cert‑manager `ClusterIssuer` capable of issuing `nico-dhcp-certificate` (for SPIFFE‑style mTLS to nico‑api or other services).

### Quick start

1. Write a small Kea config JSON for your tenant subnet and create the DHCP ConfigMap.
2. Point your tenant switches / DHCP relay to the `nico-dhcp` Service IP (UDP/67).
3. Deploy DHCP:

   ```bash
   kubectl apply -k deploy/nico-base/dhcp -n <NICO_NAMESPACE>
   ```

---

## NICo DNS

**Role**  
`nico-dns` is the **authoritative DNS service** for NICo‑managed hosts and internal services. It answers queries for the internal zones and forwards anything else to a recursive resolver such as the Unbound deployment.

### What it deploys

Path: `deploy/nico-base/dns/`

- StatefulSet `nico-dns`
- Service `nico-dns` – UDP/TCP **53**
- TLS
    - `Certificate/nico-dns-certificate` → `Secret/nico-dns-certificate`
- RBAC
    - `ServiceAccount/nico-dns`
    - `Role/RoleBinding nico-dns`

### External inputs you must provide

- ConfigMap `<NICO_DNS_CONFIGMAP>` with at least:
    - `NICO_API` – URL for the nico‑api gRPC endpoint (e.g. `https://nico-api.<NICO_NAMESPACE>.svc.cluster.local:1079`).
    - Any additional DNS or zone settings your environment requires.
- A cert‑manager `ClusterIssuer` for `nico-dns-certificate`.

### Quick start

1. Create the DNS ConfigMap with `NICO_API` pointing at your nico‑api Service.
2. Ensure cert‑manager is running and the ClusterIssuer for `nico-dns-certificate` exists.
3. Deploy DNS:

   ```bash
   kubectl apply -k deploy/nico-base/dns -n <NICO_NAMESPACE>
   ```

---

## NICo Hardware Health

**Role**  
`nico-hardware-health` continuously polls host and DPU BMCs for health information (fans, temperatures, leak sensors, etc.), exposes those metrics via Prometheus, and notifies nico‑api when it detects problems so operators get alerts on failing hardware.

### What it deploys

Path: `deploy/nico-base/hardware-health/`

- Deployment `nico-hardware-health`
- Service `nico-hardware-health` – HTTP metrics on TCP **9009**
- TLS
    - `Certificate/nico-hardware-health-certificate` → `Secret/nico-hardware-health-certificate`
- RBAC
    - `ServiceAccount/nico-hardware-health`
    - `Role/RoleBinding nico-hardware-health`

The pod:

- Uses SPIFFE certs from `/var/run/secrets/spiffe.io` to talk back to nico‑api.
- Exposes Prometheus metrics at `:9009/metrics`.

### External inputs you must provide

- A reachable nico‑api endpoint.
- A Prometheus instance (or other metrics system) scraping the `nico-hardware-health` Service.
- A cert‑manager `ClusterIssuer` for the hardware‑health certificate.

### Quick start

1. Confirm nico‑api is running and reachable from `<NICO_NAMESPACE>`.
2. Deploy hardware health:

   ```bash
   kubectl apply -k deploy/nico-base/hardware-health -n <NICO_NAMESPACE>
   ```

3. Point Prometheus at `nico-hardware-health:9009` to ingest metrics.

---

## NICo NTP

**Role**  
`nico-ntp` provides a redundant chrony‑based NTP service for NICo clusters.

### What it deploys

Path: `deploy/nico-base/ntp/`

- StatefulSet `nico-ntp` (3 replicas with pod anti‑affinity)
- Headless Service `nico-ntp` – NTP on UDP **123** (pods reachable via `nico-ntp-<i>.nico-ntp.<NICO_NAMESPACE>.svc`)

The container runs `dockurr/chrony` and reads `NTP_SERVERS` / `NTP_DIRECTIVES` from env vars.

### External inputs you must provide

- Update `NTP_SERVERS` to point at your upstream time sources plus the peer pods (adjust the default `nico-system` namespace in an overlay).
- Optionally set `NTP_DIRECTIVES` for additional chrony tuning.

### Quick start

1. Patch the StatefulSet env to your upstream NTP servers.
2. Deploy NTP:

   ```bash
   kubectl apply -k deploy/nico-base/ntp -n <NICO_NAMESPACE>
   ```

3. Hand out the `nico-ntp` pod hostnames via DHCP option 42 or node configs.

---

## NICo PXE

**Role**  
`nico-pxe` serves the HTTP/iPXE entrypoint and boot artifacts for tenant machines, using SPIFFE certs to call back into NICo services.

### What it deploys

Path: `deploy/nico-base/pxe/`

- Deployment `nico-pxe`
- Services
    - `nico-pxe` – HTTP on TCP **8080**
    - `nico-pxe-metrics` – metrics on TCP **8080**
- TLS
    - `Certificate/nico-pxe-certificate` → `Secret/nico-pxe-certificate`
- RBAC
    - `ServiceAccount/nico-pxe`
    - `Role/RoleBinding nico-pxe` (CertificateRequests for cert‑manager)

The pod mounts SPIFFE material at `/var/run/secrets/spiffe.io`, reads Rocket/pxe config from `/tmp/nico`, and reloads when the `nico-pxe-config` ConfigMap changes.

### External inputs you must provide

- A published PXE image (override `yourdockerregistry.com/path/to/nico-core:latest`).
- ConfigMap(s) with `Rocket.toml` / templates at `/tmp/nico` plus any env ConfigMap (`nico-pxe-env-config`) your boot flow requires.
- A cert‑manager `ClusterIssuer` for the SPIFFE certificate.

### Quick start

1. Build/publish the PXE image and patch the Deployment to use it.
2. Create the config/env ConfigMaps referenced above.
3. Deploy PXE:

   ```bash
   kubectl apply -k deploy/nico-base/pxe -n <NICO_NAMESPACE>
   ```

---

## NICo SSH Console

**Role**  
`nico-ssh-console-rs` exposes SSH access to server and DPU consoles, querying nico‑api for targets and shipping console logs through an embedded OpenTelemetry collector.

### What it deploys

Path: `deploy/nico-base/ssh-console-rs/`

- Deployment `nico-ssh-console-rs` (SSH server + OTel collector sidecar)
- Services
    - `nico-ssh-console-rs` – SSH on TCP **22**
    - `nico-ssh-console-rs-metrics` – metrics on TCP **9009**
- Config
    - ConfigMaps `ssh-console-rs-config-files` (`config.toml`) and `ssh-console-rs-otelcol-config`
    - KSOPS generator `ssh-host-key-secret-generator.yaml` → `Secret/ssh-host-key`
- TLS
    - `Certificate/nico-ssh-console-rs-certificate` → `Secret/nico-ssh-console-rs-certificate`
- RBAC
    - `ServiceAccount/nico-ssh-console-rs`
    - `Role/RoleBinding nico-ssh-console-rs` (CertificateRequests)

Key settings live in `config-files/config.toml` (nico‑api URL, SPIFFE cert paths, SSH CA fingerprints, logging paths). The sidecar tails `/var/log/consoles` using the OTel config.

### External inputs you must provide

- Fill out `config.toml` with your nico‑api endpoint, trusted CA fingerprints, and any authorized keys or test settings.
- Provide an encrypted `secrets/ssh_host_key.enc.yaml` so KSOPS can create `ssh-host-key`.
- Add exporters/remote targets to `config-files/otelcol-config.yaml` (for example, a Loki endpoint).
- A cert‑manager `ClusterIssuer` compatible with the SPIFFE certificate.

### Quick start

1. Update the ConfigMaps and KSOPS secret with your site settings.
2. Ensure cert‑manager can issue via `vault-nico-issuer` (or patch the issuerRef).
3. Deploy SSH console:

   ```bash
   kubectl apply -k deploy/nico-base/ssh-console-rs -n <NICO_NAMESPACE>
   ```

---

## NICo Base Kustomization

**Role**  
`deploy/nico-base/kustomization.yaml` bundles the core NICo services into one base for overlays.

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
   kubectl apply -k deploy/nico-base -n <NICO_NAMESPACE>
   ```

---

## NICo Unbound Base

**Role**  
`nico-unbound` provides a **recursive DNS resolver** for NICo deployments. Authoritative services (like `nico-dns`) can forward unknown lookups here, and the included exporter publishes Prometheus metrics for Unbound.

### What it deploys

Path: `deploy/nico-unbound-base/`

- Deployment `nico-unbound` with the Unbound server and `unbound_exporter` sidecar (config reload via Stakater reloader annotations).
- Service `nico-unbound` – DNS on UDP/TCP **53**, metrics on TCP **9167**.
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
   kubectl apply -k deploy/nico-unbound-base -n <NICO_NAMESPACE>
   ```

---

## Components

**Role**  
Reusable Kustomize components that layer registry credentials and boot artifact sidecars onto NICo workloads.

### What it includes

Path: `deploy/components/`

- Component `boot-artifacts-containers` – JSON6902 patch that adds an EmptyDir volume plus sidecar containers to `nico-pxe` and `nico-api` Deployments. The sidecars copy `x86_64`, `aarch64`, `apt`, `firmware`, and machine-validation artifacts into `/nico-boot-artifacts/blobs/internal`, including a legacy x86_64 image for backward compatibility.
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
3. Components are used in `nico-system` kustomization
---

## NICo System

**Role**  
Reference overlay that deploys NICo + Unbound into the `nico-system` namespace with external access points and environment defaults.

### What it deploys

Path: `deploy/nico-system/`

- Namespace `nico-system` plus a Kustomize base that pulls in `../nico-base` and `../nico-unbound-base`.
- Components `../components/imagepullsecret` and `../components/boot-artifacts-containers`.
- External `Service`s for DHCP, PXE (80/8080), API (443→1079), SSH console (22), DNS (per‑pod TCP/UDP 53), and NTP (per‑pod UDP 123).
- ConfigMaps generated for `nico-dns`, `nico-system-nico-database-config`, and `vault-cluster-info` with default literals for this environment.
- Certificate patches that add namespace‑specific DNSNames and SPIFFE URIs for all NICo cert-manager `Certificate`s, plus a patch targeting the `nico-pg-cluster` Postgres resource.
- Name suffix hashing disabled to keep stable names.

### External inputs you must provide

- Assign LoadBalancer IPs / addresses for the external Services (for example via the parent `deploy/kustomization.yaml` Metallb patches) or adapt to your cloud LB configuration.
- Ensure the `nico-pg-cluster` Postgres instance and the secret referenced by `SECRET_REF` exist, or update the literals.
- Point the Vault settings (`VAULT_SERVICE`, mounts) at your Vault cluster, or patch the ConfigMap.
- Provide the `imagepullsecret` Secret in `nico-system` and publish the boot artifact images referenced by the components.

### Quick start

1. Update the literals and image overrides in `deploy/nico-system/kustomization.yaml` (and the top-level `deploy/kustomization.yaml` if you use the Metallb IP patches) to match your environment.
2. Apply the overlay:

   ```bash
   kubectl apply -k deploy/nico-system
   ```

3. Confirm LoadBalancer IPs are assigned and cert-manager issues the NICo certificates.
