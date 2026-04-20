# `.forge` DNS Zone — Service Endpoint Reference

## Overview

NICo (ncx-infrastructure-controller) depends on a set of well-known hostnames in the `.forge` DNS zone. These names are resolved by DPU agents, host PXE loaders, and other in-band management components at runtime. Several of these hostnames are **compiled into binaries or embedded shell scripts** and cannot be changed without rebuilding the software.

Before deploying NICo, you must configure DNS A records that resolve each `.forge` hostname to the appropriate service virtual IP (VIP) on your out-of-band (OOB) management network. A site-local recursive resolver (Unbound or equivalent) running on your site controller is the recommended approach.

---

## Endpoint Quick Reference

| Hostname | Port | Protocol | Consumers | Backing Service | Purpose |
|---|---|---|---|---|---|
| `carbide-api.forge` | 443 | gRPC / TLS | DPU agents, admin CLI, PXE service, DHCP plugin, FMDS, health probe | `carbide-api` pod | NICo gRPC API |
| `carbide-pxe.forge` | 80 | HTTP | DPU agents, iPXE clients | `carbide-pxe` pod | iPXE scripts, cloud-init payloads, boot artifacts, internal APT |
| `carbide-static-pxe.forge` | 80 | HTTP | Host PXE loader (scout) | `carbide-static-pxe` pod | Static boot files: `scout.cpio.zst`, `scout.efi`, BFB images |
| `carbide-ntp.forge` | 123 | UDP (NTP) | DPU agents, managed hosts (DHCP option 42) | `carbide-ntp` pods | NTP time synchronisation |
| `unbound.forge` | 53 | UDP / TCP (DNS) | DPU agents, managed hosts (DHCP option 6) | `forge-unbound` pod | Site-local recursive DNS resolver |
| `otel-receiver.forge` | 443 | gRPC / TLS (OTLP) | DPU otel-collector sidecars | otel-receiver service | OpenTelemetry ingestion endpoint |
| `socks.forge` | 1888 | SOCKS5 | DPU agent extension service pods | SOCKS5 proxy service | Outbound HTTP/HTTPS proxy for DPU-hosted workloads |

---

## Endpoint Details

### `carbide-api.forge` — NICo gRPC API

**Port:** 443 (TLS)  
**Protocol:** gRPC over TLS  
**In-cluster address:** `carbide-api.forge-system.svc.cluster.local:1079`

The primary NICo management API. All management-plane components communicate with NICo through this address. Clients on the OOB network connect on port 443; the pod itself listens on port 1079.

**Consumers:**
- `carbide-agent` (DPU agent) — phones home for network configuration, workflow state, and provisioning instructions
- `carbide-admin-cli` — operator administration over gRPC
- `carbide-pxe` — fetches machine records to generate per-machine cloud-init and iPXE scripts
- `carbide-dhcp` DHCP plugin — queries the API during DHCPDISCOVER
- Forge Metadata Service (`fmds`) — metadata queries and distribution
- `health` probe service — periodic health polling

**Configurability:** Most services accept a `CARBIDE_API_URL` environment variable or an equivalent config file entry to override this address. The compiled default in binaries and config files is `https://carbide-api.forge`. Because this is a default rather than a hardcoded constant, it can be overridden at deploy time without rebuilding.

---

### `carbide-pxe.forge` — PXE / Boot Service

**Port:** 80 (HTTP)  
**Protocol:** HTTP  
**In-cluster address:** `carbide-pxe.forge-system.svc.cluster.local`

Serves dynamic per-machine iPXE boot scripts, cloud-init payloads, boot artifacts, and the internal APT package repository to DPU agents and PXE-booting clients.

**Consumers:**
- `carbide-agent` (DPU agent) — resolves this hostname at startup to locate boot artifacts and the internal APT repository (paths under `/public/blobs/internal/`)
- iPXE clients during initial machine network boot

**Configurability:** The DPU agent (`crates/agent/src/main_loop.rs`) resolves `carbide-pxe.forge` directly via DNS. **This lookup is not overridable via config in the compiled agent.** The PXE service itself accepts a `CARBIDE_PXE_URL` environment variable to override the URL it advertises to clients, but the agent's DNS lookup for this name is fixed.

> **Warning:** `carbide-pxe.forge` is hardcoded in the compiled `carbide-agent` binary (`crates/agent/src/main_loop.rs`). This DNS record must exist and resolve correctly on the OOB network for DPU agents to function. Changing this hostname requires rebuilding the DPU agent.

---

### `carbide-static-pxe.forge` — Static Boot Asset Server

**Port:** 80 (HTTP)  
**Protocol:** HTTP  
**In-cluster address:** `carbide-static-pxe.forge-system.svc.cluster.local`

Serves pre-built, version-controlled boot assets used during host bring-up. Unlike `carbide-pxe.forge`, content here is static rather than dynamically generated per machine.

**Consumers:**
- Scout host PXE loader — downloads `scout.cpio.zst` (the initramfs), `scout.efi`, and BFB images used during host network boot and DPU firmware provisioning

**Configurability:** The URL is hardcoded in host boot shell scripts (`pxe/common_files/scout-loader-rclocal`, `pxe/common_files/check-scout-updates.sh`) that are embedded in boot images at build time. The server-side deployment can set `CARBIDE_STATIC_PXE_URL` to override the URL used by the PXE service, but the embedded client scripts that run on hosts **cannot be reconfigured at runtime**.

> **Warning:** `carbide-static-pxe.forge` is hardcoded in host boot scripts compiled into boot images (`pxe/common_files/scout-loader-rclocal`, `pxe/common_files/check-scout-updates.sh`). Changing this hostname requires rebuilding all host boot images.

---

### `carbide-ntp.forge` — NTP Service

**Port:** 123 (UDP)  
**Protocol:** NTP  
**In-cluster addresses:** `carbide-ntp-1.carbide-ntp.forge-system.svc.cluster.local`, `carbide-ntp-2.carbide-ntp.forge-system.svc.cluster.local`, `carbide-ntp-3.carbide-ntp.forge-system.svc.cluster.local`

Provides NTP time synchronisation for DPU agents and managed hosts. The service is backed by three pods for redundancy; configure multiple DNS A records for `carbide-ntp.forge` pointing to each pod's VIP.

**Consumers:**
- `carbide-agent` (DPU agent) — resolves `carbide-ntp.forge` at startup to discover NTP server addresses; the resolved addresses are also pushed to managed hosts via DHCP option 42

**Configurability:** The DPU agent resolves `carbide-ntp.forge` directly via DNS (`crates/agent/src/main_loop.rs`). **This lookup is not overridable via config in the compiled agent.**

> **Warning:** `carbide-ntp.forge` is hardcoded in the compiled `carbide-agent` binary (`crates/agent/src/main_loop.rs`). This DNS record must exist and resolve correctly on the OOB network. Changing this hostname requires rebuilding the DPU agent.

**Multiple A records (recommended):** Configure one A record per NTP pod instance to provide redundancy. Clients will receive all addresses and select among them.

---

### `unbound.forge` — Recursive DNS Resolver

**Port:** 53 (UDP and TCP)  
**Protocol:** DNS  
**In-cluster service:** `forge-unbound` in the `forge-system` namespace

The site-local recursive DNS resolver. DPU agents and managed hosts use this resolver for all DNS lookups, including resolution of other `.forge` names. The resolver address is distributed to clients via DHCP option 6.

**Consumers:**
- DPU agents — all DNS resolution during provisioning and normal operation
- Managed host operating systems — configured as the primary name server via DHCP

**Configurability:** The resolver address is not compiled into binaries; it is distributed to clients via DHCP and can be changed by updating the DHCP server configuration. The `.forge` zone data must be loaded into Unbound (see [DNS Configuration](#dns-configuration) below) for all other hostnames in this document to resolve correctly.

---

### `otel-receiver.forge` — OpenTelemetry Receiver

**Port:** 443 (TLS)  
**Protocol:** gRPC / TLS (OTLP — OpenTelemetry Protocol)

Ingests telemetry (metrics, traces, and logs) exported by otel-collector sidecars running on managed BlueField DPUs.

**Consumers:**
- `carbide-otelcol` — the otel-collector sidecar deployed on each DPU via the `bluefield/charts/carbide-otelcol` Helm chart
- Site controller otel agents (`bluefield/otel/site-controller/`)

**Configurability:** The endpoint is set in otel-collector configuration YAML files (`bluefield/charts/carbide-otelcol/files/otel_config.yaml`, `bluefield/otel/otel_config.yaml`, `bluefield/otel/site-controller/otel_config.yaml`). Changing the address requires updating those files and redeploying the otel-collector.

---

### `socks.forge` — SOCKS5 Outbound Proxy

**Port:** 1888  
**Protocol:** SOCKS5

Provides outbound HTTP/HTTPS connectivity for Kubernetes workloads launched by the DPU agent as extension services. The agent sets `HTTP_PROXY=socks5://socks.forge:1888` and `HTTPS_PROXY=socks5://socks.forge:1888` in the environment of every extension service pod it starts.

**Consumers:**
- Kubernetes pods launched by the DPU agent as extension services (`crates/agent/src/extension_services/k8s_pod_handler.rs`)

**Configurability:** The proxy address and port are **hardcoded in the compiled `carbide-agent` binary** (`crates/agent/src/extension_services/k8s_pod_handler.rs`). Changing this address requires rebuilding the DPU agent.

> **Warning:** `socks.forge:1888` is hardcoded in the compiled `carbide-agent` binary (`crates/agent/src/extension_services/k8s_pod_handler.rs`).

---

## Network Topology

`.forge` service endpoints are hosted on the site controller (control plane). All service VIPs have their routes injected into both the underlay and the overlay.

**DPU agents** and **managed hosts** reach `.forge` endpoints over the OOB/admin management network. All `.forge` names must be resolvable from this network path.

**Tenant workloads** can reach the service VIPs at the IP level but are not configured to use `unbound.forge` as their DNS resolver and will not resolve `.forge` names.

---

## Hardcoded vs. Configurable Endpoints

| Hostname | Hardcoded in | Configurable at deploy time? |
|---|---|---|
| `carbide-api.forge` | Default value only (`crates/host-support/src/agent_config.rs`, config defaults across services) | **Yes** — override via `CARBIDE_API_URL` env var or config file |
| `carbide-pxe.forge` | Compiled into `carbide-agent` (`crates/agent/src/main_loop.rs`) | **No** — requires rebuilding `carbide-agent` |
| `carbide-static-pxe.forge` | Embedded in host boot scripts (`pxe/common_files/scout-loader-rclocal`, `pxe/common_files/check-scout-updates.sh`) | **No** — requires rebuilding host boot images |
| `carbide-ntp.forge` | Compiled into `carbide-agent` (`crates/agent/src/main_loop.rs`) | **No** — requires rebuilding `carbide-agent` |
| `unbound.forge` | Not compiled into binaries; distributed via DHCP option 6 | **Yes** — update DHCP server configuration |
| `otel-receiver.forge` | otel-collector config YAML (`bluefield/charts/carbide-otelcol/files/otel_config.yaml`, etc.) | **Yes** — update otel-collector config files and redeploy |
| `socks.forge` | Compiled into `carbide-agent` (`crates/agent/src/extension_services/k8s_pod_handler.rs`) | **No** — requires rebuilding `carbide-agent` |

---

## DNS Configuration

### Using Unbound (`local_data.conf`)

Populate `deploy/files/unbound/local_data.conf` with the site controller VIP for each service and apply the changes to your cluster. Each entry in that file includes a comment describing the service, its port, and any hardcoded-hostname warnings. The Unbound pod will restart automatically once the updated ConfigMap is live.

### Using Other DNS Providers

Any DNS server that can serve authoritative responses for the `.forge` zone on your OOB management network is supported. Create A records for each hostname listed above pointing to the appropriate VIP.

> **Note:** `.forge` is not a publicly registered TLD. It is used exclusively on the isolated OOB management network and should not be forwarded to upstream public resolvers. Configure your DNS server to treat `.forge` as a locally authoritative zone with no upstream forwarding.

---

## Deployment Checklist

After configuring DNS, verify that all records resolve correctly from a host or DPU on the OOB management network:

```bash
for name in carbide-api.forge carbide-pxe.forge carbide-static-pxe.forge \
            carbide-ntp.forge unbound.forge otel-receiver.forge socks.forge; do
    printf "%-30s -> %s\n" "$name" "$(dig +short "$name" @<UNBOUND_VIP> || echo 'FAILED')"
done
```

Verify reachability on expected ports:

```bash
# NICo gRPC API (TLS handshake)
openssl s_client -connect carbide-api.forge:443 </dev/null 2>/dev/null | grep -E "^(subject|Verify)"

# PXE service
curl -sf --max-time 5 http://carbide-pxe.forge/ -o /dev/null && echo "carbide-pxe OK" || echo "carbide-pxe FAILED"

# Static PXE service
curl -sf --max-time 5 http://carbide-static-pxe.forge/ -o /dev/null && echo "carbide-static-pxe OK" || echo "carbide-static-pxe FAILED"

# NTP
ntpdate -q carbide-ntp.forge

# DNS resolver (should return a result for an external name)
dig +short +timeout=3 example.com @unbound.forge

# OTEL receiver (TLS handshake)
openssl s_client -connect otel-receiver.forge:443 </dev/null 2>/dev/null | grep -E "^(subject|Verify)"

# SOCKS proxy (TCP connect)
nc -zv socks.forge 1888
```

See `helm/PREREQUISITES.md` for additional deployment prerequisites.
