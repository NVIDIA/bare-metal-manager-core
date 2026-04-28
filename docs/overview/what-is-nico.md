# What is NICo?

NICo (NCX Infra Controller) is an open source suite of microservices for site-local, zero-trust bare-metal lifecycle management. It automates hardware discovery, firmware validation, DPU provisioning, network isolation, and tenant sanitization — enabling NVIDIA Cloud Partners (NCPs) and infrastructure operators to stand up and operate GB200/GB300-class AI infrastructure at scale.

NICo is open source under the Apache 2.0 license.

## The problem NICo solves

Operating GPU infrastructure at scale exposes a consistent set of operational gaps:

- **Rack bringup takes too long.** Hardware discovery, validation, firmware alignment, and network setup are largely manual. Every cluster ends up slightly different, and bringing a new rack online can take days or weeks.
- **Multi-tenancy is risky without hardened isolation.** Sharing GPU fleets safely requires strong workload isolation, predictable performance, and reliable tenant transitions. Without it, teams either over-provision or accept security risk.
- **Reusing bare metal between tenants is slow and error-prone.** Sanitization, attestation, and trust re-establishment often require custom scripts and manual steps, creating operational drift and risk.
- **Firmware and configuration drift is constant.** Across mixed hardware generations, BIOS, firmware, NIC drivers, and network configs diverge — making it difficult to maintain a stable, ISV-ready baseline.

NICo exists to make GPU infrastructure behave like a cloud primitive, not a bespoke ops project.

## What NICo does

NICo runs as a collection of microservices on a Kubernetes cluster co-located in the datacenter it manages (the "site controller"). It manages the full lifecycle of bare-metal hosts — from initial rack discovery through tenant provisioning, ongoing operations, and secure reuse.

Each managed host is a **BlueField DPU + host server pair**. The DPU acts as the enforcement boundary for network isolation and security; NICo provisions and manages it directly, independently of what runs on the host.

NICo's core responsibilities:

- Provision and manage DPU OS, firmware, and HBN configuration
- Maintain hardware inventory of all managed hosts
- Automate discovery, validation, and attestation via Redfish (out-of-band)
- Monitor hardware health continuously and react to health state changes
- Manage host firmware (UEFI, BMC) and enforce security lockdown
- Manage BMC and UEFI credentials per device via Redfish
- Allocate IP addresses, configure BGP routing, and manage DNS
- Enforce network isolation across Ethernet, InfiniBand, and NVLink planes
- Orchestrate host provisioning (PXE/iPXE), tenant release, and sanitization

## Components and Services

NICo is deployed as a set of core services running on the site controller Kubernetes cluster:

- **NICo Core (gRPC API)** — the central control plane. All components and external systems query and drive state through it. Exposes a gRPC API for internal component communication and a REST API for operator and ISV integration.
- **DHCP** — provides IP addresses to all underlay devices: Host BMCs, DPU BMCs, DPU OOB interfaces, and host overlay addresses.
- **PXE** — delivers OS images to managed hosts at boot time via iPXE. Hosts boot from PXE by default; a local bootable device is used if present. Stateless configurations can pin hosts to a specific image.
- **Hardware Health** — pulls health and configuration telemetry from each DPU agent and reports state back to NICo Core.
- **SSH Console** — provides virtual serial console access and logging over SSH. Console output from each host is streamed to the logging system, queryable via Grafana and `logcli`.
- **DNS** — provides domain name resolution using two services: `nico-dns` handles queries from the site controller and managed nodes; `unbound` provides recursive DNS to managed machines and instances.

Together these services are referred to as the **Site Controller**.

### Supporting Services

- **Site Agent** — maintains a northbound Temporal connection to NICo REST to sync data and delegate gRPC requests to NICo Core. Enables NICo REST to be deployed centrally in cloud while NICo Core runs on-site.
- **Admin CLI** — provides an admin-level command-line interface into NICo Core via the gRPC API.

### NICo REST

NICo REST is a collection of microservices that expose NICo's capabilities as a REST API — the primary interface for operators and ISVs. It can be deployed co-located with the site controller or centrally in cloud, with one or more Site Agents connecting from the datacenter. Multiple site controllers in different datacenters can connect to a single NICo REST deployment through their respective Site Agents.

## Architecture overview

![NICo architecture diagram](../static/nico_arch_diagram.png)

NICo is deployed as a suite of microservices on a Kubernetes cluster co-located in the datacenter it manages. This suite of microservices forms the control plane, known as the **Site Controller**. The Kubernetes cluster requires a minimum of three nodes for high availability, and all NICo control plane services communicate over gRPC.

### NICo Core as the single source of truth

NICo Core is the central control plane service and the only component that reads from and writes to the Postgres database, making it the single source of truth for all system state. Every other service — DHCP, PXE, hardware health — is stateless: they forward requests to NICo Core and derive their configuration from it rather than maintaining their own state.

NICo Core implements **state machines** for every resource it manages: managed hosts, network segments, InfiniBand partitions, and NVLink partitions. State handlers run periodically (typically every 30 seconds) and are the *only* component that may change a resource's lifecycle state. API calls from operators or tenants queue an intent ("provision this host"), and the state machine drives the actual transition. This makes lifecycle management deterministic and automatically retries on transient failures — a temporarily unreachable BMC does not require operator intervention.

### The DPU as the enforcement boundary

Each managed host is a BlueField DPU paired with a host server. The DPU is the critical architectural element: it runs the `dpu-agent`, which maintains a persistent gRPC connection to NICo Core, polls for its desired network configuration every 30 seconds, applies it via HBN (Host-Based Networking with Containerized Cumulus, configured via NVUE), and reports its observed state back. NICo never marks a configuration as applied until the DPU confirms it.

Because the DPU operates independently of the host OS, network isolation is enforced even if the host is compromised, unresponsive, or being sanitized. The host's primary networking path runs through the DPU — including a per-host DHCP server that runs on the DPU itself, so host DHCP traffic never reaches the underlay network.

### Out-of-band management via Redfish

NICo manages and monitors hosts exclusively through out-of-band channels. The **Site Explorer** component within NICo Core continuously crawls BMC endpoints over the OOB network using Redfish — collecting hardware inventory, firmware versions, power state, and boot configuration. This is how hosts are discovered, how DPUs are matched to their host servers via serial number correlation, and how provisioning sequences are triggered (power cycles, boot order changes, BIOS attribute configuration). The **Hardware Health** service independently scrapes BMC sensor data via Redfish on a 60-second interval and exports it as Prometheus metrics.

### Networking isolation

Tenant isolation across network planes is reconciled by dedicated monitor processes that continuously compare desired state against observed state:

- **Ethernet** — the DPU agent applies L3 VXLAN/EVPN configuration directly on the DPU via HBN
- **InfiniBand** — `IbFabricMonitor` reconciles P_Key partition assignments against UFM
- **NVLink** — `NvlPartitionMonitor` manages logical partition assignments via NMX-M APIs

A tenant's instance appears as `Configuring` until all applicable network planes confirm the desired configuration is in place.

## Where NICo fits

NICo sits below Kubernetes and platform layers. It exposes clean REST and gRPC APIs that higher-level systems — BMaaS, VMaaS, orchestration engines, ISV control planes — can consume directly. It does not dictate how scheduling, tenancy policy, or workloads are managed above it.

```
┌─────────────────────────────────────┐
│   ISV / NCP Control Plane           │
├─────────────────────────────────────┤
│   Kubernetes / BMaaS / VMaaS        │
├─────────────────────────────────────┤
│   NICo  ◄── you are here            │
├─────────────────────────────────────┤
│   BlueField DPU + Host Hardware     │
└─────────────────────────────────────┘
```

NICo is the layer that makes the hardware predictable, repeatable, and safe — so the layers above it can treat bare metal as a reliable building block.
